#!/usr/bin/env python3
import sys
import os
import shutil
import struct
import subprocess
import json
import argparse
import tempfile
import zipfile
from typing import List, Tuple
import math

# --- Configuration & Constants ---
REQUIRED_TOOLS = ["ffmpeg", "mp4edit"]
# Unique marker to locate the subtitle payload in the binary
PAYLOAD_MARKER = b"$$POLYGLOT_PAYLOAD_START$$"
# HTML Comment Start (<!--) and End (-->)
COMMENT_START = b"\x3C\x21\x2D\x2D"
COMMENT_END = b"\x2D\x2D\x3E"

US_CONSTITUTION = "We the People of the United States, in Order to form a more perfect Union, establish Justice, insure domestic Tranquility, provide for the common defence, promote the general Welfare, and secure the Blessings of Liberty to ourselves and our Posterity, do ordain and establish this Constitution for the United States of America. "

def get_constitution_padding(size: int) -> str:
    repeats = (size // len(US_CONSTITUTION)) + 1
    return (US_CONSTITUTION * repeats)[:size]

def check_dependencies():
    """Verifies that all required external tools are available in the PATH."""
    missing = [tool for tool in REQUIRED_TOOLS if not shutil.which(tool)]
    if missing:
        print(f"Error: Missing required external tools: {', '.join(missing)}", file=sys.stderr)
        print("Please ensure ffmpeg and bento4 (mp4edit) are installed.", file=sys.stderr)
        sys.exit(1)

LANGUAGES = [
    "eng", "spa", "fra", "deu", "zho", "jpn", "rus", "por", "ita", "nld",
    "swe", "nor", "dan", "fin", "pol", "tur", "ell", "ces", "hun", "ron",
    "ara", "heb", "hin", "kor", "msa", "tha", "vie", "ind", "fil", "ukr",
    "afr", "sqi", "amh", "arg", "hye", "asm", "ast", "aze", "eus", "bel",
    "ben", "bos", "bre", "bul", "mya", "cat", "cos", "hrv", "est", "glg",
    "kat", "guj", "isl", "ina", "gle", "kab", "kan", "kas", "kaz", "khm",
    "kir", "kur", "lav", "lit", "mkd", "mai", "mal", "mar", "mon", "nep",
    "nob", "nno", "oci", "ori", "pus", "fas", "pan", "srd", "gla", "srp",
    "sin", "slk", "slv", "tgl", "tam", "tat", "tel", "uig", "uzb", "wln",
    "cym", "zul"
]

VARIATIONS = [
    "",              # Normal
    "SRT",           # SRT text
    "SDH",           # Subtitles for the Deaf and Hard of hearing
    "Forced",        # Forced Narrative
    "CC",            # Closed Captions
    "Commentary"     # Director's commentary
]

def get_video_duration(media_path: str) -> float:
    try:
        output = subprocess.check_output(
            ['ffprobe', '-v', 'error', '-show_entries', 'format=duration',
             '-of', 'default=noprint_wrappers=1:nokey=1', media_path]
        )
        return float(output.strip())
    except Exception as e:
        print(f"Warning: Could not get video duration, defaulting to 60s. {e}", file=sys.stderr)
        return 60.0

def number_to_4b_be(num: int) -> bytes:
    return struct.pack('>I', num)

def patch_zip_offsets(zip_bytes: bytearray, offset_shift: int) -> Tuple[bytearray, bytearray]:
    """Parses ZIP binary, splits EOCD, and shifts internal offsets."""
    eocd_idx = -1
    search_limit = max(len(zip_bytes) - 65557, -1)
    
    for i in range(len(zip_bytes) - 22, search_limit, -1):
        if zip_bytes[i:i+4] == b'\x50\x4b\x05\x06':
            eocd_idx = i
            break
    
    if eocd_idx == -1:
        return bytearray(), bytearray()

    body = zip_bytes[:eocd_idx]
    eocd = zip_bytes[eocd_idx:]

    idx = 0
    while True:
        idx = body.find(b'\x50\x4b\x01\x02', idx)
        if idx == -1:
            break
        
        current_offset = struct.unpack('<I', body[idx+42:idx+46])[0]
        new_offset = current_offset + offset_shift
        body[idx+42:idx+46] = struct.pack('<I', new_offset)
        idx += 4
    
    if len(eocd) >= 20:
        current_cd_offset = struct.unpack('<I', eocd[16:20])[0]
        new_cd_offset = current_cd_offset + offset_shift
        eocd[16:20] = struct.pack('<I', new_cd_offset)

    return body, eocd

def create_merged_zip(zip_paths: List[str], temp_dir: str) -> bytes:
    """Merges multiple ZIP files into a single bytes object."""
    if not zip_paths:
        return b""
    
    out_path = os.path.join(temp_dir, "merged.zip")
    with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as z_out:
        for z_path in zip_paths:
            try:
                with zipfile.ZipFile(z_path, 'r') as z_in:
                    for item in z_in.infolist():
                        z_out.writestr(item, z_in.read(item.filename))
            except Exception as e:
                print(f"Warning: Error processing zip '{z_path}': {e}", file=sys.stderr)

    if os.path.exists(out_path):
        with open(out_path, 'rb') as f:
            return f.read()
    return b""

def main():
    parser = argparse.ArgumentParser(description="Polyglot generator: MP4 (Video) + HTML (Browser) + ZIP.")
    parser.add_argument("output", help="Path of resulting polyglot file")
    parser.add_argument("input_media", help="Path of input video or audio file")
    parser.add_argument("-H", "--html", help="Path to HTML document")
    parser.add_argument("-z", "--zip", action="append", help="Path to ZIP archives")
    parser.add_argument("-S", "--size", type=float, help="Force allocation size in MB")
    
    args = parser.parse_args()
    check_dependencies()

    output_path = os.path.abspath(args.output)
    media_path = os.path.abspath(args.input_media)
    
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_atom = os.path.join(tmp_dir, "temp.atom")
        tmp_srt = os.path.join(tmp_dir, "payload.srt")
        tmp_mp4_initial = os.path.join(tmp_dir, "temp_initial.mp4")
        tmp_mp4_muxed = os.path.join(tmp_dir, "temp_muxed.mp4")

        # --- 1. Prepare FTYP Atom (The Magic Header) ---
        ftyp_buffer = bytearray(256)
        ftyp_buffer[0:4] = number_to_4b_be(256) # Atom Size
        ftyp_buffer[4:8] = b"ftyp"
        ftyp_buffer[8:12] = b"mp42"            # Major Brand
        ftyp_buffer[12:16] = number_to_4b_be(0) # Version
        
        # FIRST compatible brand (offset 16) is the comment start
        ftyp_buffer[16:20] = COMMENT_START      # <!--
        ftyp_buffer[20:24] = b"isom"
        ftyp_buffer[24:28] = b"mp42"
        ftyp_buffer[28:32] = b"avc1"
        
        with open(tmp_atom, 'wb') as f:
            f.write(ftyp_buffer)

        # --- 2. Process Video/Audio ---
        print("[*] Transcoding media to ensure MP4 structure...")
        ffmpeg_cmd = [
            'ffmpeg', '-y', '-i', media_path,
            '-c:v', 'libx264', '-preset', 'medium', '-crf', '20',
            '-pix_fmt', 'yuv420p', '-movflags', '+faststart',
            '-f', 'mp4', tmp_mp4_initial
        ]
        subprocess.check_call(ffmpeg_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # --- 3. Prepare Payloads ---
        zip_body, zip_eocd = b"", b""
        raw_zip = create_merged_zip(args.zip, tmp_dir)
        if raw_zip:
            zip_body, zip_eocd = patch_zip_offsets(bytearray(raw_zip), 0)

        html_raw = b"<h1>Polyglot</h1>"
        if args.html:
            with open(args.html, 'rb') as f:
                html_raw = f.read()

        # --- 4. Construct HTML Payload Wrapper ---
        payload_prefix = b"\n" + COMMENT_END + b"\n" # -->
        
        html_wrapper_start = b"""
        <style>
            body { visibility: hidden; margin: 0; padding: 0; overflow: hidden; background-color: #000; }
            #_p { visibility: visible; position: absolute; top: 0; left: 0; width: 100vw; height: 100vh; background-color: #fff; overflow: auto; z-index: 9999; }
        </style>
        <div id="_p">
        """
        
        html_wrapper_end = b"""
        </div>
        <script>try{window.stop();}catch(e){}</script>
        <!-- 
        """
        
        full_payload_content = payload_prefix + html_wrapper_start + html_raw + html_wrapper_end + zip_body
        
        # --- 5. Allocate Subtitle Space ---
        # Calculate needed size
        alloc_size = int(len(full_payload_content) * 1.5) + 5000
        if args.size:
            alloc_size = int(args.size * 1024 * 1024)
        
        print(f"[*] Allocating {alloc_size} bytes for payload...")
        
        # Chunking Logic to support large payloads (>64KB)
        MAX_CHUNK_SIZE = 60000 
        
        video_duration = get_video_duration(tmp_mp4_initial)
        max_cues_per_track = max(1, int(video_duration // 10))
        track_capacity = max_cues_per_track * MAX_CHUNK_SIZE
        num_tracks = math.ceil(alloc_size / track_capacity)
        
        srt_paths = []
        remaining_size = alloc_size
        track_idx = 0
        
        while remaining_size > 0:
            tmp_srt = os.path.join(tmp_dir, f"payload_{track_idx}.srt")
            srt_paths.append(tmp_srt)
            
            with open(tmp_srt, "w") as f:
                if track_idx == 0:
                    marker_str = PAYLOAD_MARKER.decode('utf-8').ljust(80, ' ')
                    pad_size = min(remaining_size, track_capacity - 80)
                    track_content = marker_str + get_constitution_padding(pad_size)
                else:
                    pad_size = min(remaining_size, track_capacity)
                    track_content = get_constitution_padding(pad_size)
                    
                remaining_size -= len(track_content)
                
                counter = 1
                start_sec = 0
                while track_content:
                    chunk_text_raw = track_content[:MAX_CHUNK_SIZE]
                    track_content = track_content[MAX_CHUNK_SIZE:]
                    
                    chunk_lines = [chunk_text_raw[i:i+80] for i in range(0, len(chunk_text_raw), 80)]
                    chunk_text_formatted = "\n".join(chunk_lines)
                    
                    end_sec = start_sec + 10 
                    t_start = "{:02d}:{:02d}:{:02d},000".format(int(start_sec // 3600), int((start_sec % 3600) // 60), int(start_sec % 60))
                    t_end = "{:02d}:{:02d}:{:02d},000".format(int(end_sec // 3600), int((end_sec % 3600) // 60), int(end_sec % 60))
                    
                    f.write(f"{counter}\n{t_start} --> {t_end}\n{chunk_text_formatted}\n\n")
                    counter += 1
                    start_sec += 10
            
            track_idx += 1

        # --- 6. Mux Subtitle Track ---
        print(f"[*] Muxing {len(srt_paths)} subtitle track(s)...")
        ffmpeg_mux_cmd = ['ffmpeg', '-y', '-i', tmp_mp4_initial]
        for srt_path in srt_paths:
            ffmpeg_mux_cmd.extend(['-i', srt_path])
            
        ffmpeg_mux_cmd.extend(['-c:v', 'copy', '-c:a', 'copy', '-c:s', 'mov_text'])
        
        ffmpeg_mux_cmd.extend(['-map', '0:v', '-map', '0:a?'])
        for i in range(len(srt_paths)):
            ffmpeg_mux_cmd.extend(['-map', f'{i+1}'])
            
        for i in range(len(srt_paths)):
            lang_idx = i // len(VARIATIONS)
            var_idx = i % len(VARIATIONS)
            lang = LANGUAGES[lang_idx] if lang_idx < len(LANGUAGES) else "und"
            variation = VARIATIONS[var_idx]
            
            if lang_idx < len(LANGUAGES):
                if variation:
                    ffmpeg_mux_cmd.extend([f'-metadata:s:s:{i}', f'language={lang}', f'-metadata:s:s:{i}', f'title={variation}'])
                else:
                    ffmpeg_mux_cmd.extend([f'-metadata:s:s:{i}', f'language={lang}'])
            else:
                ffmpeg_mux_cmd.extend([f'-metadata:s:s:{i}', f'language={lang}', f'-metadata:s:s:{i}', f'title=Track {i+1}'])
            
        ffmpeg_mux_cmd.append(tmp_mp4_muxed)
        
        subprocess.check_call(
            ffmpeg_mux_cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        # --- 7. Replace FTYP Atom ---
        print("[*] Patching FTYP header...")
        subprocess.check_call(
            ['mp4edit', '--replace', f'ftyp:{tmp_atom}', tmp_mp4_muxed, output_path],
            stdout=subprocess.DEVNULL
        )

        # --- 8. Inject Payload ---
        print("[*] Injecting HTML/ZIP payload...")
        
        with open(output_path, 'r+b') as f:
            file_bytes = f.read()
            
            payload_marker_idx = file_bytes.find(PAYLOAD_MARKER)
            if payload_marker_idx == -1:
                sys.exit("Error: Could not locate subtitle payload container.")

            # Scan for accidental "-->"
            header_end = 20
            accidental_closer = file_bytes.find(COMMENT_END, header_end, payload_marker_idx)
            
            if accidental_closer != -1:
                print(f"WARNING: Accidental HTML comment closer (-->) found at offset {accidental_closer}.", file=sys.stderr)

            # Zip Offsets
            zip_start_offset = payload_marker_idx + len(payload_prefix) + len(html_wrapper_start) + len(html_raw) + len(html_wrapper_end)
            final_zip_blob = b""
            if zip_body:
                patched_body, _ = patch_zip_offsets(zip_body + zip_eocd, zip_start_offset)
                final_zip_blob = patched_body + _

            # Construct Payload
            final_injection = (
                payload_prefix + 
                html_wrapper_start + 
                html_raw + 
                html_wrapper_end + 
                final_zip_blob + 
                b"<!--" 
            )
            
            # Check size against what we ACTUALLY have allocated (approximate check)
            # Since we chunked, the total allocated space is roughly alloc_size + marker len
            if len(final_injection) > len(PAYLOAD_MARKER) + alloc_size:
                 print(f"Error: Payload ({len(final_injection)}) is larger than allocated space ({alloc_size}).", file=sys.stderr)
                 sys.exit(1)

            # WARNING for large payloads
            if len(final_injection) > 60000:
                print("WARNING: Payload > 60KB. If FFmpeg fragmented the subtitle track, injection might corrupt video data.", file=sys.stderr)
                print("         Verify the output file works correctly.", file=sys.stderr)

            f.seek(payload_marker_idx)
            f.write(final_injection)

    print(f"[+] Success: {output_path}")

if __name__ == "__main__":
    main()
