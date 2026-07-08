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
from typing import List, Tuple, Optional

# --- Configuration & Constants ---
REQUIRED_TOOLS = ["ffmpeg", "convert", "mp4edit"]

# --- Helper Functions ---

def check_dependencies():
    """Verifies that all required external tools are available in the PATH."""
    missing = [tool for tool in REQUIRED_TOOLS if not shutil.which(tool)]
    if missing:
        print(f"Error: Missing required external tools: {', '.join(missing)}", file=sys.stderr)
        print("Please ensure ffmpeg, imagemagick (convert), and bento4 (mp4edit) are installed.", file=sys.stderr)
        sys.exit(1)

def number_to_4b_le(num: int) -> bytes:
    return struct.pack('<I', num)

def number_to_4b_be(num: int) -> bytes:
    return struct.pack('>I', num)

def patch_zip_offsets(zip_bytes: bytearray, offset_shift: int) -> Tuple[bytearray, bytearray]:
    """
    Parses a ZIP binary, splits the EOCD, and shifts internal offsets.
    Returns (patched_body, patched_eocd).
    """
    # Find EOCD signature: 0x06054b50 (PK\x05\x06)
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

    # Patch offsets in Central Directory Headers (Signature: 0x02014b50 / PK\x01\x02)
    idx = 0
    while True:
        idx = body.find(b'\x50\x4b\x01\x02', idx)
        if idx == -1:
            break
        
        current_offset = struct.unpack('<I', body[idx+42:idx+46])[0]
        new_offset = current_offset + offset_shift
        body[idx+42:idx+46] = struct.pack('<I', new_offset)
        idx += 4
    
    # Patch offset in EOCD
    if len(eocd) >= 20:
        current_cd_offset = struct.unpack('<I', eocd[16:20])[0]
        new_cd_offset = current_cd_offset + offset_shift
        eocd[16:20] = struct.pack('<I', new_cd_offset)

    return body, eocd

def create_merged_zip(zip_paths: List[str], temp_dir: str) -> bytes:
    """Merges multiple ZIP files into a single bytes object using standard lib."""
    if not zip_paths:
        return b""
    
    out_path = os.path.join(temp_dir, "merged.zip")
    
    with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as z_out:
        for z_path in zip_paths:
            try:
                with zipfile.ZipFile(z_path, 'r') as z_in:
                    for item in z_in.infolist():
                        z_out.writestr(item, z_in.read(item.filename))
            except zipfile.BadZipFile:
                print(f"Warning: '{z_path}' is not a valid zip file. Skipping.", file=sys.stderr)
            except Exception as e:
                print(f"Warning: Error processing zip '{z_path}': {e}", file=sys.stderr)

    if os.path.exists(out_path):
        with open(out_path, 'rb') as f:
            return f.read()
    return b""

def main():
    parser = argparse.ArgumentParser(
        description="Polyglot generator for media files (Image + Video/Audio + HTML + PDF + ZIP)."
    )
    
    parser.add_argument("output", help="Path of resulting polyglot file")
    parser.add_argument("image", help="Path of input image file")
    parser.add_argument("input_media", help="Path of input video or audio file")
    parser.add_argument("appendables", nargs="*", help="Path(s) of files to append without parsing")

    parser.add_argument("-H", "--html", help="Path to HTML document")
    parser.add_argument("-p", "--pdf", help="Path to PDF document")
    parser.add_argument("-z", "--zip", action="append", help="Path to ZIP-like archive (repeatable)")
    parser.add_argument("-e", "--extra", help="Path to short (<200b) file to include near the header")

    args = parser.parse_args()

    check_dependencies()

    output_path = os.path.abspath(args.output)
    image_path = os.path.abspath(args.image)
    media_path = os.path.abspath(args.input_media)
    
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_png = os.path.join(tmp_dir, "temp.png")
        tmp_atom = os.path.join(tmp_dir, "temp.atom")
        tmp_mp4_0 = os.path.join(tmp_dir, "temp0.mp4")
        tmp_mp4_1 = os.path.join(tmp_dir, "temp1.mp4")
        tmp_mp4_2 = os.path.join(tmp_dir, "temp2.mp4")

        # --- 1. Process Image ---
        print("[*] Processing image...")
        try:
            # Force first frame [0] to prevent multiple output files for GIFs
            subprocess.check_call(
                ['convert', f"{image_path}[0]", '-define', 'png:color-type=6', '-depth', '8', 
                 '-alpha', 'on', '-strip', tmp_png],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError:
            sys.exit("Error: Failed to convert image. Check ImageMagick installation.")

        png_size = os.path.getsize(tmp_png)
        with open(tmp_png, 'rb') as f:
            png_bytes = f.read()

        # --- 2. Prepare FTYP Atom ---
        ftyp_buffer = bytearray(256 + 32)
        ftyp_buffer[2] = 1
        ftyp_buffer[3] = 32
        ftyp_buffer[4:8] = b"ftyp"

        header_data = bytes([
            0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70,
            0x69, 0x73, 0x6f, 0x6d, 0x00, 0x00, 0x02, 0x00,
            0x69, 0x73, 0x6f, 0x6d, 0x69, 0x73, 0x6f, 0x32,
            0x61, 0x76, 0x63, 0x31, 0x6d, 0x70, 0x34, 0x31,
        ])
        ftyp_buffer[256:256+len(header_data)] = header_data

        ftyp_buffer[12] = 32 
        ftyp_buffer[14:18] = number_to_4b_le(png_size)

        # --- 3. Process Video/Audio ---
        print("[*] Processing video/audio...")
        is_video = False
        try:
            probe_cmd = ['ffprobe', '-v', 'error', '-select_streams', 'v', 
                         '-show_entries', 'stream=codec_type', '-of', 'json', media_path]
            probe_out = subprocess.check_output(probe_cmd, stderr=subprocess.DEVNULL)
            if json.loads(probe_out).get('streams'):
                is_video = True
        except: pass

        ffmpeg_cmd = ['ffmpeg', '-y', '-i', media_path]
        if is_video:
            ffmpeg_cmd.extend([
                '-c:v', 'libx264', '-strict', '-2', '-preset', 'slow',
                '-pix_fmt', 'yuv420p', '-vf', 'scale=trunc(iw/2)*2:trunc(ih/2)*2',
                '-f', 'mp4', tmp_mp4_0
            ])
        else:
            ffmpeg_cmd.extend(['-c:a', 'aac', '-b:a', '192k', tmp_mp4_0])

        subprocess.check_call(ffmpeg_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with open(tmp_atom, 'wb') as f:
            f.write(ftyp_buffer)
        
        subprocess.check_call(
            ['mp4edit', '--replace', f'ftyp:{tmp_atom}', tmp_mp4_0, tmp_mp4_1],
            stdout=subprocess.DEVNULL
        )

        # --- 4. Prepare ZIP ---
        zip_body = b""
        zip_eocd = b""
        raw_zip_data = create_merged_zip(args.zip, tmp_dir)
        if raw_zip_data:
            zip_body, zip_eocd = patch_zip_offsets(bytearray(raw_zip_data), 0)

        # --- 5. Prepare HTML ---
        html_string = b""
        if args.html:
            try:
                with open(args.html, 'rb') as f:
                    html_string = b"--><style>body{font-size:0}</style><div style=font-size:initial>" + f.read() + b"</div><!--"
            except IOError as e:
                print(f"Error reading HTML: {e}", file=sys.stderr)

        # --- 6. Inject Payloads (SKIP Atom) ---
        print("[*] Injecting payloads...")
        skip_payload_len = len(html_string) + len(png_bytes) + len(zip_body)
        skip_buffer = bytearray(skip_payload_len + 8)
        skip_buffer[0:4] = number_to_4b_be(skip_payload_len + 8)
        skip_buffer[4:8] = b"skip"
        
        cursor = 8
        if html_string:
            skip_buffer[cursor:cursor+len(html_string)] = html_string
            cursor += len(html_string)
        
        skip_buffer[cursor:cursor+len(png_bytes)] = png_bytes
        cursor += len(png_bytes)
        
        if zip_body:
            skip_buffer[cursor:] = zip_body

        with open(tmp_atom, 'wb') as f:
            f.write(skip_buffer)
        
        subprocess.check_call(
            ['mp4edit', '--insert', f'skip:{tmp_atom}', tmp_mp4_1, tmp_mp4_2],
            stdout=subprocess.DEVNULL
        )

        # --- 7. Patch MP4 Offsets ---
        with open(tmp_mp4_2, 'rb') as f:
            mp4_ref_bytes = f.read()
        
        skip_header_sig = skip_buffer[0:8]
        found_idx = mp4_ref_bytes.find(skip_header_sig)
        if found_idx == -1:
            sys.exit("Critical Error: Could not find injected atom offset.")

        payload_start = found_idx + 8
        png_offset = payload_start + len(html_string)
        zip_offset = png_offset + len(png_bytes)

        if zip_body and zip_eocd:
            full_raw_zip = zip_body + zip_eocd
            patched_body, patched_eocd = patch_zip_offsets(full_raw_zip, zip_offset)
            with open(tmp_mp4_2, 'r+b') as f:
                f.seek(zip_offset)
                f.write(patched_body)
            zip_eocd = patched_eocd

        # --- 8. Finalize FTYP ---
        ftyp_buffer[18:22] = number_to_4b_le(png_offset)
        ftyp_buffer[4:8] = bytes([1, 0, 0, 0])
        ftyp_buffer[240:256] = b"isomiso2avc1mp41"

        atom_free_addr = 22
        if args.extra:
            try:
                with open(args.extra, 'rb') as f:
                    extra_data = f.read(200)
                    ftyp_buffer[atom_free_addr : atom_free_addr + len(extra_data)] = extra_data
                    atom_free_addr += len(extra_data)
            except IOError: pass

        ftyp_buffer[atom_free_addr : atom_free_addr + 4] = b"<!--"
        atom_free_addr += 4

        pdf_bytes = b""
        if args.pdf:
            try:
                with open(args.pdf, 'rb') as f:
                    pdf_bytes = f.read()
                mp4_size = os.path.getsize(tmp_mp4_2)
                ftyp_buffer[atom_free_addr] = 0x0A
                ftyp_buffer[atom_free_addr + 1 : atom_free_addr + 10] = pdf_bytes[0:9]
                atom_free_addr += 10
                
                offset = 30 + len(str(mp4_size))
                extra_len = len(open(args.extra, 'rb').read(200)) if args.extra else 0
                while True:
                    offset -= 1
                    length_val = mp4_size - atom_free_addr - extra_len - offset 
                    obj_string = f"\n1 0 obj\n<</Length {length_val}>>\nstream\n"
                    if offset == len(obj_string):
                        break
                
                obj_bytes = obj_string.encode('utf-8')
                insert_idx = atom_free_addr + extra_len
                ftyp_buffer[insert_idx : insert_idx + len(obj_bytes)] = obj_bytes
            except Exception as e:
                print(f"Error preparing PDF headers: {e}", file=sys.stderr)

        with open(tmp_atom, 'wb') as f:
            f.write(ftyp_buffer)
        
        subprocess.check_call(
            ['mp4edit', '--replace', f'ftyp:{tmp_atom}', tmp_mp4_2, output_path],
            stdout=subprocess.DEVNULL
        )

        # --- 9. Final Fixes & Appends ---
        print("[*] Finalizing file...")
        
        # ICO Bithack
        with open(output_path, 'r+b') as f:
            f.seek(3)
            f.write(bytes([0]))
        
        # PDF Append & Fix
        if args.pdf and pdf_bytes:
            # We must recalculate file size because injections might have changed data
            current_file_size = os.path.getsize(output_path)
            
            obj_terminator = b"\nendstream\nendobj\n"
            pdf_buffer = bytearray(obj_terminator + pdf_bytes)
            
            xref_marker = b"\nxref"
            xref_start_idx = pdf_buffer.find(xref_marker)

            if xref_start_idx != -1:
                try:
                    xref_start = xref_start_idx + 1
                    offset_marker = b"\n0000000000"
                    offset_start = pdf_buffer.find(offset_marker, xref_start) + 1
                    startxref_marker = b"\nstartxref"
                    startxref_start = pdf_buffer.find(startxref_marker, xref_start) + 1
                    startxref_end = pdf_buffer.find(b"\n", startxref_start + 11)

                    if xref_start > 0 and offset_start > 0 and startxref_start > 0:
                        
                        xref_header = pdf_buffer[xref_start : offset_start].decode('utf-8', errors='ignore')
                        count = int(xref_header.strip().split()[-1])

                        curr = offset_start
                        for _ in range(count):
                            offset_str = pdf_buffer[curr : curr + 10]
                            offset_val = int(offset_str)
                            # Use current file size for offset calculation
                            new_offset = offset_val + current_file_size + len(obj_terminator)
                            
                            new_offset_str = "{:010d}".format(new_offset).encode('utf-8')
                            pdf_buffer[curr : curr + 10] = new_offset_str
                            curr = pdf_buffer.find(b"\n", curr + 1) + 1
                        
                        startxref_val = int(pdf_buffer[startxref_start + 10 : startxref_end])
                        new_startxref = str(startxref_val + current_file_size + len(obj_terminator)).encode('utf-8')
                        pdf_buffer[startxref_start + 10 : startxref_start + 10 + len(new_startxref)] = new_startxref
                        
                        eof_marker = b"\n%%EOF\n"
                        eof_pos = startxref_start + 10 + len(new_startxref)
                        pdf_buffer[eof_pos : eof_pos + len(eof_marker)] = eof_marker
                        
                        fill_start = eof_pos + len(eof_marker)
                        if fill_start < len(pdf_buffer):
                            pdf_buffer[fill_start:] = b'\x00' * (len(pdf_buffer) - fill_start)
                            
                except Exception as e:
                    print(f"Warning: PDF Offset patching failed: {e}", file=sys.stderr)

            with open(output_path, 'ab') as f:
                f.write(pdf_buffer)

        # Append additional binaries
        if args.appendables:
            for path in args.appendables:
                try:
                    with open(path, 'rb') as f_in, open(output_path, 'ab') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                except IOError as e:
                    print(f"Error appending file {path}: {e}", file=sys.stderr)

        # Append ZIP EOCD last
        if zip_eocd:
            with open(output_path, 'ab') as f:
                f.write(zip_eocd)

    print(f"[+] Successfully created polyglot: {output_path}")

if __name__ == "__main__":
    main()
