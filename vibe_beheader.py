#!/usr/bin/env python3
import sys
import os
import shutil
import struct
import subprocess
import random
import string
import json

def print_help_and_exit():
    print("""\
Usage: beheader.py <output> <image> <video|audio> [-options] [appendable...]

Polyglot generator for media files.

Arguments:
    output                Path of resulting polyglot file
    image                 Path of input image file
    video|audio           Path of input video (or audio) file
    appendable            Path(s) of files to append without parsing

Options:
    -h, --html <path>     Path to HTML document
    -p, --pdf <path>      Path to PDF document
    -z, --zip <path>      Path to ZIP-like archive (repeatable)
    -e, --extra <path>    Path to short (<200b) file to include near the header
    --help                Print this help message and exit

Notes:
    * Video (and audio) gets re-encoded to MP4, images get converted to PNG in an ICO container.
    * Repeated ZIP files (e.g. `-z foo.zip -z bar.zip`) will be re-packed into one file. In case of conflict, files in later archives overwrite previous files.
    * ZIP-like archives are inserted last, after any appendables.
    * The `--extra` data gets inserted at address 22. Input size is not regulated - exceeding ~200 bytes or less may break other components.
    * Dependencies: ffmpeg, imagemagick, zip, unzip, bento4 (https://www.bento4.com/downloads/)
""")
    sys.exit(1)

# Helpers
def number_to_4b_le(num):
    return struct.pack('<I', num)

def number_to_4b_be(num):
    return struct.pack('>I', num)

def pad_left(s, target_len, pad_char="0"):
    return str(s).rjust(target_len, pad_char)

def patch_zip_offsets(zip_bytes, offset_shift):
    """
    Parses a ZIP file binary, splits the EOCD, and shifts all internal offsets.
    Returns (patched_body_bytes, patched_eocd_bytes).
    """
    # Find EOCD (End of Central Directory) signature: 0x06054b50
    # Scan backwards from the end
    eocd_idx = -1
    for i in range(len(zip_bytes) - 22, max(len(zip_bytes) - 65557, -1), -1):
        if zip_bytes[i:i+4] == b'\x50\x4b\x05\x06':
            eocd_idx = i
            break
    
    if eocd_idx == -1:
        raise Exception("Could not find EOCD in ZIP file")

    body = bytearray(zip_bytes[:eocd_idx])
    eocd = bytearray(zip_bytes[eocd_idx:])

    # 1. Patch offsets in Central Directory Headers (Signature: 0x02014b50)
    # The 'Relative offset of local header' is at bytes 42-46
    idx = 0
    while True:
        idx = body.find(b'\x50\x4b\x01\x02', idx)
        if idx == -1:
            break
        
        current_offset = struct.unpack('<I', body[idx+42:idx+46])[0]
        new_offset = current_offset + offset_shift
        body[idx+42:idx+46] = struct.pack('<I', new_offset)
        idx += 4
    
    # 2. Patch offset in EOCD
    # The 'Offset of start of central directory' is at bytes 16-20
    current_cd_offset = struct.unpack('<I', eocd[16:20])[0]
    new_cd_offset = current_cd_offset + offset_shift
    eocd[16:20] = struct.pack('<I', new_cd_offset)

    return body, eocd

def main():
    # Parse command line by cloning argv
    argv = list(sys.argv)

    extra_data = b""
    html_path = None
    pdf_path = None
    zip_files = []

    # Search for supported flags, handle them, and remove them from argv
    i = len(argv) - 1
    while i >= 0:
        match = True
        curr = argv[i]
        
        if curr == "--help":
            print_help_and_exit()
        
        elif curr in ("--html", "-h"):
            if i + 1 < len(argv):
                html_path = argv[i + 1]
            else:
                match = False
        
        elif curr in ("--pdf", "-p"):
            if i + 1 < len(argv):
                pdf_path = argv[i + 1]
            else:
                match = False
        
        elif curr in ("--zip", "-z"):
            if i + 1 < len(argv):
                zip_files.append(argv[i + 1])
            else:
                match = False
        
        elif curr in ("--extra", "-e"):
            if i + 1 < len(argv):
                try:
                    with open(argv[i + 1], 'rb') as f:
                        extra_data = f.read()
                except Exception as e:
                    print(f"Error reading extra file: {e}")
                    sys.exit(1)
            else:
                match = False
        
        else:
            match = False
        
        if match:
            argv.pop(i + 1)
            argv.pop(i)
        
        i -= 1

    # Handle mandatory arguments
    # argv[0] is script name, so we need at least 4 items total (script + 3 args)
    if len(argv) < 4:
        print_help_and_exit()

    output_path = argv[1]
    image_path = argv[2]
    video_path = argv[3]

    # Treat remaining arguments as appendable binaries
    appendables = argv[4:]

    # Determine path to mp4edit utility
    mp4edit_path = "mp4edit"
    if os.path.exists("./mp4edit"):
        mp4edit_path = "./mp4edit"

    # Generate temp file base
    tmp_base = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    tmp_png = tmp_base + ".png"
    tmp_atom = tmp_base + ".atom"
    tmp_mp4_0 = tmp_base + "0.mp4"
    tmp_mp4_1 = tmp_base + "1.mp4"
    tmp_mp4_2 = tmp_base + "2.mp4"
    tmp_zip_dir = tmp_base + "dir"
    tmp_zip = tmp_base + ".zip"

    ftyp_buffer = bytearray(256 + 32)

    try:
        # Convert input image to 32 bpp PNG, strip all metadata
        subprocess.check_call(f'convert "{image_path}" -define png:color-type=6 -depth 8 -alpha on -strip "{tmp_png}"', shell=True)

        png_size = os.path.getsize(tmp_png)
        
        # ICO signature
        ftyp_buffer[2] = 1

        # Write the MP4 "ftyp" atom name
        ftyp_buffer[4:8] = b"ftyp"

        # VLC workaround (see original comments)
        ftyp_buffer[3] = 32
        
        # Standard MP4 "header" data
        header_data = bytes([
            0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70,
            0x69, 0x73, 0x6f, 0x6d, 0x00, 0x00, 0x02, 0x00,
            0x69, 0x73, 0x6f, 0x6d, 0x69, 0x73, 0x6f, 0x32,
            0x61, 0x76, 0x63, 0x31, 0x6d, 0x70, 0x34, 0x31,
        ])
        ftyp_buffer[256:256+len(header_data)] = header_data

        ftyp_buffer[12] = 32 # First image bit depth
        ftyp_buffer[14:18] = number_to_4b_le(png_size) # Image data size

        # Check video stream type
        probe_cmd = f'ffprobe -v error -select_streams v -show_entries stream=codec_type -of json "{video_path}"'
        try:
            probe_out = subprocess.check_output(probe_cmd, shell=True, stderr=subprocess.DEVNULL)
            probe_json = json.loads(probe_out)
            is_video = len(probe_json.get('streams', [])) > 0
        except:
            is_video = False

        # Re-encode input video
        if is_video:
            subprocess.check_call(f'ffmpeg -i "{video_path}" -c:v libx264 -strict -2 -preset slow -pix_fmt yuv420p -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" -f mp4 "{tmp_mp4_0}" -y', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.check_call(f'ffmpeg -i "{video_path}" -c:a aac -b:a 192k "{tmp_mp4_0}" -y', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Write atom to file
        with open(tmp_atom, 'wb') as f:
            f.write(ftyp_buffer)
        
        subprocess.check_call(f'{mp4edit_path} --replace ftyp:"{tmp_atom}" "{tmp_mp4_0}" "{tmp_mp4_1}"', shell=True)

        # Handle ZIP creation early so we have the data
        zip_body = b""
        zip_eocd = b""
        
        if zip_files:
            os.makedirs(tmp_zip_dir, exist_ok=True)
            for curr in zip_files:
                subprocess.check_call(f'unzip -o -d "{tmp_zip_dir}" "{curr}"', shell=True, stdout=subprocess.DEVNULL)
            
            cwd = os.getcwd()
            os.chdir(tmp_zip_dir)
            subprocess.check_call(f'zip -r9 "../{tmp_zip}" .', shell=True, stdout=subprocess.DEVNULL)
            os.chdir(cwd)
            
            with open(tmp_zip, 'rb') as f:
                raw_zip_data = f.read()
            
            # Temporarily separate body and EOCD, we don't know the offset yet
            # We will patch them later
            eocd_idx = -1
            for i in range(len(raw_zip_data) - 22, max(len(raw_zip_data) - 65557, -1), -1):
                if raw_zip_data[i:i+4] == b'\x50\x4b\x05\x06':
                    eocd_idx = i
                    break
            
            if eocd_idx != -1:
                zip_body = raw_zip_data[:eocd_idx]
                zip_eocd = raw_zip_data[eocd_idx:]
            else:
                print("Warning: Generated ZIP has no EOCD. Ignoring ZIP.")

        # Wrap HTML
        html_string = b""
        if html_path:
            with open(html_path, 'rb') as f:
                content = f.read()
                prefix = b"--><style>body{font-size:0}</style><div style=font-size:initial>"
                suffix = b"</div><!--"
                html_string = prefix + content + suffix
        
        with open(tmp_png, 'rb') as f:
            png_bytes = f.read()

        # Create skip atom
        # Now includes HTML + PNG + ZIP Body (unpatched)
        skip_payload_len = len(png_bytes) + len(html_string) + len(zip_body)
        skip_buffer_data = bytearray(skip_payload_len)
        
        cursor = 0
        if html_string:
            skip_buffer_data[cursor:cursor+len(html_string)] = html_string
            cursor += len(html_string)
        
        skip_buffer_data[cursor:cursor+len(png_bytes)] = png_bytes
        cursor += len(png_bytes)
        
        if zip_body:
            skip_buffer_data[cursor:] = zip_body
        
        skip_buffer_len = len(skip_buffer_data) + 8
        skip_buffer = bytearray(skip_buffer_len)
        skip_buffer[0:4] = number_to_4b_be(skip_buffer_len)
        skip_buffer[4:8] = b"skip"
        skip_buffer[8:] = skip_buffer_data

        with open(tmp_atom, 'wb') as f:
            f.write(skip_buffer)
        
        subprocess.check_call(f'{mp4edit_path} --insert skip:"{tmp_atom}" "{tmp_mp4_1}" "{tmp_mp4_2}"', shell=True)

        # Find offsets
        with open(tmp_mp4_2, 'rb') as f:
            mp4_ref_bytes = f.read()
        
        # skip header is the first 8 bytes of skip_buffer
        skip_header = skip_buffer[0:8]
        found_idx = mp4_ref_bytes.find(skip_header)
        if found_idx == -1:
             raise Exception("Could not find injected atom offset")
        
        # Calculate offsets
        payload_start = found_idx + 8
        png_offset = payload_start + len(html_string)
        zip_offset = png_offset + len(png_bytes)

        # Now that we know where the zip landed, we can patch the offsets
        # inside the MP4 file (overwriting the unpatched zip body)
        if zip_body and zip_eocd:
            # We reconstruct the full zip logic to perform patching, 
            # but we only write the body back to the middle of the file.
            # We keep the EOCD for the end.
            
            # Combine back to patch easily (or just patch the pieces we have)
            # Let's use the helper. We construct a fake full zip to use the helper.
            full_raw_zip = zip_body + zip_eocd
            patched_body, patched_eocd = patch_zip_offsets(full_raw_zip, zip_offset)
            
            # Overwrite the zip body in the file
            with open(tmp_mp4_2, 'r+b') as f:
                f.seek(zip_offset)
                f.write(patched_body)
            
            # Update our EOCD reference for appending later
            zip_eocd = patched_eocd

        # Set PNG data offset
        ftyp_buffer[18:22] = number_to_4b_le(png_offset)
        # Set ICO image count to 1 and clear atom name
        ftyp_buffer[4:8] = bytes([1, 0, 0, 0])

        # Write brands
        ftyp_buffer[240:256] = b"isomiso2avc1mp41"

        atom_free_addr = 22
        
        if extra_data:
            ftyp_buffer[atom_free_addr : atom_free_addr + len(extra_data)] = extra_data
            atom_free_addr += len(extra_data)
        
        ftyp_buffer[atom_free_addr : atom_free_addr + 4] = b"<!--"
        atom_free_addr += 4

        if pdf_path:
            with open(pdf_path, 'rb') as f:
                pdf_bytes = f.read()
            
            mp4_size = os.path.getsize(tmp_mp4_2)
            
            ftyp_buffer[atom_free_addr] = 0x0A
            ftyp_buffer[atom_free_addr + 1 : atom_free_addr + 10] = pdf_bytes[0:9]
            atom_free_addr += 10

            obj_string = ""
            offset = 30 + len(str(mp4_size))
            
            while True:
                offset -= 1
                length_val = mp4_size - atom_free_addr - len(extra_data) - offset
                obj_string = f"\n1 0 obj\n<</Length {length_val}>>\nstream\n"
                if offset == len(obj_string):
                    break
            
            obj_bytes = obj_string.encode('utf-8')
            insert_idx = atom_free_addr + len(extra_data)
            ftyp_buffer[insert_idx : insert_idx + len(obj_bytes)] = obj_bytes
            atom_free_addr += len(obj_bytes)

        # Write final atom and replace
        with open(tmp_atom, 'wb') as f:
            f.write(ftyp_buffer)
        
        subprocess.check_call(f'{mp4edit_path} --replace ftyp:"{tmp_atom}" "{tmp_mp4_2}" "{output_path}"', shell=True)

        # Fix bithack
        with open(output_path, 'r+b') as f:
            f.seek(3)
            f.write(bytes([0]))

        if pdf_path:
            obj_terminator = b"\nendstream\nendobj\n"
            with open(pdf_path, 'rb') as f:
                pdf_content = f.read()
            
            # Construct PDF buffer
            pdf_buffer = bytearray()
            pdf_buffer.extend(obj_terminator)
            pdf_buffer.extend(pdf_content)

            # Fix offsets
            xref_marker = b"\nxref"
            xref_start_idx = pdf_buffer.find(xref_marker)

            if xref_start_idx != -1:
                xref_start = xref_start_idx + 1
                offset_marker = b"\n0000000000"
                offset_start = pdf_buffer.find(offset_marker, xref_start) + 1
                startxref_marker = b"\nstartxref"
                startxref_start = pdf_buffer.find(startxref_marker, xref_start) + 1
                startxref_end = pdf_buffer.find(b"\n", startxref_start + 11)

                try:
                    if xref_start > 0 and offset_start > 0 and startxref_start > 0 and startxref_end > 0:
                        output_file_size = os.path.getsize(output_path)
                        
                        xref_header = pdf_buffer[xref_start : offset_start].decode('utf-8', errors='ignore')
                        count_str = xref_header.strip().replace("\n", " ").split(" ")[-1]
                        count = int(count_str)

                        curr = offset_start
                        for _ in range(count):
                            offset_str = pdf_buffer[curr : curr + 10].decode('utf-8')
                            offset_val = int(offset_str.strip())
                            new_offset = offset_val + output_file_size + len(obj_terminator)
                            
                            new_offset_str = pad_left(new_offset, 10)[:10]
                            pdf_buffer[curr : curr + 10] = new_offset_str.encode('utf-8')
                            
                            curr = pdf_buffer.find(b"\n", curr + 1) + 1
                        
                        startxref_str = pdf_buffer[startxref_start + 10 : startxref_end].decode('utf-8').strip()
                        startxref_val = int(startxref_str)
                        new_startxref = str(startxref_val + output_file_size + len(obj_terminator))
                        
                        nsx_bytes = new_startxref.encode('utf-8')
                        pdf_buffer[startxref_start + 10 : startxref_start + 10 + len(nsx_bytes)] = nsx_bytes
                        
                        eof_marker = b"\n%%EOF\n"
                        eof_pos = startxref_start + 10 + len(nsx_bytes)
                        pdf_buffer[eof_pos : eof_pos + len(eof_marker)] = eof_marker
                        
                        fill_start = eof_pos + len(eof_marker)
                        pdf_buffer[fill_start:] = b'\x00' * (len(pdf_buffer) - fill_start)
                        
                except Exception as e:
                    print(e)
                    print("WARNING: Failed to fix PDF offsets. This is probably still fine.")
            
            with open(output_path, 'ab') as f:
                f.write(pdf_buffer)

        # Append files
        for path in appendables:
            if path:
                with open(path, 'rb') as f_in:
                    with open(output_path, 'ab') as f_out:
                        shutil.copyfileobj(f_in, f_out)
        
        # Append ZIP EOCD pointer last (if exists)
        if zip_eocd:
            with open(output_path, 'ab') as f:
                f.write(zip_eocd)

    except Exception as e:
        print(e, file=sys.stderr)
        if hasattr(e, 'stderr'):
            print(e.stderr)

    finally:
        # Cleanup
        if os.path.exists(tmp_png): os.remove(tmp_png)
        if os.path.exists(tmp_atom): os.remove(tmp_atom)
        if os.path.exists(tmp_mp4_0): os.remove(tmp_mp4_0)
        if os.path.exists(tmp_mp4_1): os.remove(tmp_mp4_1)
        if os.path.exists(tmp_mp4_2): os.remove(tmp_mp4_2)
        if os.path.exists(tmp_zip): os.remove(tmp_zip)
        if os.path.exists(tmp_zip_dir): shutil.rmtree(tmp_zip_dir)

if __name__ == "__main__":
    main()
