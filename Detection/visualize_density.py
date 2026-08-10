#!/usr/bin/env python3
import sys
import string
import math

def calculate_base64_density(chunk):
    if not chunk:
        return 0
    
    b64_chars = set((string.ascii_letters + string.digits + "+/=").encode())
    b64_count = sum(1 for byte in chunk if byte in b64_chars)
    return b64_count / len(chunk)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 visualize_density.py <file_path>")
        sys.exit(1)
        
    filepath = sys.argv[1]
    chunk_size = 200 * 1000 # 200KB to match the YARA rule
    
    try:
        with open(filepath, 'rb') as f:
            print(f"\nAnalyzing {filepath} in 200KB chunks...\n")
            print(f"{'Chunk':<15} | {'Histogram (Base64 Density)':<42} | {'Density %'}")
            print("-" * 75)
            
            chunk_idx = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                    
                density = calculate_base64_density(chunk)
                
                # Create the visual bar (40 chars wide)
                bar_length = 40
                filled_blocks = int(density * bar_length)
                empty_blocks = bar_length - filled_blocks
                
                bar = '█' * filled_blocks + '░' * empty_blocks
                
                # Highlight anomalies
                alert = " <-- [ANOMALY DETECTED]" if density > 0.75 else ""
                
                # Format chunk label
                mb_offset = (chunk_idx * chunk_size) / 1000000
                label = f"#{chunk_idx} ({mb_offset:.1f}MB)"
                
                print(f"{label:<15} | {bar} | {density*100:>5.1f}%{alert}")
                
                chunk_idx += 1
                
    except FileNotFoundError:
        print(f"Error: Could not find file {filepath}")

if __name__ == "__main__":
    main()
