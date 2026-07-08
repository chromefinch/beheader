#!/usr/bin/env python3
import subprocess
import json
import re
import sys
import argparse
import tempfile
import os
import math

def get_subtitle_streams(media_file):
    """Uses ffprobe to list all subtitle streams in the media file."""
    cmd = [
        "ffprobe", 
        "-v", "quiet", 
        "-print_format", "json", 
        "-show_streams", 
        "-select_streams", "s", 
        media_file
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        return data.get('streams', [])
    except subprocess.CalledProcessError as e:
        print(f"Error reading streams: {e}")
        return []
    except json.JSONDecodeError:
        print("Error decoding ffprobe output.")
        return []

def extract_subtitle_text(media_file, stream_index):
    """Extracts raw text from a specific subtitle stream using ffmpeg."""
    with tempfile.NamedTemporaryFile(suffix=".srt", delete=False) as temp_srt:
        temp_filename = temp_srt.name
    
    cmd = [
        "ffmpeg",
        "-y",
        "-v", "quiet",
        "-i", media_file,
        "-map", f"0:{stream_index}",
        "-c:s", "srt",
        temp_filename
    ]
    
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        with open(temp_filename, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            # Basic SRT parsing: remove numbers and timestamps
            text_lines = []
            for line in content.splitlines():
                line = line.strip()
                # Skip sequence numbers
                if line.isdigit():
                    continue
                # Skip timestamps
                if "-->" in line:
                    continue
                if line:
                    text_lines.append(line)
            
            return "\n".join(text_lines)
    except subprocess.CalledProcessError:
        # ffmpeg can fail if the stream is empty or unsupported format
        return None
    finally:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)

def calculate_shannon_entropy(data):
    """Calculates Shannon entropy of a string."""
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def analyze_text(text):
    """Analyzes text for anomalies like large word length, base64 density."""
    if not text:
        return None
    
    # Clean out html tags if they exist (common in subtitles)
    clean_text = re.sub(r'<[^>]+>', '', text)
    
    # To handle evasion by padding with spaces, we'll split by any whitespace
    words = re.split(r'\s+', clean_text)
    words = [w for w in words if w]
    
    if not words:
        return None
    
    max_word_len = max(len(w) for w in words)
    avg_word_len = sum(len(w) for w in words) / len(words)
    
    # Calculate percentage of characters in words > 20 characters
    long_words = [w for w in words if len(w) > 20]
    total_chars = sum(len(w) for w in words)
    long_words_chars = sum(len(w) for w in long_words)
    
    perc_long_words = (long_words_chars / total_chars) * 100 if total_chars > 0 else 0
    
    # Check Base64 character density (A-Z, a-z, 0-9, +, /, =)
    b64_chars = sum(1 for c in clean_text if re.match(r'[A-Za-z0-9+/=]', c))
    total_non_whitespace = sum(1 for c in clean_text if not c.isspace())
    b64_density = (b64_chars / total_non_whitespace) * 100 if total_non_whitespace > 0 else 0
    
    # Calculate entropy
    entropy = calculate_shannon_entropy(clean_text)

    # Determine Confidence (0-100)
    confidence = 0
    
    # Highly anomalous if maximum word length is > 60 in subtitles
    if max_word_len > 60:
        confidence += 30
    if max_word_len > 100:
        confidence += 20
        
    # If a large percentage of the text is made of long words
    if perc_long_words > 15:
        confidence += 20
    if perc_long_words > 50:
        confidence += 30
        
    # Base64 density in long text (binary payloads)
    if b64_density > 85 and avg_word_len > 10:
        confidence += 20
        
    # Extremely low entropy (e.g., padding of just underscores or spaces)
    # or extremely high entropy (encrypted)
    if entropy < 3.0:
        confidence += 20
    elif entropy > 5.5:
        confidence += 10
        
    # Cap at 100
    confidence = min(confidence, 100)
    
    return {
        "max_word_len": max_word_len,
        "avg_word_len": round(avg_word_len, 2),
        "perc_long_words": round(perc_long_words, 2),
        "b64_density": round(b64_density, 2),
        "entropy": round(entropy, 2),
        "confidence": confidence,
        "preview": clean_text[:100].replace('\n', ' ')
    }

def main():
    parser = argparse.ArgumentParser(description="Subtitle Anomaly Detector")
    parser.add_argument("media_file", help="Path to the media file (e.g., MP4)")
    args = parser.parse_args()

    if not os.path.exists(args.media_file):
        print(f"File not found: {args.media_file}")
        sys.exit(1)
        
    print(f"[*] Analyzing {args.media_file}...")
    streams = get_subtitle_streams(args.media_file)
    print(f"[*] Found {len(streams)} subtitle streams.")
    
    stream_results = []
    
    for stream in streams:
        idx = stream.get('index')
        lang = stream.get('tags', {}).get('language', 'und')
        codec = stream.get('codec_name', 'unknown')
        
        print(f"\n--- Stream {idx} (Lang: {lang}, Codec: {codec}) ---")
        text = extract_subtitle_text(args.media_file, idx)
        
        if text is None:
            print("[-] Failed to extract text.")
            continue
            
        stats = analyze_text(text)
        if not stats:
            print("[-] Stream is empty or contains no readable text.")
            continue
            
        print(f"  Max Word Length  : {stats['max_word_len']}")
        print(f"  Avg Word Length  : {stats['avg_word_len']}")
        print(f"  % Long Words     : {stats['perc_long_words']}%")
        print(f"  Base64 Density   : {stats['b64_density']}%")
        print(f"  Entropy          : {stats['entropy']}")
        print(f"  Preview          : {stats['preview']}")
        
        confidence = stats['confidence']
        stream_results.append({
            'idx': idx,
            'lang': lang,
            'confidence': confidence,
            'max_word_len': stats['max_word_len'],
            'avg_word_len': stats['avg_word_len'],
            'perc_long_words': stats['perc_long_words'],
            'b64_density': stats['b64_density'],
            'entropy': stats['entropy']
        })
        
        if confidence > 75:
            rating = "HIGH"
            color = "\033[91m" # Red
        elif confidence > 40:
            rating = "MEDIUM"
            color = "\033[93m" # Yellow
        else:
            rating = "LOW"
            color = "\033[92m" # Green
        reset = "\033[0m"
        
        print(f"  {color}Anomaly Confidence : {confidence}% ({rating}){reset}")

    print("\n" + "="*60)
    print("FINAL REPORT & CONSOLIDATED REVIEW")
    print("="*60)
    
    if not stream_results:
        print("No valid subtitle streams were analyzed.")
        return

    print("Individual Stream Scores:")
    for res in stream_results:
        print(f" - Stream {res['idx']:<3} (Lang: {res['lang']:<3}) -> Confidence: {res['confidence']}%")
        
    num_streams = len(stream_results)
    avg_confidence = sum(res['confidence'] for res in stream_results) / num_streams
    
    avg_max_word_len = sum(res['max_word_len'] for res in stream_results) / num_streams
    max_max_word_len = max(res['max_word_len'] for res in stream_results)
    
    avg_avg_word_len = sum(res['avg_word_len'] for res in stream_results) / num_streams
    max_avg_word_len = max(res['avg_word_len'] for res in stream_results)
    
    avg_perc_long = sum(res['perc_long_words'] for res in stream_results) / num_streams
    max_perc_long = max(res['perc_long_words'] for res in stream_results)
    
    avg_b64 = sum(res['b64_density'] for res in stream_results) / num_streams
    max_b64 = max(res['b64_density'] for res in stream_results)
    
    avg_entropy = sum(res['entropy'] for res in stream_results) / num_streams
    max_entropy = max(res['entropy'] for res in stream_results)
    
    print(f"\nConsolidated Statistics (Average | Maximum):")
    print(f"  Max Word Length  : {avg_max_word_len:.2f} | {max_max_word_len:.2f}")
    print(f"  Avg Word Length  : {avg_avg_word_len:.2f} | {max_avg_word_len:.2f}")
    print(f"  % Long Words     : {avg_perc_long:.2f}% | {max_perc_long:.2f}%")
    print(f"  Base64 Density   : {avg_b64:.2f}% | {max_b64:.2f}%")
    print(f"  Entropy          : {avg_entropy:.2f} | {max_entropy:.2f}")
    
    if avg_confidence > 50:
        overall_rating = "HIGH LIKELIHOOD OF MALICIOUS PAYLOADS"
        overall_color = "\033[91m"
    elif avg_confidence > 25:
        overall_rating = "MEDIUM (SUSPICIOUS)"
        overall_color = "\033[93m"
    else:
        overall_rating = "LOW (CLEAN)"
        overall_color = "\033[92m"
        
    print(f"\n{overall_color}TOTAL AVERAGE SCORE: {avg_confidence:.2f}% - {overall_rating}\033[0m")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
