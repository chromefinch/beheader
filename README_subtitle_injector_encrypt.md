# Subtitle Injector 🎬📁

`subtitle_injector.py` is a command-line polyglot generator that hides arbitrary **HTML** and **ZIP** archives inside an **MP4 Video/Audio** file. 

Unlike other polyglot generators that use MP4 `skip` or `free` atoms to hold payload data, this tool uses a **subtitle track** (specifically the `mov_text` timed text track) to allocate space, then overwrites the subtitle binary stream with the payloads.

For a typical 60-second video, you can easily hide nearly 200 MB of encrypted payloads
---

## 🛠️ How It Works (The Subtitle Exploitation)

The tool constructs a polyglot file using the following sequence:

1. **Magic FTYP Header**:
   - It crafts a 256-byte `ftyp` (file type) header for the MP4.
   - It overwrites the first compatible brand in the `ftyp` header with the ASCII bytes for `<!--` (`\x3C\x21\x2D\x2D`), which is the start of an HTML comment.
   - When loaded in a web browser, the browser treats the initial binary sequence of the video container as a comment and ignores it.

2. **Transcoding**:
   - The input media is transcoded via `ffmpeg` to H.264/AAC MP4 with `mov_text` compatibility, ensuring a standard, clean MP4 layout.

3. **Subtitle track allocation**:
   - The script creates a standard SRT subtitle file (`payload.srt`) containing a unique marker (`$$POLYGLOT_PAYLOAD_START$$`) followed by a long sequence of padding characters (`_`).
   - If the payload is larger than 64KB, the script splits the payload into multiple subtitle cue chunks to avoid line length limitations of SRT and MP4 parsers, formatting lines to 80 characters.
   - This SRT file is muxed into the media using `ffmpeg` as a timed text track (`-c:s mov_text`), reserving space directly inside the media stream.

4. **Payload Injection**:
   - The script scans the compiled MP4 binary for `$$POLYGLOT_PAYLOAD_START$$`.
   - It replaces the pre-allocated subtitle padding space with the HTML + ZIP payload:
     - First, it writes `-->` to close the initial `ftyp` comment.
     - It adds CSS to hide the raw binary garbage from the page layout (`body { visibility: hidden; }`).
     - It writes the raw HTML code inside a visible container (`#_p`).
     - It executes `window.stop()` in JS to prevent the browser from loading the trailing binary contents of the MP4 file.
     - Finally, it appends `<!--` to comment out any remaining binary data.
     - It inserts the ZIP archive body directly after the HTML code.
   - Offsets inside the ZIP file (such as Central Directory headers) are dynamically patched based on the absolute starting index of the ZIP body within the final MP4.

---

## 📋 Prerequisites

To run this tool, you must have the following command-line utilities installed and available in your system's `PATH`:

- **FFmpeg** (`ffmpeg`): For transcoding the media file and muxing the timed subtitle track.
- **Bento4** (`mp4edit`): For patching and replacing the `ftyp` header with the HTML-comment-hacked brand header.

### Installation

On macOS (using Homebrew):
```bash
brew install ffmpeg bento4
```

On Debian/Ubuntu:
```bash
sudo apt-get install ffmpeg bento4
```

---

## 🚀 Usage

```bash
python3 subtitle_injector.py <output> <input_media> [options]
```

### Arguments

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `output` | Positional | Target path for the generated polyglot file. |
| `input_media` | Positional | Path to the input video or audio file. |

### Options

| Flag | Long Flag | Description |
| :--- | :--- | :--- |
| `-H` | `--html` | Path to the HTML document to embed. Defaults to a placeholder header if omitted. |
| `-z` | `--zip` | Path to a ZIP archive to embed. Can be specified multiple times to merge archives. |
| `-S` | `--size` | Force allocation size in Megabytes (MB). Useful for pre-allocating space for large zip files. |

---

## 💡 Examples

### 1. Embed an HTML Page in a Video
Creates a file `play.mp4` that plays as a standard video in media players but opens an interactive HTML portal when loaded in a web browser.
```bash
python3 subtitle_injector.py play.mp4 raw_video.mov --html dashboard.html
python3 subtitle_injector.py -H subtitle_injector_encrypt.html -S 2 verysus3.mp4 sus.mp4
```

### 2. Embed HTML and ZIP Assets with Custom Allocation
Pre-allocates 5MB inside the subtitle stream to accommodate a larger ZIP archive containing extra files:
```bash
python3 subtitle_injector.py output.mp4 video.mp4 \
  --html game.html \
  --zip assets.zip \
  --size 5.0
```

---

## ⚠️ Notes and Limitations

> [!WARNING]
> FFmpeg handles subtitle tracks differently depending on size. If the final injection payload is larger than **60KB**, it could be split across fragmented subtitle packets in the media file, which might corrupt the media containers. For very large files, verify the integrity of both the MP4 playback and ZIP extraction.
