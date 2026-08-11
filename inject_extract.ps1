#Requires -Version 5.1
<#
.SYNOPSIS
    Scatter-Gather Subtitle Injector / Extractor (Encrypted)

.DESCRIPTION
    PowerShell port of subtitle_injector_encrypt.html.

    Injects a payload file into an MP4 carrier by scatter-writing an
    encrypted, Base64-encoded binary stream into underscore segments
    embedded in the file. Supports optional XOR encryption and automatic
    multi-part spanning when the payload exceeds a single carrier's capacity.

    INJECT MODE
        Reads the carrier, maps every run of '_' bytes (10-80 chars, bounded
        by newlines) as writable slots, packages the payload with its filename,
        optionally XOR-encrypts it, wraps it in a framed binary stream, Base64-
        encodes the stream, and scatter-writes the characters into those slots.
        Outputs one file per part:
            Single part  ->  injected_<carrier>   (or -Output path)
            Multi-part   ->  injected_part1_<carrier>, injected_part2_<carrier>, …

    EXTRACT MODE
        Scans the carrier(s) for Base64 lines (10-100 chars, only A-Za-z0-9+/=_),
        strips underscores, concatenates, decodes the stream, reassembles parts
        across multiple carriers, XOR-decrypts, and writes the recovered file.

.PARAMETER Mode
    'inject' or 'extract'

.PARAMETER Carrier
    Path(s) to the carrier MP4 file(s).
    Inject  : supply a single file.
    Extract : supply one file per part in order  (part1.mp4, part2.mp4, …).

.PARAMETER Payload
    File to hide inside the carrier (inject mode only).

.PARAMETER Output
    Inject  : full path for the single-part output file.
              Ignored for multi-part (names are auto-generated).
    Extract : directory where the recovered file is saved.
              Defaults to the current working directory.

.PARAMETER Key
    Optional XOR encryption / decryption key string.
    Must match between inject and extract.

.EXAMPLE
    .\subtitle_injector.ps1 -Mode inject -Carrier movie.mp4 -Payload secret.zip
.EXAMPLE
    .\subtitle_injector.ps1 -Mode inject -Carrier movie.mp4 -Payload secret.zip -Key "mySecret"
.EXAMPLE
    .\subtitle_injector.ps1 -Mode extract -Carrier injected_movie.mp4 -Key "mySecret"
.EXAMPLE
    .\subtitle_injector.ps1 -Mode extract -Carrier part1.mp4,part2.mp4 -Key "mySecret"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('inject','extract')][string]$Mode,
    [Parameter(Mandatory)][string[]]$Carrier,
    [string]$Payload = "",
    [string]$Output  = "",
    [string]$Key     = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── CONSTANTS ────────────────────────────────────────────────────────────────
$UTF8            = [System.Text.Encoding]::UTF8
$POLYGLOT_PREFIX = $UTF8.GetBytes("`n-->`n")   # 5 bytes: 0x0A 0x2D 0x2D 0x3E 0x0A
$POLYGLOT_SUFFIX = $UTF8.GetBytes("<!--")       # 4 bytes
$MAGIC_FOOTER    = $UTF8.GetBytes('$$CPM10_EOF$$')  # 13 bytes
$UNDERSCORE      = [byte]0x5F
$HEADER_SIZE     = 10   # [4B sessionID][1B partIdx][1B flags][4B chunkLen]

# ─── LOGGING ──────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Msg, [string]$Level = 'info')
    $sym = switch ($Level) { 'ok' {'[+]'} 'err' {'[!]'} 'warn' {'[~]'} default {'[>]'} }
    $col = switch ($Level) { 'ok' {'Green'} 'err' {'Red'} 'warn' {'Yellow'} default {'Cyan'} }
    Write-Host "$sym $Msg" -ForegroundColor $col
}

function Format-Bytes([long]$n) {
    if ($n -eq 0) { return '0 B' }
    $units = 'B','KB','MB','GB'
    $i = [Math]::Min([Math]::Floor([Math]::Log($n, 1024)), 3)
    return '{0:F2} {1}' -f ($n / [Math]::Pow(1024, $i)), $units[$i]
}

# ─── BIG-ENDIAN BINARY HELPERS ────────────────────────────────────────────────
# All multi-byte values in the protocol are big-endian, matching the HTML's
# DataView default (littleEndian = false).

function Get-U32BE([byte[]]$d, [int]$o) {
    ([long]$d[$o] -shl 24) -bor ([long]$d[$o+1] -shl 16) -bor ([long]$d[$o+2] -shl 8) -bor [long]$d[$o+3]
}

function Set-U32BE([byte[]]$d, [int]$o, [long]$v) {
    $d[$o]   = [byte](($v -shr 24) -band 0xFF)
    $d[$o+1] = [byte](($v -shr 16) -band 0xFF)
    $d[$o+2] = [byte](($v -shr  8) -band 0xFF)
    $d[$o+3] = [byte]( $v          -band 0xFF)
}

function Get-U16BE([byte[]]$d, [int]$o) {
    ([int]$d[$o] -shl 8) -bor [int]$d[$o+1]
}

function Set-U16BE([byte[]]$d, [int]$o, [int]$v) {
    $d[$o]   = [byte](($v -shr 8) -band 0xFF)
    $d[$o+1] = [byte]( $v         -band 0xFF)
}

# ─── UTILITY ──────────────────────────────────────────────────────────────────
function Find-Seq([byte[]]$haystack, [byte[]]$needle) {
    $limit = $haystack.Length - $needle.Length
    for ($i = 0; $i -le $limit; $i++) {
        $hit = $true
        for ($j = 0; $j -lt $needle.Length; $j++) {
            if ($haystack[$i+$j] -ne $needle[$j]) { $hit = $false; break }
        }
        if ($hit) { return $i }
    }
    return -1
}

function Copy-Bytes([byte[]]$src, [int]$start, [int]$len) {
    # Returns a fresh byte[] slice — avoids PowerShell's Object[] unwrapping issue.
    $out = [byte[]]::new($len)
    [Array]::Copy($src, $start, $out, 0, $len)
    $out
}

# ─── XOR CIPHER ───────────────────────────────────────────────────────────────
# key cycles over the data, byte-by-byte.  If key is empty, data passes through.
function Invoke-Xor([byte[]]$data, [string]$keyStr) {
    if ([string]::IsNullOrEmpty($keyStr)) { return $data }
    [byte[]]$key = $UTF8.GetBytes($keyStr)
    [byte[]]$out = [byte[]]::new($data.Length)
    for ($i = 0; $i -lt $data.Length; $i++) {
        $out[$i] = $data[$i] -bxor $key[$i % $key.Length]
    }
    $out
}

# ─── WRITABLE SEGMENT MAPPER ──────────────────────────────────────────────────
# Scans for consecutive runs of 0x5F ('_') that are:
#   • 10-80 bytes long
#   • immediately preceded and followed by a newline (0x0A or 0x0D)
# These are the carrier's steganographic "slots".
function Get-Segments([byte[]]$data) {
    $segs  = [System.Collections.Generic.List[hashtable]]::new()
    $csIdx = -1
    $csLen = 0

    for ($i = 0; $i -lt $data.Length; $i++) {
        if ($data[$i] -eq $UNDERSCORE) {
            if ($csIdx -lt 0) { $csIdx = $i }
            $csLen++
        } else {
            if ($csIdx -ge 0) {
                $before = if ($csIdx -gt 0)              { $data[$csIdx - 1]        } else { 0 }
                $after  = if (($csIdx + $csLen) -lt $data.Length) { $data[$csIdx + $csLen] } else { 0 }
                if ($csLen -ge 10 -and $csLen -le 80 -and
                    ($before -eq 10 -or $before -eq 13) -and
                    ($after  -eq 10 -or $after  -eq 13)) {
                    $segs.Add(@{ start = $csIdx; len = $csLen })
                }
                $csIdx = -1; $csLen = 0
            }
        }
    }
    # Handle a segment at the very end of the file
    if ($csIdx -ge 0) {
        $before = if ($csIdx -gt 0) { $data[$csIdx-1] } else { 0 }
        $after  = if (($csIdx+$csLen) -lt $data.Length) { $data[$csIdx+$csLen] } else { 0 }
        if ($csLen -ge 10 -and $csLen -le 80 -and
            ($before -eq 10 -or $before -eq 13) -and
            ($after  -eq 10 -or $after  -eq 13)) {
            $segs.Add(@{ start = $csIdx; len = $csLen })
        }
    }
    return $segs
}

# ─── INJECT ───────────────────────────────────────────────────────────────────
function Invoke-Inject {
    if ([string]::IsNullOrEmpty($Payload)) {
        Write-Log "-Payload is required for inject mode." err; exit 1
    }
    $cPath = $Carrier[0]
    foreach ($p in @($cPath, $Payload)) {
        if (-not (Test-Path $p)) { Write-Log "File not found: $p" err; exit 1 }
    }

    [byte[]]$cBytes = [IO.File]::ReadAllBytes($cPath)
    [byte[]]$pBytes = [IO.File]::ReadAllBytes($Payload)
    $pName = [IO.Path]::GetFileName($Payload)
    $cName = [IO.Path]::GetFileName($cPath)
    $cDir  = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($cPath))
    if (-not $cDir) { $cDir = (Get-Location).Path }

    Write-Log "Carrier : $cName  ($(Format-Bytes $cBytes.Length))"
    Write-Log "Payload : $pName  ($(Format-Bytes $pBytes.Length))"

    # ── Package: [uint16 nameLen][nameBytes][payloadBytes] ────────────────────
    [byte[]]$nameBytes = $UTF8.GetBytes($pName)
    [byte[]]$cleartext = [byte[]]::new(2 + $nameBytes.Length + $pBytes.Length)
    Set-U16BE $cleartext 0 $nameBytes.Length
    [Array]::Copy($nameBytes, 0, $cleartext, 2,                    $nameBytes.Length)
    [Array]::Copy($pBytes,    0, $cleartext, 2 + $nameBytes.Length, $pBytes.Length)

    [byte[]]$encData = Invoke-Xor $cleartext $Key
    Write-Log "Encrypted payload : $(Format-Bytes $encData.Length)"

    # ── Measure capacity ──────────────────────────────────────────────────────
    $segs = Get-Segments $cBytes
    if ($segs.Count -eq 0) {
        Write-Log "No writable underscore segments found in carrier." err; exit 1
    }
    Write-Log "Segments found    : $($segs.Count)"

    # Each Base64 char costs ~1.34 raw bytes; subtract protocol overhead + safety margin
    $POLY_OVERHEAD = $POLYGLOT_PREFIX.Length + $HEADER_SIZE + $MAGIC_FOOTER.Length + $POLYGLOT_SUFFIX.Length
    $rawCap  = [long]0
    foreach ($s in $segs) { $rawCap += $s.len }
    $avail   = [long]([Math]::Floor($rawCap / 1.34)) - $POLY_OVERHEAD - 100

    Write-Log "Available capacity: ~$(Format-Bytes $avail)"
    if ($avail -le 0) { Write-Log "Carrier is too small to hold the payload." err; exit 1 }

    $total    = [long]$encData.Length
    $numParts = [int][Math]::Ceiling($total / $avail)
    $sessID   = [long](Get-Random -Minimum 1 -Maximum ([long]0xFFFFFFFF))

    Write-Log "Session ID : 0x$('{0:X8}' -f $sessID)"
    Write-Log "Parts      : $numParts"

    # ── Injection loop (one output file per part) ─────────────────────────────
    for ($part = 1; $part -le $numParts; $part++) {
        $off      = ($part - 1) * $avail
        $remain   = $total - $off
        $isLast   = ($remain -le $avail)
        $chunkLen = [int](if ($isLast) { $remain } else { $avail })
        [byte[]]$chunk = Copy-Bytes $encData $off $chunkLen

        Write-Log "Injecting part $part/$numParts  ($(Format-Bytes $chunkLen))…"

        # 10-byte span header
        [byte[]]$hdr = [byte[]]::new($HEADER_SIZE)
        Set-U32BE $hdr 0 $sessID
        $hdr[4] = [byte]$part
        $hdr[5] = [byte](if ($isLast) { 0x01 } else { 0x00 })
        Set-U32BE $hdr 6 [long]$chunkLen

        # Binary stream: PREFIX + header + chunk + MAGIC_FOOTER + SUFFIX
        $sLen     = $POLYGLOT_PREFIX.Length + $hdr.Length + $chunk.Length + $MAGIC_FOOTER.Length + $POLYGLOT_SUFFIX.Length
        [byte[]]$stream = [byte[]]::new($sLen)
        $ptr = 0
        foreach ($src in @($POLYGLOT_PREFIX, $hdr, $chunk, $MAGIC_FOOTER, $POLYGLOT_SUFFIX)) {
            [Array]::Copy($src, 0, $stream, $ptr, $src.Length)
            $ptr += $src.Length
        }

        # Base64-encode the entire stream
        [string]$b64     = [Convert]::ToBase64String($stream)
        [int]   $dataLen = $b64.Length

        # Scan segments from the end to find enough capacity
        $startSeg = -1
        $found    = 0
        for ($i = $segs.Count - 1; $i -ge 0; $i--) {
            $found += $segs[$i].len
            if ($found -ge $dataLen) { $startSeg = $i; break }
        }
        if ($startSeg -lt 0) {
            Write-Log "Allocation failed for part $part — not enough segment space." err; exit 1
        }

        # Clone the original carrier and scatter-write Base64 chars into slots
        [byte[]]$blob = [byte[]]::new($cBytes.Length)
        [Array]::Copy($cBytes, $blob, $cBytes.Length)

        $sp = 0; $si = $startSeg
        while ($sp -lt $dataLen -and $si -lt $segs.Count) {
            $seg = $segs[$si]
            $wl  = [Math]::Min($seg.len, $dataLen - $sp)
            for ($k = 0; $k -lt $wl; $k++) {
                $blob[$seg.start + $k] = [byte][char]$b64[$sp + $k]
            }
            $sp += $wl; $si++
        }

        # Build output filename / path
        if ($numParts -gt 1) {
            $outName = "injected_part${part}_$cName"
            $outPath = Join-Path $cDir $outName
        } elseif ($Output) {
            $outPath = $Output
        } else {
            $outPath = Join-Path $cDir "injected_$cName"
        }

        [IO.File]::WriteAllBytes($outPath, $blob)
        Write-Log "Saved: $outPath" ok
        Write-Host ("  Progress: {0}%" -f [int]([Math]::Round($part / $numParts * 100)))
    }

    Write-Log "ALL PARTS INJECTED." ok
}

# ─── EXTRACT ──────────────────────────────────────────────────────────────────
# Assembly state persists across calls to Process-Carrier for multi-part sets.
$script:asm = @{ parts = @{}; total = 0; sessID = $null }

function Process-Carrier([string]$cPath) {
    if (-not (Test-Path $cPath)) { Write-Log "File not found: $cPath" err; return }

    [byte[]]$data = [IO.File]::ReadAllBytes($cPath)
    Write-Log "Scanning: $([IO.Path]::GetFileName($cPath))  ($(Format-Bytes $data.Length))"

    # ── Collect valid Base64 lines (10-100 chars, chars in A-Za-z0-9+/=_) ────
    # Lines of all underscores decode to empty after stripping and are ignored.
    $sb      = [System.Text.StringBuilder]::new()
    $fragCnt = 0
    $lineS   = 0

    for ($i = 0; $i -le $data.Length; $i++) {
        if ($i -eq $data.Length -or $data[$i] -eq 10 -or $data[$i] -eq 13) {
            $len = $i - $lineS
            if ($len -ge 10 -and $len -le 100) {
                # Validate every byte in this line
                $ok = $true
                for ($k = $lineS; $k -lt $i; $k++) {
                    $b = $data[$k]
                    if (-not (
                        ($b -ge 65 -and $b -le 90)  -or   # A-Z
                        ($b -ge 97 -and $b -le 122) -or   # a-z
                        ($b -ge 48 -and $b -le 57)  -or   # 0-9
                        $b -eq 43 -or   # +
                        $b -eq 47 -or   # /
                        $b -eq 61 -or   # =
                        $b -eq 95       # _  (padding; stripped below)
                    )) { $ok = $false; break }
                }
                if ($ok) {
                    $added = $false
                    for ($k = $lineS; $k -lt $i; $k++) {
                        if ($data[$k] -ne 95) { $sb.Append([char]$data[$k]) | Out-Null; $added = $true }
                    }
                    if ($added) { $fragCnt++ }
                }
            }
            $lineS = $i + 1
        }
    }

    if ($fragCnt -eq 0) { Write-Log "No payload fragments found in this carrier." warn; return }
    Write-Log "Fragments : $fragCnt"

    # ── Decode Base64 stream ──────────────────────────────────────────────────
    [string]$fullB64 = $sb.ToString()
    while ($fullB64.Length % 4 -ne 0) { $fullB64 += '=' }

    try { [byte[]]$stream = [Convert]::FromBase64String($fullB64) }
    catch { Write-Log "Base64 decode error: $_" err; return }

    # ── Parse framed stream ───────────────────────────────────────────────────
    $pStart = Find-Seq $stream $POLYGLOT_PREFIX
    if ($pStart -lt 0) { Write-Log "POLYGLOT_PREFIX marker not found." err; return }

    $hStart = $pStart + $POLYGLOT_PREFIX.Length
    if ($stream.Length -lt $hStart + $HEADER_SIZE) { Write-Log "Stream too short." err; return }

    $sessID  = Get-U32BE  $stream  $hStart
    $partIdx = [int]$stream[$hStart + 4]
    $flags   = [int]$stream[$hStart + 5]
    $cLen    = [int](Get-U32BE $stream ($hStart + 6))
    $isEOF   = ($flags -band 0x01) -ne 0

    Write-Log "Part $partIdx  |  Len: $(Format-Bytes $cLen)  |  IsEOF: $isEOF"

    $cStart  = $hStart + $HEADER_SIZE
    $safeEnd = [Math]::Min($stream.Length, $cStart + $cLen)
    [byte[]]$chunk = Copy-Bytes $stream $cStart ($safeEnd - $cStart)

    # ── Update assembly state ─────────────────────────────────────────────────
    if ($null -ne $script:asm.sessID -and $script:asm.sessID -ne $sessID) {
        Write-Log "Session ID changed — resetting assembly." warn
        $script:asm = @{ parts = @{}; total = 0; sessID = $sessID }
    }
    $script:asm.sessID              = $sessID
    $script:asm.parts[$partIdx]     = $chunk
    if ($isEOF) { $script:asm.total = $partIdx }

    $have = $script:asm.parts.Count
    $need = if ($script:asm.total -gt 0) { $script:asm.total } else { '?' }
    Write-Log "Assembly: [$have / $need]"

    if ($script:asm.total -gt 0 -and $have -eq $script:asm.total) {
        Complete-Assembly
    }
}

function Complete-Assembly {
    Write-Log "Assembling $($script:asm.total) part(s)…"

    $size = [long]0
    for ($i = 1; $i -le $script:asm.total; $i++) { $size += $script:asm.parts[$i].Length }

    [byte[]]$full = [byte[]]::new($size)
    $ptr = 0
    for ($i = 1; $i -le $script:asm.total; $i++) {
        $p = $script:asm.parts[$i]
        [Array]::Copy($p, 0, $full, $ptr, $p.Length)
        $ptr += $p.Length
    }

    # ── Decrypt and unpack ────────────────────────────────────────────────────
    [byte[]]$dec = Invoke-Xor $full $Key

    try {
        $nameLen = Get-U16BE $dec 0
        $name    = $UTF8.GetString($dec, 2, $nameLen)
        $dStart  = 2 + $nameLen
        [byte[]]$payload = Copy-Bytes $dec $dStart ($dec.Length - $dStart)

        Write-Log "Extracted: $name  ($(Format-Bytes $payload.Length))" ok

        $outDir = if ($Output) { $Output } else { (Get-Location).Path }
        if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
        $outPath = Join-Path $outDir $name

        [IO.File]::WriteAllBytes($outPath, $payload)
        Write-Log "Saved: $outPath" ok
    } catch {
        Write-Log "Assembly finalization error: $_" err
    }
}

function Invoke-Extract {
    foreach ($c in $Carrier) { Process-Carrier $c }
    if ($script:asm.total -eq 0 -and $script:asm.parts.Count -gt 0) {
        Write-Log "Parts received but EOF not yet seen. Provide remaining carrier files." warn
    }
}

# ─── ENTRY POINT ──────────────────────────────────────────────────────────────
switch ($Mode) {
    'inject'  { Invoke-Inject }
    'extract' { Invoke-Extract }
}
