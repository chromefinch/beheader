param(
    [Parameter(Position=0)]
    [string]$File,
    [Parameter(Position=1)]
    [string]$Password
)

# Show usage help when running without arguments
if ([string]::IsNullOrWhiteSpace($File)) {
    Write-Host "=== Polyglot Payload Extractor ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\extract.ps1 <my_file.mp4> [<password>]"
    Write-Host ""
    exit 0
}

# If the file is provided but no password is, prompt the user for it
if ($null -eq $Password -or $Password -eq "") {
    $Password = Read-Host -Prompt "Enter decryption password (press Enter for none)"
}

Write-Host "=== Polyglot Payload Extractor ===" -ForegroundColor Cyan
Write-Host ""

# --- Step 1: Read the file ---
if (-not (Test-Path $File)) {
    Write-Host "ERROR: File not found: $File" -ForegroundColor Red
    exit 1
}

$B = [IO.File]::ReadAllBytes($File)
Write-Host ("Input file: {0} ({1} bytes)" -f $File, $B.Length) -ForegroundColor Green

# Locate the end of the HTML wrapper if it exists (using optimized IndexOf search for "window.stop")
$scanStart = 0
$stopIdx = -1
$i = 0
while ($true) {
    $i = [Array]::IndexOf($B, [byte]119, $i) # 'w'
    if ($i -eq -1 -or $i -gt ($B.Length - 11)) { break }
    # check for "indow.stop"
    if ($B[$i+1] -eq 105 -and $B[$i+2] -eq 110 -and $B[$i+3] -eq 100 -and $B[$i+4] -eq 111 -and 
        $B[$i+5] -eq 119 -and $B[$i+6] -eq 46 -and $B[$i+7] -eq 115 -and $B[$i+8] -eq 116 -and 
        $B[$i+9] -eq 111 -and $B[$i+10] -eq 112) {
        $stopIdx = $i
        break
    }
    $i++
}

if ($stopIdx -ne -1) {
    $scanStart = $stopIdx + 200
    Write-Host ("Skipping HTML wrapper. Starting scan at offset 0x{0:X}" -f $scanStart) -ForegroundColor Green
} else {
    $scanStart = 0
}

# --- Step 2: Extract stream chunks ---
$streamBytes = New-Object System.Collections.Generic.List[byte]

# Scan for Binary Mode Chunks: 0xCA, 0xFE, 0xBA, 0xBE (using optimized IndexOf search starting at $scanStart)
Write-Host "Scanning for CAFEBABE binary chunks..." -ForegroundColor Yellow
$i = $scanStart
while ($true) {
    $i = [Array]::IndexOf($B, [byte]0xCA, $i)
    if ($i -eq -1 -or $i -gt ($B.Length - 5)) { break }
    if ($B[$i+1] -eq 0xFE -and $B[$i+2] -eq 0xBA -and $B[$i+3] -eq 0xBE) {
        $len = $B[$i+4]
        if ($len -gt 0 -and ($i + 5 + $len) -le $B.Length) {
            $chunkBytes = New-Object byte[] $len
            [Array]::Copy($B, $i + 5, $chunkBytes, 0, $len)
            $streamBytes.AddRange($chunkBytes)
            $i += (4 + $len)
        } else {
            $i++
        }
    } else {
        $i++
    }
}

# If no binary chunks found, scan for Text Mode base64 chunks: {{{{ ... }}}} (using optimized IndexOf search starting at $scanStart)
if ($streamBytes.Count -eq 0) {
    Write-Host "No binary chunks found. Scanning for Text Mode chunks ({{{{ ... }}}})..." -ForegroundColor Yellow
    
    $base64Builder = New-Object System.Text.StringBuilder
    
    $i = $scanStart
    while ($true) {
        $i = [Array]::IndexOf($B, [byte]0x7B, $i)
        if ($i -eq -1 -or $i -gt ($B.Length - 8)) { break }
        if ($B[$i+1] -eq 0x7B -and $B[$i+2] -eq 0x7B -and $B[$i+3] -eq 0x7B) {
            # Find end anchor within 2000 bytes limit
            $endIdx = -1
            $searchLimit = [Math]::Min($i + 2000, $B.Length - 4)
            for ($j = $i + 4; $j -lt $searchLimit; $j++) {
                if ($B[$j] -eq 0x7D -and $B[$j+1] -eq 0x7D -and $B[$j+2] -eq 0x7D -and $B[$j+3] -eq 0x7D) {
                    $endIdx = $j
                    break
                }
            }
            if ($endIdx -ne -1) {
                $charCount = $endIdx - ($i + 4)
                $isValid = $true
                $chunkCharsFiltered = New-Object System.Collections.Generic.List[char]
                for ($k = 0; $k -lt $charCount; $k++) {
                    $byteVal = $B[$i + 4 + $k]
                    if (($byteVal -ge 65 -and $byteVal -le 90) -or 
                        ($byteVal -ge 97 -and $byteVal -le 122) -or 
                        ($byteVal -ge 48 -and $byteVal -le 57) -or 
                        ($byteVal -eq 43) -or ($byteVal -eq 47) -or ($byteVal -eq 61)) {
                        $chunkCharsFiltered.Add([char]$byteVal)
                    } elseif ($byteVal -eq 32 -or $byteVal -eq 9 -or $byteVal -eq 10 -or $byteVal -eq 13) {
                        # Skip whitespace
                    } else {
                        $isValid = $false
                        break
                    }
                }
                if ($isValid) {
                    $chunkString = [string]::new($chunkCharsFiltered.ToArray())
                    $base64Builder.Append($chunkString) | Out-Null
                }
                $i = $endIdx + 3
            } else {
                $i++
            }
        } else {
            $i++
        }
    }
    
    $base64Str = $base64Builder.ToString().Trim()
    if (-not [string]::IsNullOrEmpty($base64Str)) {
        while (($base64Str.Length % 4) -ne 0) {
            $base64Str += "="
        }
        try {
            $decodedBytes = [System.Convert]::FromBase64String($base64Str)
            $streamBytes.AddRange($decodedBytes)
            Write-Host "Successfully decoded Text Mode base64 stream." -ForegroundColor Green
        } catch {
            Write-Host "Failed to decode base64 stream: $_" -ForegroundColor Red
        }
    }
}

if ($streamBytes.Count -eq 0) {
    Write-Host "ERROR: No payload segments found in file." -ForegroundColor Red
    exit 1
}

$stream = $streamBytes.ToArray()
Write-Host ("Extracted stream size: {0} bytes" -f $stream.Length) -ForegroundColor Green

# --- Step 3: Parse the protocol stream ---
# Find POLYGLOT_PREFIX: \n-->\n (10, 45, 45, 62, 10)
$prefix = @(10, 45, 45, 62, 10)
$pStart = -1
for ($i = 0; $i -lt ($stream.Length - $prefix.Length + 1); $i++) {
    $match = $true
    for ($j = 0; $j -lt $prefix.Length; $j++) {
        if ($stream[$i + $j] -ne $prefix[$j]) {
            $match = $false
            break
        }
    }
    if ($match) {
        $pStart = $i
        break
    }
}

if ($pStart -eq -1) {
    Write-Host "ERROR: Polyglot prefix not found in the stream." -ForegroundColor Red
    exit 1
}

$headerStart = $pStart + $prefix.Length
if ($stream.Length -lt ($headerStart + 10)) {
    Write-Host "ERROR: Stream is too short to contain header." -ForegroundColor Red
    exit 1
}

# Parse header (10 bytes):
# SessionID: bytes 0-3 (Big-Endian)
# PartIdx: byte 4
# IsEOF: byte 5
# ChunkLength: bytes 6-9 (Big-Endian)
$sessionIDBytes = New-Object byte[] 4
[Array]::Copy($stream, $headerStart, $sessionIDBytes, 0, 4)

$partIdx = $stream[$headerStart+4]
$isEOF = $stream[$headerStart+5]

$chunkLengthBytes = New-Object byte[] 4
[Array]::Copy($stream, $headerStart + 6, $chunkLengthBytes, 0, 4)

if ([BitConverter]::IsLittleEndian) {
    [Array]::Reverse($sessionIDBytes)
    [Array]::Reverse($chunkLengthBytes)
}
$sessionID = [BitConverter]::ToUInt32($sessionIDBytes, 0)
$chunkLength = [BitConverter]::ToUInt32($chunkLengthBytes, 0)

Write-Host ("Session ID  : 0x{0:X8}" -f $sessionID) -ForegroundColor Cyan
Write-Host ("Part Index  : {0}" -f $partIdx) -ForegroundColor Cyan
Write-Host ("Is Last Part: {0}" -f ($isEOF -eq 1)) -ForegroundColor Cyan
Write-Host ("Payload Size: {0} bytes" -f $chunkLength) -ForegroundColor Cyan

$chunkStart = $headerStart + 10
if ($stream.Length -lt ($chunkStart + $chunkLength)) {
    Write-Host "WARNING: Stream is shorter than declared chunk length. Adjusting." -ForegroundColor Yellow
    $chunkLength = $stream.Length - $chunkStart
}

if ($chunkLength -le 0) {
    Write-Host "ERROR: Extracted chunk length is zero or negative." -ForegroundColor Red
    exit 1
}

$chunkData = New-Object byte[] $chunkLength
[Array]::Copy($stream, $chunkStart, $chunkData, 0, $chunkLength)

# --- Step 4: Decrypt using XOR cipher ---
if (-not [string]::IsNullOrEmpty($Password)) {
    Write-Host "Decrypting payload with password..." -ForegroundColor Yellow
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
    $decrypted = New-Object byte[] $chunkData.Length
    for ($k = 0; $k -lt $chunkData.Length; $k++) {
        $keyByte = $keyBytes[$k % $keyBytes.Length]
        $decrypted[$k] = [byte]($chunkData[$k] -bxor $keyByte)
    }
} else {
    Write-Host "No password provided. Proceeding with cleartext payload." -ForegroundColor Yellow
    $decrypted = $chunkData
}

# --- Step 5: Extract filename and output file ---
if ($decrypted.Length -lt 2) {
    Write-Host "ERROR: Decrypted data is too small to contain filename length." -ForegroundColor Red
    exit 1
}

$nameLenBytes = New-Object byte[] 2
[Array]::Copy($decrypted, 0, $nameLenBytes, 0, 2)
if ([BitConverter]::IsLittleEndian) {
    [Array]::Reverse($nameLenBytes)
}
$nameLen = [BitConverter]::ToUInt16($nameLenBytes, 0)

if ($decrypted.Length -lt (2 + $nameLen)) {
    Write-Host "ERROR: Decrypted data is too small to contain filename." -ForegroundColor Red
    exit 1
}

$nameBytes = New-Object byte[] $nameLen
[Array]::Copy($decrypted, 2, $nameBytes, 0, $nameLen)
$filename = [System.Text.Encoding]::UTF8.GetString($nameBytes)

$fileDataLen = $decrypted.Length - (2 + $nameLen)
if ($fileDataLen -gt 0) {
    $fileData = New-Object byte[] $fileDataLen
    [Array]::Copy($decrypted, 2 + $nameLen, $fileData, 0, $fileDataLen)
} else {
    $fileData = @()
}

Write-Host ("Extracted filename : {0}" -f $filename) -ForegroundColor Green
Write-Host ("Extracted file size: {0} bytes" -f $fileData.Length) -ForegroundColor Green

[IO.File]::WriteAllBytes($filename, $fileData)
Write-Host "Success! Extracted file saved to '$filename'" -ForegroundColor Green