param([string]$Carrier, [string]$Key = "")

$raw = [IO.File]::ReadAllBytes($Carrier)
$sb  = [Text.StringBuilder]::new()
$ls  = 0

# Collect valid Base64 lines (10-100 chars, A-Za-z0-9+/=_), strip underscores
for ($i = 0; $i -le $raw.Length; $i++) {
    if ($i -eq $raw.Length -or $raw[$i] -eq 10 -or $raw[$i] -eq 13) {
        $n = $i - $ls
        if ($n -ge 10 -and $n -le 100) {
            $ok = $true
            for ($j = $ls; $j -lt $i -and $ok; $j++) {
                $b  = $raw[$j]
                $ok = ($b -ge 65 -and $b -le 90) -or ($b -ge 97 -and $b -le 122) -or
                      ($b -ge 48 -and $b -le 57) -or $b -eq 43 -or $b -eq 47 -or $b -eq 61 -or $b -eq 95
            }
            if ($ok) {
                for ($j = $ls; $j -lt $i; $j++) {
                    if ($raw[$j] -ne 95) { $sb.Append([char]$raw[$j]) | Out-Null }
                }
            }
        }
        $ls = $i + 1
    }
}

# Decode Base64 stream
$b64 = $sb.ToString()
while ($b64.Length % 4) { $b64 += '=' }
[byte[]]$st = [Convert]::FromBase64String($b64)

# Find prefix marker "\n-->\n" (bytes: 10 45 45 62 10)
$pfx = [byte[]]@(10, 45, 45, 62, 10)
$px  = -1
for ($i = 0; $i -le $st.Length - 5 -and $px -lt 0; $i++) {
    $ok = $true
    for ($j = 0; $j -lt 5 -and $ok; $j++) { $ok = $st[$i + $j] -eq $pfx[$j] }
    if ($ok) { $px = $i }
}

# Skip 10-byte header (sessionID + partIdx + flags), read chunkLen (last 4 bytes)
$h  = $px + 5
$cl = (([int]$st[$h+6] -shl 24) -bor ([int]$st[$h+7] -shl 16) -bor ([int]$st[$h+8] -shl 8) -bor $st[$h+9])
[byte[]]$ch = $st[($h + 10)..($h + 9 + $cl)]

# XOR decrypt (no-op if key is empty)
if ($Key) {
    $kb  = [Text.Encoding]::UTF8.GetBytes($Key)
    $dec = [byte[]]::new($ch.Length)
    for ($i = 0; $i -lt $ch.Length; $i++) { $dec[$i] = $ch[$i] -bxor $kb[$i % $kb.Length] }
    $ch = $dec
}

# Unpack: [uint16 nameLen][name bytes][payload bytes]
$nl = (([int]$ch[0] -shl 8) -bor $ch[1])
$nm = [Text.Encoding]::UTF8.GetString($ch, 2, $nl)
[IO.File]::WriteAllBytes($nm, [byte[]]($ch[(2 + $nl)..($ch.Length - 1)]))
Write-Host "Saved: $nm"
