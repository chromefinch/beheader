$P='injected.mp4'; $B=[IO.File]::ReadAllBytes($P); $M=[IO.MemoryStream]::new();
for($i=0; $i-lt$B.Length-6; $i++){
  if($B[$i]-eq0xCA -and $B[$i+1]-eq0xFE -and $B[$i+2]-eq0xBA -and $B[$i+3]-eq0xBE){
    $L=$B[$i+4]; $M.Write($B,$i+5,$L); $i+=$L+4
  }
}
$R=$M.ToArray();
for($i=0; $i-lt$R.Length-5; $i++){
  if($R[$i]-eq10 -and $R[$i+1]-eq45 -and $R[$i+2]-eq45 -and $R[$i+3]-eq62){
    $H=$i+5; $Len=($R[$H+6]*0x1000000)+($R[$H+7]*0x10000)+($R[$H+8]*0x100)+$R[$H+9];
    $D=$R[($H+10)..($H+9+$Len)]; $N=($D[0]*256)+$D[1];
    [IO.File]::WriteAllBytes('extracted_payload.exe', $D[($N+2)..($D.Length-1)]);
    Write-Host "SUCCESS: Extracted $($D.Length) bytes"; break
  }
}
