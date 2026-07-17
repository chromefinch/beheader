rule Large_Base64 {
    meta:
        author = "Antigravity"
        description = "Detects large blocks of Base64 encoded data embedded in MP4 media files."
        date = "2026-07-17"
    strings:
        // MP4 magic bytes (acting as the anchor/filter)
        $ftyp = "ftyp"
        
        // Base64 patterns
        $b64_small_block = /[A-Za-z0-9+\/]{64}/
        $b64_chunked = /([A-Za-z0-9+\/]{60,100}[\r\n]{1,2}){10}/
        $b64_padded_2 = /[A-Za-z0-9+\/]{100,}==/
        $b64_padded_1 = /[A-Za-z0-9+\/]{100,}[^=]=/
    condition:
        // ftyp must be near the start of the file (within the first 16KB)
        $ftyp in (0..16384) 
        and 
        (
            #b64_small_block > 16 or 
            $b64_chunked or 
            $b64_padded_1 or 
            $b64_padded_2
        )
}
