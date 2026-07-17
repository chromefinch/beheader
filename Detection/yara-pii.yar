rule PII_SSN {
    meta:
        author = "Antigravity"
        description = "Detects potential Social Security Numbers (PII)"
        date = "2026-07-16"
    strings:
        // Broadened to catch synthetic/test SSNs (e.g., 999-XX-XXXX or 000-XX-XXXX)
        $ssn = /[0-9]{3}-[0-9]{2}-[0-9]{4}/
    condition:
        $ssn
}
