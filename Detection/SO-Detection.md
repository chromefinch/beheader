Here is a complete, end-to-end write-up of the process. You can use this as the foundation for your methodology or execution section.

1. **Enable Advanced Configuration:** Required to unhide backend policy trees.
Log into the Security Onion Console (SOC) and navigate to **Administration -> Configuration**. Click the **Options** menu at the top of the page and toggle **Show advanced settings** to **ON**.


2. **Update Zeek File Extraction Policy:**
Navigate the configuration tree to `zeek` -> `policy` -> `file_extraction`. To instruct Zeek to drop icons and MP4s to disk for Strelka to scan, add the following key-value mappings to the bottom of the configuration array:

```json
{"image/x-icon":"ico"}
{"video/mp4":"mp4"}

```


3. **Synchronize the Grid:**
Click the checkmark icon on the right to save the configuration. Open the **Options** menu at the top again and select **Synchronize Grid**. Allow a few minutes for the Salt stack to push the policy and restart the Zeek service.


4. **Deploy the Polyglot YARA Rule:**
Navigate to the **Detections** interface and load the custom YARA rule. Ensure the severity is declared as an integer (`severity = 3`) so the Elastic ingest pipeline correctly assigns a "High" severity label in the alerts:

```yara
rule Polyglot_ICO_MP4_Base64 {
    meta:
        author = "Antigravity"
        description = "Detects large blocks of Base64 encoded data embedded in MP4 or ICO/MP4 polyglot files."
        date = "2026-07-28"
        severity = 3
    strings:
        $ico_magic = { 00 00 01 00 }
        $ftyp = "ftyp"
        
        $b64_small_block = /[A-Za-z0-9+\/]{64}/
        $b64_chunked = /([A-Za-z0-9+\/]{60,100}[\r\n]{1,2}){10}/
        $b64_padded_2 = /[A-Za-z0-9+\/]{100,}==/
        $b64_padded_1 = /[A-Za-z0-9+\/]{100,}[^=]=/
        $b64_subtitle_chunk = /[a-zA-Z0-9+\/]{32}/
    condition:
        ($ico_magic at 0 or $ftyp in (0..16384)) 
        and 
        (
            $b64_chunked or 
            $b64_padded_1 or 
            $b64_padded_2
        )
}

```

*(Note: Wait ~15 minutes for the Detections sync to push the rule to Strelka).*


5. **Execute the Network Transfer:**
Push the malicious `injected_funnycats.mp4` (prepended with the ICO magic bytes) across the network. Zeek will identify it as `image/x-icon`, extract it to the staging folder as an `.ico`, and Strelka will scan it against the active YARA ruleset.


6. **Filter and Attribute in Elastic:**
Navigate to **Dashboards -> Alert Data**. To rapidly isolate alerts that have a carved file associated with them, apply the following filter in the search bar:

```text
log.id.fuid: exists

```

Locate the `Polyglot_ICO_MP4_Base64` alert. Expand the log and locate the **FUID** (File UID, e.g., `FvIWLtGXZtj...`). Pivot on this FUID to find the original `zeek.files` log, which reveals the original `.mp4` filename and the Connection UID (CUID) needed to attribute the upload back to the attacker's Source IP.