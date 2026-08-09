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
rule High_Entropy_Base64_in_MP4_or_ICO {
    meta:
        author = "John Porpora Augmented by Google's Antigravity"
        description = "Dynamically spot-checks Base64 matches across the entire file for high entropy, avoiding crashing on large files by capping the loop while still checking matches at the beginning, middle, and end."
        
    strings:
        // Match a block of 60 to 120 base64 characters
        $b64 = /[A-Za-z0-9+\/]{60,120}/
    condition:
        (
            uint32(0) == 0x00010000 // ICO magic
            or 
            uint32be(4) == 0x66747970 // MP4 ftyp
        )
        and 
        #b64 > 0 
        and 
        (
            // We evaluate exactly 500 matches distributed evenly across the entire file.
            // This ensures we find the payload even if it's hidden at the very end.
            for any i in (1..500): (
                (1 + (i - 1) * (#b64 \ 500)) <= #b64 and 
                math.entropy(@b64[1 + (i - 1) * (#b64 \ 500)], !b64[1 + (i - 1) * (#b64 \ 500)]) > 5.2
            )
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
