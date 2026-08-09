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
//Security Onion should already import basic modules. 
//import "math"
rule High_Density_Base64_Payload_in_MP4_ICO {
    meta:
        author = "John Porpora Augmented by Google's Antigravity"
        description = "Scans massive chunks of MP4/ICO files to find dense Base64 regions using math.count, avoiding YARA regex engine limits and warnings."
        date = "2026-08-06"
        severity = 3
    condition:
        (
            uint32(0) == 0x00010000 // ICO magic
            or 
            uint32be(4) == 0x66747970 // MP4 ftyp
        )
        and 
        (
            for any i in (0..10000): ( // Scan up to 2GB in 200KB chunks
                (i * 200000 < filesize) and 
                (
                    // YARA lacks a native summation loop for integers, so we manually count and sum 
                    // the occurrences of all 64 Base64 byte values within the current 200KB window.
                    // 
                    // Benign binary data is random across all 256 possible byte values. Therefore, 
                    // the statistical probability of any byte naturally falling into the 64-character 
                    // Base64 alphabet is exactly 25% (64/256). In a benign 200KB chunk, the sum of 
                    // Base64 bytes will naturally hover around 50,000.
                    // 
                    // However, if a massive Base64 payload is injected, that chunk is no longer 
                    // random binary—it becomes almost 100% Base64 characters. If our total sum 
                    // exceeds 150,000 bytes (75% density), it guarantees we've hit an injected payload.
                    (
                    /* '+' and '/' */
                    math.count(43, i*200000, 200000) + math.count(47, i*200000, 200000) +
                    /* '0'-'9' */
                    math.count(48, i*200000, 200000) + math.count(49, i*200000, 200000) + math.count(50, i*200000, 200000) + math.count(51, i*200000, 200000) +
                    math.count(52, i*200000, 200000) + math.count(53, i*200000, 200000) + math.count(54, i*200000, 200000) + math.count(55, i*200000, 200000) +
                    math.count(56, i*200000, 200000) + math.count(57, i*200000, 200000) +
                    /* '=' */
                    math.count(61, i*200000, 200000) +
                    /* 'A'-'Z' */
                    math.count(65, i*200000, 200000) + math.count(66, i*200000, 200000) + math.count(67, i*200000, 200000) + math.count(68, i*200000, 200000) +
                    math.count(69, i*200000, 200000) + math.count(70, i*200000, 200000) + math.count(71, i*200000, 200000) + math.count(72, i*200000, 200000) +
                    math.count(73, i*200000, 200000) + math.count(74, i*200000, 200000) + math.count(75, i*200000, 200000) + math.count(76, i*200000, 200000) +
                    math.count(77, i*200000, 200000) + math.count(78, i*200000, 200000) + math.count(79, i*200000, 200000) + math.count(80, i*200000, 200000) +
                    math.count(81, i*200000, 200000) + math.count(82, i*200000, 200000) + math.count(83, i*200000, 200000) + math.count(84, i*200000, 200000) +
                    math.count(85, i*200000, 200000) + math.count(86, i*200000, 200000) + math.count(87, i*200000, 200000) + math.count(88, i*200000, 200000) +
                    math.count(89, i*200000, 200000) + math.count(90, i*200000, 200000) +
                    /* 'a'-'z' */
                    math.count(97, i*200000, 200000) + math.count(98, i*200000, 200000) + math.count(99, i*200000, 200000) + math.count(100, i*200000, 200000) +
                    math.count(101, i*200000, 200000) + math.count(102, i*200000, 200000) + math.count(103, i*200000, 200000) + math.count(104, i*200000, 200000) +
                    math.count(105, i*200000, 200000) + math.count(106, i*200000, 200000) + math.count(107, i*200000, 200000) + math.count(108, i*200000, 200000) +
                    math.count(109, i*200000, 200000) + math.count(110, i*200000, 200000) + math.count(111, i*200000, 200000) + math.count(112, i*200000, 200000) +
                    math.count(113, i*200000, 200000) + math.count(114, i*200000, 200000) + math.count(115, i*200000, 200000) + math.count(116, i*200000, 200000) +
                    math.count(117, i*200000, 200000) + math.count(118, i*200000, 200000) + math.count(119, i*200000, 200000) + math.count(120, i*200000, 200000) +
                    math.count(121, i*200000, 200000) + math.count(122, i*200000, 200000)
                    ) > 150000
                )
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
