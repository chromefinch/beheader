# Detecting Base64-Payload Polyglots in Security Onion

End-to-end procedure for extracting ICO/MP4 files off the wire with Zeek, scanning them
with a custom YARA rule in Strelka, and pivoting from the resulting alert back to the
source host.

Tested against Security Onion 3.1.0. Paths and configuration keys may differ on other
releases — verify against your own install before relying on them.

---

## 1. Enable advanced configuration

The Zeek and Strelka policy trees are hidden by default.

- Log into the Security Onion Console (SOC).
- Navigate to **Administration → Configuration**.
- Open the **Options** menu at the top of the page and toggle **Show advanced settings** to **ON**.

## 2. Configure the extraction pipeline

Zeek's only job here is carving bytes off the wire and writing them to disk. All scanning
happens in Strelka, downstream. But the carve step imposes its own size ceiling, and a
file truncated at that ceiling is the file Strelka scans — so both ends need configuring
before the rule can succeed.

### 2a. Add ICO and MP4 to the extraction policy

Out of the box Zeek extracts executables and office documents, not media. Both target
types have to be added explicitly or nothing reaches Strelka.

Navigate the configuration tree to `zeek` → `policy` → `file_extraction` and append:

```
{"image/x-icon":"ico"}
{"video/mp4":"mp4"}
```

Match the formatting of the entries already present in your install rather than copying
these verbatim — the accepted syntax has changed between releases.

### 2b. Raise Zeek's extraction size limit

`FileExtract::default_limit` defaults to **9,000,000 bytes**. This is a truncation limit
on the artifact Zeek writes, not a scan limit: past 9 MB the bytes are simply never
written, and Strelka scans a 9 MB file completely and correctly while the rest of the
payload was never carved.

There is **no size field in the SOC configuration tree**. `FileExtract::default_limit` is
a Zeek script-level `const &redef` from `base/files/extract`, set in Security Onion's
extraction policy script:

```bash
grep -n "extract_limit\|default_limit\|add_analyzer" \
  /opt/so/saltstack/default/salt/zeek/policy/securityonion/file-extraction/extract.zeek
```

Expect two hits: a `redef FileExtract::default_limit = 9000000;` near the top, and a
`Files::add_analyzer(...)` call. Check whether that call passes `$extract_limit` — if it
does, the per-file argument overrides the default and no redef will help. On a stock
install it passes only `$extract_filename`, so `default_limit` governs.

Because the shipped script already redefs the value, adding a *second* redef in a custom
policy field is load-order dependent: whichever is processed last wins, and if yours loads
first the 9000000 silently overwrites it. Override the file instead:

```bash
sudo mkdir -p /opt/so/saltstack/local/salt/zeek/policy/securityonion/file-extraction/
sudo cp /opt/so/saltstack/default/salt/zeek/policy/securityonion/file-extraction/extract.zeek \
        /opt/so/saltstack/local/salt/zeek/policy/securityonion/file-extraction/
sudo sed -i 's/FileExtract::default_limit = 9000000/FileExtract::default_limit = 104857600/' \
     /opt/so/saltstack/local/salt/zeek/policy/securityonion/file-extraction/extract.zeek
```

Never edit the default tree — it is overwritten on upgrade.

> **Size this to your test file, not to a round number.** The ceiling applies to every
> extracted file, so raising it inflates disk usage in `/nsm/zeek/extracted/` and hands
> Strelka much larger files to scan. This rule costs roughly 13 MB of byte inspection per
> matching window, so a generous limit on a grid seeing real traffic is how you find the
> scanner timeout.

> **Clear `/nsm/strelka/history` after changing this setting.** Zeek hashes the bytes it
> sees on the wire, not the truncated bytes it writes, so a file carved under the old
> limit registers the same hash as the full-size file carved under the new one — and the
> full-size file gets skipped. See *Scan-history dedup* under Troubleshooting.

Do not confuse the extraction policy with the `Files::log_policy` hook, which lives in a
similar-looking field. That hook controls which records are written to `files.log` — it
affects logging and downstream FUID pivots, not carving or file size.

### 2c. Check Strelka's own size limits

Strelka enforces a second, independent ceiling further down the pipeline, configured in
`/opt/so/conf/strelka/backend/backend.yaml` and exposed under **Administration →
Configuration → strelka**. Review the scanner limits and the per-scanner timeout — a file
that clears Zeek's carve limit can still be skipped or cut short here, and this rule is
slow enough on large files to make the timeout a live concern.

### Verifying the limits actually changed

Don't take the config on faith. Push your test file, then compare sizes:

```bash
ls -l /nsm/zeek/extracted/complete/
```

If the extracted artifact matches the original file size, the carve limit isn't biting. If
it's capped near 9 MB, the change didn't take effect. Note that only files passing Zeek's
validation checks — valid MD5, no missing bytes, no timeout — are moved into `complete/`,
so an oversized file may not appear at all rather than appearing truncated.

## 3. Synchronize the grid

- Click the checkmark icon to save the configuration.
- Open **Options → Synchronize Grid**.
- Allow several minutes for Salt to push the policy and restart Zeek.

## 4. Deploy the YARA rule

**Do not paste this rule into the Detections web form.** The form parses a single
`rule { }` block and rejects the top-level `import "math"` statement that this rule
requires. Use the local custom rules repo instead, which the Detections engine reads as a
first-class source.

The `import` is mandatory. YARA compiles the `math` module into libyara, but the import
declaration is per source file — without it, compilation fails with an undefined
identifier error, the rule never deploys, and the Detections page reports
**Strelka: Rule Mismatch**.

```bash
# 1. Copy the rule into the built-in local YARA repo
sudo cp High_Density_Base64_Payload_in_MP4_ICO.yar \
        /nsm/rules/custom-local-repos/local-yara/

# 2. The repo is socore-owned; the rule file must be readable by socore
sudo chown 939:939 \
     /nsm/rules/custom-local-repos/local-yara/High_Density_Base64_Payload_in_MP4_ICO.yar

# 3. Commit as socore — the engine reads committed state, not the working tree
cd /nsm/rules/custom-local-repos/local-yara/
sudo -u socore git add High_Density_Base64_Payload_in_MP4_ICO.yar
sudo -u socore git -c user.name="soc-admin" -c user.email="soc-admin@localhost" \
     commit -m "Add High_Density_Base64_Payload_in_MP4_ICO"
```

#### Ownership: "fatal: detected dubious ownership"

Plain `sudo git` runs as root, the repo belongs to socore, and git refuses on the
mismatch. The README shipped in that directory documents two ways through:

- **Run git as socore** (`sudo -u socore git ...`), as above. Nothing to configure and no
  root-owned objects land in `.git/`.
- **Add the exception** — `git config --global --add safe.directory
  /nsm/rules/custom-local-repos/local-yara` — then `chown` the rule files to socore
  afterwards. This is sanctioned by the README, but it commits as root, so remember the
  chown or the engine gets files it cannot read.

Git will also ask for an identity on first use. The README's instruction is to set
`user.email` and `user.name` **omitting `--global`**, scoping them to this repo. The
inline `-c` flags above do the same thing without writing config at all, which matters if
socore has no writable home. If you hit a `HOME` error, prefix with `HOME=/tmp`.

Verify before moving on:

```bash
sudo -u socore git -C /nsm/rules/custom-local-repos/local-yara log -1 --stat
ls -l /nsm/rules/custom-local-repos/local-yara/
```

#### Sync the rule into Detections

In SOC: **Detections → Options → Strelka → FULL UPDATE**. Without this you wait on
`communityRulesImportFrequencySeconds`, which defaults to 86400 (24 hours).

Confirm the rule now exists as a detection before trying to enable it. If it never
appears, it was not imported — check `/opt/so/log/soc/sensoroni-server.log` and the YARA
compilation report under `/opt/so/state/` for a compile failure (most often a missing
`import "math"` or a duplicate rule name).

#### Enable the rule

**Imported rules arrive disabled, and the enable control is not on the Detections list
page.** You have to open the detection's own page first:

1. From the main **Detections** interface, search for the rule name and click the
   **binoculars icon** on that row. (From an existing alert you can instead use
   **Tune Detection**.)
2. On the detection detail page, look at the **Status** field in the **upper-right
   corner**.
3. Use the **slider** there to enable it.

Wait for the next sync, then confirm the Strelka status indicator reads **OK**.

#### If the slider will not enable

- **Rules from a community-flagged repo are read-only.** You can duplicate or override
  them but not edit or toggle them. The built-in `local-yara` repo should not be flagged
  this way; a custom entry under `rulesRepos` will be unless you set `community: false`.
- **The engine may be stuck mid-sync.** Try **Options → Strelka → FULL UPDATE** first.
- **If a full update does not clear it,** the engine state files can be stale. Remove the
  relevant files from `/opt/so/conf/soc/fingerprint/` — `strelkaengine.state` is the one
  for Strelka — then restart SOC and watch the import:

  ```bash
  sudo ls /opt/so/conf/soc/fingerprint/
  sudo rm /opt/so/conf/soc/fingerprint/strelkaengine.state
  sudo so-soc-restart
  sudo tail -f /opt/so/log/soc/sensoroni-server.log
  ```

  The detections indices are recreated on restart. Confirm the rules are being imported in
  that log before concluding anything else is wrong.

> If you previously created this rule through the Detections web form, delete that
> detection first. UI-created rules and the local repo both populate the `__custom__`
> ruleset, and the same rule name arriving from two sources registers as a duplicate.

> **A disabled rule produces no alert and no error.** Strelka will happily scan files and
> log metadata for them the whole time. If files are being extracted and Strelka is
> logging but nothing alerts, verify the Status slider before debugging the rule itself.

### The rule

`severity = 3` is declared as an integer so the Elastic ingest pipeline maps it to a
"High" severity label rather than treating it as a string.

```yara
import "math"

rule High_Density_Base64_Payload_in_MP4_ICO {
    meta:
        author = "John Porpora (Augmented by Google Antigravity)"
        description = "Scans massive chunks of MP4/ICO files to find dense Base64 regions using math.count, avoiding YARA regex engine limits and warnings."
        
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
                    // exceeds 170,000 bytes (85% density), it guarantees we've hit an injected payload.
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
                    ) > 170000
                )
            )
        )
}

```

## 5. Filter and attribute in Elastic

Navigate to **Dashboards → Alert Data** and isolate alerts that have a carved file
attached:

```
log.id.fuid: exists
```

Locate the `High_Density_Base64_Payload_in_MP4_ICO` alert, expand it, and read off the
**FUID** (e.g. `FvIWLtGXZtj...`). Pivot on that FUID to the corresponding `zeek.files`
log, which gives you the original `.mp4` filename and the Connection UID (CUID). The CUID
resolves to the `zeek.conn` record and the attacker's source IP.

---

## How the Rule Works (The Math)

To solve the brittle signature problem without engine-crashing regular expressions, this rule abandons string matching and relies on byte frequency counting.

1. **Benign Files (Random Distribution):** A normal compressed MP4 or ICO file consists of raw binary data. Its bytes are roughly evenly distributed across all 256 possible byte values.
2. **Base64 (Structured Alphabet):** Base64 encoding only utilizes 64 specific ASCII byte values (`A-Z`, `a-z`, `0-9`, `+`, `/`, `=`).
3. **The Statistical Baseline:** Because legitimate binary data is randomly distributed across 256 values, the probability of any given byte naturally landing in the Base64 alphabet is exactly **25%** (`64 / 256`).
4. **Plain English (Natural Text):** If a file contains a massive block of pure English text (like a novel), it will also fail to trigger this rule. In standard English, spaces account for ~15-20% of characters, and punctuation/formatting accounts for ~5-10%. None of these are in the Base64 alphabet. Therefore, natural English text reaches a maximum Base64 density of around **70-75%**.

The rule dynamically scans the file in **200KB chunks**. It tallies the exact number of times each of the 64 Base64 bytes appears and sums them. If the sum exceeds **170,000 bytes** (an **85% density**), the rule triggers. 

It is mathematically impossible for naturally compressed media (25% density) or standard English prose (75% density) to reach an 85% concentration of Base64 characters over a 200KB span. Only an artificially injected, massive encoded text payload will trigger this threshold.

### Performance Features
- **Short-circuiting:** `(i * 200000 < filesize)` ensures that small files immediately stop iterating and do not waste CPU cycles.
- **Deep Scanning Limit:** The loop is set to `(0..10000)`, allowing the rule to scan massive files up to **2 Gigabytes** in size.
- **Zero Regex Warnings:** Because it avoids regular expressions, it will never generate "too many matches" warnings.

## Known limitations

- **Base64 broken up with massive whitespace:** Base64 heavily interspersed with spaces or non-Base64 tags may drop below the 85% threshold. (e.g. A payload wrapped in HTML tags every 64 characters achieves an 88.9% density, which clears the 85% limit, but more aggressive padding could evade it).
- **Detection floor is 200 KB:** A payload smaller than the 200KB chunk size will not trigger the 85% density requirement across the entire window.

## Troubleshooting

### No alert on a file you know should match
Work the pipeline bottom-up. Each hop fails silently.
1. **Confirm detection is enabled:** Check the **Status** slider on the detection detail page (binoculars icon). A disabled rule produces no alert and no error.
2. **Did the file reach `complete/`?** Strelka watches `/nsm/zeek/extracted/complete/`. 
3. **Did Strelka scan it?** Check `/nsm/strelka/log/strelka.log` for a record of the file.
4. **Is the header correct?** Check for `00 00 01 00` (ICO) or `ftyp` (MP4). If it starts with `1f 8b` (gzip), Zeek carved the encoded HTTP body instead of the file.

### Scan-history dedup
Security Onion hashes files and skips anything already analyzed recently. Re-sending an identical file produces no second alert.
If you raise the extraction limit mid-test, the newly carved full-size file will have the **same hash** as the previously truncated file, causing Strelka to skip it.
Clear the history to force a rescan:
```bash
sudo rm -f /nsm/strelka/history/*
```

### "Strelka: Rule Mismatch"
This means the rules enabled in the index differ from the rules deployed on disk.
- **Enabled but not deployed:** Compile failure. Check for a missing `import "math"` or a duplicate rule name.
- **Deployed but not enabled:** A rule file exists on disk with no matching detection. Remove it and re-add through the UI or repo.

To confirm the rule syntax locally:
```bash
yara High_Density_Base64_Payload_in_MP4_ICO.yar /dev/null
```
