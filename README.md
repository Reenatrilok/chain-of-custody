# Chain of Custody Tracker (Cyber Forensics Demo)

An interactive command-line tool that demonstrates **chain of custody** for digital evidence.

## What it demonstrates
- **Evidence fingerprinting**: every file is hashed with SHA-256 at collection time.
- **Tamper-evident log**: each custody event stores the hash of the previous event (hash chain), so rewriting history is detectable.
- **Custody validation**: only the current custodian can hand evidence over; unexplained gaps are rejected.
- **Integrity verification**: re-computes every hash and reports exactly what was altered.
- **Tamper simulation**: edit the log or the evidence file, then watch verification fail.

## Run it
```bash
python chain_of_custody.py
```
Requires Python 3.8+. No external libraries.

## Demo scenario
1. `1` Register `sample_evidence/usb_dump.txt` (collected by Officer Rao).
2. `2` Hand it to an analyst (ANALYZED), then to a vault keeper (STORED).
3. `3` View the full history.
4. `4` Verify: **INTEGRITY OK**.
5. `5` Simulate tampering, then `4` again: **INTEGRITY FAILED**.
6. `2` Try handing over as someone who doesn't hold the evidence: **Rejected**.

## Chain of custody lifecycle
Identification -> Collection -> Acquisition -> Transport -> Analysis -> Storage -> Court presentation

## Files
| File | Purpose |
|------|---------|
| `chain_of_custody.py` | The application |
| `sample_evidence/usb_dump.txt` | Dummy evidence file to practise with |
| `custody.db` | SQLite database (created on first run, git-ignored) |
