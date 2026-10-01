#!/usr/bin/env python3
"""
Chain of Custody Tracker - Cyber Forensics Demo
------------------------------------------------
An interactive command-line tool that shows how digital evidence is tracked
from collection to court:

  * Evidence is fingerprinted with SHA-256 (proves the file never changed)
  * Every handover is written to a log where each entry contains the hash of
    the previous entry (a mini blockchain), so editing history is detectable
  * An integrity check re-computes everything and reports tampering

Only the Python standard library is used. Run:  python chain_of_custody.py
"""

import hashlib
import os
import sqlite3
from datetime import datetime, timezone

DB_FILE = "custody.db"
GENESIS_HASH = "0" * 64
ACTIONS = ["COLLECTED", "TRANSFERRED", "ANALYZED", "STORED", "RELEASED"]


# ---------------------------------------------------------------- helpers
def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def sha256_file(path):
    """Hash a file in chunks so large disk images don't fill memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def entry_hash(evidence_id, action, from_p, to_p, location, notes, ts, prev):
    """Fingerprint of one log entry, linked to the previous entry."""
    payload = "|".join(
        [str(evidence_id), action, from_p, to_p, location, notes, ts, prev]
    )
    return hashlib.sha256(payload.encode()).hexdigest()


# --------------------------------------------------------------- database
def connect():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_no TEXT, description TEXT,
            file_path TEXT, file_hash TEXT
        );
        CREATE TABLE IF NOT EXISTS custody_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER, action TEXT,
            from_person TEXT, to_person TEXT,
            location TEXT, notes TEXT, timestamp TEXT,
            prev_hash TEXT, entry_hash TEXT
        );
        """
    )
    return conn


def last_entry(conn, evidence_id):
    return conn.execute(
        "SELECT * FROM custody_log WHERE evidence_id=? ORDER BY id DESC LIMIT 1",
        (evidence_id,),
    ).fetchone()


def add_log(conn, evidence_id, action, from_p, to_p, location, notes):
    prev = last_entry(conn, evidence_id)
    prev_hash = prev["entry_hash"] if prev else GENESIS_HASH
    ts = utc_now()
    h = entry_hash(evidence_id, action, from_p, to_p, location, notes, ts, prev_hash)
    conn.execute(
        """INSERT INTO custody_log
           (evidence_id, action, from_person, to_person, location, notes,
            timestamp, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?,?)""",
        (evidence_id, action, from_p, to_p, location, notes, ts, prev_hash, h),
    )
    conn.commit()


def pick_evidence(conn):
    rows = conn.execute("SELECT id, case_no, description FROM evidence").fetchall()
    if not rows:
        print("  No evidence registered yet. Use option 1 first.")
        return None
    for r in rows:
        print(f"  [{r['id']}] Case {r['case_no']} - {r['description']}")
    try:
        eid = int(input("Evidence ID: ").strip())
    except ValueError:
        print("  Please enter a number.")
        return None
    if not conn.execute("SELECT 1 FROM evidence WHERE id=?", (eid,)).fetchone():
        print("  No such evidence ID.")
        return None
    return eid


# ----------------------------------------------------------------- actions
def register_evidence(conn):
    print("\n--- Register new evidence ---")
    case_no = input("Case number: ").strip()
    desc = input("Description (e.g. 'Suspect laptop SSD image'): ").strip()
    path = input("Path to evidence file (try sample_evidence/usb_dump.txt): ").strip()
    if not os.path.isfile(path):
        print("  File not found. Evidence needs a file so it can be hashed.")
        return
    collector = input("Collected by: ").strip()
    location = input("Collected at (location): ").strip()

    file_hash = sha256_file(path)
    cur = conn.execute(
        "INSERT INTO evidence (case_no, description, file_path, file_hash) VALUES (?,?,?,?)",
        (case_no, desc, path, file_hash),
    )
    conn.commit()
    add_log(conn, cur.lastrowid, "COLLECTED", "-", collector, location,
            f"Initial SHA-256: {file_hash[:16]}...")
    print(f"  Registered as evidence #{cur.lastrowid}")
    print(f"  SHA-256: {file_hash}")


def transfer_custody(conn):
    print("\n--- Record a custody event ---")
    eid = pick_evidence(conn)
    if eid is None:
        return
    holder = last_entry(conn, eid)["to_person"]
    print(f"  Current custodian: {holder}")
    print("  Actions:", ", ".join(ACTIONS[1:]))
    action = input("Action: ").strip().upper()
    if action not in ACTIONS[1:]:
        print("  Invalid action.")
        return
    from_p = input(f"Handed over by [{holder}]: ").strip() or holder
    if from_p != holder:
        print(f"  Rejected: {from_p} does not hold this evidence ({holder} does).")
        print("  An unexplained gap like this is exactly what breaks a chain of custody!")
        return
    to_p = input("Received by: ").strip()
    location = input("Location: ").strip()
    notes = input("Purpose / notes: ").strip()
    add_log(conn, eid, action, from_p, to_p, location, notes)
    print("  Event logged and chained to the previous entry.")


def view_history(conn):
    print("\n--- Custody history ---")
    eid = pick_evidence(conn)
    if eid is None:
        return
    rows = conn.execute(
        "SELECT * FROM custody_log WHERE evidence_id=? ORDER BY id", (eid,)
    ).fetchall()
    for i, r in enumerate(rows, 1):
        print(f"\n  #{i} {r['timestamp']}  {r['action']}")
        print(f"     {r['from_person']} -> {r['to_person']}  @ {r['location']}")
        print(f"     Notes: {r['notes']}")
        print(f"     Entry hash: {r['entry_hash'][:20]}...")


def verify_integrity(conn, eid=None, quiet=False):
    """Re-compute every hash. Returns True if the chain is intact."""
    if eid is None:
        if not quiet:
            print("\n--- Verify integrity ---")
        eid = pick_evidence(conn)
        if eid is None:
            return None
    ev = conn.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
    rows = conn.execute(
        "SELECT * FROM custody_log WHERE evidence_id=? ORDER BY id", (eid,)
    ).fetchall()

    problems = []
    prev = GENESIS_HASH
    for i, r in enumerate(rows, 1):
        if r["prev_hash"] != prev:
            problems.append(f"Entry #{i}: link to previous entry is broken")
        expected = entry_hash(eid, r["action"], r["from_person"], r["to_person"],
                              r["location"], r["notes"], r["timestamp"], r["prev_hash"])
        if expected != r["entry_hash"]:
            problems.append(f"Entry #{i}: contents were modified after logging")
        prev = r["entry_hash"]

    if not os.path.isfile(ev["file_path"]):
        problems.append("Evidence file is missing")
    elif sha256_file(ev["file_path"]) != ev["file_hash"]:
        problems.append("Evidence file hash does NOT match the original - file altered!")

    if problems:
        print("  INTEGRITY FAILED")
        for p in problems:
            print("   -", p)
        return False
    print(f"  INTEGRITY OK: {len(rows)} log entries verified, file hash matches.")
    return True


def simulate_tampering(conn):
    print("\n--- Tamper simulation (demo only) ---")
    print("  1) Secretly edit a log entry in the database")
    print("  2) Modify the evidence file itself")
    choice = input("Choose: ").strip()
    eid = pick_evidence(conn)
    if eid is None:
        return
    if choice == "1":
        first = conn.execute(
            "SELECT id FROM custody_log WHERE evidence_id=? ORDER BY id LIMIT 1", (eid,)
        ).fetchone()
        conn.execute("UPDATE custody_log SET to_person='Unknown Person' WHERE id=?",
                     (first["id"],))
        conn.commit()
        print("  An attacker rewrote who first collected the evidence...")
    elif choice == "2":
        path = conn.execute("SELECT file_path FROM evidence WHERE id=?",
                            (eid,)).fetchone()["file_path"]
        with open(path, "a") as f:
            f.write("\n[tampered line]")
        print("  An attacker appended data to the evidence file...")
    else:
        print("  Invalid choice.")
        return
    print("  Now run option 4 (Verify) and watch it get caught.")


# -------------------------------------------------------------------- main
MENU = """
===== Chain of Custody Tracker =====
 1. Register new evidence
 2. Record custody event (transfer / analysis / storage / release)
 3. View custody history
 4. Verify integrity
 5. Simulate tampering (demo)
 6. Exit
"""


def main():
    conn = connect()
    handlers = {
        "1": register_evidence,
        "2": transfer_custody,
        "3": view_history,
        "4": verify_integrity,
        "5": simulate_tampering,
    }
    while True:
        print(MENU)
        choice = input("Select: ").strip()
        if choice == "6":
            print("Goodbye!")
            break
        handler = handlers.get(choice)
        if handler:
            handler(conn)
        else:
            print("  Invalid option.")


if __name__ == "__main__":
    main()
