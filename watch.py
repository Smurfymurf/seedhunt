#!/usr/bin/env python3
"""
watch.py - continuous, resumable seed hunter.

Wraps seedhunt.py with:
  - persistent state, so a repo/path is never scanned twice
  - query rotation, so coverage widens over time instead of repeating
  - periodic balance re-checks on every address ever derived
  - ntfy alerts only for NEWLY funded wallets
"""

import argparse, json, os, random, time
from pathlib import Path
import requests
import seedhunt as sh

STATE = Path("state"); STATE.mkdir(exist_ok=True)
SEEN_F, ADDR_F, ALERT_F, QSTATE = (STATE / n for n in
    ("seen.json", "addresses.json", "alerts.json", "queries.json"))
RESCAN_DAYS, RECHECK_DAYS = 180, 30

def load(p, d): return json.loads(p.read_text()) if p.exists() else d
def save(p, v): p.write_text(json.dumps(v, indent=1))

def notify(title, msg, priority="default"):
    topic = os.environ.get("NTFY_TOPIC")
    if not topic: return
    try:
        requests.post("https://ntfy.sh/" + topic, data=str(msg)[:3500].encode(),
                      headers={"Title": title, "Priority": priority, "Tags": "seedling"},
                      timeout=10)
    except Exception as e:
        print("notify failed:", e)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=14)
    a = ap.parse_args()
    deadline = time.time() + a.minutes * 60
    now = time.time()

    seen = load(SEEN_F, {}); addrs = load(ADDR_F, {})
    alerted = load(ALERT_F, {}); qstate = load(QSTATE, {})

    # ---- 1. rotating discovery, least-recently-used query first
    pool = [f"{q} {b}" for q in sh.GH_QUERIES for b in sh.STAR_BUCKETS]
    random.shuffle(pool)
    pool.sort(key=lambda q: qstate.get(q, 0))

    cands, used = {}, 0
    for q in pool:
        if time.time() > deadline - 300: break
        qstate[q] = now; used += 1
        try:
            for c in sh.search_github_code(q, 1, 800):
                k = f"{c.repo}/{c.path}"
                if k in seen and now - seen[k] < RESCAN_DAYS * 86400: continue
                cands[k] = c
        except Exception as e:
            print("query failed:", q, e)

    for rx in sh.GREP_REGEXES:
        if time.time() > deadline - 300: break
        try:
            for c in sh.search_grepapp(rx, 2):
                k = f"{c.repo}/{c.path}"
                if k in seen and now - seen[k] < RESCAN_DAYS * 86400: continue
                cands[k] = c
        except Exception as e:
            print("grep failed:", e)

    print(f"[watch] {used} queries, {len(cands)} new candidate files")

    # ---- 2. triage anything new
    if cands:
        sh.CAND_FILE.write_text(json.dumps([sh.asdict(c) for c in cands.values()], indent=1))
        try:
            sh.triage(argparse.Namespace(passphrases=[""]))
        except Exception as e:
            print("triage failed:", e)
        for k in cands: seen[k] = now
        if sh.FIND_FILE.exists():
            for r in json.loads(sh.FIND_FILE.read_text()):
                for chain, path, addr in r["rows"]:
                    addrs.setdefault(f"{chain}:{addr}",
                                     {"seed": r["secret"], "path": path, "checked": now})

    # ---- 3. re-check every address we have ever derived
    due = [k for k, v in addrs.items() if now - v.get("checked", 0) > RECHECK_DAYS * 86400]
    print(f"[watch] {len(due)} addresses due for re-check")
    new_funds = 0
    for k in due:
        if time.time() > deadline: break
        chain, addr = k.split(":", 1)
        try:
            bal = sh.balance(chain, addr)
        except Exception:
            continue
        addrs[k]["checked"] = now
        if bal and (bal if isinstance(bal, float) else any(bal.values())) and k not in alerted:
            alerted[k] = now; new_funds += 1
            print("  NEW FUNDS", k, bal)
            notify("NEW FUNDS", f"{bal} {chain}\naddr {addr}\npath {addrs[k]['path']}\n"
                                f"seed {addrs[k]['seed']}", "high")

    # ---- 4. persist
    save(SEEN_F, seen); save(ADDR_F, addrs); save(ALERT_F, alerted); save(QSTATE, qstate)
    notify("watch run done",
           f"{len(cands)} new files, {len(addrs)} addresses tracked, {new_funds} new funded")
    print(f"[watch] done. tracking {len(addrs)} addresses.")

if __name__ == "__main__":
    main()
