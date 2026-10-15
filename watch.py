#!/usr/bin/env python3
"""
watch.py - continuous, resumable seed hunter.

Wraps seedhunt.py with:
  - persistent state, so a repo/path is never scanned twice
  - query rotation, so coverage widens over time instead of repeating
  - periodic balance re-checks on every address ever derived
  - ntfy alerts the moment anything funded appears
"""

import argparse, json, os, random, time
from pathlib import Path
import requests
import seedhunt as sh

STATE = Path("state"); STATE.mkdir(exist_ok=True)
SEEN_F, ADDR_F, QSTATE = (STATE / n for n in ("seen.json", "addresses.json", "queries.json"))
FUNDED_F = STATE / "funded.json"
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
    ap.add_argument("--discover", type=float, default=8, help="minutes for discovery")
    a = ap.parse_args()
    now = time.time()
    discover_until = now + a.discover * 60
    deadline = now + a.minutes * 60

    seen = load(SEEN_F, {}); addrs = load(ADDR_F, {})
    qstate = load(QSTATE, {}); funded = load(FUNDED_F, {})
    new_funds = 0

    def persist():
        save(SEEN_F, seen); save(ADDR_F, addrs)
        save(QSTATE, qstate); save(FUNDED_F, funded)

    def record_funded(chain, addr, path, seed, bal):
        """Dedupe, alert, and archive in one place."""
        nonlocal new_funds
        key = f"{chain}:{addr}"
        if key in funded: return
        funded[key] = {"chain": chain, "addr": addr, "path": path, "seed": seed,
                       "balance": bal,
                       "found": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        new_funds += 1
        print("  FUNDED", key, bal)
        notify("FUNDED SEED",
               f"{bal} {chain}\naddr {addr}\npath {path}\nseed {seed}", "high")

    try:
        # ---- 1. rotating discovery, least-recently-used query first
        pool = [f"{q} {b}" for q in sh.GH_QUERIES for b in sh.STAR_BUCKETS]
        random.shuffle(pool)
        pool.sort(key=lambda q: qstate.get(q, 0))

        cands, used = {}, 0
        for q in pool:
            if time.time() > discover_until: break
            qstate[q] = now; used += 1
            try:
                got = sh.search_github_code(q, 1, 800)
                if not got and " " in q:
                    got = sh.search_github_code(q.rsplit(" ", 1)[0], 1, 800)
                for c in got:
                    k = f"{c.repo}/{c.path}"
                    if k in seen and now - seen[k] < RESCAN_DAYS * 86400: continue
                    cands[k] = c
                print(f"    {q} -> {len(got)}")
            except Exception as e:
                print("query failed:", q, e)

        for rx in sh.GREP_REGEXES:
            if time.time() > discover_until: break
            try:
                got = sh.search_grepapp(rx, 2)
                for c in got:
                    k = f"{c.repo}/{c.path}"
                    if k in seen and now - seen[k] < RESCAN_DAYS * 86400: continue
                    cands[k] = c
                print(f"    grep {rx[:30]} -> {len(got)}")
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
                    for chain, path, addr, bal in r["funded"]:
                        record_funded(chain, addr, path, r["secret"], bal)
            persist()
            print(f"[watch] state saved. tracking {len(addrs)} addresses.")

        # ---- 3. re-check every address we have ever derived
        due = [k for k, v in addrs.items() if now - v.get("checked", 0) > RECHECK_DAYS * 86400]
        print(f"[watch] {len(due)} addresses due for re-check")
        for k in due:
            if time.time() > deadline: break
            chain, addr = k.split(":", 1)
            try:
                bal = sh.balance(chain, addr)
            except Exception:
                continue
            addrs[k]["checked"] = now
            if bal and (bal if isinstance(bal, float) else any(bal.values())):
                record_funded(chain, addr, addrs[k]["path"], addrs[k]["seed"], bal)

    finally:
        persist()
        notify("watch run done",
               f"{len(addrs)} addresses tracked, {new_funds} new funded, "
               f"{len(funded)} total ever")
        print(f"[watch] done. {len(funded)} funded addresses known.")

if __name__ == "__main__":
    main()