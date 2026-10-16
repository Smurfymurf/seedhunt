#!/usr/bin/env python3
"""
watch.py - continuous, resumable seed hunter.

Partitions the search space by query x star bucket x push-date window so each
run works genuinely new ground instead of re-reading the same top 100 results.
"""

import argparse, json, os, random, time
from pathlib import Path
import requests
import seedhunt as sh

STATE = Path("state"); STATE.mkdir(exist_ok=True)
SEEN_F, ADDR_F, QSTATE = (STATE / n for n in ("seen.json", "addresses.json", "queries.json"))
FUNDED_F, HB_F = STATE / "funded.json", STATE / "heartbeat.json"
RESCAN_DAYS, RECHECK_DAYS = 180, 7
RECHECK_PER_RUN = 2500

DATE_WINDOWS = [
    "pushed:>2025-06-01",
    "pushed:2024-06-01..2025-05-31",
    "pushed:2023-06-01..2024-05-31",
    "pushed:2022-06-01..2023-05-31",
    "pushed:2021-06-01..2022-05-31",
    "pushed:2020-06-01..2021-05-31",
    "pushed:<2020-06-01",
]

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
    ap.add_argument("--minutes", type=float, default=20)
    ap.add_argument("--discover", type=float, default=12, help="minutes for discovery")
    a = ap.parse_args()
    now = time.time()
    discover_until = now + a.discover * 60
    deadline = now + a.minutes * 60

    seen = load(SEEN_F, {}); addrs = load(ADDR_F, {})
    qstate = load(QSTATE, {}); funded = load(FUNDED_F, {})
    hb = load(HB_F, {"t": 0})
    new_funds = 0

    def persist():
        save(SEEN_F, seen); save(ADDR_F, addrs)
        save(QSTATE, qstate); save(FUNDED_F, funded); save(HB_F, hb)

    def record_funded(chain, addr, path, seed, bal):
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
        # ---- 1. rotating discovery across the full partition grid
        pool = [f"{q} {b} {w}" for q in sh.GH_QUERIES
                for b in sh.STAR_BUCKETS for w in DATE_WINDOWS]
        random.shuffle(pool)
        pool.sort(key=lambda q: qstate.get(q, 0))

        cands, used, hits = {}, 0, 0
        for q in pool:
            if time.time() > discover_until: break
            qstate[q] = now; used += 1
            try:
                got = sh.search_github_code(q, 1, 400)
                fresh = 0
                for c in got:
                    k = f"{c.repo}/{c.path}"
                    if k in seen and now - seen[k] < RESCAN_DAYS * 86400: continue
                    cands[k] = c; fresh += 1
                hits += fresh
                print(f"    {q} -> {len(got)} raw, {fresh} new")
            except Exception as e:
                print("query failed:", q, e)
            if len(cands) >= 3000:
                print("    [cap] 3000 candidates, stopping discovery")
                break

        print(f"[watch] {used}/{len(pool)} partitions, {len(cands)} new candidate files")

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

        # ---- 3. re-check, oldest first, bounded per run
        due = [k for k, v in addrs.items() if now - v.get("checked", 0) > RECHECK_DAYS * 86400]
        due.sort(key=lambda k: addrs[k].get("checked", 0))
        print(f"[watch] {len(due)} addresses due, checking up to {RECHECK_PER_RUN}")
        for k in due[:RECHECK_PER_RUN]:
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
        quiet = not new_funds and not cands
        stale = now - hb.get("t", 0) > 12 * 3600
        if not quiet or stale:
            hb["t"] = now; save(HB_F, hb)
            notify("watch run done",
                   f"{len(cands)} new files, {len(addrs)} addresses, "
                   f"{len(funded)} funded ever")
        else:
            print("[watch] nothing new, staying quiet")
        print(f"[watch] done. {len(funded)} funded addresses known.")

if __name__ == "__main__":
    main()