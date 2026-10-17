#!/usr/bin/env python3
"""
watch.py - continuous, resumable hunter. Run under cron/systemd every 20-30 min.

  python watch.py --minutes 20 --discover 10

State lives in seedhunt's SQLite DB, so runs are atomic and resumable: an
interrupted run never loses progress and never re-reads a blob it has already
processed.
"""

import argparse
import seedhunt as sh

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=20)
    ap.add_argument("--discover", type=float, default=10, help="minutes spent discovering")
    ap.add_argument("--max-candidates", type=int, default=4000)
    a = ap.parse_args()

    sh.init_db()

    # 1) discover new ground only (partition grid is LRU-ordered, so no repeats)
    sh.say("[watch] discovering")
    pool_hits = 0
    for query in _rotating_queries():
        got = sh.search_github_code(query)
        fresh = 0
        for c in got:
            if not sh.q("SELECT 1 FROM candidates WHERE repo=? AND path=?", (c.repo, c.path)):
                fresh += 1
            sh.add_candidate(c.repo, c.path, c.source, c.query)
        pool_hits += fresh
        sh.say(f"    {query} -> {len(got)} raw, {fresh} new")
        if pool_hits >= a.max_candidates:
            break
    sh.say(f"[watch] {pool_hits} new candidates")

    # 2) triage everything untriaged (blob-hash deduped, so this is cheap)
    before = sh.q("SELECT COUNT(*) FROM funded")[0][0]
    sh.triage(argparse.Namespace(batch=20000))
    new_funds = sh.q("SELECT COUNT(*) FROM funded")[0][0] - before

    if new_funds:
        sh.notify("seedhunt: funded!",
                  f"{new_funds} new funded address(es). Total "
                  f"{sh.q('SELECT COUNT(*) FROM funded')[0][0]}.")
    elif pool_hits:
        sh.notify("seedhunt run", f"{pool_hits} new candidates. "
                                  f"{sh.q('SELECT COUNT(*) FROM addrs')[0][0]} addresses tracked.")

    # 3) recheck the oldest addresses
    sh.check_pending()

    # 4) heartbeat every 12h so you know it is alive
    import time
    if time.time() - float(sh.meta_get("heartbeat", 0)) > 12 * 3600:
        sh.meta_set("heartbeat", time.time())
        sh.notify("seedhunt alive",
                  f"{sh.q('SELECT COUNT(*) FROM candidates')[0][0]} candidates, "
                  f"{sh.q('SELECT COUNT(*) FROM funded')[0][0]} funded ever")

    sh.say(f"[watch] done. {sh.q('SELECT COUNT(*) FROM funded')[0][0]} funded known.")


def _rotating_queries():
    import random
    pool = [f"{q} {b}" for q in sh.GH_QUERIES for b in sh.STAR_BUCKETS]
    random.shuffle(pool)
    known = {r[0]: r[1] for r in sh.q("SELECT q,last FROM queries")}
    pool.sort(key=lambda s: known.get(s, 0))
    return pool


if __name__ == "__main__":
    main()