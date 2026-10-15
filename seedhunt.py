#!/usr/bin/env python3
"""
seedhunt.py - autonomous GitHub-wide hunter for leaked crypto seed phrases & private keys.

  python seedhunt.py discover     # find candidate repos/paths -> candidates.json
  python seedhunt.py triage       # fetch + validate + derive + balance
  python seedhunt.py all          # both
  python seedhunt.py deep         # trufflehog full-history pass (needs trufflehog)
"""

import argparse, json, os, re, time, threading, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

import requests

# ---------------------------------------------------------------- config

UA = {"User-Agent": "seedhunt/1.2", "Accept": "application/vnd.github+json"}
TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
if TOKEN:
    UA["Authorization"] = f"Bearer {TOKEN}"
TEXTMATCH = dict(UA, Accept="application/vnd.github.text-match+json")

HERE = Path(__file__).parent
CACHE = HERE / ".seedhunt_cache"
CACHE.mkdir(exist_ok=True)
CAND_FILE = HERE / "candidates.json"
FIND_FILE = HERE / "findings.json"

# Code search is capped at 10/min even when authenticated. Core is 60/hour unauth,
# 5000/hour auth -- which is why a token is still essential.
GH_CODE_RPM = 9
CORE_RPM = 70 if TOKEN else 0.9
GREP_RPM = 50
RAW_WORKERS = 12
BAL_WORKERS = 6
MAX_BYTES = 2_000_000

STAR_BUCKETS = ["stars:0..2", "stars:3..10", "stars:11..50",
                "stars:51..200", "stars:201..1000", "stars:>1000"]

GH_QUERIES = [
    "MNEMONIC= filename:.env",
    "mnemonic filename:.env",
    '"seedPhrase" language:TypeScript',
    '"seedPhrase" language:JavaScript',
    '"recovery phrase" filename:*.md',
    "filename:mnemonic.txt",
    "filename:seed.txt",
    "filename:.secret",
    "filename:wallet.json",
    "mnemonic filename:hardhat.config.js",
    "mnemonic filename:truffle-config.js",
    "mnemonic filename:deploy.js",
    "mnemonic filename:config.js",
    "mnemonic filename:*.yaml",
    '"MNEMONIC" filename:*.yml',
    "mnemonic filename:*.json",
]

GREP_REGEXES = [
    r"mnemonic\s*[:=]\s*[\"']?(?:[a-z]{2,8}\s){11}[a-z]{2,8}",
    r"seedPhrase\s*[:=]\s*[\"']?(?:[a-z]{2,8}\s){11}",
    r"MNEMONIC\s*=\s*[\"']?(?:[a-z]{2,8}\s){11}",
    r"seed_phrase\s*[:=]",
    r"recovery[\s_-]?phrase\s*[:=]",
    r"(?:[a-z]{3,8}\s){23}[a-z]{3,8}",
]

EVM_RPCS = {
    "ethereum": ["https://eth.llamarpc.com", "https://cloudflare-eth.com"],
    "polygon":  ["https://polygon-rpc.com"],
    "base":     ["https://mainnet.base.org"],
    "bsc":      ["https://bsc-dataseed.binance.org"],
}
BTC_INDEXES = 2
EVM_INDEXES = 3

# ---------------------------------------------------------------- plumbing

class Rate:
    def __init__(self, per_min):
        self.gap = 60.0 / per_min
        self.lock = threading.Lock()
        self.next_at = 0.0
    def wait(self):
        with self.lock:
            now = time.time()
            self.next_at = max(now, self.next_at)
            sleep = self.next_at - now
            self.next_at += self.gap
        if sleep > 0:
            time.sleep(sleep)

GH_CODE_RATE, CORE_RATE, GREP_RATE = Rate(GH_CODE_RPM), Rate(CORE_RPM), Rate(GREP_RPM)
_print_lock = threading.Lock()

def say(*a):
    with _print_lock:
        print(*a, flush=True)

def unwrap(v):
    if isinstance(v, dict):
        return v.get("raw") or v.get("value") or ""
    return v if isinstance(v, str) else ""

def req(method, url, *, headers=None, rate=None, tries=4, **kw):
    r = None
    for attempt in range(tries):
        if rate: rate.wait()
        try:
            r = requests.request(method, url, headers=headers or UA, timeout=30, **kw)
        except requests.RequestException:
            if attempt == tries - 1: raise
            time.sleep(2 ** attempt); continue
        if r.status_code in (403, 429):
            reset = r.headers.get("X-RateLimit-Reset")
            wait = max(2, min(70, int(reset) - int(time.time()))) if reset else 5 * (attempt + 1)
            say(f"    [rate] {r.status_code}, sleeping {wait}s")
            time.sleep(wait); continue
        if r.status_code >= 500:
            time.sleep(2 ** attempt); continue
        return r
    return r

# ---------------------------------------------------------------- discovery

@dataclass
class Candidate:
    repo: str
    path: str
    source: str
    query: str
    signals: int = 1
    stars: int = 0
    branch: str = ""

_meta_lock = threading.Lock()
_star_cache = {}

def fetch_stars(full_name):
    with _meta_lock:
        if full_name in _star_cache: return _star_cache[full_name]
    stars = 0
    try:
        r = req("GET", f"https://api.github.com/repos/{full_name}", rate=CORE_RATE)
        if r.status_code == 200:
            stars = r.json().get("stargazers_count", 0)
    except Exception:
        pass
    with _meta_lock:
        _star_cache[full_name] = stars
    return stars

def search_github_code(query, pages, budget):
    out, seen = [], set()
    def walk(q, depth=0):
        if len(out) >= budget: return
        page = 1
        while page <= pages and len(out) < budget:
            r = req("GET", "https://api.github.com/search/code",
                    headers=TEXTMATCH, rate=GH_CODE_RATE,
                    params={"q": q, "per_page": 100, "page": page})
            if r.status_code == 422: return
            if r.status_code != 200: break
            j = r.json()
            for it in j.get("items", []):
                key = (it["repository"]["full_name"], it["path"])
                if key in seen: continue
                seen.add(key)
                out.append(Candidate(it["repository"]["full_name"], it["path"], "github", q))
            if j.get("total_count", 0) >= 1000 and depth < 2 and page == 1:
                for win in ["pushed:>2024-01-01", "pushed:2022-01-01..2023-12-31",
                            "pushed:2020-01-01..2021-12-31", "pushed:<2020-01-01"]:
                    walk(f"{q} {win}", depth + 1)
                return
            if len(j.get("items", [])) < 100: break
            page += 1
    walk(query)
    return out

def search_grepapp(regex, pages=3):
    out = []
    for page in range(1, pages + 1):
        r = req("GET", "https://grep.app/api/search", rate=GREP_RATE,
                params={"q": regex, "page": page})
        if r.status_code != 200: break
        try:
            j = r.json()
        except Exception:
            break
        hits = (j.get("hits") or {}).get("hits") or []
        if not hits: break
        for h in hits:
            repo, path = unwrap(h.get("repo")), unwrap(h.get("path"))
            if repo and path:
                out.append(Candidate(repo, path, "grepapp", regex))
    return out

def discover(args):
    cands = {}
    def add(c):
        k = (c.repo, c.path)
        if k in cands: cands[k].signals += 1
        else: cands[k] = c

    say(f"[discover] github code search: {len(GH_QUERIES)} queries x {len(STAR_BUCKETS)} shards")
    if not TOKEN:
        say("[discover] WARNING: no GITHUB_TOKEN. Slow, and metadata will crawl.")
    for q in GH_QUERIES:
        for bucket in STAR_BUCKETS:
            for c in search_github_code(f"{q} {bucket}", args.pages, args.max_candidates):
                add(c)
        say(f"    {q[:44]:<44} total={len(cands)}")
        if len(cands) >= args.max_candidates: break

    say(f"[discover] grep.app regex: {len(GREP_REGEXES)} patterns")
    for rx in GREP_REGEXES:
        for c in search_grepapp(rx):
            add(c)
        say(f"    {rx[:44]:<44} total={len(cands)}")

    ranked = sorted(cands.values(), key=lambda c: (c.signals, -c.stars), reverse=True)
    if args.max_candidates: ranked = ranked[:args.max_candidates]

    say(f"[discover] fetching star counts for top {min(args.star_limit, len(ranked))} repos")
    for c in ranked[:args.star_limit]:
        c.stars = fetch_stars(c.repo)
    ranked.sort(key=lambda c: (c.signals, -c.stars), reverse=True)

    CAND_FILE.write_text(json.dumps([asdict(c) for c in ranked], indent=2))
    say(f"[discover] {len(ranked)} candidate files across {len({c.repo for c in ranked})} repos")
    return ranked

# ---------------------------------------------------------------- validation

from mnemonic import Mnemonic
_MN = Mnemonic("english")
WORDLIST = set(_MN.wordlist)
LENS = (24, 21, 18, 15, 12)

def find_phrases(text):
    toks = [t.lower() for t in re.split(r"[^A-Za-z]+", text) if t]
    if len(toks) > 60000: toks = toks[:60000]
    found = set()
    for i, t in enumerate(toks):
        if t not in WORDLIST: continue
        for L in LENS:
            if i + L > len(toks): continue
            if any(toks[j] not in WORDLIST for j in range(i, i + L)): continue
            p = " ".join(toks[i:i + L])
            if _MN.check(p): found.add(p)
    return sorted(found)

HEX_RE = re.compile(r"(?<![0-9a-fA-F])(?:0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])")

def find_keys(text):
    out = set()
    for m in HEX_RE.finditer(text):
        s = m.group(0)
        out.add(s[2:].lower() if s[:2].lower() == "0x" else s.lower())
    return sorted(out)

# ---------------------------------------------------------------- derivation

def derive(phrase, passphrase=""):
    from bip_utils import (Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes,
                           Bip49, Bip49Coins, Bip84, Bip84Coins, Bip86, Bip86Coins)
    seed = Bip39SeedGenerator(phrase).Generate(passphrase)
    rows = []
    def addr(cls, coin, idx):
        return (cls.FromSeed(seed, coin).Purpose().Coin().Account(0)
                .Change(Bip44Changes.CHAIN_EXT).AddressIndex(idx).PublicKey().ToAddress())
    for idx in range(BTC_INDEXES):
        rows.append(("bitcoin", f"m/44'/0'/0'/0/{idx}", addr(Bip44, Bip44Coins.BITCOIN, idx)))
        rows.append(("bitcoin", f"m/49'/0'/0'/0/{idx}", addr(Bip49, Bip49Coins.BITCOIN, idx)))
        rows.append(("bitcoin", f"m/84'/0'/0'/0/{idx}", addr(Bip84, Bip84Coins.BITCOIN, idx)))
        rows.append(("bitcoin", f"m/86'/0'/0'/0/{idx}", addr(Bip86, Bip86Coins.BITCOIN, idx)))
    for idx in range(EVM_INDEXES):
        rows.append(("evm", f"m/44'/60'/0'/0/{idx}", addr(Bip44, Bip44Coins.ETHEREUM, idx)))
    return rows

# ---------------------------------------------------------------- balances

_bal_cache = {}

def btc_balance(a):
    r = requests.get(f"https://mempool.space/api/address/{a}", timeout=20)
    if r.status_code != 200: return None
    cs = r.json().get("chain_stats", {})
    return (cs.get("funded_txo_sum", 0) - cs.get("spent_txo_sum", 0)) / 1e8

def evm_balance(a):
    total = {}
    for chain, rpcs in EVM_RPCS.items():
        for rpc in rpcs:
            try:
                r = requests.post(rpc, timeout=20, json={
                    "jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
                    "params": [a, "latest"]})
                if r.status_code == 200 and r.json().get("result"):
                    v = int(r.json()["result"], 16) / 1e18
                    if v > 0: total[chain] = v
                    break
            except Exception:
                continue
    return total

def balance(chain, a):
    k = (chain, a)
    if k in _bal_cache: return _bal_cache[k]
    try:
        out = evm_balance(a) if chain == "evm" else (btc_balance(a) if chain == "bitcoin" else {})
    except Exception:
        out = None
    _bal_cache[k] = out
    return out

# ---------------------------------------------------------------- triage

def fetch_raw(repo, path, branch=None):
    qp = urllib.parse.quote(path)
    for b in dict.fromkeys([branch] if branch else ["main", "master"]):
        try:
            r = requests.get(f"https://raw.githubusercontent.com/{repo}/{b}/{qp}",
                             timeout=25, stream=True, headers={"User-Agent": "seedhunt/1.2"})
        except requests.RequestException:
            continue
        if r.status_code != 200: continue
        buf, size = [], 0
        for chunk in r.iter_content(65536):
            buf.append(chunk); size += len(chunk)
            if size > MAX_BYTES: break
        return b"".join(buf).decode("utf-8", "ignore")
    return ""

def triage(args):
    cands = [Candidate(**c) for c in json.loads(CAND_FILE.read_text())]
    say(f"[triage] fetching {len(cands)} candidate files")
    confirmed = {}

    def work(c):
        try:
            text = fetch_raw(c.repo, c.path, c.branch)
        except Exception:
            return c, [], []
        if not text: return c, [], []
        return c, find_phrases(text), find_keys(text)

    done = 0
    with ThreadPoolExecutor(RAW_WORKERS) as ex:
        for fut in as_completed([ex.submit(work, c) for c in cands]):
            c, phrases, keys = fut.result()
            done += 1
            if done % 50 == 0: say(f"    ...{done}/{len(cands)}")
            for p in phrases:
                confirmed.setdefault(p, []).append(f"{c.repo}/{c.path}")
                say(f"    SEED  {c.repo}/{c.path}")
            for k in keys:
                confirmed.setdefault("0x" + k, []).append(f"{c.repo}/{c.path}")

    seeds = {k: v for k, v in confirmed.items() if not k.startswith("0x")}
    keys = {k: v for k, v in confirmed.items() if k.startswith("0x")}
    say(f"[triage] {len(seeds)} unique valid seed phrases, {len(keys)} raw 64-hex strings")

    jobs = [("seed", p, "") for p in seeds]
    for pp in (args.passphrases or []):
        if pp: jobs += [("seed", p, pp) for p in seeds]
    jobs += [("key", k, "") for k in keys]

    say(f"[triage] deriving + checking balances ({len(jobs)} jobs)")
    results = []

    def derive_job(kind, secret, passphrase):
        try:
            if kind == "key":
                from bip_utils import EthAddrEncoder
                return secret, passphrase, [("evm", "raw", EthAddrEncoder.EncodeKey(
                    bytes.fromhex(secret[2:])))], ""
            return secret, passphrase, derive(secret, passphrase), ""
        except Exception as e:
            return secret, passphrase, [], str(e)

    with ThreadPoolExecutor(BAL_WORKERS) as ex:
        for fut in as_completed([ex.submit(derive_job, *j) for j in jobs]):
            secret, pp, rows, err = fut.result()
            hits = []
            for chain, path, a in rows:
                bal = balance(chain, a)
                if bal and (bal if isinstance(bal, float) else any(bal.values())):
                    hits.append((chain, path, a, bal))
            results.append({"secret": secret, "passphrase": pp, "rows": rows,
                            "funded": hits, "error": err})
            if hits: say(f"    FUNDED  {secret[:40]}")

    results.sort(key=lambda r: -len(r["funded"]))
    FIND_FILE.write_text(json.dumps(results, indent=2))

    print("\n" + "=" * 72)
    print("FUNDED")
    print("=" * 72)
    any_hit = False
    for r in results:
        for chain, path, a, bal in r["funded"]:
            any_hit = True
            amt = bal if isinstance(bal, float) else ", ".join(f"{v:.6f} {k}" for k, v in bal.items())
            print(f"\n  {amt}   [{chain}] {path}\n  addr {a}")
            print(f"  seed {r['secret'][:90]}{'...' if len(r['secret']) > 90 else ''}"
                  + (f"   passphrase: {r['passphrase']!r}" if r["passphrase"] else ""))
            print(f"  src  {', '.join(confirmed.get(r['secret'], [])[:3])}")
    if not any_hit:
        print("\n  nothing funded. derived addresses are in findings.json")
    print(f"\n[full results] {FIND_FILE}")
    return results

# ---------------------------------------------------------------- deep

def deep(args):
    import subprocess
    repos = sorted({c["repo"] for c in json.loads(CAND_FILE.read_text())})
    say(f"[deep] trufflehog history scan on {len(repos)} repos")
    found = {}
    for repo in repos:
        try:
            p = subprocess.run(["trufflehog", "git", f"https://github.com/{repo}",
                                "--json", "--no-update"],
                               capture_output=True, text=True, timeout=900)
        except FileNotFoundError:
            say("[deep] trufflehog not on PATH"); return
        except subprocess.TimeoutExpired:
            say(f"    timeout {repo}"); continue
        for line in p.stdout.splitlines():
            try: j = json.loads(line)
            except Exception: continue
            for ph in find_phrases(j.get("Raw") or ""):
                found.setdefault(ph, set()).add(repo)
        say(f"    {repo}")
    (HERE / "deep_findings.json").write_text(json.dumps({k: sorted(v) for k, v in found.items()}, indent=2))
    say(f"[deep] {len(found)} phrases from history")

# ---------------------------------------------------------------- cli

def main():
    ap = argparse.ArgumentParser(description="autonomous GitHub seed-phrase hunter")
    ap.add_argument("mode", choices=["discover", "triage", "all", "deep"])
    ap.add_argument("--pages", type=int, default=2, help="code search pages per query (100/page)")
    ap.add_argument("--max-candidates", type=int, default=3000)
    ap.add_argument("--star-limit", type=int, default=400, help="repos to fetch star counts for")
    ap.add_argument("--passphrases", nargs="*", default=[""])
    a = ap.parse_args()
    if a.mode in ("discover", "all"): discover(a)
    if a.mode in ("triage", "all"):   triage(a)
    if a.mode == "deep":              deep(a)

if __name__ == "__main__":
    main()
