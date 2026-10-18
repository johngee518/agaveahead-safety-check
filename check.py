#!/usr/bin/env python3
"""Agave Ahead external safety checker (public checker-repo template). Python standard library only, NO secrets.

Probes the LIVE site from outside, like a visitor. The site's code lives and deploys in its own (private) repo.
quick mode (hourly): key pages 200, 404 page, SSL, security headers, HTTP->HTTPS, Google Safe Browsing
  (keyless Transparency Report lookup), outbound-link allowlist + sampled hijack/broken check, content-hash baseline,
  secrets in the PUBLISHED files (pattern scan + gitleaks on the downloaded copy if installed), exposed source files.
full mode (daily / manual): quick + every sitemap page and every outbound link.
Dependency audits (npm audit) cannot run here (no site code); they run in the site repo (dependency-audit workflow).

  python3 check.py [quick|full]            SITE_URL=http://localhost:8080 python3 check.py quick
  python3 check.py quick --only up,safebrowsing      checks: up,ssl,headers,safebrowsing,links,content,secrets,exposed
  python3 check.py --update-baseline       refresh baseline.json after an intended change, then commit it
Exit code 1 on any FAIL. Writes a Markdown summary to $GITHUB_STEP_SUMMARY and report.md."""
from __future__ import annotations
import glob
import argparse, datetime as dt, hashlib, html, json, os, random, re, shutil, socket, ssl, subprocess, sys, tempfile, time
import urllib.error, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.environ.get("SAFETY_CONFIG", os.path.join(ROOT, "config.json"))))
BASE = os.environ.get("SITE_URL", CFG["site_url"]).rstrip("/")
HOST = urllib.parse.urlparse(BASE).hostname or ""
UA = CFG.get("user_agent", "Mozilla/5.0 (X11; Linux x86_64) SafetyCheck/1.0")
TO = CFG.get("timeout_seconds", 15)
RESULTS: list[tuple[str, str, str]] = []
PAGES: dict[str, str] = {}   # path -> html body (filled by check_up)

def rec(status, check, detail=""):
    RESULTS.append((status, check, detail)); print(f"[{status}] {check}: {detail}", flush=True)

# TLS stays verified (CERT_REQUIRED). ttbonline.gov does not send its intermediate, so the public intermediate
# (Entrust OV TLS Issuing RSA CA 2, from Mozilla CCADB) is bundled in certs/ and added to the system trust store.
_CTX = ssl.create_default_context()
for _pem in sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs", "*.pem"))): _CTX.load_verify_locations(_pem)
_HTTPS = urllib.request.HTTPSHandler(context=_CTX)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None

def fetch(url, method="GET", follow=True, maxbytes=3_000_000, tries=2):
    """-> (status, final_url, headers(lower), body str, error). Retries 5xx/429/network once (JRG pattern)."""
    last = None
    for _ in range(tries):
        try:
            op = urllib.request.build_opener(_HTTPS) if follow else urllib.request.build_opener(_HTTPS, NoRedirect)
            req = urllib.request.Request(url, method=method, headers={"User-Agent": UA, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.8"})
            with op.open(req, timeout=TO) as r:
                body = r.read(maxbytes).decode("utf-8", "replace") if method == "GET" else ""
                return r.status, r.geturl(), {k.lower(): v for k, v in r.headers.items()}, body, None
        except urllib.error.HTTPError as e:
            try: body = e.read(200_000).decode("utf-8", "replace")
            except Exception: body = ""
            res = (e.code, e.geturl() or url, {k.lower(): v for k, v in (e.headers or {}).items()}, body, None)
            if e.code < 500 and e.code != 429: return res
            last = res
        except Exception as e:
            last = (0, url, {}, "", f"{type(e).__name__}: {e}")
        time.sleep(1.0)
    return last

def is_local():
    u = urllib.parse.urlparse(BASE)
    return u.scheme != "https" or HOST in ("localhost", "127.0.0.1", "0.0.0.0") or HOST.endswith(".local")

SITE_HOSTS = {HOST, "www." + HOST, HOST.removeprefix("www.")} | set(CFG.get("site_hosts", []))  # canonical/alias hosts
SKIP_LINK = re.compile(CFG["outbound_links"].get("skip_regex", r"^$"))
def same_site(h): return (h or "").lower() in SITE_HOSTS

def sitemap_paths():
    s, _, _, body, err = fetch(BASE + "/sitemap.xml")
    if s != 200: rec("FAIL", "Sitemap", f"/sitemap.xml returned {s or err}"); return []
    return [urllib.parse.urlparse(u).path or "/" for u in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", body)]

# ---------- pages ----------
def check_up(full=False):
    paths = list(CFG["key_pages"])
    if full: paths += sitemap_paths()
    else: paths += CFG.get("crawl_pages", [])
    paths = list(dict.fromkeys(paths))
    with ThreadPoolExecutor(10) as ex: res = list(ex.map(lambda p: (p, fetch(BASE + p)), paths))
    bad = []
    for p, (s, final, h, body, err) in res:
        if s != 200: bad.append(f"{p}={s or err}"); continue
        if not same_site(urllib.parse.urlparse(final).hostname): bad.append(f"{p} redirected off-site to {final}"); continue
        if "html" in h.get("content-type", ""): PAGES[p] = body
    if bad: rec("FAIL", "Site up", "; ".join(bad[:15]))
    else: rec("PASS", "Site up", f"{len(res)} pages returned 200 ({'key + sitemap' if full else 'key pages'})")
    s, _, h, body, err = fetch(BASE + "/safety-check-does-not-exist-%d/" % int(time.time()), tries=1)
    marker = CFG.get("not_found_marker")
    if s == 404 and marker and marker not in body:
        rec(CFG.get("not_found_mode", "warn").upper(), "404 page", f"missing page returns 404 but not the site's 404 page (marker {marker!r} absent)")
    elif s == 404: rec("PASS", "404 page", "missing page returns 404" + (" with the site's 404 page" if marker else ""))
    else: rec(CFG.get("not_found_mode", "warn").upper(), "404 page",
              f"missing page returned {s or err}, expected 404 (on Cloudflare Pages add a 404.html, otherwise every unknown URL serves the homepage with 200)")

def check_ssl():
    if is_local(): return rec("SKIP", "SSL", f"{BASE} is http/localhost")
    for host in CFG.get("ssl_hosts") or [HOST]:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=TO) as sock, ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
            exp = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc)
            days = (exp - dt.datetime.now(dt.timezone.utc)).days
            c = CFG["ssl"]
            rec("FAIL" if days < c["fail_days"] else "WARN" if days < c["warn_days"] else "PASS", "SSL",
                f"{host} valid, expires {exp:%Y-%m-%d} ({days} days)")
        except Exception as e: rec("FAIL", "SSL", f"{host} invalid/unreachable: {type(e).__name__}: {e}")

def check_headers():
    c = CFG["headers"]; mode = c.get("mode", "warn").upper()
    s, _, h, body, err = fetch(BASE + "/")
    if s != 200: return rec("FAIL", "Security headers", f"homepage returned {s or err}")
    missing = [x for x in c["required"] if x not in h]
    if is_local() and "strict-transport-security" in missing: missing.remove("strict-transport-security")
    if c.get("frame_protection") and "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        missing.append("x-frame-options or CSP frame-ancestors")
    if missing: rec("FAIL" if mode == "FAIL" else "WARN", "Security headers", "missing: " + ", ".join(missing))
    else: rec("PASS", "Security headers", "all required headers present")
    if is_local(): return rec("SKIP", "HTTP->HTTPS", "local URL")
    s, _, h2, _, err = fetch(f"http://{HOST}/", follow=False, tries=1)
    loc = h2.get("location", "")
    if s in (301, 302, 307, 308) and loc.startswith("https://"): rec("PASS", "HTTP->HTTPS", f"http://{HOST} redirects to HTTPS")
    else: rec("FAIL", "HTTP->HTTPS", f"http://{HOST} does not redirect to HTTPS (status {s or err}, location {loc!r})")

# ---------- Google Safe Browsing: keyless Transparency Report lookup (same endpoint as JRG's check.py) ----------
SB_TEXT = {1: "no unsafe content found", 2: "UNSAFE", 3: "SOME PAGES UNSAFE", 4: "no site-level verdict (check specific URLs)",
           5: "hosts uncommon downloads", 6: "no data yet (normal for a new site)"}
def safebrowsing_lookup(host):
    url = "https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site=" + urllib.parse.quote(host)
    s, _, _, body, err = fetch(url)
    try:
        data = json.loads(body.split("\n", 1)[1].strip()) if body.startswith(")]}'") else json.loads(body)
        row = data[0]; return row[1], row[2:7], None
    except Exception: return None, None, f"status {s or err}"

def check_safebrowsing():
    hosts = list(dict.fromkeys(CFG.get("safe_browsing_hosts") or ([] if is_local() else [HOST])))
    if not hosts: return rec("SKIP", "Safe Browsing", "local URL and no safe_browsing_hosts configured")
    for host in hosts:
        code, flags, err = safebrowsing_lookup(host)
        if code is None: rec("WARN", "Safe Browsing", f"lookup for {host} unavailable ({err}); skipped this run")
        elif code in (2, 3, 5) or any(f is True for f in flags): rec("FAIL", "Safe Browsing", f"Google flags {host}: {SB_TEXT.get(code, code)} (flags {flags})")
        else: rec("PASS", "Safe Browsing", f"{host}: {SB_TEXT.get(code, code)}")

# ---------- outbound links ----------
PARKED = re.compile(r"domain (is|may be) for sale|buy this domain|this domain is parked|parked free|domain parking|hugedomains|sedo\.com/search", re.I)
def allowed(host, allow): host = (host or "").lower(); return any(host == d or host.endswith("." + d) for d in allow)

def link_check(u, allow):
    s, final, h, body, err = fetch(u)
    fh = urllib.parse.urlparse(final).hostname or ""
    if s == 0: return "unreach", f"{u} ({err})"
    if h.get("cf-mitigated") == "challenge" or s in (403, 429, 503) or "captcha" in body[:50_000].lower(): return "unreach", f"{u} ({s} bot-block?)"
    if not allowed(fh, allow): return "hijack", f"{u} -> {final}"
    if s in (400, 404, 410) or s >= 500: return "broken", f"{u} ({s})"
    if s == 200 and PARKED.search(body[:200_000]): return "hijack", f"{u} looks parked/for sale"
    return "ok", u

def check_links(full=False):
    c = CFG["outbound_links"]; out = {}
    for p, body in PAGES.items():
        for m in re.finditer(r'<(?:a|iframe|img|script|link)\b[^>]*?(?:href|src)="([^"]+)"', body):
            u = urllib.parse.urlparse(urllib.parse.urljoin(BASE + p, html.unescape(m.group(1))))
            if u.scheme in ("http", "https") and not same_site(u.hostname) and not SKIP_LINK.search(u.geturl()): out.setdefault(u.geturl(), p)
    links = sorted(out)
    bad = [f"{u} (on {out[u]})" for u in links if not allowed(urllib.parse.urlparse(u).hostname, c["allowlist"])]
    if bad: rec("FAIL", "Outbound links: allowlist", f"{len(bad)} link(s) to non-allowlisted domains: " + ", ".join(bad[:10]))
    else: rec("PASS", "Outbound links: allowlist", f"all {len(links)} outbound URLs on allowlisted domains")
    rnd = random.Random(dt.date.today().isoformat())
    sample = links if full else rnd.sample(links, min(len(links), c["sample_size"]))
    with ThreadPoolExecutor(12) as ex: res = list(ex.map(lambda u: link_check(u, c["allowlist"]), sample))
    by = {k: [m for st, m in res if st == k] for k in ("hijack", "broken", "unreach")}
    if by["hijack"]: rec("FAIL", "Outbound links: hijack", "; ".join(by["hijack"][:10]))
    else: rec("PASS", "Outbound links: hijack", f"{len(sample) - len(by['unreach'])}/{len(sample)} checked links resolve on allowlist, none parked")
    md = lambda k: "FAIL" if c.get(k, "warn").upper() == "FAIL" else "WARN"
    if by["broken"]: rec(md("broken_mode"), "Outbound links: broken", "; ".join(by["broken"][:10]))
    else: rec("PASS", "Outbound links: broken", f"none broken in {len(sample)} checked")
    if by["unreach"]: rec(md("unreachable_mode"), "Outbound links: unverifiable", f"{len(by['unreach'])}/{len(sample)} (network/bot-block): " + "; ".join(by["unreach"][:5]))

# ---------- content hash baseline ----------
def page_hashes():
    c = CFG["content_hash"]; res = {}
    for p in c["pages"]:
        s, _, _, t, err = fetch(BASE + p)
        for pat, rep in c["normalize_regex"]: t = re.sub(pat, rep, t)
        t = t.replace(BASE, "{SITE}")
        res[p] = hashlib.sha256(t.encode()).hexdigest() if s == 200 else f"HTTP {s or err}"
    return res

def check_content(update=False):
    path = os.path.join(ROOT, CFG["content_hash"]["baseline_file"]); cur = page_hashes()
    if update:
        json.dump({"generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "site_url": BASE, "pages": cur}, open(path, "w"), indent=2)
        return rec("PASS", "Content hashes", f"baseline updated ({len(cur)} pages) -> {os.path.basename(path)}")
    if not os.path.exists(path): return rec("WARN", "Content hashes", "no baseline yet; run --update-baseline")
    b = json.load(open(path))
    if b.get("site_url", BASE).rstrip("/") != BASE: rec("WARN", "Content hashes", f"baseline was made against {b.get('site_url')}, not {BASE}")
    changed = [p for p in cur if b["pages"].get(p) != cur[p]]
    if changed: rec("FAIL", "Content hashes", "unexpected change on: " + ", ".join(changed) + " (if intended, run --update-baseline and commit)")
    else: rec("PASS", "Content hashes", f"{len(cur)} key pages match baseline")

# ---------- secrets in the PUBLISHED files (replaces repo gitleaks/npm, which need site code) ----------
ASSET_EXT = (".js", ".mjs", ".css", ".json", ".webmanifest", ".txt", ".xml", ".map", ".html")
def published_files():
    files = dict(PAGES)
    for p in CFG["secrets"].get("extra_paths", []): files.setdefault(p, None)
    for body in list(PAGES.values()):
        for m in re.finditer(r'(?:href|src)="([^"]+)"', body):
            u = urllib.parse.urlparse(urllib.parse.urljoin(BASE + "/", html.unescape(m.group(1))))
            if (not u.netloc or same_site(u.hostname)) and u.path.lower().endswith(ASSET_EXT): files.setdefault(u.path, None)
    todo = [p for p, b in files.items() if b is None]
    with ThreadPoolExecutor(10) as ex:
        for p, (s, _, _, b, _) in zip(todo, ex.map(lambda p: fetch(BASE + p), todo)): files[p] = b if s == 200 else ""
    return {p: b for p, b in files.items() if b}

def check_secrets():
    c = CFG["secrets"]; files = published_files()
    pats = {k: re.compile(v) for k, v in c["patterns"].items()}; hits = set()
    for p, t in files.items():
        for n, rx in pats.items():
            for m in rx.finditer(t):
                if not any(a in m.group(0) for a in c.get("allow_substrings", [])): hits.add(f"{n} in {p}")
    if hits: rec("FAIL", "Secrets: published files", "; ".join(sorted(hits)[:10]))
    else: rec("PASS", "Secrets: published files", f"no key patterns in {len(files)} live files (pages + js/css/json/manifest)")
    gl = shutil.which("gitleaks")
    if not gl: return rec("SKIP", "Secrets: gitleaks (published files)", "gitleaks not installed (the workflow installs it)")
    with tempfile.TemporaryDirectory() as d:
        for i, (p, t) in enumerate(files.items()):
            fn = os.path.join(d, f"{i:04d}_" + re.sub(r"[^A-Za-z0-9._-]", "_", p.strip("/") or "index")[:80])
            open(fn, "w").write(t)
        cmd = [gl, "dir", d, "--no-banner", "--no-color", "--redact", "-v"]
        cfgf = os.path.join(ROOT, ".gitleaks.toml")
        if os.path.exists(cfgf): cmd += ["--config", cfgf]
        r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode == 0: rec("PASS", "Secrets: gitleaks (published files)", f"no leaks in {len(files)} live files")
    else:
        txt = r.stdout + r.stderr
        rules = re.findall(r"RuleID:\s*(\S+)", txt); fl = [re.sub(r"^\d{4}_", "", os.path.basename(x)) for x in re.findall(r"File:\s*(\S+)", txt)]
        rec("FAIL", "Secrets: gitleaks (published files)", "; ".join(f"{a} in {b}" for a, b in zip(rules, fl))[:600] or txt.strip()[-400:])

def check_exposed():
    """Source/config files that must never be served (a build or upload mistake would leak them)."""
    bad = []
    for p in CFG.get("must_not_serve", []):
        s, _, h, body, err = fetch(BASE + p, tries=1, maxbytes=20_000)
        if s == 200 and not re.search(r"<!doctype html|<html", body[:2000], re.I): bad.append(f"{p} (200, {h.get('content-type', '?')})")
    for p in CFG.get("must_404", []):  # pages that must stay off until approved (e.g. /sponsor/ while sponsorships are off)
        s, _, h, body, err = fetch(BASE + p, tries=1, maxbytes=20_000)
        if s != 404: bad.append(f"{p} ({s}, must be 404 until approved)")
    if bad: rec("FAIL", "Exposed files", "served publicly: " + ", ".join(bad))
    else: rec("PASS", "Exposed files", f"none of {len(CFG.get('must_not_serve', []))} source/config paths are served")

CHECKS = ["up", "ssl", "headers", "safebrowsing", "links", "content", "secrets", "exposed"]

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("mode", nargs="?", default="quick", choices=["quick", "full"])
    ap.add_argument("--only"); ap.add_argument("--skip"); ap.add_argument("--update-baseline", action="store_true")
    a = ap.parse_args(); full = a.mode == "full"; t0 = time.time()
    print(f"Safety check for {CFG['site_name']} at {BASE} ({a.mode})\n")
    if a.update_baseline: check_content(update=True); return 0
    sel = a.only.split(",") if a.only else list(CHECKS)
    if a.skip: sel = [s for s in sel if s not in a.skip.split(",")]
    if any(s in sel for s in ("links", "secrets")) and "up" not in sel: sel.insert(0, "up")  # they need crawled pages
    fn = {"up": lambda: check_up(full), "ssl": check_ssl, "headers": check_headers, "safebrowsing": check_safebrowsing,
          "links": lambda: check_links(full), "content": check_content, "secrets": check_secrets, "exposed": check_exposed}
    for n in sel:
        try: fn[n]()
        except Exception as e: rec("FAIL", n, f"checker crashed: {type(e).__name__}: {e}")
    counts = {s: sum(1 for r in RESULTS if r[0] == s) for s in ("PASS", "WARN", "FAIL", "SKIP")}
    md = [f"## Safety check: {CFG['site_name']} ({BASE}): {'FAILED' if counts['FAIL'] else 'PASSED'}",
          f"Mode: **{a.mode}** · {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC} · {time.time() - t0:.1f}s", "",
          "| Status | Check | Detail |", "|---|---|---|"]
    md += [f"| {s} | {c} | {d.replace('|', '/')[:400]} |" for s, c, d in RESULTS]
    md += ["", " / ".join(f"{k}: {v}" for k, v in counts.items())]
    out = "\n".join(md); print("\n" + out)
    open(os.path.join(ROOT, "report.md"), "w").write(out + "\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"): open(os.environ["GITHUB_STEP_SUMMARY"], "a").write(out + "\n")
    return 1 if counts["FAIL"] else 0

if __name__ == "__main__": sys.exit(main())
