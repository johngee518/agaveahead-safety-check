#!/usr/bin/env python3
"""Daily technical SEO check (stdlib only). Ported from johngee518/setaside-safety-check (b3561e2) for Agave Ahead.
Agave Ahead edits: identical UA to check.py; one request at a time with a ~1.5 s gap; stop at the first 403
(Cloudflare challenge: report it, never retry harder); EXPECT_NOINDEX=1 pre-launch mode; real 404 checked per language.

Usage:
  python3 seo_check.py https://example.com [--max-pages 25] [--json report.json]
                       [--warn-only] [--timeout 15]

Reads robots.txt and sitemap.xml, samples pages from the sitemap (homepage first),
and checks: titles, meta descriptions, canonical, exactly one H1, heading order,
noindex, JSON-LD validity/types, image alt text, Open Graph/Twitter tags, viewport,
lang, favicon, hreflang (if present), real 404 status, broken internal links,
www/apex canonical host, http->https redirect.

Exit code: 0 = no FAIL, 1 = at least one FAIL, 2 = could not run.
"""
import argparse, html, json, os, re, sys, ssl, gzip, time
import urllib.request, urllib.error, urllib.parse
from html.parser import HTMLParser
import xml.etree.ElementTree as ET

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36 AgaveAhead-safety-check"  # identical to check.py (config.json user_agent)
DELAY = float(os.environ.get("SEO_DELAY", "1.5"))  # polite: one page at a time, ~1.5 s apart
EXPECT_NOINDEX = os.environ.get("EXPECT_NOINDEX") == "1"  # pre-launch: noindex + robots Disallow: / are REQUIRED
_last = [0.0]


class Blocked(Exception):
    """First 403 seen: stop the whole run (likely a bot challenge), do not hammer the site."""
CTX = ssl.create_default_context()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url, timeout=15, follow=True, method="GET"):
    """Return dict(status, url, headers, body, error, redirects)."""
    redirects = []
    cur = url
    opener = urllib.request.build_opener(NoRedirect)  # default HTTPS context (same TLS/ALPN as safety_check.py; a custom context got Cloudflare-challenged)
    for _ in range(10):
        wait = DELAY - (time.time() - _last[0])
        if wait > 0:
            time.sleep(wait)
        _last[0] = time.time()
        req = urllib.request.Request(cur, method=method, headers={"User-Agent": UA})  # same request shape as safety_check.py
        try:
            r = opener.open(req, timeout=timeout)
            status, headers, body = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            status, headers = e.code, e.headers
            try:
                body = e.read()
            except Exception:
                body = b""
        except Exception as e:
            return {"status": None, "url": cur, "headers": {}, "body": "", "error": str(e), "redirects": redirects}
        if status == 403:
            raise Blocked(cur)
        if headers.get("Content-Encoding") == "gzip" and body:
            try:
                body = gzip.decompress(body)
            except Exception:
                pass
        if status in (301, 302, 303, 307, 308) and follow:
            loc = urllib.parse.urljoin(cur, headers.get("Location", ""))
            redirects.append((status, cur, loc))
            cur = loc
            continue
        text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
        return {"status": status, "url": cur, "headers": headers, "body": text, "bytes": len(body),
                "error": None, "redirects": redirects}
    return {"status": None, "url": cur, "headers": {}, "body": "", "error": "too many redirects", "redirects": redirects}


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = None; self._in_title = False
        self.metas = []; self.links = []; self.anchors = []; self.imgs = []
        self.headings = []; self._h = None; self._htext = ""
        self.html_lang = None; self.jsonld = []; self._in_ld = False; self._ld = ""
        self.scripts = 0; self.styles = 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html":
            self.html_lang = a.get("lang")
        elif tag == "title" and self.title is None:
            self._in_title = True; self.title = ""
        elif tag == "meta":
            self.metas.append(a)
        elif tag == "link":
            self.links.append(a)
            if "stylesheet" in a.get("rel", "").lower():
                self.styles += 1
        elif tag == "a" and "href" in a:
            self.anchors.append(a["href"])
        elif tag == "img":
            self.imgs.append(a)
        elif tag == "script":
            if a.get("type", "").lower() == "application/ld+json":
                self._in_ld = True; self._ld = ""
            elif a.get("src"):
                self.scripts += 1
        elif re.fullmatch(r"h[1-6]", tag):
            self._h = int(tag[1]); self._htext = ""

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "script" and self._in_ld:
            self._in_ld = False; self.jsonld.append(self._ld)
        elif self._h and tag == f"h{self._h}":
            self.headings.append((self._h, " ".join(self._htext.split())))
            self._h = None

    def handle_data(self, d):
        if self._in_title:
            self.title += d
        if self._in_ld:
            self._ld += d
        if self._h:
            self._htext += d

    def meta(self, key):
        key = key.lower()
        for m in self.metas:
            if m.get("name", "").lower() == key or m.get("property", "").lower() == key:
                return m.get("content")
        return None


def ld_types(obj, out):
    if isinstance(obj, list):
        for o in obj:
            ld_types(o, out)
    elif isinstance(obj, dict):
        t = obj.get("@type")
        if isinstance(t, list):
            out.extend(map(str, t))
        elif t:
            out.append(str(t))
        for k in ("@graph", "mainEntity", "itemListElement", "publisher", "author", "offers"):
            if k in obj:
                ld_types(obj[k], out)
    return out


# --- Structured-data required fields (Agave Ahead additions) ---------------------------------------------
LD_REQUIRED = {
    "Article": ("headline", "datePublished", "dateModified", "author"),
    "BlogPosting": ("headline", "datePublished", "dateModified", "author"),
    "NewsArticle": ("headline", "datePublished", "dateModified", "author"),
    "FAQPage": ("mainEntity",),
    "Question": ("name", "acceptedAnswer"),
    "Answer": ("text",),
    "ItemList": ("itemListElement",),
    "BreadcrumbList": ("itemListElement",),
    "Brand": ("name",),
    "Organization": ("name",),
    "WebSite": ("name", "url"),
    "WebPage": ("name", "url"),
    "CollectionPage": ("name", "url"),
    "AboutPage": ("name", "url"),
    "Product": ("name",),
}


def ld_missing(obj, where="", out=None):
    """Return a list of 'Type: missing field' problems for every typed node (recursing into nested objects)."""
    out = [] if out is None else out
    if isinstance(obj, list):
        for o in obj:
            ld_missing(o, where, out)
    elif isinstance(obj, dict):
        ts = obj.get("@type")
        for t in (ts if isinstance(ts, list) else [ts] if ts else []):
            for f in LD_REQUIRED.get(str(t), ()):
                v = obj.get(f)
                if v in (None, "", [], {}):
                    out.append(f"{t}: missing {f}")
            if t == "Product" and not any(obj.get(k) for k in ("offers", "review", "aggregateRating")):
                out.append("Product: needs offers, review or aggregateRating (do not use Product without them)")
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                ld_missing(v, where, out)
    return out


# --- robots.txt: AI answer-engine and search crawlers that must not be blocked at launch ---------------------
AI_CRAWLERS = ["Googlebot", "Bingbot", "Applebot", "Google-Extended", "Applebot-Extended", "GPTBot", "OAI-SearchBot",
               "ChatGPT-User", "PerplexityBot", "Perplexity-User", "ClaudeBot", "Claude-SearchBot", "Claude-User", "CCBot",
               "Amazonbot", "meta-externalagent", "DuckDuckBot"]


def robots_groups(body):
    """Parse robots.txt into {user-agent (lowercase): [(directive, value), ...]}; consecutive User-agent lines share a group."""
    groups, cur, last_ua = {}, [], False
    for raw in body.splitlines():
        line = raw.split("#")[0].strip()
        if ":" not in line:
            continue
        k, v = (x.strip() for x in line.split(":", 1))
        k = k.lower()
        if k == "user-agent":
            if not last_ua:
                cur = []
            cur.append(v.lower()); groups.setdefault(v.lower(), [])
            last_ua = True
        elif k in ("allow", "disallow"):
            last_ua = False
            for ua in cur:
                groups[ua].append((k, v))
        else:
            last_ua = False
    return groups


def robots_blocks_root(groups, ua):
    """True if the group that applies to `ua` (its own group, else '*') disallows the whole site (Disallow: / with no Allow: /)."""
    rules = groups.get(ua.lower(), groups.get("*", []))
    dis = any(k == "disallow" and v == "/" for k, v in rules)
    allow = any(k == "allow" and v == "/" for k, v in rules)
    return dis and not allow


def check_ai_robots(body, rep, scope="robots.txt"):
    groups = robots_groups(body)
    blocked = [ua for ua in AI_CRAWLERS if robots_blocks_root(groups, ua)]
    if EXPECT_NOINDEX:
        rep.ok(scope, f"pre-launch: {len(blocked)}/{len(AI_CRAWLERS)} search/AI crawlers blocked (expected before launch)")
    elif blocked:
        rep.fail(scope, "blocks search/AI crawlers at launch: " + ", ".join(blocked))
    else:
        rep.ok(scope, f"allows all {len(AI_CRAWLERS)} listed search/AI crawlers")
    if not EXPECT_NOINDEX and not re.search(r"(?im)^\s*sitemap:\s*\S+", body):
        rep.fail(scope, "no Sitemap: line (required at launch)")


def footer_unlinked(body, site_name=""):
    """Footer rule: section headings and the site name in the footer must be links. Returns plain-text items found."""
    m = re.search(r"<footer\b.*?</footer>", body, re.S | re.I)
    if not m:
        return []
    ft = m.group(0)
    out = []
    for h in re.findall(r"<h[2-6]\b[^>]*>(.*?)</h[2-6]>", ft, re.S | re.I):
        if "<a " not in h.lower():
            out.append(html.unescape(re.sub(r"<[^>]+>", "", h)).strip())
    if site_name:
        plain = html.unescape(re.sub(r"<[^>]+>", " ", re.sub(r"<a\b.*?</a>", " ", ft, flags=re.S | re.I)))
        if re.search(r"(?<!\w)" + re.escape(site_name) + r"(?!\w)", plain):
            out.append(site_name)
    return [x for x in out if x]


def parse_sitemap(url, timeout, seen=None, depth=0):
    seen = seen if seen is not None else set()
    urls, problems = [], []
    if url in seen or depth > 3:
        return urls, problems
    seen.add(url)
    r = fetch(url, timeout)
    if r["status"] != 200:
        return urls, [f"sitemap {url} returned {r['status'] or r['error']}"]
    try:
        root = ET.fromstring(r["body"].encode("utf-8"))
    except ET.ParseError as e:
        return urls, [f"sitemap {url} is not valid XML: {e}"]
    ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    if root.tag.endswith("sitemapindex"):
        for loc in root.findall(".//s:sitemap/s:loc", ns):
            u, p = parse_sitemap(loc.text.strip(), timeout, seen, depth + 1)
            urls += u; problems += p
    elif root.tag.endswith("urlset"):
        urls += [l.text.strip() for l in root.findall(".//s:url/s:loc", ns) if l.text]
    else:
        problems.append(f"sitemap {url} root is <{root.tag}>, expected urlset/sitemapindex")
    return urls, problems


class Report:
    def __init__(self):
        self.items = []  # (level, scope, message)

    def add(self, level, scope, msg):
        self.items.append((level, scope, msg))

    def fail(self, s, m): self.add("FAIL", s, m)
    def warn(self, s, m): self.add("WARN", s, m)
    def ok(self, s, m): self.add("PASS", s, m)


def check_page(url, base_host, rep, timeout, all_titles, all_descs, link_targets):
    r = fetch(url, timeout)
    path = urllib.parse.urlparse(url).path or "/"
    if r["status"] != 200:
        rep.fail(path, f"returned HTTP {r['status'] or r['error']}")
        return None
    if r["redirects"]:
        rep.warn(path, f"sitemap URL redirects ({len(r['redirects'])} hop) to {r['url']}")
    if len(r["redirects"]) > 1:
        rep.fail(path, f"redirect chain of {len(r['redirects'])} hops")
    p = PageParser()
    try:
        p.feed(r["body"])
    except Exception as e:
        rep.warn(path, f"HTML parse issue: {e}")
    info = {"url": url, "bytes": r.get("bytes", 0), "scripts": p.scripts, "styles": p.styles}
    for item in footer_unlinked(r["body"], p.meta("og:site_name") or ""):
        rep.fail(path, f"footer names a page/section without a link: {item!r}")
    # robots meta / header
    robots = (p.meta("robots") or "") + " " + (p.meta("googlebot") or "") + " " + str(r["headers"].get("X-Robots-Tag", ""))
    if EXPECT_NOINDEX:
        if "noindex" in robots.lower():
            rep.ok(path, "noindex present (expected before launch)")
        else:
            rep.fail(path, "noindex missing but EXPECT_NOINDEX=1 (pre-launch pages must stay out of search)")
    elif "noindex" in robots.lower():
        rep.fail(path, "page is set to noindex (meta robots or X-Robots-Tag)")
    # title
    t = " ".join((p.title or "").split())
    info["title"] = t
    if not t:
        rep.fail(path, "missing <title>")
    else:
        if not 30 <= len(t) <= 65:
            rep.warn(path, f"title length {len(t)} (aim 30-60): {t!r}")
        all_titles.setdefault(t, []).append(path)
    # description
    d = " ".join((p.meta("description") or "").split())
    info["description"] = d
    if not d:
        rep.fail(path, "missing meta description")
    else:
        if not 70 <= len(d) <= 165:
            rep.warn(path, f"meta description length {len(d)} (aim 70-160)")
        all_descs.setdefault(d, []).append(path)
    # canonical
    canon = [l.get("href") for l in p.links if "canonical" in l.get("rel", "").lower().split()]
    info["canonical"] = canon
    if not canon:
        rep.fail(path, "missing rel=canonical")
    elif len(canon) > 1:
        rep.fail(path, f"{len(canon)} canonical tags")
    else:
        ch = urllib.parse.urlparse(urllib.parse.urljoin(url, canon[0])).netloc
        if ch != base_host:
            rep.fail(path, f"canonical points to other host: {canon[0]}")
    # headings
    h1s = [h for h in p.headings if h[0] == 1]
    info["h1"] = [h[1] for h in h1s]
    if len(h1s) != 1:
        rep.fail(path, f"{len(h1s)} H1 tags (need exactly 1)")
    prev = 0
    for lvl, _ in p.headings:
        if prev and lvl > prev + 1:
            rep.warn(path, f"heading level skips from H{prev} to H{lvl}")
            break
        prev = lvl
    # social
    for k in ("og:title", "og:description", "og:image", "og:url", "og:type"):
        if not p.meta(k):
            (rep.fail if k in ("og:title", "og:image") else rep.warn)(path, f"missing {k}")
    if not p.meta("twitter:card"):
        rep.warn(path, "missing twitter:card")
    img = p.meta("og:image")
    info["og_image"] = img
    # JSON-LD
    types = []
    ld_bad = 0
    for blob in p.jsonld:
        try:
            obj = json.loads(blob)
        except Exception as e:
            rep.fail(path, f"invalid JSON-LD: {e}"); ld_bad += 1
            continue
        ld_types(obj, types)
        for m in sorted(set(ld_missing(obj))):
            rep.fail(path, f"JSON-LD {m}"); ld_bad += 1
    info["jsonld_problems"] = ld_bad
    info["jsonld"] = types
    if not p.jsonld:
        rep.warn(path, "no JSON-LD structured data")
    if re.search(r"/(blog|news|posts?|articles?)/(?!category/|tag/|page/)[^/]+", path) and not any(
            t in ("Article", "BlogPosting", "NewsArticle") for t in types):
        rep.warn(path, "blog/news post has no Article/BlogPosting JSON-LD")
    # images
    missing = [i.get("src", "")[:80] for i in p.imgs if "alt" not in i]
    info["imgs"] = len(p.imgs); info["imgs_no_alt"] = len(missing)
    if missing:
        rep.warn(path, f"{len(missing)}/{len(p.imgs)} <img> without alt attribute")
    # basics
    vp = p.meta("viewport")
    if not vp or "width=device-width" not in vp:
        rep.fail(path, "missing/incorrect viewport meta")
    if not p.html_lang:
        rep.fail(path, "missing <html lang>")
    info["lang"] = p.html_lang
    if not any(set(l.get("rel", "").lower().split()) & {"icon"} for l in p.links):
        rep.warn(path, "no <link rel=icon> (favicon)")
    # hreflang
    hl = [(l.get("hreflang"), l.get("href")) for l in p.links if l.get("hreflang")]
    info["hreflang"] = hl
    if hl:
        codes = [c for c, _ in hl]
        if "x-default" not in [c.lower() for c in codes]:
            rep.warn(path, "hreflang set present but no x-default")
        if not any(urllib.parse.urljoin(url, h).rstrip("/") == url.rstrip("/") for _, h in hl):
            rep.warn(path, "hreflang set does not include a self-reference")
        for c, h in hl:
            if not re.fullmatch(r"(x-default|[a-z]{2,3}(-[A-Za-z]{2,4})?)", c, re.I):
                rep.fail(path, f"invalid hreflang code {c!r}")
            link_targets.add(urllib.parse.urljoin(url, h).split("#")[0])
    # GSC
    if p.meta("google-site-verification"):
        info["gsc_meta"] = True
    # internal links
    for href in p.anchors:
        if href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")) or "/cdn-cgi/" in href:
            continue
        absu = urllib.parse.urljoin(url, href).split("#")[0]
        if urllib.parse.urlparse(absu).netloc == base_host:
            link_targets.add(absu)
    return info


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base")
    ap.add_argument("--max-pages", type=int, default=25)
    ap.add_argument("--max-links", type=int, default=150, help="max internal links to verify")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", help="write full results to this JSON file")
    ap.add_argument("--warn-only", action="store_true", help="always exit 0")
    ap.add_argument("--skip-http", action="store_true", help="skip the http:// -> https:// check (port 80 blocked)")
    ap.add_argument("--robots-file", help="offline: check a local robots.txt (e.g. the launch-only file) and exit")
    a = ap.parse_args()
    if a.robots_file:
        rep = Report(); check_ai_robots(open(a.robots_file, encoding="utf-8").read(), rep, scope=a.robots_file)
        for lvl, sc, m in rep.items if hasattr(rep, "items") else []:
            print(f"  [{lvl}] {sc}: {m}")
        return 1 if any(x[0] == "FAIL" for x in getattr(rep, "items", [])) else 0

    base = a.base.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base
    rep = Report()
    home = fetch(base + "/", a.timeout)
    if home["status"] != 200:
        print(f"ERROR: homepage {base}/ returned {home['status'] or home['error']}")
        _h = home.get('headers') or {}
        print(f"  server={_h.get('server')} cf-mitigated={_h.get('cf-mitigated')} cf-ray={_h.get('cf-ray')}")
        return 2
    final = urllib.parse.urlparse(home["url"])
    host = final.netloc
    if final.scheme != "https":
        rep.fail("site", "homepage does not end on https")
    if len(home["redirects"]) > 1:
        rep.fail("site", f"homepage redirect chain: {home['redirects']}")

    # host variants
    bare = host[4:] if host.startswith("www.") else host
    # *.pages.dev has no www host of its own (and Agave Ahead uses no www/domain redirects), so only the bare host is checked there.
    no_www = bare.endswith(".pages.dev") or os.environ.get("SEO_NO_WWW") == "1"
    variants = [f"https://{bare}/"] + ([] if no_www else [f"https://www.{bare}/"])
    if not a.skip_http:
        variants += [f"http://{bare}/"] + ([] if no_www else [f"http://www.{bare}/"])
    for v in variants:
        r = fetch(v, a.timeout)
        hops = len(r["redirects"])
        if r["status"] is None:
            (rep.warn if v.startswith("http://") else rep.fail)("site", f"{v} unreachable: {r['error']}")
        elif urllib.parse.urlparse(r["url"]).netloc != host:
            rep.fail("site", f"{v} ends on {r['url']} (not canonical host {host})")
        elif v.rstrip("/") != f"https://{host}" and hops == 0:
            rep.fail("site", f"{v} serves 200 without redirecting to https://{host}/ (duplicate host)")
        elif hops > 1:
            rep.warn("site", f"{v} takes {hops} redirects to reach canonical")

    # robots
    rb = fetch(f"https://{host}/robots.txt", a.timeout)
    sitemaps = []
    if rb["status"] != 200:
        rep.fail("robots.txt", f"returned {rb['status'] or rb['error']}")
    else:
        body = rb["body"]
        sitemaps = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", body)
        cur_ua, blocks = None, []
        for line in body.splitlines():
            line = line.split("#")[0].strip()
            if line.lower().startswith("user-agent:"):
                cur_ua = line.split(":", 1)[1].strip()
            elif line.lower().startswith("disallow:") and cur_ua in ("*", "Googlebot"):
                val = line.split(":", 1)[1].strip()
                if val == "/":
                    (rep.ok if EXPECT_NOINDEX else rep.fail)("robots.txt", f"Disallow: / for {cur_ua} blocks the whole site" + (" (expected before launch)" if EXPECT_NOINDEX else ""))
                elif val:
                    blocks.append(val)
        if blocks:
            rep.ok("robots.txt", "disallows: " + ", ".join(blocks))
        if not sitemaps:
            (rep.ok if EXPECT_NOINDEX else rep.warn)("robots.txt", "no Sitemap: line" + (" (expected while Disallow: / is in place)" if EXPECT_NOINDEX else ""))
        check_ai_robots(body, rep)
    # llms.txt (plain-text site summary for AI answer engines)
    lt = fetch(f"https://{host}/llms.txt", a.timeout)
    if lt["status"] != 200:
        rep.fail("llms.txt", f"returned {lt['status'] or lt['error']}")
    elif not lt["body"].lstrip().startswith("# "):
        rep.fail("llms.txt", "does not start with a '# Title' line")
    elif "text/html" in str(lt["headers"].get("Content-Type", "")).lower():
        rep.fail("llms.txt", "served as HTML (expected text/plain)")
    else:
        rep.ok("llms.txt", f"present ({len(lt['body'])} chars, {len(re.findall(r'\]\(https?://', lt['body']))} links)")
    if not sitemaps:
        sitemaps = [f"https://{host}/sitemap.xml"]
    urls, probs = [], []
    for sm in sitemaps:
        u, p = parse_sitemap(sm, a.timeout)
        urls += u; probs += p
    for p in probs:
        rep.fail("sitemap", p)
    urls = list(dict.fromkeys(urls))
    if not urls and not probs:
        rep.fail("sitemap", "sitemap has no URLs")
    for u in urls:
        if urllib.parse.urlparse(u).netloc != host:
            rep.fail("sitemap", f"URL on non-canonical host: {u}")
            break

    # sitemap URL statuses (HEAD-ish, all of them up to 200)
    bad_sm = 0
    for u in urls[:200]:
        r = fetch(u, a.timeout, follow=False)
        if r["status"] != 200:
            bad_sm += 1
            rep.fail("sitemap", f"{u} returned {r['status'] or r['error']}")
    # pages
    # round-robin across top-level sections so every page type gets sampled
    groups = {}
    for u in urls:
        if u.rstrip("/") == f"https://{host}":
            continue
        seg = (urllib.parse.urlparse(u).path.strip("/").split("/") or [""])[0]
        groups.setdefault(seg, []).append(u)
    sample, i = [f"https://{host}/"], 0
    while len(sample) < a.max_pages and any(len(g) > i for g in groups.values()):
        for g in groups.values():
            if len(g) > i and len(sample) < a.max_pages:
                sample.append(g[i])
        i += 1
    titles, descs, targets, pages = {}, {}, set(), []
    for u in sample:
        info = check_page(u, host, rep, a.timeout, titles, descs, targets)
        if info:
            pages.append(info)
    for t, ps in titles.items():
        if len(ps) > 1:
            rep.fail("site", f"duplicate title on {ps}: {t!r}")
    for d, ps in descs.items():
        if len(ps) > 1:
            rep.warn("site", f"duplicate meta description on {len(ps)} pages: {ps[:5]}")
    # broken links
    checked = set(sample)
    broken = []
    for t in sorted(targets - checked)[: a.max_links]:
        r = fetch(t, a.timeout)
        if r["status"] is None or r["status"] >= 400:
            broken.append((t, r["status"] or r["error"]))
    for t, s in broken:
        rep.fail("links", f"broken internal link {t} -> {s}")
    # 404
    for pre in [""] + [f"/{c}" for c in os.environ.get("SEO_LANG_PREFIXES", "es,ja").split(",") if c]:
        r = fetch(f"https://{host}{pre}/this-page-should-not-exist-{int(time.time())}/", a.timeout)
        if r["status"] != 404:
            rep.fail("site", f"missing page {pre or '/'}… returns HTTP {r['status']} instead of 404 (soft 404)")
        else:
            rep.ok("site", f"missing page under {pre or '/'} returns a real 404")
    # GSC
    if any(p.get("gsc_meta") for p in pages):
        rep.ok("site", "google-site-verification meta present")

    fails = [i for i in rep.items if i[0] == "FAIL"]
    warns = [i for i in rep.items if i[0] == "WARN"]
    print(f"SEO check for https://{host}/  pages={len(pages)} sitemap_urls={len(urls)} "
          f"links_checked={min(len(targets - checked), a.max_links)}")
    for lvl in ("FAIL", "WARN", "PASS"):
        for l, s, m in rep.items:
            if l == lvl:
                print(f"  [{l}] {s}: {m}")
    print(f"SUMMARY: {len(fails)} fail, {len(warns)} warn")
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"host": host, "sitemap_urls": urls, "pages": pages,
                       "items": rep.items}, f, indent=2, default=str)
    if fails and not a.warn_only:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Blocked as b:
        print(f"SEO check STOPPED: HTTP 403 at {b} (bot challenge?). Not retrying.")
        print("SUMMARY: 1 fail, 0 warn")
        sys.exit(1)
