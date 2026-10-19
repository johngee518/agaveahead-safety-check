# Agave Ahead safety check

Repo: **johngee518/agaveahead-safety-check** (public; check scripts and config only, no site code, no secrets). Workflow stays `.disabled` until launch.
Agave-specific: `/sponsor/` must return 404 while sponsorships are off (`must_404`); no Amazon domains on the allowlist; TTB registry links allowlisted.

Automated, $0 external safety check for the Agave Ahead site. Python standard library only, **no secrets, no site code**.
The site itself lives and deploys in its own repo. This repo is public so GitHub Actions minutes are free and unlimited.

**Schedule:** every hour at :17 UTC (quick). The 13:17 UTC run is the daily full run. Manual: Actions → Agave Ahead safety check → Run workflow.

**Quick checks:** key pages return 200; 404 page; SSL valid and not near expiry; security headers; HTTP→HTTPS;
Google Safe Browsing (keyless Transparency Report lookup); outbound domains on an allowlist and a daily sample checked for
hijacks/parked domains/broken links; key pages match `baseline.json`; no secrets in the published pages and assets
(pattern scan + gitleaks); source/config files such as `/.env` or `/package.json` are not served.

**Daily full check:** quick + every sitemap page and every outbound link.

**Not here:** dependency audits (`npm audit`) and gitleaks over the site's git history run in the site repo.

**On failure** the run fails and GitHub emails the repo owner; the run summary lists exactly what broke.
If a content change is intentional: `python3 check.py --update-baseline` and commit `baseline.json`.

## Daily SEO check (disabled)
`scripts/seo_check.py` (ported from johngee518/setaside-safety-check) + `.github/workflows/seo-daily.yml.disabled` (daily 12:17 UTC; stdlib only, no secrets; opens/closes an "SEO alert" issue).

Agave Ahead additions: every JSON-LD block must parse and carry the required fields for its type (Article/BlogPosting: headline, datePublished, dateModified, author; FAQPage → Question → Answer text; ItemList, Brand, WebPage/CollectionPage name+url; Product only with offers, review or aggregateRating). `/llms.txt` must exist as plain text starting with `# Title`. With `EXPECT_NOINDEX=0` (launch), robots.txt must not block Googlebot, Bingbot, Applebot, Google-Extended, Applebot-Extended, GPTBot, OAI-SearchBot, ChatGPT-User, PerplexityBot, Perplexity-User, ClaudeBot, Claude-SearchBot, Claude-User, CCBot, Amazonbot, meta-externalagent or DuckDuckBot, and must have a Sitemap line. Offline: `EXPECT_NOINDEX=0 python3 scripts/seo_check.py x --robots-file path/to/robots.txt`.
Polite by design: same User-Agent and request shape as `check.py`, one request at a time ~1.5 s apart (`SEO_DELAY`), and the run stops at the first HTTP 403 instead of retrying.
Pre-launch: `EXPECT_NOINDEX=1` (default) requires noindex and robots `Disallow: /`. Real 404s are checked at `/`, `/es/` and `/ja/` (`SEO_LANG_PREFIXES`).
At launch: rename the workflow, set repo variables `SITE_URL=https://agaveahead.com` and `EXPECT_NOINDEX=0`, and re-enable repo Actions.
