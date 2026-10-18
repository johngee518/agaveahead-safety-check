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
`scripts/seo_check.py` + `.github/workflows/seo-daily.yml.disabled` (daily 11:17 UTC; stdlib only, no secrets).
Pre-launch: `EXPECT_NOINDEX=1` (default) expects noindex on every page. At launch: rename the workflow, set repo variables `SITE_URL=https://agaveahead.com` and `EXPECT_NOINDEX=0`.
Local: `EXPECT_NOINDEX=1 python3 scripts/seo_check.py http://localhost:8091 --skip-http --warn-only`.
