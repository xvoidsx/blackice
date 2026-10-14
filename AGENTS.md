# AGENTS.md — Blackice contributor guide

Blackice is xvoidsx's Manifest V3 ad/tracker blocker: a fork of
[uBlock Origin Lite](https://github.com/uBlockOrigin/uBOL-home) (uBOL)
with a nightshadeNeon interface. Chromium is the supported platform;
Firefox ships as a signed `.xpi` in every release.

## Source map

- `uBlock/` — the engine source (inner upstream repo). `src/` is the
  extension code, `platform/mv3/` the MV3 platform layer. **Treat as
  read-only except for Blackice's documented patch set.**
- `chromium/`, `firefox/` — per-browser packaging sources and locales.
- `docs/`, `publish-extension/` — upstream docs and store-publish helpers.
- `Makefile`, `package.json` — top-level build orchestration (uBOL-home root).
- Blackice's own surface lives in the uBOL source it patches: the popup
  command card, the element picker/zapper (neon-pink highlight, sparkle
  trail), the katakana-rain dashboard, the first-run welcome page, and
  the rebranded locale strings. If you change Blackice UI, that's where.

## Building

Prerequisites: `node`, `python3`, `make`, network access (filter lists
are fetched at build time, never faked or stubbed).

```sh
cd uBlock
make mv3-chromium
```

Output: `uBlock/dist/build/blackice.chromium/` (load unpacked via
`chrome://extensions` → Developer mode). `dist/` is a build artifact —
never commit it; the shippable zip goes on a GitHub Release.

## Branding rules

- User-visible strings say **Blackice**. The extension locale name is
  `Blackice`; the build directory is `blackice.chromium`.
- Firefox: extension name is `blackice`, extension ID is
  `rav3nwing@proton.me` (set in
  `uBlock/platform/mv3/firefox/manifest.json`).
- Keep Raymond Hill's copyright and all upstream source notices intact.
  Add xvoidsx copyright **only** for Blackice modifications.
- Never present Blackice as an official uBlock project. It is a fork —
  say so everywhere, proudly (see README Attribution).
- Filter-list names and legitimate upstream references stay as-is.

## Version scheme

Date-based: `2026.922.1113` (year.monthday.build). The version on the
extension card in `chrome://extensions` is always ground truth — check
it before debugging a reported issue.

## Engine boundaries (hard rules)

- The blocking engine and DNR conversion are upstream's. Do not modify
  filtering behavior.
- **Filter philosophy (Raven, 2026-10-14):** block all ads and trackers as
  much as possible, no matter what. We adopt Brave's and uBO's way of
  doing things, and bring in our own filters when necessary. This is how
  blackice becomes the best MV3 adblocker out there. Curated lists ship
  real or not at all — never placeholders.
- The patch stack is interface, branding, defaults, and curated lists.
- The element zapper is an upstream uBOL capability, restyled — not a
  Blackice invention. Don't claim otherwise.
- No fake statistics, controls, lists, or functionality. The popup shows
  only what is genuinely measurable.
- Motion respects `prefers-reduced-motion`.
- Do not dogfood Blackice alongside uBOL or uBO — they fight over the
  same requests.

## Filter lists

Blackice ships uBO's filter lists plus Brave's
([brave/adblock-lists](https://github.com/brave/adblock-lists)).
Integration point: `uBlock/platform/mv3/rulesets.json` (the MV3 DNR
compiler reads this, not `assets.json` alone). To add a new curated
list:

1. Add the entry to `uBlock/assets/assets.json` (for the dashboard UI).
2. Add the entry to `uBlock/platform/mv3/rulesets.json` (for DNR
   compilation) — id, name, group, enabled flag, URL, homeURL.
3. Rebuild and verify the rules appear in
   `uBlock/dist/build/blackice.chromium/rulesets/main/`.

`brave-unbreak` (226 DNR rules) was the first Brave list, added
2026-10-14 — it fixed YouTube's anti-adblock reload loop.

## Privacy

Blackice collects nothing: no accounts, analytics, telemetry, or network
requests of its own. The policy lives in `PRIVACY.md` (also the URL used
in the Chrome Web Store listing). If a change ever collects data, the
policy changes first.

## Releasing

Releases are built by the `create_release.yml` GitHub Actions workflow
(trigger via workflow_dispatch). It:

1. Builds all four platforms: Chromium, Edge, Firefox (`.xpi`), Safari.
2. Commits updated MV3 package files back to the repo.
3. Creates a GitHub Release and attaches all four zips automatically
   (GITHUB_TOKEN can upload assets; the surrogate credential cannot).

Artifact naming: `blackice-{platform}-{version}.zip`, e.g.
`blackice-chromium-2026.1014.625.zip` (Firefox: `.xpi`). The naming is
set in `uBlock/tools/make-mv3.sh` (`UBOL_PACKAGE_NAME`) and echoed into
env vars in `create_release.yml`.

Release notes template: `.github/workflows/RELEASE_BODY.md`.

Manual steps (Raven): Chrome Web Store and Edge Add-ons submissions are
uploaded by hand from the release zips. See "Store automation" below.

## License

GPLv3 (`LICENSE` at root; `uBlock/LICENSE.txt` covers engine sources).

## Store automation (planned, Raven 2026-10-14)
- Full automation via store upload APIs (Chrome Web Store, Edge Add-ons, Mozilla AMO) — needs Raven to create API credentials and add as GitHub Secrets. Workflow will trigger on release publish and auto-submit to all three stores.
- Safari excluded (App Store process, can't test).

## Self-hosted extension updates (exploring, Raven 2026-10-14)
- Idea: xvoidsx's own extension update pipeline via Chromium's `update_url` manifest field — bypasses Web Store review queues, Lains handle the whole process (weekly rebuild → release → auto-update).
- Keep Chrome/Edge/Mozilla store listings for discovery, but own the pipeline as backup and for navi machines (blackice is force-installed there anyway).
- Worth exploring when there's free time. Also applies to future xvoidsx extensions.
- Tracked in Linear (XVOIDSX-30) + Notion.
