# AGENTS.md — Blackice contributor guide

Blackice is xvoidsx's Manifest V3 ad/tracker blocker: a fork of
[uBlock Origin Lite](https://github.com/uBlockOrigin/uBOL-home) (uBOL)
with a nightshadeNeon interface. Chromium is the supported platform;
a Firefox MV3 target exists in-tree but is unpackaged and untested.

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

## Privacy

Blackice collects nothing: no accounts, analytics, telemetry, or network
requests of its own. The policy lives in `PRIVACY.md` (also the URL used
in the Chrome Web Store listing). If a change ever collects data, the
policy changes first.

## Store review (hard-won lesson, 2026-10-14)

Chrome Web Store's MV3 scanner flags **any** `document.createElement("script")`
with a remote `src`, even inside filter-list scriptlets. uBO's lists include
compatibility shims that re-inject third-party scripts (e.g. a gocomics.com
scriptlet re-injecting `cdn.viafoura.net/entry/index.js`) — the scanner
doesn't care that it's filter data, not the extension loading remote code.

`tools/sanitize-scriptlets.sh` strips these at build time (wired into
`create_release.yml` for all four platforms). Removing a tracker re-enabler
aligns with the block-everything philosophy, so this is a feature, not a
workaround. Before every store submission, verify the built zip contains no
remote-script-injection patterns in `rulesets/scripting/`.

## Releasing

1. Build and dogfood the zip.
2. Tag `v<version>` (e.g. `v2026.922.1113`).
3. GitHub Release with the store zip attached (manifest at zip root)
   and sideload instructions: unzip → `chrome://extensions` →
   Developer mode → Load unpacked → select the folder.
4. Chrome Web Store upload is a separate manual step (Raven's dev account).

## License

GPLv3 (`LICENSE` at root; `uBlock/LICENSE.txt` covers engine sources).

## Store automation (planned, Raven 2026-10-14)
- Full automation via store upload APIs (Chrome Web Store, Edge Add-ons, Mozilla AMO) — needs Raven to create API credentials and add as GitHub Secrets. Workflow will trigger on release publish and auto-submit to all three stores.
- Safari excluded (App Store process, can't test).

## Self-hosted extension updates (exploring, Raven 2026-10-14)
- Idea: xvoidsx's own extension update pipeline via Chromium's `update_url` manifest field — bypasses Web Store review queues, Lains handle the whole process (weekly rebuild → release → auto-update).
- Keep Chrome/Edge/Mozilla store listings for discovery, but own the pipeline as backup and for navi machines (blackice is force-installed there anyway).
- Worth exploring when there's free time. Also applies to future xvoidsx extensions.
- Tracked in Linear + Notion.
