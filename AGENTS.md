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

- The blocking engine, filter-list machinery, and DNR conversion are
  upstream's. Do not modify filtering behavior.
- The patch stack is interface, branding, defaults, and genuine curated
  lists. Curated lists ship real or not at all — never placeholders.
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

## Releasing

1. Build and dogfood the zip.
2. Tag `v<version>` (e.g. `v2026.922.1113`).
3. GitHub Release with the store zip attached (manifest at zip root)
   and sideload instructions: unzip → `chrome://extensions` →
   Developer mode → Load unpacked → select the folder.
4. Chrome Web Store upload is a separate manual step (Raven's dev account).

## License

GPLv3 (`LICENSE` at root; `uBlock/LICENSE.txt` covers engine sources).
