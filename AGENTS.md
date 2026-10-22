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

### Build tree of record (resolved 2026-10-22)

- **The `xvoidsx/blackice` repo is the tree of record.** The patch set
  was synced into it on 2026-10-22 (commit `667fdd8`): brave wiring
  (`assets.json` + `rulesets.json`), About links, Firefox manifest,
  the blackice `create_release.yml` + `RELEASE_BODY.md`, the root
  `tools/sanitize-scriptlets.sh`, and the hardened `make-mv3.sh`. An
  acceptance build from a plain repo checkout matched the hand-built
  2026.1022.705 rule-for-rule (70,494 main rules, brave-unbreak 226).
- **Releases are cut by CI**: dispatch `create_release.yml` (or drive
  it with `gh-release-pkg`); Actions builds all four platforms and
  attaches the assets — the API credential cannot upload release
  assets itself. Verified end-to-end 2026-10-22: run 39740341036 →
  release 2026.1022.725, whose zips passed every gate below.
- Local builds (from `~/workspace/blackice/uBOL-home` or a repo
  checkout) are for dogfooding and the kori path. The patch set now
  lives in BOTH trees — a fix applied to only one re-opens the
  2026.1018.700 failure mode (that build silently lost the Brave
  filters because the repo lagged the build tree).
- **Purge the ruleset cache before every local build:**
  `rm -rf uBlock/dist/build/mv3-data/chromium uBlock/dist/build/mv3-data/edge`
  (keep `mv3-data/secret.txt`). `make-rulesets` reuses cached list
  texts with *no* expiry check; a stale cache compiles silently —
  build 2026.1022.632 shipped month-old lists (rus-0 compiled
  6003 → 0 rules) and only the per-list audit caught it.
- The build's Node fetcher intermittently returns empty for some list
  hosts (easylist.to, cdn.jsdelivr.net) from the build VM while curl
  works; the build then dies with "Filter list should not be empty".
  Seed that list's cache file via curl from its canonical URL and
  verify the content (title header, size, line count) before rerunning.
- **Edge:** the workflow's Edge step passes no `before=`, so
  `tools/sanitize-scriptlets.sh` never runs for Edge. Run it manually
  on the Edge build dir before zipping, and verify the viafoura CDN
  line is gone (see Store review).
- **Locale strip:** after building, strip `_locales` in the build dir
  to `en` only, then zip. Shipping all locales makes regional
  storefronts display the upstream name; en-only + `default_locale:
  en` makes every region display "Blackice".

### The Blackice patch set (what makes it ours)

Kept in the build tree's `uBlock/` working copy:

- nightshadeNeon UI: popup command card, element picker/zapper
  styling, katakana-rain dashboard, first-run welcome page, icons.
- Rebranded locale strings (`extName` = "Blackice", fork-attribution
  About strings stay — see Branding rules).
- **Curated lists:** Brave's `brave-unbreak` is wired in at two
  points — `uBlock/assets/assets.json` and the MV3 compilation entry
  point `uBlock/platform/mv3/rulesets.json` (`id: brave-unbreak`,
  group `default`, enabled). Both are required; the manifest of a
  correct build declares it.
- **About links** (since 2026.1022.705): the dashboard About tab's
  Privacy / Documentation / Changelog links point at
  `github.com/xvoidsx/blackice` (`PRIVACY.md`, repo root, releases) —
  not upstream's wiki. Pointers that are genuinely upstream's stay:
  filter-issue reporting goes to the uAssets tracker, and copyright
  headers stay untouched.

### Our own filters (when we get there)

When xvoidsx authors its own list: host the list file in this repo,
add an entry pointing at it in **both** `assets.json` and
`platform/mv3/rulesets.json` (group `default`, enabled), rebuild, and
gate on its compiled rules appearing in the output zips (next
section). Same bar as every curated list: real or not at all.

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

## Verifying a build (release gates)

No zip is done until both platform zips pass, checked against the
previous release's zips:

- Manifest declares every expected ruleset (57 as of 2026-10),
  **including `brave-unbreak`**; its compiled rules are present
  (~226 rules: `rulesets/main/brave-unbreak.json`; Edge keeps
  rulesets at the package root, so `brave-unbreak.json` there).
- uBO's core lists are healthy: per-list main-rule counts in the same
  band as the previous release (ublock-filters ~5.6k, easylist
  ~3.7k, rus-0 ~6k, irn-0 ~700). A collapse toward 0 means a bad
  fetch or a stale cache — rebuild, don't ship.
- `permissions` / `host_permissions` identical to the previous
  release (changes kick store submissions into manual review).
- `_locales` contains only `en`; `extName` reads "Blackice"; no
  manifest `key` or `update_url` (until the kori pipeline lands).
- Zero remote-script-injection patterns under `rulesets/scripting/`
  (the sanitize gate above).

## Releasing

1. Build and dogfood the zip.
2. Tag `v<version>` (e.g. `v2026.922.1113`).
3. GitHub Release with the store zip attached (manifest at zip root)
   and sideload instructions: unzip → `chrome://extensions` →
   Developer mode → Load unpacked → select the folder.
4. Chrome Web Store upload is a separate manual step (Raven's dev account).

Local builds are published to GitHub Releases the same way (recent
releases use the bare version as the tag, e.g. `2026.1022.705`, with
notes from `.github/workflows/RELEASE_BODY.md` and the Chromium +
Edge zips attached) so anyone can sideload without the stores.
Release *asset uploads* cannot go through the API credential
(`uploads.github.com` rejects it) — create the release via API, then
attach the zips from the web UI.

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
