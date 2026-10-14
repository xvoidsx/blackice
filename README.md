# blackice
<img width="1328" height="670" alt="image" src="https://github.com/user-attachments/assets/27fec579-be9c-46c3-a401-7914c975b4f7" />

###### the Blackice welcome page, greeting you and inviting you to open the dashboard

A Manifest V3 ad and tracker blocker with a nightshadeNeon soul. Forged on top of the wonderful [Ublock Origin Lite](https://github.com/uBlockOrigin/uBOL-home) — with [Brave's filter lists](https://github.com/brave/adblock-lists) now standing alongside uBO's. Block all ads and trackers, as much as possible, no matter what.

## Get blackice

- **Chrome Web Store:** [blackice](https://chromewebstore.google.com/detail/blackice/nncobpmjfngafidkngebojkabaabbkhm?authuser=0&hl=en)
- **Edge Add-ons:** pending — in review
- **Firefox:** coming soon
- **Manual install / sideload:** grab the zip for your browser from [GitHub Releases](https://github.com/xvoidsx/blackice/releases), unzip, then load unpacked via `chrome://extensions` → Developer mode → Load unpacked → select the folder.

## The xvoidsx extension store — coming soon

We're building our own extension store: an xvoidsx-run update pipeline for blackice and future xvoidsx extensions. Our own updates, our own review process (instant), our own rules. The Chrome, Edge, and Mozilla stores stay for discovery — but we own the pipeline.

## prettier privacy

<img width="360" height="578" alt="2026-09-22T07:47:09,607575348-05:00" src="https://github.com/user-attachments/assets/e0a98c20-ea0d-419a-9569-5e350339a698" />

###### blackice popover interface

**blackice** makes blocking ads and trackers easy, with a beautiful [nightshadeNeon](https://rav3ndust.xyz/wiki/nightshadeNeon.html)-drenched UI. 

Four profiles — *Off*, *Permissive*, *Standard*, *Ghost* — live per-tab block counts, a matched-rules view, and glitch-status lines, all in a 360px command card.

<img width="642" height="607" alt="2026-09-22T07:56:25,205410137-05:00" src="https://github.com/user-attachments/assets/8d53fad4-6381-4645-9f20-c5a8ba3af027" />

###### blackice settings screen

**blackice** also has an easy-to-understand Settings page, with a **Command Deck** showing some of your privacy stats: 

- The number of ads, trackers, and other nuisances blocked so far
- The number of active filtering rules
- The number of filter lists that are turned on
- The **protection mode** that is currently being used

Past the Command Deck, the dashboard carries the full uBlock Origin Lite toolkit in Blackice dress: a **Filter Lists** page for choosing which curated lists stand guard (uBO's lists plus Brave's — including `brave-unbreak`, which keeps YouTube playing nice), **Custom Filters** for writing your own rules, and the settings themselves — all under the katakana rain.



## Attribution

Blackice would not exist without [Raymond Hill](https://github.com/gorhill)
and the uBlock Origin contributors. The blocking engine, filter-list
machinery, and DNR conversion are theirs, unchanged.

It also stands on the work of the [Brave](https://brave.com) team, whose
[adblock lists](https://github.com/brave/adblock-lists) ship alongside
uBO's in every Blackice build.

- Upstream engine: © Raymond Hill / uBlock Origin contributors
- Brave filter lists: © Brave Software
- Blackice modifications (UI, branding, defaults): © xvoidsx
- This is a fork of uBlock Origin Lite, not an official uBlock project.

Base: uBOL-home@ef846e7, uBlock@bf7c476, plus the Blackice patch set.

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
Upstream's `uBlock/LICENSE.txt` also applies to the engine sources.

## Building

Prerequisites: `node`, `python3`, `make`, and network access (filter lists
are fetched at build time).

```sh
cd uBlock
make mv3-chromium
```

The unpacked extension lands in `uBlock/dist/build/blackice.chromium/`.
Load it via `chrome://extensions` → Developer mode → Load unpacked.

Manifest versions are date-based (`2026.922.1113` style); the version on the
extension card in `chrome://extensions` is always ground truth.

## Releasing

Releases are built automatically by the `create_release.yml` GitHub Actions
workflow — it compiles all four platforms (Chromium, Edge, Firefox, Safari)
and attaches the zips to a GitHub Release. Artifacts are named
`blackice-{platform}-{version}.zip` (e.g. `blackice-chromium-2026.1014.625.zip`;
Firefox ships as `.xpi`).

Store submissions (Chrome Web Store, Edge Add-ons, Mozilla AMO) are manual
for now — see AGENTS.md for the automation plan.

## Notes

- Do not run Blackice alongside uBlock Origin Lite or uBlock Origin —
  they will fight over the same requests.
- Firefox (MV3) ships as a signed `.xpi` in every release; the extension
  name is `blackice` and the ID is `rav3nwing@proton.me`.
- Filter lists ship as curated defaults: uBO's lists plus Brave's
  (`brave-unbreak` and more to come). xvoidsx-maintained lists are
  planned and will always be real lists, never placeholders.

## Privacy

See [PRIVACY.md](PRIVACY.md). Short version: Blackice collects nothing.
