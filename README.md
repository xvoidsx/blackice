# blackice
<img width="1328" height="670" alt="image" src="https://github.com/user-attachments/assets/27fec579-be9c-46c3-a401-7914c975b4f7" />

###### the Blackice welcome page, greeting you and inviting you to open the dashboard

A Manifest V3 ad and tracker blocker with a nightshadeNeon soul. Forged on top of the wonderful [Ublock Origin Lite](https://github.com/uBlockOrigin/uBOL-home).

## prettier privacy

<img width="360" height="578" alt="2026-09-22T07:47:09,607575348-05:00" src="https://github.com/user-attachments/assets/e0a98c20-ea0d-419a-9569-5e350339a698" />

**blackice** makes blocking ads and trackers easy, with a beautiful [nightshadeNeon](https://rav3ndust.xyz/wiki/nightshadeNeon.html)-drenched UI. Four profiles — Off, Permissive, Standard, Ghost — live per-tab block counts, a matched-rules view, and glitch-status lines, all in a 360px command card.


## Attribution

Blackice would not exist without [Raymond Hill](https://github.com/gorhill)
and the uBlock Origin contributors. The blocking engine, filter-list
machinery, and DNR conversion are theirs, unchanged.

- Upstream engine: © Raymond Hill / uBlock Origin contributors
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

## Notes

- Do not run Blackice alongside uBlock Origin Lite or uBlock Origin —
  they will fight over the same requests.
- A Firefox (MV3) target exists in the tree but is not yet packaged or
  tested; Chromium is the supported platform for now.
- Filter lists ship as curated defaults; xvoidsx-maintained lists are
  planned and will always be real lists, never placeholders.

## Privacy

See [PRIVACY.md](PRIVACY.md). Short version: Blackice collects nothing.
