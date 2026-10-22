**Blackice** — xvoidsx's MV3 ad/tracker blocker. A fork of uBlock Origin Lite with a nightshadeNeon interface, blending uBO's filter lists with Brave's filters for the best of both blocking worlds.

- [Documentation](https://github.com/xvoidsx/blackice#readme)
- [Privacy policy](https://github.com/xvoidsx/blackice/blob/main/PRIVACY.md)

## Release notes

%changelog%
- Brave's `brave-unbreak` filters are included alongside uBO's — they fix the YouTube anti-adblock playback loop seen with stock uBOL.
- [Commit history](https://github.com/xvoidsx/blackice/commits/%tag%)

## Installation

Store installs update automatically once each store's review clears; the packages below are for sideloading or getting it early.

- Chromium-based browsers: `blackice-chromium-%tag%.zip` — unzip → `chrome://extensions` → Developer mode → **Load unpacked** → select the folder.
- Microsoft Edge: `blackice-edge-%tag%.zip` — same flow via `edge://extensions`.
- Firefox: `blackice-firefox-%tag%.xpi` (unsigned — temporary install via `about:debugging`, or a Firefox build with signature checks relaxed).
- Safari: `blackice-safari-%tag%.zip` — the Safari extension package (for the macOS app build).

Engine credit: uBlock Origin Lite by Raymond Hill (GPLv3). Filter credit includes Brave (`brave-unbreak`) and the many list authors whose work ships inside.
