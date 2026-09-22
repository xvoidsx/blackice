/*******************************************************************************

    uBlock Origin Lite - a comprehensive, MV3-compliant content blocker
    Copyright (C) 2025-present Raymond Hill

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see {http://www.gnu.org/licenses/}.

    Home: https://github.com/gorhill/uBlock
*/

(async ( ) => {

/******************************************************************************/

const ubolOverlay = self.ubolOverlay;
if ( ubolOverlay === undefined ) { return; }
if ( ubolOverlay.file === '/zapper-ui.html' ) { return; }

/******************************************************************************/

// https://www.reddit.com/r/uBlockOrigin/comments/bktxtb/scrolling_doesnt_work/emn901o
//   Override 'fixed' position property on body element if present.

// With touch-driven devices, first highlight the element and remove only
// when tapping again the highlighted area.

function zapElementAtPoint(mx, my, options) {
    if ( options.highlight ) {
        const elem = ubolOverlay.elementFromPoint(mx, my);
        if ( elem ) {
            ubolOverlay.highlightElements([ elem ]);
        }
        return;
    }

    let elemToRemove = ubolOverlay.highlightedElements?.[0] ?? null;
    if ( elemToRemove === null && mx !== undefined ) {
        elemToRemove = ubolOverlay.elementFromPoint(mx, my);
    }

    if ( elemToRemove instanceof Element === false ) { return; }

    const getStyleValue = (elem, prop) => {
        const style = window.getComputedStyle(elem);
        return style ? style[prop] : '';
    };

    // Heuristic to detect scroll-locking: remove such lock when detected.
    let maybeScrollLocked = elemToRemove.shadowRoot instanceof DocumentFragment;
    if ( maybeScrollLocked === false ) {
        let elem = elemToRemove;
        do {
            maybeScrollLocked =
                parseInt(getStyleValue(elem, 'zIndex'), 10) >= 1000 ||
                getStyleValue(elem, 'position') === 'fixed';
            elem = elem.parentElement;
        } while ( elem !== null && maybeScrollLocked === false );
    }
    if ( maybeScrollLocked ) {
        const doc = document;
        if ( getStyleValue(doc.body, 'overflowY') === 'hidden' ) {
            doc.body.style.setProperty('overflow', 'auto', 'important');
        }
        if ( getStyleValue(doc.body, 'position') === 'fixed' ) {
            doc.body.style.setProperty('position', 'initial', 'important');
        }
        if ( getStyleValue(doc.documentElement, 'position') === 'fixed' ) {
            doc.documentElement.style.setProperty('position', 'initial', 'important');
        }
        if ( getStyleValue(doc.documentElement, 'overflowY') === 'hidden' ) {
            doc.documentElement.style.setProperty('overflow', 'auto', 'important');
        }
    }
    // blackice: shrink-and-fade the doomed element, fire a neon particle
    // burst with an expanding shockwave ring at its position, then remove
    // it. Snappy (~400ms), and skipped entirely under prefers-reduced-motion.
    blackicePoofRemove(elemToRemove);
    self.setTimeout(( ) => {
        // The tool may have been quit during the poof; the overlay tears
        // down its frame and port on quit, so check before re-highlighting.
        if ( ubolOverlay.frame !== null ) {
            ubolOverlay.highlightElementAtPoint(mx, my);
        }
    }, blackicePoofDuration());
}

/******************************************************************************/

// blackice zapper flair. Everything is inline-styled with !important so the
// page's own CSS can't fight the animation; all nodes are cleaned up after.
function blackicePoofDuration() {
    return blackiceReducedMotion() ? 0 : 400;
}

function blackiceReducedMotion() {
    return self.matchMedia !== undefined &&
        self.matchMedia('(prefers-reduced-motion: reduce)').matches === true;
}

function blackicePoofRemove(elem) {
    if ( blackiceReducedMotion() ) {
        elem.remove();
        return;
    }
    // Never animate away the root nodes themselves; just remove.
    if ( elem === document.documentElement || elem === document.body ) {
        elem.remove();
        return;
    }
    const rect = elem.getBoundingClientRect();
    elem.style.setProperty('transition', 'transform 0.28s ease-in, opacity 0.28s ease-in', 'important');
    elem.style.setProperty('transform-origin', 'center center', 'important');
    // Force a reflow so the transition actually runs.
    void elem.offsetWidth;
    elem.style.setProperty('transform', 'scale(0.82)', 'important');
    elem.style.setProperty('opacity', '0', 'important');

    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;
    const host = document.createElement('div');
    host.setAttribute('aria-hidden', 'true');
    host.style.cssText =
        'position:fixed;' +
        `left:${cx}px;top:${cy}px;` +
        'width:0;height:0;' +
        'z-index:2147483647;' +
        'pointer-events:none;';
    const colors = [ '#ff10f0', '#00ffff', '#ff10f0', '#39ff14', '#00ffff', '#ffffff' ];
    for ( let i = 0; i < 30; i++ ) {
        const p = document.createElement('div');
        const color = colors[i % colors.length];
        const size = 3 + Math.random() * 6;
        p.style.cssText =
            'position:absolute;' +
            `width:${size}px;height:${size}px;` +
            'border-radius:50%;' +
            `background:${color};` +
            `box-shadow:0 0 10px ${color};` +
            'left:0;top:0;' +
            'transition:transform 0.38s ease-out, opacity 0.38s ease-out;';
        host.appendChild(p);
        const angle = Math.random() * Math.PI * 2;
        const dist = 40 + Math.random() * 95;
        const dx = Math.cos(angle) * dist;
        const dy = Math.sin(angle) * dist;
        self.requestAnimationFrame(( ) => {
            p.style.transform = `translate(${dx}px, ${dy}px) scale(0.3)`;
            p.style.opacity = '0';
        });
    }
    // blackice: expanding shockwave rings for extra drama.
    const ringColors = [ '#ff10f0', '#00ffff' ];
    for ( let r = 0; r < ringColors.length; r++ ) {
        const ringColor = ringColors[r];
        const ring = document.createElement('div');
        ring.style.cssText =
            'position:absolute;' +
            'width:56px;height:56px;' +
            'left:-28px;top:-28px;' +
            'border-radius:50%;' +
            `border:2px solid ${ringColor};` +
            `box-shadow:0 0 14px ${ringColor}, inset 0 0 14px ${ringColor};` +
            'transform:scale(0.15);' +
            'opacity:0.95;' +
            `transition:transform 0.38s ease-out ${r * 0.07}s, ` +
            `opacity 0.38s ease-out ${r * 0.07}s;`;
        host.appendChild(ring);
        self.requestAnimationFrame(( ) => {
            ring.style.transform = 'scale(2.6)';
            ring.style.opacity = '0';
        });
    }
    document.documentElement.appendChild(host);
    self.setTimeout(( ) => {
        elem.remove();
        host.remove();
    }, blackicePoofDuration());
}

/******************************************************************************/

function onKeyPressed(ev) {
    if ( ev.key !== 'Delete' && ev.key !== 'Backspace' ) { return; }
    ev.stopPropagation();
    ev.preventDefault();
    zapElementAtPoint();
}

/******************************************************************************/

// blackice: sparkle trail that follows the cursor while zapper mode is
// active. IMPORTANT: the overlay installs a fullscreen iframe (zapper-ui.html)
// which swallows all pointer events, so a mousemove listener on the page
// window here would NEVER fire (v5 learned this the hard way — the trail
// silently never appeared). Instead we ride the 'highlightElementAtPoint'
// messages the iframe already forwards on every hover; those carry the
// cursor's viewport coordinates. Sparkles spawn at the pointer and fade on
// their own, so there is no follow-lag failure mode. pointer-events:none and
// a topmost z-index (the sparkle layer is created after the iframe, so it
// paints above the overlay's translucent veil) so it never interferes with
// the hover-highlight outline or click-to-zap. Fully removed on quit, never
// created under prefers-reduced-motion.
let blackiceSparkleLayer = null;
let blackiceSparkleLast = 0;
const blackiceSparkleColors = [ '#ff10f0', '#00ffff', '#ffffff', '#39ff14' ];

function blackiceSpawnSparkles(x, y) {
    if ( blackiceSparkleLayer === null ) { return; }
    // Cap live nodes so fast mouse movement can't spam the DOM.
    if ( blackiceSparkleLayer.childElementCount > 28 ) { return; }
    const n = Math.random() < 0.5 ? 2 : 1;
    for ( let i = 0; i < n; i++ ) {
        const s = document.createElement('div');
        const size = 2 + Math.random() * 4;
        const color = blackiceSparkleColors[
            (Math.random() * blackiceSparkleColors.length) | 0
        ];
        const ox = (Math.random() - 0.5) * 10;
        const oy = (Math.random() - 0.5) * 10;
        s.style.cssText =
            'position:fixed;' +
            `left:${x + ox}px;top:${y + oy}px;` +
            `width:${size}px;height:${size}px;` +
            'border-radius:50%;' +
            `background:${color};` +
            `box-shadow:0 0 6px ${color};` +
            'pointer-events:none;' +
            'transition:transform 0.42s ease-out, opacity 0.42s ease-out;';
        blackiceSparkleLayer.appendChild(s);
        const dx = (Math.random() - 0.5) * 26;
        const dy = -8 - Math.random() * 22;
        self.requestAnimationFrame(( ) => {
            s.style.transform = `translate(${dx}px, ${dy}px) scale(0.15)`;
            s.style.opacity = '0';
        });
        self.setTimeout(( ) => { s.remove(); }, 460);
    }
}

// Cursor position forwarded by the overlay iframe on hover (see note
// above about why we can't listen for mousemove on the page window).
function blackiceHoverSparkles(x, y) {
    if ( typeof x !== 'number' || typeof y !== 'number' ) { return; }
    const now = self.performance.now();
    if ( now - blackiceSparkleLast < 42 ) { return; }
    blackiceSparkleLast = now;
    blackiceSpawnSparkles(x, y);
}

function blackiceSparkleStart() {
    if ( blackiceReducedMotion() ) { return; }
    if ( blackiceSparkleLayer !== null ) { return; }
    const layer = document.createElement('div');
    layer.setAttribute('aria-hidden', 'true');
    layer.style.cssText =
        'position:fixed;left:0;top:0;width:100vw;height:100vh;' +
        'z-index:2147483647;pointer-events:none;';
    document.documentElement.appendChild(layer);
    blackiceSparkleLayer = layer;
    blackiceSparkleLast = 0;
}

function blackiceSparkleStop() {
    if ( blackiceSparkleLayer === null ) { return; }
    blackiceSparkleLayer.remove();
    blackiceSparkleLayer = null;
}

/******************************************************************************/

function startZapper() {
    self.addEventListener('keydown', onKeyPressed, true);
    blackiceSparkleStart();
}

function quitZapper() {
    self.removeEventListener('keydown', onKeyPressed, true);
    blackiceSparkleStop();
}

/******************************************************************************/

function onMessage(msg) {
    switch ( msg.what ) {
    case 'startTool':
        startZapper();
        break;
    case 'quitTool':
        quitZapper();
        break;
    case 'highlightElementAtPoint':
        // The overlay iframe forwards the cursor position on every hover;
        // this is the only reliable cursor feed while the tool is active.
        blackiceHoverSparkles(msg.mx, msg.my);
        break;
    case 'zapElementAtPoint':
        zapElementAtPoint(msg.mx, msg.my, msg.options);
        if ( msg.options.highlight !== true && msg.options.stay !== true ) {
            quitZapper();
        }
        break;
    default:
        break;
    }
}

/******************************************************************************/

await ubolOverlay.install('/zapper-ui.html', onMessage);

/******************************************************************************/

})();


void 0;
