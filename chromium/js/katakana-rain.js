/*******************************************************************************

    blackice - katakana rain backdrop for the dashboard and welcome page.
    Lightweight canvas, slow fall, very low alpha so text stays readable.
    Static single frame under prefers-reduced-motion.

    Copyright (C) 2026-present xvoidsx
    SPDX-License-Identifier: GPL-3.0-or-later
*/

(function () {
    'use strict';

    // Don't stack multiple rains if the script is ever included twice.
    if ( document.getElementById('biRain') !== null ) { return; }

    const reducedMotion = window.matchMedia !== undefined &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches === true;

    const canvas = document.createElement('canvas');
    canvas.id = 'biRain';
    canvas.setAttribute('aria-hidden', 'true');
    document.body.prepend(canvas);
    const ctx = canvas.getContext('2d');

    // Katakana block U+30A1..U+30F6 plus digits.
    let glyphs = '';
    for ( let c = 0x30A1; c <= 0x30F6; c++ ) {
        glyphs += String.fromCharCode(c);
    }
    glyphs += '0123456789';

    const COLORS = [
        '255,16,240',   // neon pink
        '0,255,255',     // cyan
        '0,255,255',
        '255,16,240',
        '57,255,20',     // neon green, rare
    ];

    const FONT_SIZE = 14;
    const COL_GAP = 30;

    let drops = [];
    let width = 0;
    let height = 0;

    function resize() {
        const dpr = Math.min(window.devicePixelRatio || 1, 2);
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = Math.floor(width * dpr);
        canvas.height = Math.floor(height * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        const cols = Math.ceil(width / COL_GAP);
        drops = [];
        for ( let i = 0; i < cols; i++ ) {
            drops.push({
                x: i * COL_GAP + Math.random() * 12,
                y: Math.random() * height,
                speed: 22 + Math.random() * 38,   // px per second, slow drift
                color: COLORS[(Math.random() * COLORS.length) | 0],
            });
        }
    }

    function drawFrame(dt) {
        ctx.clearRect(0, 0, width, height);
        ctx.font = `${FONT_SIZE}px "Noto Sans", monospace`;
        ctx.textBaseline = 'top';
        for ( const d of drops ) {
            const ch = glyphs[(Math.random() * glyphs.length) | 0];
            const head = Math.random() < 0.12;
            const alpha = head ? 0.22 : 0.08 + Math.random() * 0.05;
            ctx.fillStyle = `rgba(${d.color},${alpha.toFixed(3)})`;
            ctx.fillText(ch, d.x, d.y);
            if ( dt > 0 ) {
                d.y += d.speed * dt;
                if ( d.y > height + FONT_SIZE ) {
                    d.y = -FONT_SIZE - Math.random() * 120;
                    d.color = COLORS[(Math.random() * COLORS.length) | 0];
                }
            }
        }
    }

    resize();
    window.addEventListener('resize', resize);

    if ( reducedMotion ) {
        // One static frame: atmosphere without motion.
        drawFrame(0);
        return;
    }

    let last = performance.now();
    // ~20fps is plenty for a slow ambient rain; keeps CPU near zero.
    let acc = 0;
    function tick(now) {
        const dt = Math.min((now - last) / 1000, 0.1);
        last = now;
        acc += dt;
        if ( acc >= 0.05 ) {
            drawFrame(acc);
            acc = 0;
        }
        requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
})();
