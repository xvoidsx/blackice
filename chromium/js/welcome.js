/*******************************************************************************

    blackice - first-run welcome page logic.

    Copyright (C) 2026-present xvoidsx
    SPDX-License-Identifier: GPL-3.0-or-later
*/

import { runtime } from './ext.js';
import { dom } from './dom.js';

/******************************************************************************/

dom.on('#biWelcomeGo', 'click', ( ) => {
    runtime.openOptionsPage();
});

/******************************************************************************/
