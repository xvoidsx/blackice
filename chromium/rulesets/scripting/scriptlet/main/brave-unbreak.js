/*******************************************************************************

    uBlock Origin Lite - a comprehensive, MV3-compliant content blocker
    Copyright (C) 2014-present Raymond Hill

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

// ruleset: brave-unbreak

// Important!
// Isolate from global scope

// Start of local scope
(function uBOL_scriptlets() {

/******************************************************************************/

class RangeParser {
    constructor(s) {
        this.not = s.charAt(0) === '!';
        if ( this.not ) { s = s.slice(1); }
        if ( s === '' ) { return; }
        const pos = s.indexOf('-');
        if ( pos !== 0 ) {
            this.min = this.max = parseInt(s, 10) || 0;
        }
        if ( pos !== -1 ) {
            this.max = parseInt(s.slice(pos + 1), 10) || Number.MAX_SAFE_INTEGER;
        }
    }
    unbound() {
        return this.min === undefined && this.max === undefined;
    }
    test(v) {
        const n = Math.min(Math.max(Number(v) || 0, 0), Number.MAX_SAFE_INTEGER);
        if ( this.min === this.max ) {
            return (this.min === undefined || n === this.min) !== this.not;
        }
        if ( this.min === undefined ) {
            return (n <= this.max) !== this.not;
        }
        if ( this.max === undefined ) {
            return (n >= this.min) !== this.not;
        }
        return (n >= this.min && n <= this.max) !== this.not;
    }
}

function abortCurrentScript(...args) {
    runAtHtmlElementFn(( ) => {
        abortCurrentScriptFn(...args);
    });
}

function abortCurrentScriptFn(
    target = '',
    needle = '',
    context = ''
) {
    if ( typeof target !== 'string' ) { return; }
    if ( target === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('abort-current-script', target, needle, context);
    const reNeedle = safe.patternToRegex(needle);
    const reContext = safe.patternToRegex(context);
    const thisScript = document.currentScript;
    const exceptionToken = getExceptionTokenFn();
    const scriptTexts = new WeakMap();
    const textContentGetter = Object.getOwnPropertyDescriptor(Node.prototype, 'textContent').get;
    const getScriptText = elem => {
        let text = textContentGetter.call(elem);
        if ( text.trim() !== '' ) { return text; }
        if ( scriptTexts.has(elem) ) { return scriptTexts.get(elem); }
        const [ , mime, content ] = /^data:([^,]*),(.+)$/.exec(elem.src.trim()) ||
            [ '', '', '' ];
        try {
            switch ( true ) {
            case mime.endsWith(';base64'):
                text = self.atob(content);
                break;
            default:
                text = self.decodeURIComponent(content);
                break;
            }
        } catch {
        }
        scriptTexts.set(elem, text);
        return text;
    };
    const validate = ( ) => {
        const e = document.currentScript;
        if ( e instanceof HTMLScriptElement === false ) { return; }
        if ( e === thisScript ) { return; }
        if ( context !== '' && reContext.test(e.src) === false ) { return; }
        if ( safe.logLevel > 1 && context !== '' ) {
            safe.uboLog(logPrefix, `Matched src\n${e.src}`);
        }
        const scriptText = getScriptText(e);
        if ( reNeedle.test(scriptText) === false ) { return; }
        if ( safe.logLevel > 1 ) {
            safe.uboLog(logPrefix, `Matched text\n${scriptText}`);
        }
        safe.uboLog(logPrefix, 'Aborted');
        throw new ReferenceError(exceptionToken);
    };
    let currentValue = trapPropertyFn(target, {
        get: function() {
            validate();
            return currentValue;
        },
        set: function(a) {
            validate();
            currentValue = a;
        }
    }, { canThrow: true });
}

function abortOnPropertyRead(
    chain = ''
) {
    if ( typeof chain !== 'string' ) { return; }
    if ( chain === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('abort-on-property-read', chain);
    const exceptionToken = getExceptionTokenFn();
    const abort = function() {
        safe.uboLog(logPrefix, 'Aborted');
        throw new ReferenceError(exceptionToken);
    };
    const makeProxy = function(owner, chain) {
        const pos = chain.indexOf('.');
        if ( pos === -1 ) {
            const desc = Object.getOwnPropertyDescriptor(owner, chain);
            if ( !desc || desc.get !== abort ) {
                Object.defineProperty(owner, chain, {
                    get: abort,
                    set: function(){}
                });
            }
            return;
        }
        const prop = chain.slice(0, pos);
        let v = owner[prop];
        chain = chain.slice(pos + 1);
        if ( v ) {
            makeProxy(v, chain);
            return;
        }
        const desc = Object.getOwnPropertyDescriptor(owner, prop);
        if ( desc && desc.set !== undefined ) { return; }
        Object.defineProperty(owner, prop, {
            get: function() { return v; },
            set: function(a) {
                v = a;
                if ( a instanceof Object ) {
                    makeProxy(a, chain);
                }
            }
        });
    };
    const owner = window;
    makeProxy(owner, chain);
}

function abortOnPropertyWrite(
    prop = ''
) {
    if ( typeof prop !== 'string' ) { return; }
    if ( prop === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('abort-on-property-write', prop);
    const exceptionToken = getExceptionTokenFn();
    let owner = window;
    for (;;) {
        const pos = prop.indexOf('.');
        if ( pos === -1 ) { break; }
        owner = owner[prop.slice(0, pos)];
        if ( owner instanceof Object === false ) { return; }
        prop = prop.slice(pos + 1);
    }
    delete owner[prop];
    Object.defineProperty(owner, prop, {
        set: function() {
            safe.uboLog(logPrefix, 'Aborted');
            throw new ReferenceError(exceptionToken);
        }
    });
}

function abortOnStackTrace(
    chain = '',
    needle = '',
    ...varargs
) {
    if ( typeof chain !== 'string' ) { return; }
    const safe = safeSelf();
    const needleDetails = safe.initPattern(needle, { canNegate: true });
    const extraArgs = safe.parseVarargs(varargs);
    if ( needle === '' ) { extraArgs.log = 'all'; }
    const makeProxy = function(owner, chain) {
        const pos = chain.indexOf('.');
        if ( pos === -1 ) {
            let v = owner[chain];
            Object.defineProperty(owner, chain, {
                get: function() {
                    const log = safe.logLevel > 1 ? 'all' : 'match';
                    if ( matchesStackTraceFn(needleDetails, log) ) {
                        throw new ReferenceError(getExceptionTokenFn());
                    }
                    return v;
                },
                set: function(a) {
                    const log = safe.logLevel > 1 ? 'all' : 'match';
                    if ( matchesStackTraceFn(needleDetails, log) ) {
                        throw new ReferenceError(getExceptionTokenFn());
                    }
                    v = a;
                },
            });
            return;
        }
        const prop = chain.slice(0, pos);
        let v = owner[prop];
        chain = chain.slice(pos + 1);
        if ( v ) {
            makeProxy(v, chain);
            return;
        }
        const desc = Object.getOwnPropertyDescriptor(owner, prop);
        if ( desc && desc.set !== undefined ) { return; }
        Object.defineProperty(owner, prop, {
            get: function() { return v; },
            set: function(a) {
                v = a;
                if ( a instanceof Object ) {
                    makeProxy(a, chain);
                }
            }
        });
    };
    const owner = window;
    makeProxy(owner, chain);
}

function collateFetchArgumentsFn(resource, options) {
    const safe = safeSelf();
    const props = [
        'body', 'cache', 'credentials', 'duplex', 'headers',
        'integrity', 'keepalive', 'method', 'mode', 'priority',
        'redirect', 'referrer', 'referrerPolicy', 'url'
    ];
    const out = {};
    if ( collateFetchArgumentsFn.collateKnownProps === undefined ) {
        collateFetchArgumentsFn.collateKnownProps = (src, out) => {
            for ( const prop of props ) {
                if ( src[prop] === undefined ) { continue; }
                out[prop] = src[prop];
            }
        };
    }
    if (
        typeof resource !== 'object' ||
        safe.Object_toString.call(resource) !== '[object Request]'
    ) {
        out.url = `${resource}`;
    } else {
        let clone;
        try {
            clone = safe.Request_clone.call(resource);
        } catch {
        }
        collateFetchArgumentsFn.collateKnownProps(clone || resource, out);
    }
    if ( typeof options === 'object' && options !== null ) {
        collateFetchArgumentsFn.collateKnownProps(options, out);
    }
    return out;
}

function generateContentFn(trusted, directive) {
    const safe = safeSelf();
    const randomize = len => {
        const chunks = [];
        let textSize = 0;
        do {
            const s = safe.Math_random().toString(36).slice(2);
            chunks.push(s);
            textSize += s.length;
        }
        while ( textSize < len );
        return chunks.join(' ').slice(0, len);
    };
    if ( directive === 'true' ) {
        return randomize(10);
    }
    if ( directive === 'emptyObj' ) {
        return '{}';
    }
    if ( directive === 'emptyArr' ) {
        return '[]';
    }
    if ( directive === 'emptyStr' ) {
        return '';
    }
    if ( directive.startsWith('length:') ) {
        const match = /^length:(\d+)(?:-(\d+))?$/.exec(directive);
        if ( match === null ) { return ''; }
        const min = parseInt(match[1], 10);
        const extent = safe.Math_max(parseInt(match[2], 10) || 0, min) - min;
        const len = safe.Math_min(min + extent * safe.Math_random(), 500000);
        return randomize(len | 0);
    }
    if ( directive.startsWith('war:') ) {
        if ( scriptletGlobals.warOrigin === undefined ) { return ''; }
        return new Promise(resolve => {
            const warOrigin = scriptletGlobals.warOrigin;
            const warName = directive.slice(4);
            const fullpath = [ warOrigin, '/', warName ];
            const warSecret = scriptletGlobals.warSecret;
            if ( warSecret !== undefined ) {
                fullpath.push('?secret=', warSecret);
            }
            const warXHR = new safe.XMLHttpRequest();
            warXHR.responseType = 'text';
            warXHR.onloadend = ev => {
                resolve(ev.target.responseText || '');
            };
            warXHR.open('GET', fullpath.join(''));
            warXHR.send();
        }).catch(( ) => '');
    }
    if ( directive.startsWith('join:') ) {
        const parts = directive.slice(7)
                .split(directive.slice(5, 7))
                .map(a => generateContentFn(trusted, a));
        return parts.some(a => a instanceof Promise)
            ? Promise.all(parts).then(parts => parts.join(''))
            : parts.join('');
    }
    if ( trusted ) {
        return directive;
    }
    return '';
}

function getExceptionTokenFn() {
    const token = getRandomTokenFn();
    const oe = self.onerror;
    self.onerror = function(msg, ...args) {
        if ( typeof msg === 'string' && msg.includes(token) ) { return true; }
        if ( oe instanceof Function ) {
            return oe.call(this, msg, ...args);
        }
    }.bind();
    return token;
}

function getRandomTokenFn() {
    const safe = safeSelf();
    return safe.String_fromCharCode(Date.now() % 26 + 97) +
        safe.Math_floor(safe.Math_random() * 982451653 + 982451653).toString(36);
}

function jsonPrune(
    rawPrunePaths = '',
    rawNeedlePaths = '',
    stackNeedle = '',
    ...varargs
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('json-prune', rawPrunePaths, rawNeedlePaths, stackNeedle);
    const stackNeedleDetails = safe.initPattern(stackNeedle, { canNegate: true });
    const extraArgs = safe.parseVarargs(varargs);
    proxyApplyFn('JSON.parse', function(context) {
        const objBefore = context.reflect();
        if ( rawPrunePaths === '' ) {
            safe.uboLog(logPrefix, safe.JSON_stringify(objBefore, null, 2));
        }
        const objAfter = objectPruneFn(
            objBefore,
            rawPrunePaths,
            rawNeedlePaths,
            stackNeedleDetails,
            extraArgs
        );
        if ( objAfter === undefined ) { return objBefore; }
        safe.uboLog(logPrefix, 'Pruned');
        if ( safe.logLevel > 1 ) {
            safe.uboLog(logPrefix, `After pruning:\n${safe.JSON_stringify(objAfter, null, 2)}`);
        }
        return objAfter;
    });
}

function jsonPruneXhrResponse(
    rawPrunePaths = '',
    rawNeedlePaths = '',
    ...varargs
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('json-prune-xhr-response', rawPrunePaths, rawNeedlePaths);
    const xhrInstances = new WeakMap();
    const extraArgs = safe.parseVarargs(varargs);
    const propNeedles = parsePropertiesToMatchFn(extraArgs.propsToMatch, 'url');
    const stackNeedle = safe.initPattern(extraArgs.stackToMatch || '', { canNegate: true });
    self.XMLHttpRequest = class extends self.XMLHttpRequest {
        open(method, url, ...args) {
            const xhrDetails = { method, url };
            let outcome = 'match';
            if ( propNeedles.size !== 0 ) {
                if ( matchObjectPropertiesFn(propNeedles, xhrDetails) === undefined ) {
                    outcome = 'nomatch';
                }
            }
            if ( outcome === 'match' ) {
                if ( safe.logLevel > 1 ) {
                    safe.uboLog(logPrefix, `Matched optional "propsToMatch", "${extraArgs.propsToMatch}"`);
                }
                xhrInstances.set(this, xhrDetails);
            }
            return super.open(method, url, ...args);
        }
        get response() {
            const innerResponse = super.response;
            const xhrDetails = xhrInstances.get(this);
            if ( xhrDetails === undefined ) {
                return innerResponse;
            }
            const responseLength = typeof innerResponse === 'string'
                ? innerResponse.length
                : undefined;
            if ( xhrDetails.lastResponseLength !== responseLength ) {
                xhrDetails.response = undefined;
                xhrDetails.lastResponseLength = responseLength;
            }
            if ( xhrDetails.response !== undefined ) {
                return xhrDetails.response;
            }
            let objBefore;
            if ( typeof innerResponse === 'object' ) {
                objBefore = innerResponse;
            } else if ( typeof innerResponse === 'string' ) {
                try {
                    objBefore = safe.JSON_parse(innerResponse);
                } catch {
                }
            }
            if ( typeof objBefore !== 'object' ) {
                return (xhrDetails.response = innerResponse);
            }
            const objAfter = objectPruneFn(
                objBefore,
                rawPrunePaths,
                rawNeedlePaths,
                stackNeedle,
                extraArgs
            );
            let outerResponse;
            if ( typeof objAfter === 'object' ) {
                outerResponse = typeof innerResponse === 'string'
                    ? safe.JSON_stringify(objAfter)
                    : objAfter;
                safe.uboLog(logPrefix, 'Pruned');
            } else {
                outerResponse = innerResponse;
            }
            return (xhrDetails.response = outerResponse);
        }
        get responseText() {
            const response = this.response;
            return typeof response !== 'string'
                ? super.responseText
                : response;
        }
    };
}

function matchObjectPropertiesFn(propNeedles, ...objs) {
    const safe = safeSelf();
    const matched = [];
    for ( const obj of objs ) {
        if ( obj instanceof Object === false ) { continue; }
        for ( const [ prop, details ] of propNeedles ) {
            let value = obj[prop];
            if ( value === undefined ) { continue; }
            if ( typeof value !== 'string' ) {
                try { value = safe.JSON_stringify(value); }
                catch { }
                if ( typeof value !== 'string' ) { continue; }
            }
            if ( safe.testPattern(details, value) === false ) { return; }
            matched.push(`${prop}: ${value}`);
        }
    }
    return matched;
}

function matchesStackTraceFn(
    needleDetails,
    logLevel = ''
) {
    const safe = safeSelf();
    const exceptionToken = getExceptionTokenFn();
    const error = new safe.Error(exceptionToken);
    const docURL = new URL(self.location.href);
    docURL.hash = '';
    // Normalize stack trace
    const reLine = /(.*?@)?(\S+)(:\d+):\d+\)?$/;
    const lines = [];
    for ( let line of safe.String_split.call(error.stack, /[\n\r]+/) ) {
        if ( line.includes(exceptionToken) ) { continue; }
        line = line.trim();
        const match = safe.RegExp_exec.call(reLine, line);
        if ( match === null ) { continue; }
        let url = match[2];
        if ( url.startsWith('(') ) { url = url.slice(1); }
        if ( url === docURL.href ) {
            url = 'inlineScript';
        } else if ( url.startsWith('<anonymous>') ) {
            url = 'injectedScript';
        }
        let fn = match[1] !== undefined
            ? match[1].slice(0, -1)
            : line.slice(0, match.index).trim();
        if ( fn.startsWith('at') ) { fn = fn.slice(2).trim(); }
        let rowcol = match[3];
        lines.push(' ' + `${fn} ${url}${rowcol}:1`.trim());
    }
    lines[0] = `stackDepth:${lines.length-1}`;
    const stack = lines.join('\t');
    const r = needleDetails.matchAll !== true &&
        safe.testPattern(needleDetails, stack);
    if (
        logLevel === 'all' ||
        logLevel === 'match' && r ||
        logLevel === 'nomatch' && !r
    ) {
        safe.uboLog(stack.replace(/\t/g, '\n'));
    }
    return r;
}

function noEvalIf(
    needle = ''
) {
    if ( typeof needle !== 'string' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('noeval-if', needle);
    const reNeedle = safe.patternToRegex(needle);
    proxyApplyFn('eval', function(context) {
        const { callArgs } = context;
        const a = String(callArgs[0]);
        if ( needle !== '' && reNeedle.test(a) ) {
            safe.uboLog(logPrefix, 'Prevented:\n', a);
            return;
        }
        if ( needle === '' || safe.logLevel > 1 ) {
            safe.uboLog(logPrefix, 'Not prevented:\n', a);
        }
        return context.reflect();
    });
}

function noWebrtc() {
    var rtcName = window.RTCPeerConnection ? 'RTCPeerConnection' : (
        window.webkitRTCPeerConnection ? 'webkitRTCPeerConnection' : ''
    );
    if ( rtcName === '' ) { return; }
    var log = console.log.bind(console);
    var pc = function(cfg) {
        log('Document tried to create an RTCPeerConnection: %o', cfg);
    };
    const noop = function() {
    };
    pc.prototype = {
        close: noop,
        createDataChannel: noop,
        createOffer: noop,
        setRemoteDescription: noop,
        toString: function() {
            return '[object RTCPeerConnection]';
        }
    };
    var z = window[rtcName];
    window[rtcName] = pc.bind(window);
    if ( z.prototype ) {
        z.prototype.createDataChannel = function() {
            return {
                close: function() {},
                send: function() {}
            };
        }.bind(null);
    }
}

function noWindowOpenIf(
    pattern = '',
    delay = '',
    decoy = ''
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('no-window-open-if', pattern, delay, decoy);
    const targetMatchResult = pattern.startsWith('!') === false;
    if ( targetMatchResult === false ) {
        pattern = pattern.slice(1);
    }
    const rePattern = safe.patternToRegex(pattern);
    const autoRemoveAfter = (parseFloat(delay) || 0) * 1000;
    const setTimeout = self.setTimeout;
    const createDecoy = function(tag, urlProp, url) {
        const decoyElem = document.createElement(tag);
        decoyElem[urlProp] = url;
        decoyElem.style.setProperty('height','1px', 'important');
        decoyElem.style.setProperty('position','fixed', 'important');
        decoyElem.style.setProperty('top','-1px', 'important');
        decoyElem.style.setProperty('width','1px', 'important');
        document.body.appendChild(decoyElem);
        setTimeout(( ) => { decoyElem.remove(); }, autoRemoveAfter);
        return decoyElem;
    };
    const noopFunc = function(){};
    proxyApplyFn('open', function open(context) {
        if ( pattern === 'debug' && safe.logLevel !== 0 ) {
            debugger; // eslint-disable-line no-debugger
            return context.reflect();
        }
        const { callArgs } = context;
        const haystack = callArgs.join(' ');
        if ( rePattern.test(haystack) !== targetMatchResult ) {
            if ( safe.logLevel > 1 ) {
                safe.uboLog(logPrefix, `Allowed (${callArgs.join(', ')})`);
            }
            return context.reflect();
        }
        safe.uboLog(logPrefix, `Prevented (${callArgs.join(', ')})`);
        if ( delay === '' ) { return null; }
        if ( decoy === 'blank' ) {
            callArgs[0] = 'about:blank';
            const r = context.reflect();
            setTimeout(( ) => { r.close(); }, autoRemoveAfter);
            return r;
        }
        const decoyElem = decoy === 'obj'
            ? createDecoy('object', 'data', ...callArgs)
            : createDecoy('iframe', 'src', ...callArgs);
        let popup = decoyElem.contentWindow;
        if ( typeof popup === 'object' && popup !== null ) {
            Object.defineProperty(popup, 'closed', { value: false });
        } else {
            popup = new Proxy(self, {
                get: function(target, prop, ...args) {
                    if ( prop === 'closed' ) { return false; }
                    const r = Reflect.get(target, prop, ...args);
                    if ( typeof r === 'function' ) { return noopFunc; }
                    return r;
                },
                set: function(...args) {
                    return Reflect.set(...args);
                },
            });
        }
        if ( safe.logLevel !== 0 ) {
            popup = new Proxy(popup, {
                get: function(target, prop, ...args) {
                    const r = Reflect.get(target, prop, ...args);
                    safe.uboLog(logPrefix, `popup / get ${prop} === ${r}`);
                    if ( typeof r === 'function' ) {
                        return (...args) => { return r.call(target, ...args); };
                    }
                    return r;
                },
                set: function(target, prop, value, ...args) {
                    safe.uboLog(logPrefix, `popup / set ${prop} = ${value}`);
                    return Reflect.set(target, prop, value, ...args);
                },
            });
        }
        return popup;
    });
}

function objectFindOwnerFn(
    root,
    path,
    prune = false
) {
    const safe = safeSelf();
    let owner = root;
    let chain = path;
    for (;;) {
        if ( typeof owner !== 'object' || owner === null  ) { return false; }
        const pos = chain.indexOf('.');
        if ( pos === -1 ) {
            if ( prune === false ) {
                return safe.Object_hasOwn(owner, chain);
            }
            let modified = false;
            if ( chain === '*' ) {
                for ( const key in owner ) {
                    if ( safe.Object_hasOwn(owner, key) === false ) { continue; }
                    delete owner[key];
                    modified = true;
                }
            } else if ( safe.Object_hasOwn(owner, chain) ) {
                delete owner[chain];
                modified = true;
            }
            return modified;
        }
        const prop = chain.slice(0, pos);
        const next = chain.slice(pos + 1);
        let found = false;
        if ( prop === '[-]' && Array.isArray(owner) ) {
            let i = owner.length;
            while ( i-- ) {
                if ( objectFindOwnerFn(owner[i], next) === false ) { continue; }
                owner.splice(i, 1);
                found = true;
            }
            return found;
        }
        if ( prop === '{-}' && owner instanceof Object ) {
            for ( const key of Object.keys(owner) ) {
                if ( objectFindOwnerFn(owner[key], next) === false ) { continue; }
                delete owner[key];
                found = true;
            }
            return found;
        }
        if (
            prop === '[]' && Array.isArray(owner) ||
            prop === '{}' && owner instanceof Object ||
            prop === '*' && owner instanceof Object
        ) {
            for ( const key of Object.keys(owner) ) {
                if (objectFindOwnerFn(owner[key], next, prune) === false ) { continue; }
                found = true;
            }
            return found;
        }
        if ( safe.Object_hasOwn(owner, prop) === false ) { return false; }
        owner = owner[prop];
        chain = chain.slice(pos + 1);
    }
}

function objectPruneFn(
    obj,
    rawPrunePaths,
    rawNeedlePaths,
    stackNeedleDetails = { matchAll: true },
    extraArgs = {}
) {
    if ( typeof rawPrunePaths !== 'string' ) { return; }
    const safe = safeSelf();
    const prunePaths = rawPrunePaths !== ''
        ? safe.String_split.call(rawPrunePaths, / +/)
        : [];
    const needlePaths = prunePaths.length !== 0 && rawNeedlePaths !== ''
        ? safe.String_split.call(rawNeedlePaths, / +/)
        : [];
    if ( stackNeedleDetails.matchAll !== true ) {
        if ( matchesStackTraceFn(stackNeedleDetails, extraArgs.logstack) === false ) {
            return;
        }
    }
    if ( objectPruneFn.mustProcess === undefined ) {
        objectPruneFn.mustProcess = (root, needlePaths) => {
            for ( const needlePath of needlePaths ) {
                if ( objectFindOwnerFn(root, needlePath) === false ) {
                    return false;
                }
            }
            return true;
        };
    }
    if ( prunePaths.length === 0 ) { return; }
    let outcome = 'nomatch';
    if ( objectPruneFn.mustProcess(obj, needlePaths) ) {
        for ( const path of prunePaths ) {
            if ( objectFindOwnerFn(obj, path, true) ) {
                outcome = 'match';
            }
        }
    }
    if ( outcome === 'match' ) { return obj; }
}

function offIdleFn(id) {
    if ( self.requestIdleCallback ) {
        return self.cancelIdleCallback(id);
    }
    return self.cancelAnimationFrame(id);
}

function onIdleFn(fn, options) {
    if ( self.requestIdleCallback ) {
        return self.requestIdleCallback(fn, options);
    }
    return self.requestAnimationFrame(fn);
}

function parsePropertiesToMatchFn(propsToMatch, implicit = '') {
    const safe = safeSelf();
    const needles = new Map();
    if ( propsToMatch === undefined || propsToMatch === '' ) { return needles; }
    const options = { canNegate: true };
    for ( const needle of safe.String_split.call(propsToMatch, /\s+/) ) {
        let [ prop, pattern ] = safe.String_split.call(needle, ':');
        if ( prop === '' ) { continue; }
        if ( pattern !== undefined && /[^$\w -]/.test(prop) ) {
            prop = `${prop}:${pattern}`;
            pattern = undefined;
        }
        if ( pattern !== undefined ) {
            needles.set(prop, safe.initPattern(pattern, options));
        } else if ( implicit !== '' ) {
            needles.set(implicit, safe.initPattern(prop, options));
        }
    }
    return needles;
}

function preventAddEventListener(
    type = '',
    pattern = '',
    ...varargs
) {
    const safe = safeSelf();
    const extraArgs = safe.parseVarargs(varargs);
    const logPrefix = safe.makeLogPrefix('prevent-addEventListener', type, pattern);
    const reType = safe.patternToRegex(type, undefined, true);
    const rePattern = safe.patternToRegex(pattern);
    const targetSelector = extraArgs.elements || undefined;
    const elementMatches = elem => {
        if ( targetSelector === 'window' ) { return elem === window; }
        if ( targetSelector === 'document' ) { return elem === document; }
        if ( elem && elem.matches && elem.matches(targetSelector) ) { return true; }
        const elems = Array.from(document.querySelectorAll(targetSelector));
        return elems.includes(elem);
    };
    const elementDetails = elem => {
        if ( elem instanceof Window ) { return 'window'; }
        if ( elem instanceof Document ) { return 'document'; }
        if ( elem instanceof Element === false ) { return '?'; }
        const parts = [];
        // https://github.com/uBlockOrigin/uAssets/discussions/17907#discussioncomment-9871079
        const id = String(elem.id);
        if ( id !== '' ) { parts.push(`#${CSS.escape(id)}`); }
        for ( let i = 0; i < elem.classList.length; i++ ) {
            parts.push(`.${CSS.escape(elem.classList.item(i))}`);
        }
        for ( let i = 0; i < elem.attributes.length; i++ ) {
            const attr = elem.attributes.item(i);
            if ( attr.name === 'id' ) { continue; }
            if ( attr.name === 'class' ) { continue; }
            parts.push(`[${CSS.escape(attr.name)}="${attr.value}"]`);
        }
        return parts.join('');
    };
    const shouldPrevent = (thisArg, type, handler) => {
        const matchesType = safe.RegExp_test(reType, type);
        const matchesHandler = safe.RegExp_test(rePattern, handler);
        const matchesEither = matchesType || matchesHandler;
        const matchesBoth = matchesType && matchesHandler;
        if ( safe.logLevel > 1 && matchesEither ) {
            debugger; // eslint-disable-line no-debugger
        }
        if ( matchesBoth && targetSelector !== undefined ) {
            if ( elementMatches(thisArg) === false ) { return false; }
        }
        return matchesBoth;
    };
    const proxyFn = function(context) {
        const { callArgs, thisArg } = context;
        let t, h;
        try {
            t = String(callArgs[0]);
            if ( typeof callArgs[1] === 'function' ) {
                h = String(safe.Function_toString(callArgs[1]));
            } else if ( typeof callArgs[1] === 'object' && callArgs[1] !== null ) {
                if ( typeof callArgs[1].handleEvent === 'function' ) {
                    h = String(safe.Function_toString(callArgs[1].handleEvent));
                }
            } else {
                h = String(callArgs[1]);
            }
        } catch {
        }
        if ( type === '' && pattern === '' ) {
            safe.uboLog(logPrefix, `Called: ${t}\n${h}\n${elementDetails(thisArg)}`);
        } else if ( shouldPrevent(thisArg, t, h) ) {
            return safe.uboLog(logPrefix, `Prevented: ${t}\n${h}\n${elementDetails(thisArg)}`);
        }
        return context.reflect();
    };
    const protect = owner => {
        const { addEventListener } = owner;
        Object.defineProperty(owner, 'addEventListener', {
            set() { },
            get() { return addEventListener; }
        });
    };
    runAt(( ) => {
        proxyApplyFn('EventTarget.prototype.addEventListener', proxyFn);
        if ( extraArgs.protect ) { protect(EventTarget.prototype); }
        if ( Object.hasOwn(document, 'addEventListener') ) {
            proxyApplyFn('document.addEventListener', proxyFn);
            if ( extraArgs.protect ) { protect(document); }
        }
        if ( Object.hasOwn(window, 'addEventListener') ) {
            proxyApplyFn('window.addEventListener', proxyFn);
            if ( extraArgs.protect ) { protect(window); }
        }
    }, extraArgs.runAt);
}

function preventBab() {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('prevent-bab');
    const signatures = [
        [ 'blockadblock' ],
        [ 'babasbm' ],
        [ /getItem\('babn'\)/ ],
        [
            'getElementById',
            'String.fromCharCode',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
            'charAt',
            'DOMContentLoaded',
            'AdBlock',
            'addEventListener',
            'doScroll',
            'fromCharCode',
            '<<2|r>>4',
            'sessionStorage',
            'clientWidth',
            'localStorage',
            'Math',
            'random',
        ],
    ];
    const check = function(s) {
        if ( typeof s !== 'string' ) { return false; }
        for ( const tokens of signatures ) {
            let match = 0;
            for ( const token of tokens ) {
                const hit = token instanceof RegExp
                    ? token.test(s)
                    : s.includes(token);
                if ( hit ) { match += 1; }
            }
            if ( (match / tokens.length) >= 0.8 ) { return true; }
        }
        return false;
    };
    proxyApplyFn('eval', function(context) {
        const a = context.callArgs[0];
        if ( !check(a) ) {
            return context.reflect();
        }
        safe.uboLog(logPrefix, 'Prevented');
        if ( document.body ) {
            document.body.style.removeProperty('visibility');
        }
        const el = document.getElementById('babasbmsgx');
        if ( el ) {
            el.parentNode.removeChild(el);
        }
    });
    proxyApplyFn('setTimeout', function(context) {
        const { callArgs } = context;
        const a = callArgs[0];
        if ( typeof a === 'string'  && /\.bab_elementid.$/.test(a) ) {
            callArgs[0] = ( ) => { };
            safe.uboLog(logPrefix, 'Prevented');
        }
        return context.reflect();
    });
}

function preventFetch(...args) {
    preventFetchFn(false, ...args);
}

function preventFetchFn(
    trusted = false,
    propsToMatch = '',
    responseBody = '',
    responseType = '',
    ...varargs
) {
    const safe = safeSelf();
    const setTimeout = self.setTimeout;
    const scriptletName = `${trusted ? 'trusted-' : ''}prevent-fetch`;
    const logPrefix = safe.makeLogPrefix(
        scriptletName,
        propsToMatch,
        responseBody,
        responseType
    );
    const extraArgs = safe.parseVarargs(varargs);
    const propNeedles = parsePropertiesToMatchFn(propsToMatch, 'url');
    const validResponseProps = {
        ok: [ false, true ],
        status: [ 403 ],
        statusText: [ '', 'Not Found' ],
        type: [ 'basic', 'cors', 'default', 'error', 'opaque' ],
    };
    const responseProps = {
        statusText: { value: 'OK' },
    };
    const responseHeaders = {};
    if ( /^\{.*\}$/.test(responseType) ) {
        try {
            Object.entries(JSON.parse(responseType)).forEach(([ p, v ]) => {
                if ( p === 'headers' && trusted ) {
                    Object.assign(responseHeaders, v);
                    return;
                }
                if ( validResponseProps[p] === undefined ) { return; }
                if ( validResponseProps[p].includes(v) === false ) { return; }
                responseProps[p] = { value: v };
            });
        }
        catch { }
    } else if ( responseType !== '' ) {
        if ( validResponseProps.type.includes(responseType) ) {
            responseProps.type = { value: responseType };
        }
    }
    proxyApplyFn('fetch', function fetch(context) {
        const { callArgs } = context;
        const details = collateFetchArgumentsFn(...callArgs);
        if ( safe.logLevel > 1 || propsToMatch === '' && responseBody === '' ) {
            const out = Array.from(Object.entries(details)).map(a => `${a[0]}:${a[1]}`);
            safe.uboLog(logPrefix, `Called: ${out.join('\n')}`);
        }
        if ( propsToMatch === '' && responseBody === '' ) {
            return context.reflect();
        }
        const matched = matchObjectPropertiesFn(propNeedles, details);
        if ( matched === undefined || matched.length === 0 ) {
            return context.reflect();
        }
        return Promise.resolve(generateContentFn(trusted, responseBody)).then(text => {
            safe.uboLog(logPrefix, `Prevented with response "${text}"`);
            const headers = Object.assign({}, responseHeaders);
            if ( headers['content-length'] === undefined ) {
                headers['content-length'] = text.length;
            }
            const response = new Response(text, { headers });
            const props = Object.assign(
                { url: { value: details.url } },
                responseProps
            );
            safe.Object_defineProperties(response, props);
            if ( extraArgs.throttle ) {
                return new Promise(resolve => {
                    setTimeout(( ) => { resolve(response); }, extraArgs.throttle);
                });
            }
            return response;
        });
    });
}

function preventSetInterval(
    needleRaw = '',
    delayRaw = ''
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('prevent-setInterval', needleRaw, delayRaw);
    const needleNot = needleRaw.charAt(0) === '!';
    const reNeedle = safe.patternToRegex(needleNot ? needleRaw.slice(1) : needleRaw);
    const range = new RangeParser(delayRaw);
    proxyApplyFn('setInterval', function(context) {
        const { callArgs } = context;
        const a = callArgs[0] instanceof Function
            ? safe.String(safe.Function_toString(callArgs[0]))
            : safe.String(callArgs[0]);
        const b = callArgs[1];
        if ( needleRaw === '' && range.unbound() ) {
            safe.uboLog(logPrefix, `Called:\n${a}\n${b}`);
            return context.reflect();
        }
        if ( reNeedle.test(a) !== needleNot && range.test(b) ) {
            callArgs[0] = function(){};
            safe.uboLog(logPrefix, `Prevented:\n${a}\n${b}`);
        }
        return context.reflect();
    });
}

function preventSetTimeout(
    needleRaw = '',
    delayRaw = ''
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('prevent-setTimeout', needleRaw, delayRaw);
    const needleNot = needleRaw.charAt(0) === '!';
    const reNeedle = safe.patternToRegex(needleNot ? needleRaw.slice(1) : needleRaw);
    const range = new RangeParser(delayRaw);
    proxyApplyFn('setTimeout', function(context) {
        const { callArgs } = context;
        const a = callArgs[0] instanceof Function
            ? safe.String(safe.Function_toString(callArgs[0]))
            : safe.String(callArgs[0]);
        const b = callArgs[1];
        if ( needleRaw === '' && range.unbound() ) {
            safe.uboLog(logPrefix, `Called:\n${a}\n${b}`);
            return context.reflect();
        }
        if ( reNeedle.test(a) !== needleNot && range.test(b) ) {
            callArgs[0] = function(){};
            safe.uboLog(logPrefix, `Prevented:\n${a}\n${b}`);
        }
        return context.reflect();
    });
}

function preventXhr(...args) {
    preventXhrFn(false, ...args);
}

function preventXhrFn(
    trusted = false,
    propsToMatch = '',
    directive = ''
) {
    if ( typeof propsToMatch !== 'string' ) { return; }
    const safe = safeSelf();
    const scriptletName = trusted ? 'trusted-prevent-xhr' : 'prevent-xhr';
    const logPrefix = safe.makeLogPrefix(scriptletName, propsToMatch, directive);
    const xhrInstances = new WeakMap();
    const propNeedles = parsePropertiesToMatchFn(propsToMatch, 'url');
    const warOrigin = scriptletGlobals.warOrigin;
    const safeDispatchEvent = (xhr, type) => {
        try {
            xhr.dispatchEvent(new Event(type));
        } catch {
        }
    };
    proxyApplyFn('XMLHttpRequest.prototype.open', function(context) {
        const { thisArg, callArgs } = context;
        xhrInstances.delete(thisArg);
        const [ method, url, ...args ] = callArgs;
        if ( warOrigin !== undefined && url.startsWith(warOrigin) ) {
            return context.reflect();
        }
        const haystack = { method, url };
        if ( propsToMatch === '' && directive === '' ) {
            safe.uboLog(logPrefix, `Called: ${safe.JSON_stringify(haystack, null, 2)}`);
            return context.reflect();
        }
        if ( matchObjectPropertiesFn(propNeedles, haystack) ) {
            const xhrDetails = Object.assign(haystack, {
                xhr: thisArg,
                defer: args.length === 0 || !!args[0],
                directive,
                headers: {
                    'date': '',
                    'content-type': '',
                    'content-length': '',
                },
                url: haystack.url,
                props: {
                    response: { value: '' },
                    responseText: { value: '' },
                    responseXML: { value: null },
                },
            });
            xhrInstances.set(thisArg, xhrDetails);
        }
        return context.reflect();
    });
    proxyApplyFn('XMLHttpRequest.prototype.send', function(context) {
        const { thisArg } = context;
        const xhrDetails = xhrInstances.get(thisArg);
        if ( xhrDetails === undefined ) {
            return context.reflect();
        }
        xhrDetails.headers['date'] = (new Date()).toUTCString();
        let xhrText = '';
        switch ( thisArg.responseType ) {
        case 'arraybuffer':
            xhrDetails.props.response.value = new ArrayBuffer(0);
            xhrDetails.headers['content-type'] = 'application/octet-stream';
            break;
        case 'blob':
            xhrDetails.props.response.value = new Blob([]);
            xhrDetails.headers['content-type'] = 'application/octet-stream';
            break;
        case 'document': {
            const parser = new DOMParser();
            const doc = parser.parseFromString('', 'text/html');
            xhrDetails.props.response.value = doc;
            xhrDetails.props.responseXML.value = doc;
            xhrDetails.headers['content-type'] = 'text/html';
            break;
        }
        case 'json':
            xhrDetails.props.response.value = {};
            xhrDetails.props.responseText.value = '{}';
            xhrDetails.headers['content-type'] = 'application/json';
            break;
        default: {
            if ( directive === '' ) { break; }
            xhrText = generateContentFn(trusted, xhrDetails.directive);
            if ( xhrText instanceof Promise ) {
                xhrText = xhrText.then(text => {
                    xhrDetails.props.response.value = text;
                    xhrDetails.props.responseText.value = text;
                });
            } else {
                xhrDetails.props.response.value = xhrText;
                xhrDetails.props.responseText.value = xhrText;
            }
            xhrDetails.headers['content-type'] = 'text/plain';
            break;
        }
        }
        if ( xhrDetails.defer === false ) {
            xhrDetails.headers['content-length'] = `${xhrDetails.props.response.value}`.length;
            Object.defineProperties(xhrDetails.xhr, {
                readyState: { value: 4 },
                responseURL: { value: xhrDetails.url },
                status: { value: 200 },
                statusText: { value: 'OK' },
            });
            Object.defineProperties(xhrDetails.xhr, xhrDetails.props);
            return;
        }
        Promise.resolve(xhrText).then(( ) => xhrDetails).then(details => {
            Object.defineProperties(details.xhr, {
                readyState: { value: 1, configurable: true },
                responseURL: { value: xhrDetails.url },
            });
            safeDispatchEvent(details.xhr, 'readystatechange');
            return details;
        }).then(details => {
            xhrDetails.headers['content-length'] = `${details.props.response.value}`.length;
            Object.defineProperties(details.xhr, {
                readyState: { value: 2, configurable: true },
                status: { value: 200 },
                statusText: { value: 'OK' },
            });
            safeDispatchEvent(details.xhr, 'readystatechange');
            return details;
        }).then(details => {
            Object.defineProperties(details.xhr, {
                readyState: { value: 3, configurable: true },
            });
            Object.defineProperties(details.xhr, details.props);
            safeDispatchEvent(details.xhr, 'readystatechange');
            return details;
        }).then(details => {
            Object.defineProperties(details.xhr, {
                readyState: { value: 4 },
            });
            safeDispatchEvent(details.xhr, 'readystatechange');
            safeDispatchEvent(details.xhr, 'load');
            safeDispatchEvent(details.xhr, 'loadend');
            safe.uboLog(logPrefix, `Prevented with response:\n${details.xhr.response}`);
        });
    });
    proxyApplyFn('XMLHttpRequest.prototype.getResponseHeader', function(context) {
        const { thisArg } = context;
        const xhrDetails = xhrInstances.get(thisArg);
        if ( xhrDetails === undefined || thisArg.readyState < thisArg.HEADERS_RECEIVED ) {
            return context.reflect();
        }
        const headerName = `${context.callArgs[0]}`;
        const value = xhrDetails.headers[headerName.toLowerCase()];
        if ( value !== undefined && value !== '' ) { return value; }
        return null;
    });
    proxyApplyFn('XMLHttpRequest.prototype.getAllResponseHeaders', function(context) {
        const { thisArg } = context;
        const xhrDetails = xhrInstances.get(thisArg);
        if ( xhrDetails === undefined || thisArg.readyState < thisArg.HEADERS_RECEIVED ) {
            return context.reflect();
        }
        const out = [];
        for ( const [ name, value ] of Object.entries(xhrDetails.headers) ) {
            if ( !value ) { continue; }
            out.push(`${name}: ${value}`);
        }
        if ( out.length !== 0 ) { out.push(''); }
        return out.join('\r\n');
    });
}

function proxyApplyFn(
    target = '',
    handler = '',
    options = {}
) {
    let context = globalThis;
    let prop = target;
    for (;;) {
        const pos = prop.indexOf('.');
        if ( pos === -1 ) { break; }
        context = context[prop.slice(0, pos)];
        if ( context instanceof Object === false ) { return; }
        prop = prop.slice(pos+1);
    }
    const fn = context[prop];
    if ( typeof fn !== 'function' ) { return; }
    if ( proxyApplyFn.CtorContext === undefined ) {
        proxyApplyFn.ctorContexts = [];
        proxyApplyFn.CtorContext = class {
            constructor(...args) {
                this.init(...args);
            }
            init(callFn, callArgs) {
                this.callFn = callFn;
                this.callArgs = callArgs;
                return this;
            }
            reflect() {
                const r = Reflect.construct(this.callFn, this.callArgs);
                this.callFn = this.callArgs = this.private = undefined;
                proxyApplyFn.ctorContexts.push(this);
                return r;
            }
            static factory(...args) {
                return proxyApplyFn.ctorContexts.length !== 0
                    ? proxyApplyFn.ctorContexts.pop().init(...args)
                    : new proxyApplyFn.CtorContext(...args);
            }
        };
        proxyApplyFn.applyContexts = [];
        proxyApplyFn.ApplyContext = class {
            constructor(...args) {
                this.init(...args);
            }
            init(callFn, thisArg, callArgs) {
                this.callFn = callFn;
                this.thisArg = thisArg;
                this.callArgs = callArgs;
                return this;
            }
            reflect() {
                const r = Reflect.apply(this.callFn, this.thisArg, this.callArgs);
                this.callFn = this.thisArg = this.callArgs = this.private = undefined;
                proxyApplyFn.applyContexts.push(this);
                return r;
            }
            static factory(...args) {
                return proxyApplyFn.applyContexts.length !== 0
                    ? proxyApplyFn.applyContexts.pop().init(...args)
                    : new proxyApplyFn.ApplyContext(...args);
            }
        };
        proxyApplyFn.isCtor = new Map();
        proxyApplyFn.proxies = new WeakMap();
        if ( (options.skipToString || proxyApplyFn.skipToString) !== true ) {
            proxyApplyFn.nativeToString = Function.prototype.toString;
            const proxiedToString = new Proxy(Function.prototype.toString, {
                apply(target, thisArg) {
                    let proxied = thisArg;
                    for(;;) {
                        const fn = proxyApplyFn.proxies.get(proxied);
                        if ( fn === undefined ) { break; }
                        proxied = fn;
                    }
                    return proxyApplyFn.nativeToString.call(proxied);
                }
            });
            proxyApplyFn.proxies.set(proxiedToString, proxyApplyFn.nativeToString);
            Function.prototype.toString = proxiedToString;
        }
    }
    if ( proxyApplyFn.isCtor.has(target) === false ) {
        proxyApplyFn.isCtor.set(target, fn.prototype?.constructor === fn);
    }
    const proxyDetails = {
        apply(target, thisArg, args) {
            return handler(proxyApplyFn.ApplyContext.factory(target, thisArg, args));
        }
    };
    if ( proxyApplyFn.isCtor.get(target) ) {
        proxyDetails.construct = function(target, args) {
            return handler(proxyApplyFn.CtorContext.factory(target, args));
        };
    }
    const proxiedTarget = new Proxy(fn, proxyDetails);
    proxyApplyFn.proxies.set(proxiedTarget, fn);
    context[prop] = proxiedTarget;
}

function removeAttr(
    rawToken = '',
    rawSelector = '',
    behavior = '',
    ...varargs
) {
    if ( typeof rawToken !== 'string' ) { return; }
    if ( rawToken === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('remove-attr',
        rawToken, rawSelector, behavior, ...varargs
    );
    const tokens = safe.String_split.call(rawToken, /\s*\|\s*/);
    const selector = tokens.map(a => {
        const b = CSS.escape(a);
        return rawSelector.includes(`[${b}]`) ? rawSelector : `${rawSelector}[${b}]`;
    }).join(',');
    const lazily = /\basap\b/.test(behavior) === false;
    const options = safe.parseVarargs(varargs);
    if ( safe.logLevel > 1 ) {
        safe.uboLog(logPrefix, `Target selector:\n\t${selector}`);
    }
    const rmattrFromNode = node => {
        for ( const attr of tokens ) {
            if ( node.hasAttribute(attr) === false ) { continue; }
            node.removeAttribute(attr);
            safe.uboLog(logPrefix, `Removed attribute '${attr}'`);
        }
    };
    const rmattr = nodes => {
        for ( const node of nodes ?? document.querySelectorAll(selector) ) {
            rmattrFromNode(node);
        }
    };
    const rmAttrLazily = ( ) => {
        if ( rmAttrLazily.timer !== undefined ) { return; }
        rmAttrLazily.timer = onIdleFn(( ) => {
            rmAttrLazily.timer = undefined;
            rmattr();
        }, { timeout: 17 });
    };
    const mutationHandler = mutations => {
        for ( const { addedNodes, removedNodes } of mutations ) {
            for ( const node of addedNodes ) {
                if ( node.nodeType !== 1 ) { continue; }
                if ( lazily ) { return rmAttrLazily(); }
                if ( node.matches(selector) ) {
                    rmattrFromNode(node);
                }
                if ( node.childElementCount ) {
                    rmattr(node.querySelectorAll(selector));
                }
            }
            if ( lazily ) { return; }
            for ( const node of removedNodes ) {
                if ( node.nodeType !== 1 ) { continue; }
                if ( node.matches(selector) ) {
                    rmattrFromNode(node);
                }
            }
        }
    };
    const stop = ( ) => {
        if ( start.observer ) {
            start.observer.disconnect();
            start.observer = undefined;
        }
        if ( rmAttrLazily.timer ) {
            offIdleFn(rmAttrLazily.timer);
            rmAttrLazily.timer = undefined;
        }
        if ( safe.logLevel > 1 ) {
            safe.uboLog(logPrefix, 'Quitting');
        }
    };
    const start = ( ) => {
        rmattr();
        if ( /\bstay\b/.test(behavior) === false ) {
            if ( options.quitAfter === undefined ) { return; }
        }
        start.observer = new MutationObserver(mutationHandler);
        start.observer.observe(document, {
            attributes: true,
            attributeFilter: tokens,
            childList: true,
            subtree: true,
        });
        if ( options.quitAfter ) {
            runAt(( ) => {
                self.setTimeout(stop, options.quitAfter * 1000);
            }, 'load');
        }
    };
    runAt(( ) => { start(); }, safe.String_split.call(behavior, /\s+/));
}

function runAt(fn, when) {
    const intFromReadyState = state => {
        const targets = {
            'loading': 1, 'asap': 1,
            'interactive': 2, 'end': 2, '2': 2,
            'complete': 3, 'idle': 3, '3': 3,
        };
        const tokens = Array.isArray(state) ? state : [ state ];
        for ( const token of tokens ) {
            const prop = `${token}`;
            if ( Object.hasOwn(targets, prop) === false ) { continue; }
            return targets[prop];
        }
        return 0;
    };
    const runAt = intFromReadyState(when);
    if ( intFromReadyState(document.readyState) >= runAt ) {
        fn(); return;
    }
    const onStateChange = ( ) => {
        if ( intFromReadyState(document.readyState) < runAt ) { return; }
        fn();
        safe.removeEventListener.apply(document, args);
    };
    const safe = safeSelf();
    const args = [ 'readystatechange', onStateChange, { capture: true } ];
    safe.addEventListener.apply(document, args);
}

function runAtHtmlElementFn(fn) {
    if ( document.documentElement ) {
        fn();
        return;
    }
    const observer = new MutationObserver(( ) => {
        observer.disconnect();
        fn();
    });
    observer.observe(document, { childList: true });
}

function safeSelf() {
    if ( safeSelf.safe ) {
        return safeSelf.safe;
    }
    const self = globalThis;
    const safe = {
        'Array_from': Array.from,
        'Error': self.Error,
        'Function_toString': Function.prototype.call.bind(self.Function.prototype.toString),
        'Math_floor': Math.floor,
        'Math_max': Math.max,
        'Math_min': Math.min,
        'Math_random': Math.random,
        'Object': Object,
        'Object_defineProperty': Object.defineProperty.bind(Object),
        'Object_defineProperties': Object.defineProperties.bind(Object),
        'Object_fromEntries': Object.fromEntries.bind(Object),
        'Object_getOwnPropertyDescriptor': Object.getOwnPropertyDescriptor.bind(Object),
        'Object_hasOwn': Object.hasOwn.bind(Object),
        'Object_toString': Object.prototype.toString,
        'RegExp': self.RegExp,
        'RegExp_test': Function.prototype.call.bind(self.RegExp.prototype.test),
        'RegExp_exec': self.RegExp.prototype.exec,
        'Request_clone': self.Request.prototype.clone,
        'String': self.String,
        'String_fromCharCode': String.fromCharCode,
        'String_split': String.prototype.split,
        'XMLHttpRequest': self.XMLHttpRequest,
        'addEventListener': self.EventTarget.prototype.addEventListener,
        'removeEventListener': self.EventTarget.prototype.removeEventListener,
        'fetch': self.fetch,
        'JSON': self.JSON,
        'JSON_parse': Function.prototype.call.bind(self.JSON.parse, self.JSON),
        'JSON_stringify': Function.prototype.call.bind(self.JSON.stringify, self.JSON),
        'log': console.log.bind(console),
        // Properties
        logLevel: 0,
        // Methods
        makeLogPrefix(...args) {
            return this.sendToLogger && `[${args.join(' \u205D ')}]` || '';
        },
        uboLog(...args) {
            if ( this.sendToLogger === undefined ) { return; }
            if ( args === undefined || args[0] === '' ) { return; }
            return this.sendToLogger('info', ...args);
            
        },
        uboErr(...args) {
            if ( this.sendToLogger === undefined ) { return; }
            if ( args === undefined || args[0] === '' ) { return; }
            return this.sendToLogger('error', ...args);
        },
        escapeRegexChars(s) {
            return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        },
        initPattern(pattern, options = {}) {
            if ( pattern === '' ) {
                return { matchAll: true, expect: true };
            }
            const expect = (options.canNegate !== true || pattern.startsWith('!') === false);
            if ( expect === false ) {
                pattern = pattern.slice(1);
            }
            const match = /^\/(.+)\/([gimsu]*)$/.exec(pattern);
            if ( match !== null ) {
                return {
                    re: new this.RegExp(
                        match[1],
                        match[2] || options.flags
                    ),
                    expect,
                };
            }
            if ( options.flags !== undefined ) {
                return {
                    re: new this.RegExp(this.escapeRegexChars(pattern),
                        options.flags
                    ),
                    expect,
                };
            }
            return { pattern, expect };
        },
        testPattern(details, haystack) {
            if ( details.matchAll ) { return true; }
            if ( details.re ) {
                return this.RegExp_test(details.re, haystack) === details.expect;
            }
            return haystack.includes(details.pattern) === details.expect;
        },
        patternToRegex(pattern, flags = undefined, verbatim = false) {
            if ( pattern === '' ) { return /^/; }
            const match = /^\/(.+)\/([gimsu]*)$/.exec(pattern);
            if ( match === null ) {
                const reStr = this.escapeRegexChars(pattern);
                return new RegExp(verbatim ? `^${reStr}$` : reStr, flags);
            }
            try {
                return new RegExp(match[1], match[2] || undefined);
            }
            catch {
            }
            return /^/;
        },
        parseVarargs(varargs) {
            const entries = varargs.reduce((out, v, i, a) => {
                if ( i & 1 ) { return out; }
                const rawValue = a[i+1];
                const value = /^\d+$/.test(rawValue)
                    ? parseInt(rawValue, 10)
                    : rawValue;
                out.push([ a[i], value ]);
                return out;
            }, []);
            return this.Object_fromEntries(entries);
        },
    };
    safeSelf.safe = safe;
    if ( scriptletGlobals.bcSecret === undefined ) { return safe; }
    // This is executed only when the logger is opened
    safe.logLevel = scriptletGlobals.logLevel || 1;
    let lastLogType = '';
    let lastLogText = '';
    let lastLogTime = 0;
    safe.toLogText = (type, ...args) => {
        if ( args.length === 0 ) { return; }
        const text = `[${document.location.hostname || document.location.href}]${args.join(' ')}`;
        if ( text === lastLogText && type === lastLogType ) {
            if ( (Date.now() - lastLogTime) < 5000 ) { return; }
        }
        lastLogType = type;
        lastLogText = text;
        lastLogTime = Date.now();
        return text;
    };
    try {
        const bc = new self.BroadcastChannel(scriptletGlobals.bcSecret);
        let bcBuffer = [];
        safe.sendToLogger = (type, ...args) => {
            const text = safe.toLogText(type, ...args);
            if ( text === undefined ) { return; }
            if ( bcBuffer === undefined ) {
                return bc.postMessage({ what: 'messageToLogger', type, text });
            }
            bcBuffer.push({ type, text });
        };
        bc.onmessage = ev => {
            const msg = ev.data;
            switch ( msg ) {
            case 'iamready!':
                if ( bcBuffer === undefined ) { break; }
                bcBuffer.forEach(({ type, text }) =>
                    bc.postMessage({ what: 'messageToLogger', type, text })
                );
                bcBuffer = undefined;
                break;
            case 'setScriptletLogLevelToOne':
                safe.logLevel = 1;
                break;
            case 'setScriptletLogLevelToTwo':
                safe.logLevel = 2;
                break;
            }
        };
        bc.postMessage('areyouready?');
    } catch {
        safe.sendToLogger = (type, ...args) => {
            const text = safe.toLogText(type, ...args);
            if ( text === undefined ) { return; }
            safe.log(`uBO ${text}`);
        };
    }
    return safe;
}

function setConstant(
    ...args
) {
    setConstantFn(false, ...args);
}

function setConstantFn(
    trusted = false,
    chain = '',
    rawValue = '',
    ...varargs
) {
    if ( chain === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('set-constant', chain, rawValue);
    const extraArgs = safe.parseVarargs(varargs);
    function setConstant(chain, rawValue) {
        const trappedProp = (( ) => {
            const pos = chain.lastIndexOf('.');
            if ( pos === -1 ) { return chain; }
            return chain.slice(pos+1);
        })();
        const cloakFunc = fn => {
            safe.Object_defineProperty(fn, 'name', { value: trappedProp });
            return new Proxy(fn, {
                defineProperty(target, prop) {
                    if ( prop !== 'toString' ) {
                        return Reflect.defineProperty(...arguments);
                    }
                    return true;
                },
                deleteProperty(target, prop) {
                    if ( prop !== 'toString' ) {
                        return Reflect.deleteProperty(...arguments);
                    }
                    return true;
                },
                get(target, prop) {
                    if ( prop === 'toString' ) {
                        return function() {
                            return `function ${trappedProp}() { [native code] }`;
                        }.bind(null);
                    }
                    return Reflect.get(...arguments);
                },
            });
        };
        if ( trappedProp === '' ) { return; }
        const thisScript = document.currentScript;
        let normalValue = validateConstantFn(trusted, rawValue, extraArgs);
        if ( rawValue === 'noopFunc' || rawValue === 'trueFunc' || rawValue === 'falseFunc' ) {
            normalValue = cloakFunc(normalValue);
        }
        let aborted = false;
        const mustAbort = function(v) {
            if ( trusted ) { return false; }
            if ( aborted ) { return true; }
            aborted =
                (v !== undefined && v !== null) &&
                (normalValue !== undefined && normalValue !== null) &&
                (typeof v !== typeof normalValue);
            if ( aborted ) {
                safe.uboLog(logPrefix, `Aborted because value set to ${v}`);
            }
            return aborted;
        };
        // https://github.com/uBlockOrigin/uBlock-issues/issues/156
        //   Support multiple trappers for the same property.
        const trapProp = function(owner, prop, configurable, handler) {
            if ( handler.init(configurable ? owner[prop] : normalValue) === false ) { return; }
            const odesc = safe.Object_getOwnPropertyDescriptor(owner, prop);
            let prevGetter, prevSetter;
            if ( odesc instanceof safe.Object ) {
                owner[prop] = normalValue;
                if ( odesc.get instanceof Function ) {
                    prevGetter = odesc.get;
                }
                if ( odesc.set instanceof Function ) {
                    prevSetter = odesc.set;
                }
            }
            try {
                safe.Object_defineProperty(owner, prop, {
                    configurable,
                    get() {
                        if ( prevGetter !== undefined ) {
                            prevGetter();
                        }
                        return handler.getter();
                    },
                    set(a) {
                        if ( prevSetter !== undefined ) {
                            prevSetter(a);
                        }
                        handler.setter(a);
                    }
                });
                safe.uboLog(logPrefix, 'Trap installed');
            } catch(ex) {
                safe.uboErr(logPrefix, ex);
            }
        };
        const trapChain = function(owner, chain) {
            const pos = chain.indexOf('.');
            if ( pos === -1 ) {
                trapProp(owner, chain, false, {
                    v: undefined,
                    init: function(v) {
                        if ( mustAbort(v) ) { return false; }
                        this.v = v;
                        return true;
                    },
                    getter: function() {
                        if ( document.currentScript === thisScript ) {
                            return this.v;
                        }
                        safe.uboLog(logPrefix, 'Property read');
                        return normalValue;
                    },
                    setter: function(a) {
                        if ( mustAbort(a) === false ) { return; }
                        normalValue = a;
                    }
                });
                return;
            }
            const prop = chain.slice(0, pos);
            const v = owner[prop];
            chain = chain.slice(pos + 1);
            if ( v instanceof safe.Object || typeof v === 'object' && v !== null ) {
                trapChain(v, chain);
                return;
            }
            trapProp(owner, prop, true, {
                v: undefined,
                init: function(v) {
                    this.v = v;
                    return true;
                },
                getter: function() {
                    return this.v;
                },
                setter: function(a) {
                    this.v = a;
                    if ( a instanceof safe.Object ) {
                        trapChain(a, chain);
                    }
                }
            });
        };
        trapChain(window, chain);
    }
    runAt(( ) => {
        setConstant(chain, rawValue);
    }, extraArgs.runAt);
}

function trapPropertyFn(propChain, handler, options = {}) {
    if ( propChain === '' ) { return; }
    let owner = self;
    let prop = propChain;
    for (;;) {
        const pos = prop.indexOf('.');
        if ( pos === -1 ) { break; }
        owner = owner[prop.slice(0, pos)];
        if ( owner instanceof Object === false ) { return; }
        prop = prop.slice(pos + 1);
    }
    const safe = safeSelf();
    if ( trapPropertyFn.db === undefined ) {
        trapPropertyFn.db = new WeakMap();
        trapPropertyFn.entryFromContext = (owner, prop) => {
            const handlers = trapPropertyFn.db.get(owner);
            return handlers?.get(prop);
        };
        trapPropertyFn.getter = (owner, prop) => {
            const entry = trapPropertyFn.entryFromContext(owner, prop);
            if ( entry === undefined ) { return; }
            let r = entry.value;
            for ( const desc of entry.stack ) {
                try { r = desc.get(); } catch (e) {
                    if ( entry.canThrow ) { throw e; }
                }
            }
            return r;
        };
        trapPropertyFn.setter = (owner, prop, value) => {
            const entry = trapPropertyFn.entryFromContext(owner, prop);
            if ( entry === undefined ) { return; }
            entry.value = value;
            for ( const desc of entry.stack ) {
                try { desc.set(value); } catch (e) {
                    if ( entry.canThrow ) { throw e; }
                }
            }
        };
    }
    const { db } = trapPropertyFn;
    const handlers = db.get(owner) || new Map();
    if ( handlers.size === 0 ) {
        db.set(owner, handlers);
    }
    const entry = handlers.get(prop) || {
        value: owner[prop],
        stack: [],
    };
    entry.stack.push(handler);
    if ( entry.stack.length > 1 ) { return entry.value; }
    Object.assign(entry, options);
    handlers.set(prop, entry);
    const desc = safe.Object_getOwnPropertyDescriptor(owner, prop);
    if ( desc instanceof safe.Object ) {
        if ( desc.get || desc.set ) {
            entry.stack.push(desc);
        }
    }
    try {
        safe.Object_defineProperty(owner, prop, {
            get() {
                return trapPropertyFn.getter(owner, prop);
            },
            set(value) {
                trapPropertyFn.setter(owner, prop, value);
            }
        });
    } catch {
    }
    return entry.value;
}

function validateConstantFn(trusted, raw, extraArgs = {}) {
    const safe = safeSelf();
    let value;
    if ( raw === 'undefined' ) {
        value = undefined;
    } else if ( raw === 'false' ) {
        value = false;
    } else if ( raw === 'true' ) {
        value = true;
    } else if ( raw === 'null' ) {
        value = null;
    } else if ( raw === "''" || raw === '' ) {
        value = '';
    } else if ( raw === '[]' || raw === 'emptyArr' ) {
        value = [];
    } else if ( raw === '{}' || raw === 'emptyObj' ) {
        value = {};
    } else if ( raw === 'noopFunc' ) {
        value = function(){};
    } else if ( raw === 'trueFunc' ) {
        value = function(){ return true; };
    } else if ( raw === 'falseFunc' ) {
        value = function(){ return false; };
    } else if ( raw === 'throwFunc' ) {
        value = function(){ throw ''; };
    } else if ( /^-?\d+$/.test(raw) ) {
        value = parseInt(raw);
        if ( isNaN(raw) ) { return; }
        if ( Math.abs(raw) > 0x7FFF ) { return; }
    } else if ( trusted ) {
        if ( raw.startsWith('json:') ) {
            try { value = safe.JSON_parse(raw.slice(5)); } catch { return; }
        } else if ( raw.startsWith('{') && raw.endsWith('}') ) {
            try { value = safe.JSON_parse(raw).value; } catch { return; }
        }
    } else {
        return;
    }
    if ( extraArgs.as !== undefined ) {
        if ( extraArgs.as === 'function' ) {
            return ( ) => value;
        } else if ( extraArgs.as === 'callback' ) {
            return ( ) => (( ) => value);
        } else if ( extraArgs.as === 'resolved' ) {
            return Promise.resolve(value);
        } else if ( extraArgs.as === 'rejected' ) {
            return Promise.reject(value);
        }
    }
    return value;
}

function zeta_8echnktd() { // nofab.js
(function() {
    'use strict';
    const noopfn = function() {
    };
    const Fab = function() {};
    Fab.prototype.check = noopfn;
    Fab.prototype.clearEvent = noopfn;
    Fab.prototype.emitEvent = noopfn;
    Fab.prototype.on = function(a, b) {
        if ( !a ) { b(); }
        return this;
    };
    Fab.prototype.onDetected = function() {
        return this;
    };
    Fab.prototype.onNotDetected = function(a) {
        a();
        return this;
    };
    Fab.prototype.setOption = noopfn;
    Fab.prototype.options = {
        set: noopfn,
        get: noopfn,
    };
    const fab = new Fab();
    const getSetFab = {
        get: function() { return Fab; },
        set: function() {}
    };
    const getsetfab = {
        get: function() { return fab; },
        set: function() {}
    };
    if ( window.hasOwnProperty('FuckAdBlock') ) { window.FuckAdBlock = Fab; }
    else { Object.defineProperty(window, 'FuckAdBlock', getSetFab); }
    if ( window.hasOwnProperty('BlockAdBlock') ) { window.BlockAdBlock = Fab; }
    else { Object.defineProperty(window, 'BlockAdBlock', getSetFab); }
    if ( window.hasOwnProperty('SniffAdBlock') ) { window.SniffAdBlock = Fab; }
    else { Object.defineProperty(window, 'SniffAdBlock', getSetFab); }
    if ( window.hasOwnProperty('fuckAdBlock') ) { window.fuckAdBlock = fab; }
    else { Object.defineProperty(window, 'fuckAdBlock', getsetfab); }
    if ( window.hasOwnProperty('blockAdBlock') ) { window.blockAdBlock = fab; }
    else { Object.defineProperty(window, 'blockAdBlock', getsetfab); }
    if ( window.hasOwnProperty('sniffAdBlock') ) { window.sniffAdBlock = fab; }
    else { Object.defineProperty(window, 'sniffAdBlock', getsetfab); }
})();
}

/******************************************************************************/

const scriptletGlobals = {}; // eslint-disable-line

const $hasHostnames$ = true;
const $hasEntities$ = true;
const $hasAncestors$ = false;
const $hasRegexes$ = true;

/******************************************************************************/

const entries = (( ) => {
    const docloc = document.location;
    const origins = [ docloc.origin ];
    if ( docloc.ancestorOrigins ) {
        origins.push(...docloc.ancestorOrigins);
    }
    return origins.map((origin, i) => {
        const beg = origin.indexOf('://');
        if ( beg === -1 ) { return; }
        const hn1 = origin.slice(beg+3)
        const end = hn1.indexOf(':');
        const hn2 = end === -1 ? hn1 : hn1.slice(0, end);
        if ( hn2.length === 0 ) { return; }
        const hns = [ hn2 ];
        for ( let pos = 0; ; ) {
            pos = hn2.indexOf('.', pos) + 1;
            if ( pos === 0 ) { break; }
            hns.push(hn2.slice(pos));
        }
        hns.push('*');
        const ens = [];
        if ( $hasEntities$ ) {
            for ( let hn of hns ) {
                for (;;) {
                    const pos = hn.lastIndexOf('.');
                    if ( pos === -1 ) { break; }
                    hn = hn.slice(0, pos);
                    ens.push(`${hn}.*`);
                }
            }
            ens.sort((a, b) => {
                const d = b.length - a.length;
                if ( d !== 0 ) { return d; }
                return a > b ? -1 : 1;
            });
        }
        return { hns, ens, i };
    }).filter(a => a);
})();
if ( entries.length === 0 ) { return; }

const todo = new Set();

if ( $hasHostnames$ ) {
    const $scriptletHostnames$ = /* 1423 */ ["mp4","1hd.*","ak.sv","nu.nl","ok.ru","yts.*","1hd.to","53.com","al.com","aof.tc","dlhd.*","dood.*","eda.ru","epn.bz","goku.*","hqq.tv","kaa.mx","kaas.*","mbs.jp","movi.*","t3.com","td.com","tmz.ng","tpi.li","voe.sx","wmj.ru","xtv.cz","yts.mx","adp.com","agar.io","anix.ac","anix.to","anix.vc","bmo.com","bold.dk","ccn.com","dlhd.so","dlhd.sx","dood.la","dood.li","dood.re","dood.wf","doood.*","gap.com","gdtot.*","goku.sx","gota.io","ifon.ca","kaas.ro","kaas.to","kwik.si","lsto.me","mbna.ca","mgsm.pl","movi.pk","netu.ac","njav.tv","quto.ru","veev.to","vox.com","4anime.*","96ar.com","9anime.*","abola.pt","anikai.*","bunkr.si","cibc.com","cineb.rs","cineby.*","cinego.*","citi.com","dlhd.dad","ebay.com","embed.su","emol.com","eztvx.to","flixhq.*","g9r6.com","hitomi.*","jav.guru","kaido.to","klz9.com","lenta.ru","megaf.cc","mgeko.cc","miruro.*","missav.*","motor.ru","mycima.*","nsmb.com","pahe.ink","poedb.tw","poop.run","rawxz.to","sflix.to","sofi.com","tiaa.org","tube8.es","tube8.fr","us7p.com","vipbox.*","wings.io","ww9g.com","xnxx.com","zdnet.de","123cine.*","2024tv.ru","2embed.me","2iptv.com","4anime.gg","actvid.rs","afisha.ru","anidl.org","anikai.to","anime4i.*","aniwave.*","apl326.me","apl332.me","apl337.me","apl351.me","awish.pro","brutal.io","bukja.net","bunkrr.su","cineby.ru","cinego.tv","cpuid.com","crichd.ac","crichd.bi","crichd.tv","dlhd.link","dnetc.net","dokazm.mk","donkey.to","doods.pro","dugrt.com","dwish.pro","e3lam.com","eater.com","eftps.gov","elixx.xyz","flixhq.to","fmovies.*","france.tv","gazeta.ru","gdtot.dad","goone.pro","hdtoday.*","hglink.to","hianime.*","hitomi.la","hoca2.com","hoca6.com","hydrahd.*","ico3c.com","ksohls.ru","lesoir.be","live9.pro","lokkio.it","mangatv.*","mapple.uk","mcloud.bz","miruro.tv","missav.ws","mixdrop.*","mlbbox.me","mlive.com","mocah.org","naver.com","nbabox.co","nbabox.me","nflbox.me","nhlbox.me","nubng.com","ouo.press","ruwix.com","sflix2.to","shootv.in","strmup.to","surfg.org","tawpa.net","toongod.*","tsb.co.uk","tube8.com","twitch.tv","ucast.pro","uqload.to","venea.net","vga4a.com","vidara.to","vidco.pro","vidmoly.*","vidsrc.cc","vidsrc.me","vidsrc.to","vidtube.*","vinovo.to","vipbox.lc","viprow.nu","voodc.com","webtor.io","weibo.com","xztgl.com","yeshd.net","yossr.com","zoechip.*","zpjid.com","123cine.to","1stream.eu","4bct9.live","9animetv.*","9kmovies.*","alghad.com","alions.pro","aloomag.ir","ancient.eu","animeflv.*","animexin.*","aniwave.to","aniyae.net","anroll.net","anumin.com","apnews.com","awolio.com","betfair.es","builder.id","canalk.com","cineby.app","crichd.com","crichd.vip","cuevana.is","curbed.com","d0000d.com","deezer.com","dlions.pro","dood.watch","doood.site","dopebox.to","dumpert.nl","dxmaps.com","edumaz.com","eye9ja.com","f2movies.*","fasel-hd.*","fflogs.com","filemoon.*","flixbaba.*","flixhub.co","fmovies.co","fmovies.ps","fmovies.to","fmoviesz.*","futemax.mn","g37.com.br","goca4u.com","gocast.pro","gomovies.*","gopst.link","hdfilme.my","hdtoday.cc","hdtodayz.*","hianime.mn","hianime.nz","hianime.to","hianime.tv","hianime.ws","hianimez.*","hoca4u.com","hydrahd.me","ingbank.pl","intuit.com","jeu2048.fr","kabbos.com","lavents.la","lcpdfr.com","lehait.net","letidor.ru","lovecdn.ru","marcus.com","marokko.nl","masa49.com","megacdn.co","megaup.net","milfzr.com","missav.com","mixdrop.my","mixdrop.sb","movies4u.*","my.mail.ru","mycima.biz","mycima.vin","myflixer.*","niaomea.me","novinky.cz","nptsr.live","passion.ru","pc3mag.com","peakpx.com","pkpics.fun","poophd.vip","popcdn.day","prmovies.*","protest.eu","racked.com","rambler.ru","remilf.xyz","rns.online","s3taku.com","sebnsc.dad","seeflix.to","series24.*","shinden.pl","snowmtl.ru","soap2day.*","sxyprn.com","sxyprn.net","ta1lsx.com","tdbank.com","termux.xyz","tgyama.com","tharen.cfd","thedaddy.*","tinde.tech","tipdoot.in","tntmac.com","tv247365.*","upload.com","uqload.net","usgate.xyz","veganab.co","vidmoly.to","vidsrc.icu","vidsrc.net","vidsrc.top","vidsrc.xyz","vodnews.pl","ydc1wes.me","yomovies.*","yuppow.com","zoechip.cc","zoroxtv.to","1nulled.com","456movie.nl","9animetv.to","a.asd.homes","allkpop.com","alphatron.*","anime4i.vip","animeflix.*","animeflv.cz","animeflv.si","animepahe.*","antronio.cl","aoezone.net","arlive.shop","autoweek.nl","b4ucast.com","bdcraft.net","berlagu.com","betfair.com","bigwarp.art","crvsport.ru","cube365.net","cuervotv.me","cuevana.biz","d4armory.io","daddyhd.com","deluxe.news","digitalt.tv","discord.com","disheye.com","dlgames.fun","dramacool.*","embasic.pro","embedhd.org","embedme.top","embedpk.net","embtaku.pro","esologs.com","fastflix.to","fastpic.org","fbstreams.*","filemoon.nl","filemoon.sx","filemoon.to","filepress.*","fmovies.wtf","fmoviesz.la","fosshub.com","fullassia.*","gamepur.com","gnicirp.com","gogoanime.*","harimanga.*","hdtodaytv.*","hdtodayz.to","hexload.com","hianimez.to","himovies.sx","hocast4.com","hurawatch.*","idlixku.com","inputmag.dk","iosgods.com","javclan.com","jkanime.net","jobwaala.in","kaliscan.io","kbizoom.com","kerapoxy.cc","kissanime.*","kissasian.*","koinbox.net","leaksat.com","likemanga.*","lol-foot.ru","luluvdo.com","malekal.com","mangafire.*","mangatv.net","mappletv.uk","masrawy.com","messitv.org","misshit.top","movies4us.*","moviesapi.*","myflixer.gs","myflixerz.*","netmovies.*","newsauto.it","nhentai.net","nytimes.com","omeplay.com","onhockey.tv","pandora.com","pgatour.com","pladrac.net","polygon.com","pornhub.com","putinho.net","putlocker.*","quicken.com","rawkuma.net","redtube.com","redtube.net","rereyano.ru","rogmovies.*","romviet.com","series24.cc","simpcity.su","simplii.com","softvela.us","sporttuna.*","sterham.net","storyy.shop","strcloud.in","streamed.su","streamup.ws","thedaddy.to","toongod.org","topembed.pw","tpknews.com","troovez.com","turbolab.it","tutocad.com","tv1337.buzz","tvableon.me","upstream.to","uqloads.xyz","ustream.pro","vid142.site","vid41c.site","vidfast.pro","vidlink.pro","vidtube.one","viewing.nyc","vipboxtv.sk","vipstand.pm","vixcloud.co","vkprime.com","vkspeed.com","volokit.xyz","walmart.com","web4free.in","winmeen.com","wired.co.uk","xgroovy.com","zerogpt.net","zonatmo.com","1233movies.*","1azayf9w.xyz","398fitus.com","81u6xl9d.xyz","9kmovies.ren","abysscdn.com","albkinema.in","almnatiq.net","alphatron.tv","animeflv.net","animeflv.one","animeflv.zip","animeland.tv","animepahe.ru","animeunity.*","animexin.dev","aniwatchtv.*","autoembed.cc","b5yucast.com","bsaktuell.de","cimaroom.com","codelist.biz","codesnse.com","compuhoy.com","cool-etv.net","coolrea.link","couchtuner.*","cricstream.*","cricwatch.io","daddylive.ru","datanodes.to","discover.com","doorbraak.be","dovkembed.pw","drakecomic.*","dz-linkk.com","embednow.top","estafed1.com","fairyabc.com","fasel-hd.cam","fastflix.top","fbstreams.co","fidelity.com","fightful.com","filecrypt.co","flexyhit.com","flixbaba.mov","flixmomo.com","flstv.online","focus4ca.com","foxtrend.net","fusevideo.io","gameflex.lat","gearside.com","girlscene.nl","godzcast.com","godzlive.com","gogoanime2.*","gogoanime3.*","gogoanimes.*","harimanga.me","haxloppd.com","hdtodaytv.tv","ikorektor.pl","instander.me","intozoom.com","intramed.net","iqksisgw.xyz","jsfiddle.net","kimcartoon.*","komikindo.tv","kooracity.cc","kriptoup.com","leekduck.com","lesite24.com","likemanga.in","looopings.nl","mangabat.com","megacloud.tv","middroid.com","mmamania.com","movies4u.bid","movies4us.co","moviesapi.to","moviesjoy.is","myflixerz.to","myfxbook.com","neko-sama.fr","netmovies.to","newatlas.com","neymartv.net","ntvstream.cx","omegascans.*","paktales.com","palemoon.org","pelisfull.tv","pepepeyo.xyz","photopea.com","playbill.com","radarbox.com","raqmedia.com","reddithd.lol","ronaldo7.pro","s2watch.link","saladnut.net","samsclub.com","sawahits.com","sbisec.co.jp","sbnation.com","serverf4.org","soap2day.day","sorumatik.co","spectrum.net","sportchek.ca","sportea.link","sportsnet.ca","sportsurge.*","stockrom.net","streamhub.to","studio.fm.br","t-mobile.com","teknorus.com","terhalak.com","theblaze.com","themezon.net","theverge.com","tiaabank.com","toonstream.*","tunimedia.tn","tutlehd4.xyz","tv247365.net","vegamovies.*","vid2a41.site","vid2faf.site","vipleague.im","visortmo.com","vvid30c.site","webwereld.nl","wideiptv.top","winsides.com","wordcount.im","worldmak.com","xhamster.com","yesmovies.vc","yomucomics.*","zinmanga.com","zodhacks.com","111movies.com","111movies.net","1qwebplay.xyz","4kwebplay.xyz","4stream.watch","7fractals.icu","8kwebplay.xyz","9anime.org.lv","adslayuda.com","alfred.camera","animeonline.*","animesaturn.*","animeunity.ch","animeunity.me","animeunity.to","aniwatchtv.to","aparttent.com","apprepack.com","aptgadget.com","asheville.com","attackertv.so","avsseries.com","bingewatch.to","bingsport.xyz","bolly4u.promo","bollyflix.how","buffsports.io","buienradar.nl","c8365730d4.nl","casertace.net","centrumher.eu","cheaplann.com","cleveland.com","cloutgist.com","cnwintech.com","comoapple.com","compstudio.in","computory.com","cozumpark.com","cr7soccer.com","cricfree.live","cricplay2.xyz","cricstream.me","doujindesu.tv","embdproxy.xyz","ersincaki.net","fastreams.com","filelions.top","filemooon.top","fisglobal.com","flamecomics.*","flowermanga.*","flyertalk.com","fmovies.world","fontsfree.pro","frenchpdf.com","fullassia.com","fullmoviesw.*","gamovideo.com","gogoanime3.cc","gogoanimes.fi","haronefit.com","hdcast123.com","hdmovie2.chat","helldivers.io","hlsplayer.org","homedepot.com","igg-games.com","infofordon.pl","jxoxkplay.xyz","kayoanime.com","keengamer.com","kimcartoon.si","kissasiantv.*","kisscartoon.*","kondoplay.cfd","krussdomi.com","laptopmag.com","likemanga.ink","listeamed.net","lojiciels.com","lolcalhost.ru","longecity.org","mandatory.com","mangabats.com","mangacrab.org","mangaworld.ac","manhastro.com","manhuatop.org","manhwatop.com","maxstream.org","metrolagu.cam","minoplres.xyz","mmastreams.me","mobilejsr.lol","mocospace.com","moumentec.com","movies4u.food","movies4u.loan","moviesjoytv.*","mp4upload.com","mrsoccer.club","mt07-forum.de","multimovies.*","my100bank.com","myviptuto.com","nbcsports.com","nelomanga.net","netflixvip.in","newzpanda.com","nicematin.com","nightpoint.io","numberozo.com","optumbank.com","polyflore.net","poradniki.net","portalenf.com","prantalks.com","prmovies.land","putlocker.vip","qqwebplay.xyz","rebe1scum.com","reliabletv.me","ridomovies.tv","rogmovies.fun","roselife.site","royalbank.com","s3embtaku.pro","shahidd4u.net","skyid.sky.com","spankbang.com","spookshow.net","sport24.co.za","sport7s01.com","sportshub.fan","sportsnest.co","sporttuna.pro","stream23.live","streambtw.com","streameast.ga","streameast.gd","streameast.io","streameast.is","streameast.to","streamtp1.com","streamvid.net","streamwish.to","swtorlogs.com","techclips.net","techkings.org","tescobank.com","theflixertv.*","theringer.com","tiermaker.com","tipslearn.com","trojmiasto.pl","tv247365.info","tv247365.link","u6lyxl0w.skin","ubuntudde.com","ufckhabib.com","vegamovies.st","vidora.stream","vidsrc.stream","vnexpress.net","vodstream.xyz","vstream.store","waves4you.com","wkconquer.com","wwwstream.pro","xrivonet.info","xsportbox.com","yallashoot.me","yellswsa.site","yomovies.taxi","zorroplay.xyz","ajanstv.com.tr","akamaicdn.life","ameriprise.com","animedevil.com","animesaturn.cx","animesuge.skin","asuracomic.net","audiostereo.pl","auto-treff.com","autopareri.com","autorambler.ru","avmkatalog.com","banglahunt.com","betfair.com.au","cartelive.club","cdnplaypro.com","championat.com","clerkopera.net","codepcplay.fun","comicsands.com","cr7soccer.site","cracksports.me","crichdplays.ru","curseforge.com","designparty.sx","dingtezuni.com","doc.moplay.org","dotmovies.guru","drakecomic.org","dudestream.com","duffelblog.com","embedsports.me","embedstream.me","emturbovid.com","eternalcbse.in","filepress.live","filmhost13.xyz","flyshayari.com","fstream365.com","fullmatch.info","funnyordie.com","gamebanana.com","gardenista.com","gatexplore.com","gdmirrorbot.nl","geforcenow.com","gettapeads.com","gogoanimes.org","golfstreams.me","gomstream.info","googlvideo.com","hackerrank.com","halftimer.shop","hdstream4u.com","hollymoviehd.*","istreameast.is","joyousplay.xyz","justembeds.cfd","kdramasmaza.co","leercapitulo.*","lulustream.com","manhwadesu.bio","megacloud.blog","megacloud.tube","methstreams.to","movies4ufree.*","moviesjoytv.to","multiembed.mov","musicradar.com","muzikonair.com","netuplayer.top","nhlmonster.com","nullscript.xyz","numankocak.com","odishadjs.link","oicanadian.com","omegascans.org","otvfoco.com.br","ozkanalkan.net","paddypower.com","pelismkvhd.com","player-cdn.com","portaldoaz.org","poscitechs.lol","primasport.one","quest4play.xyz","rapid-cloud.co","riftherald.com","rojadirectas.*","rolasdanet.com","rugbystreams.*","seriesonline.*","shazysport.xyz","shrinkme.click","sitelatest.com","slogoanime.com","soccer100.shop","socceronline.*","solarmovieru.*","sosyalbook.com","sport-play.xyz","sportsonline.*","sportsurge.net","steakguard.com","streameast.app","streameast.xyz","streamion.city","streamruby.com","streams.center","streamtape.com","streamwish.com","streamwish.top","swatchseries.*","techhelpbd.com","techus.website","teechbeats.com","tennisonline.*","thuthuatjb.com","tikitakatv.net","timesunion.com","tntsports.site","torenmedya.com","trivela.com.br","userlytics.com","v-network.site","vidplay.online","vidstreaming.*","watchomovies.*","watchseries8.*","whatfontis.com","wikisport.best","wikisport.wiki","worldsports.me","worldsports.st","xmegadrive.com","yomucomics.com","yourupload.com","zizicoi.online","123moviesfree.*","accuweather.com","aktuelsanat.net","aliezstream.pro","animeflv.com.co","animeidhentai.*","antenasport.org","antenasport.top","antennasports.*","bansports.store","baudasdicas.com","bestsolaris.com","betterstream.cc","bloodycount.net","books-world.net","boxingstream.me","brownheaven.net","bucketpages.com","buffstreams.app","canadiantire.ca","chapmanganato.*","chapmanganelo.*","chzzk.naver.com","cinemablend.com","cloudnestra.com","cloudy.upns.one","couchtuner.show","dailytechs.shop","deejayplaza.com","diffchecker.com","dnaofsports.com","elitepvpers.com","embed.meomeo.pw","embedsports.top","embedstreams.me","evdealmanca.com","expertszone.icu","faces4watch.com","fiveyardlab.com","flamecomics.xyz","flashsports.org","flowermanga.net","foostreamtv.xyz","forex4news.info","forum.nlmod.net","french-stream.*","fullmoviesw.com","futbolandres.eu","gameshdlive.net","gdriveplayer.to","generalpill.net","givemereddit.eu","go-streamer.net","gomstreams.info","gowiththevlo.nl","guitarworld.com","halotracker.com","hollymoviehd.cc","ilovetoplay.xyz","inventiva.co.in","jwplayerhls.com","kickassanime.mx","kickassanimes.*","krakenfiles.com","leercapitulo.co","linecrystal.com","livejournal.com","livescience.com","livesports4u.pw","livestreames.us","lotusgamehd.xyz","loudersound.com","mangakatana.com","mmafighting.com","motogpstream.me","movies2watch.tv","moviesflix8.com","multimovies.fyi","nbcssports.shop","nizarstream.com","o2tvseries4.com","paltrypaste.com","pandamovies.org","picassoappk.com","poscitechs.shop","qatarstreams.me","rnbxclusive1.me","rontechtips.com","rugbystreams.me","saidochesto.top","secondnexus.com","seriesonline.ac","sevenforums.com","smarthard.click","sneakernews.com","socceronline.me","sons-stream.com","souq-design.com","sportsonline.si","sportsonline.so","streameast.live","streamhd247.pro","streamingon.org","streamking.live","subtitlecat.com","sussytoons.site","swatchseries.is","taazaalerts.com","technorozen.com","tennisonline.me","thepicpedia.com","timeanddate.com","topstreams.info","totalbeauty.com","trancebazar.com","turkry-rasd.com","tvsportslive.fr","twinkietown.com","vakilsearch.com","valhallas.click","venusembed.site","videograbber.cc","vidhideplus.com","watchseries8.to","wiflix-pro.site","windowcross.net","xstreameast.com","abolishstand.net","absentescape.net","airlinercafe.com","aktualnosci.news","almasdarnews.com","antennasports.ru","bitcoinsport.pro","blockadblock.com","bostanekotob.com","carsguide.com.au","cgbsesupport.com","chapmanganato.to","cioupdate.com.tr","civildigital.com","cizzyscripts.com","clickndownload.*","crackstreams.app","creativebloq.com","daddy-stream.xyz","daddynews.online","dartsstreams.com","demonicscans.org","eduschool40.blog","epicplayplay.cfd","ewrc-results.com","eyespeeled.click","foreverhealth.in","forgepattern.net","frontedelblog.it","futbolandres.xyz","grandoldteam.com","hamzaerol.com.tr","hanatyury.online","illnessstamp.net","insidesport.info","iskandinavya.com","jogging-plus.com","keylerbenden.com","kickass-anime.ru","kickassanimes.io","klsescreener.com","kollyinsider.com","live.redditf.xyz","liveruparojs.icu","livesteching.com","m.reviewrate.net","mag.asteroids.jp","modzillamods.com","movieshdwatch.to","mylivestream.pro","nachrichten.cyou","nativesurge.info","nbadigestnow.com","new.sussytoons.*","nobodywalked.com","notebookcheck.nl","olympuscomic.com","piratecat.online","pirotskevesti.rs","play.frembed.lol","popcornfilmz.com","portallos.com.br","prajwaldesai.com","pureinfotech.com","rabbitstream.net","raven-mythic.com","rojadirecta1.net","rule34hentai.net","smartermuver.com","solarmagazine.nl","solarmovieru.com","speci4leagle.com","sportshub.stream","ssuathletics.com","stream.nflbox.me","streamblasters.*","streambucket.net","streamcenter.xyz","streamexpert.pro","streamhd247.info","streamingnow.mov","stronstream.shop","tastycookery.com","technicalatg.xyz","telefoniatech.it","thenextdroid.com","thestreameast.gg","thestreameast.to","tsnsports.online","tweaking4all.com","vidstreaming.xyz","viwlivehdplay.ru","vpshostplans.com","vsichkifilmi.net","warcraftlogs.com","webplatform.news","ziggo-gratis.com","ziggogratis.shop","acommunity.com.tw","affiliate.fc2.com","animeidhentai.com","animeonline.ninja","animeunity.com.co","bitcoinarabic.com","bollywoodhindi.in","brookethoughi.com","browncrossing.net","bunniescdn.online","cad-elearning.com","canadajobbank.org","canyoublockit.com","chapmanganelo.com","checkresultbd.com","cloudhostingz.com","cookiewebplay.xyz","coolwallpapers.me","dailybanner.co.uk","databaseitalia.it","directpay.irs.gov","dynamicsupply.net","euro2024direct.ru","fitforcedaily.com","freemovieswatch.*","freesportshq.shop","french-stream.one","gamehdlive.online","gamingsinners.com","geeksforgeeks.org","gomstreams.online","good-football.org","grostembed.online","hardwaresfera.com","healthsafe-id.com","heypoorplayer.com","insidermonkey.com","kaisekareblog.com","katholisches.info","kishanganjnews.in","latestreview.tech","ldcstreaming.info","leveling-solo.org","lewblivehdplay.ru","lightnovelpub.com","linenstandard.net","mahabhulekh712.in","marinetraffic.com","mcskinhistory.com","mondomobileweb.it","multimovies.cloud","musicfeeds.com.au","nbcsportsedge.com","newsdigestcap.com","nullphpscript.com","processbigger.com","readcomiconline.*","rojadirecta1.site","rollingwheel.shop","sciencedirect.com","shiningawards.com","snapinsta.monster","soccerworldcup.me","stellarthread.com","sticky-sports.cfd","streamblasters.pm","streamcaster.live","streameeeeee.site","streamingunity.to","super-sports.shop","superherohype.com","theregister.co.uk","tribunaplovdiv.bg","tripplestream.com","tryhardsports.com","turkedebiyati.org","vacantseats.click","venusarchives.com","verpornocomic.com","watchomovies.guru","yakkachannels.icu","youtubevanced.com","123movies-series.*","allafinedelpalo.it","bizz-streams2u.xyz","bombaysamachar.com","brjogostorrent.net","citibankonline.com","clickndownload.cfd","connectonebank.com","craftpip.github.io","currentcruelty.net","digitalfacts4u.com","elegantpelican.dev","esercizinglese.com","evdeingilizcem.com","extremosports.club","flashdumpfiles.com","freekicksoccer.org","freemovieswatch.cc","gamerevolution.com","geniuseducares.com","heroesneverdie.com","historicseries.com","kamuisilanlari.net","keighleynews.co.uk","listenonrepeat.com","livefootball24.com","livestreamtvv.site","motortrader.com.my","notodoanimacion.es","odiasongsworld.com","pagalmp3status.com","player.videasy.net","pokemonforever.com","polandinarabic.com","portalportuario.cl","readcomiconline.li","readlightnovel.org","rollingwheel.store","sarkariexam365.com","soccerstream100.co","sozgazetesi.org.tr","sportsstreams.shop","stokourbeti.online","stylisheleg4nt.com","tapeadsenjoyer.com","thefashionspot.com","thegraveplayer.win","theherald-news.com","thetimesweekly.com","tnt-sportslive.xyz","tripplestream.shop","watchadsontape.com","westernjournal.com","admissionnotice.com","arabgamingworld.com","askeribirlikler.com","calendarpedia.co.uk","canadianjobbank.org","chakrirkhabar247.in","choosingnothing.com","computercoach.co.nz","daddylivestream.xyz","footballstreams.lol","freestreams-live.my","healthyguide.com.ng","how2electronics.com","kashmirobserver.net","kupujemprodajem.com","lightnovelworld.com","live.esportivos.fun","live.esportivos.one","mangaworldadult.net","mcloud.vvid30c.site","medjugorje-news.com","nakedcapitalism.com","nepaleseteacher.org","new.sussytoons.site","notiziariodelweb.it","onehealthcareid.com","popcorntimeonline.*","sports-stream.click","sugargliderfaqs.com","theonegenerator.com","thetruedefender.com","triipplestreams.xyz","tube.perverzija.com","vegamovies4u.beauty","voleybolmagazin.com","watch-movies.com.pk","112midden-zeeland.nl","animenewsnetwork.com","chicago.suntimes.com","daddyliveplayer.shop","daddylivestream.shop","designeroccasion.com","expatguideturkey.com","fresheroffcampus.com","lesmoutonsenrages.fr","loriwithinfamily.com","mystreamnetwork.site","photoshop-online.biz","powerrangergames.com","punto-informatico.it","raidersixgameapk.com","realcleardefense.com","revistavanityfair.es","ringwitdatwixtor.com","sandratableother.com","special-streams.site","streamingcommunity.*","theodysseyonline.com","viaplaysports.online","windows101tricks.com","columbiaspectator.com","curiosandosimpara.com","ebay-kleinanzeigen.de","edwardarriveoften.com","glamourmagazine.co.uk","ibanking-services.com","japancamerahunter.com","juancarlosmolinos.net","justdoelectronics.com","lereportersablais.com","librarywhispering.com","live.esportivos.click","northwestfirearms.com","polovniautomobili.com","popcorntimeonline.xyz","premiumembeding.cloud","reddit-streams.online","reptiles-universe.com","smokingmeatforums.com","totalsportek.football","whisperingauroras.com","cathouseonthekings.com","digitalcameraworld.com","finance.kooorazoom.net","fullversionforever.com","player.mangafrenzy.net","streamingcommunity.ooo","universal-lover-zz.icu","wallpapers.ispazio.net","washingtoninformer.com","aulasdeinglesgratis.net","coastcapitalsavings.com","edgedeliverynetwork.com","file-zz40pd56-embed.com","gadgets.techymedies.com","greenocktelegraph.co.uk","stream.sportsspeed.site","tdcommercialbanking.com","compensationcoincide.net","databasegdriveplayer.xyz","electricaltechnology.org","gbf7wrqapjg1js045ye8.com","ganardineroporinternet.me","sharonwhiledemocratic.com","governmentofcanadajobs.com","innercircletrading.website","interestingengineering.com","blaulichtreport-saarland.de","reddit-soccerstreams.online","streaminglearningcenter.com","whisperingauroras.comos.xyz","springfieldspringfield.co.uk","xn-----0b4asja7ccgu2b4b0gd0eejfg2jpa1b1e9zva7a0347s4da2797e8qri.xn--1ck2e1b"];
    const collectArglistRefIndices = (out, hn, r) => {
        let l = 0, i = 0, d = 0;
        let candidate = '';
        while ( l < r ) {
            i = l + r >>> 1;
            candidate = $scriptletHostnames$[i];
            d = hn.length - candidate.length;
            if ( d === 0 ) {
                if ( hn === candidate ) {
                    out.add(i); break;
                }
                d = hn < candidate ? -1 : 1;
            }
            if ( d < 0 ) {
                r = i;
            } else {
                l = i + 1;
            }
        }
        return i + 1;
    };
    const indicesFromHostname = (out, hnDetails, suffix = '') => {
        if ( hnDetails.hns.length === 0 ) { return; }
        let r = $scriptletHostnames$.length;
        for ( const hn of hnDetails.hns ) {
            r = collectArglistRefIndices(out, `${hn}${suffix}`, r);
        }
        if ( $hasEntities$ ) {
            let r = $scriptletHostnames$.length;
            for ( const en of hnDetails.ens ) {
                r = collectArglistRefIndices(out, `${en}${suffix}`, r);
            }
        }
    };
    const todoIndices = new Set();
    indicesFromHostname(todoIndices, entries[0]);
    if ( $hasAncestors$ ) {
        for ( const entry of entries ) {
            if ( entry.i === 0 ) { continue; }
            indicesFromHostname(todoIndices, entry, '>>');
        }
    }
    // Collect arglist references
    if ( todoIndices.size ) {
        const $scriptletArglistRefs$ = /* 1423 */ "156;157,191;157,191,192;179;157;157,191;157,191;11;15;4;157,191;157,191;185,186;107;157,191;22,157;191;151,156,157,158;92;157,191;66;11;4;157,191;157,156;185,186;98;146,157,156,152,205,206,207,162;11;12;157;157;157,156;11;62;15;157;157,156;157,156;157;157;157,191;157,191;11;157,191;157,191;30;4;157;157;157,164,165,166;4;11;121;191;157;157;185,186;157;54;157,191;157,193;157,191;91;157,191;157;11;157,191;157,191;157,191;11;157,191,192,193;11;157,191;24;157;157,191;157,191,192;157,191;157;157,191;157,156,191;185,186;157;157,191;157,191;157;185,186;157,191;132;157,191;73;157;191;191;11;11;160,161,162,163,157;160,161,162,163,157;4;191;13;157,193;30;58;157,191;157;157;79;157,191;157;186;4;157,156,191;157,191;157,191;157;157,156;157,156;157;157,191;14;4;157;157,191;157,191;96;149,153,151;157;149,153,151;157,191,192;4;4;157,191;157;4;157,156;4;54;11;157;157,191;157,191;6;185,186;191;157;157,191;157,193;157,191;157,191;157;191;157,191;157,193;157,191,192;61;157;4;157,191;191,192;157,156;191;157;157,191;157,156,191;15;106;208;191;157,191;192;192;4;157,191;56;157,191;157,156;191;191;4;157,191;11;160,161,162,163,157;8;191;157;72;4;191;157;191;157,191;157;157,156;157,191;157;150,198,199,197,200,201,202,203,204;150,198,199,197,200,201,202,203,204;157;157,156;141;157,193;157;4;157,191;157,191;157,156,191;157,156;157,193;157,191;157,191;4;157,191;4;29;191;157,191;157,156;157,191;157,191;167,168;184;167,168;11;4;4;157,191;149,153,151;149,153,151,157;157,191;54;157;80;157;157;157,191;157,191;173;78;4;4;157,191;157,191;118;157,191,193;157,191;157,191;150,151,152,157,191;150,151,152;150,151,152;157,191;157;4;157;157;157,191;157,191,192;157;157,191;157,191;157,191;157,191;157,191;157,191;157,156,191;157,191;157;157,191;11;11;87;4;157;27,142;4;185,186;157,191,192,193;169,170;175;157;157;191;83;157;191;157,191;157,191;157;152;157,191,192;157,191;157;-183;157,193;185,186;40;157;4;191;157,156;157,191;39;54;185,186;157,193;185,186;157;157,191,192;191;157,191;157,191;157,191;157,191;157;157;4;11;4;4;157;157,191;4;167,168;4;157,191;156;157,191;157;4;157,191;157,191,192;157,156,191;157,156;157,191;4;157;157,191;157,191;191;157;4;157,191,192;157,191;157,191,192;15;157,191;157,191;157,191;157;157;157,191;157;53;157;171;157;55;191;11;157,191;157;187;157,156;157;136;157,191,192;4;5;-3;4;4;157,191;191;191,192;194,195,196,197;191;157;118;157;157;191;157,191;157;157,193;157,191;150,151,152;157;46;157,191;15;157;157,191;157,191;157,191;157,156;157,191;157,191;157,156,191;157,156;157,191;191;4;18;157;157;167,168;191;4;157;151,156,157,158;151,156,157,158;4;4;157,191;157,156;157,191;89;157,191;191;157,191;82;157;157;157,191;157,191;157,156,191;157,191;157,191;4;157;25;157;157;8;15;157;54;161,157;4;157,191;11;157,191;160,161,157;160,161;191;157,191;122;157,191;157;11;4;157,191;191,192;157;157;157;157,191;157;157,191;157,191,192,193;4;4;59;4;157;157;157;191;157;157,156;157,156;157,191,192;157;191;133;150,198,199,197,200,201,202,203,204;191,192;157,191;157,156;157;191,192;11;4;4;57;157;126;143,157,191;157,191;157;157,191,192,193;157;157,191;157,191,193;157,191;4;157,191;157,191;157;157,191;157,191;149,157,164,165,166,191;157,191;157,191;157,191;157,191;157;4;4;4;156;4;157,191;157;157,191;157,191;191,192;157;157;11;174;191;157,191;4;191;4;64;157,191,192;191;157,191;11;137;191;4;157,191,192;157;157;156;157,191,192;157;157;23;180;157,156;157;157,191;157,191;157,191;191;157,193;191;124;167,168;4;38;157,193;123;151,156,157,158,191;157;4;4;116;4;191;172;157,191;157,156,191;4;54;191;157,191;157,191;157;157,191;21;157;157,191;15;157;157;157,191;4;52;28;157,191;127;84;76;4;157;157;157,156;191;11;4;11;54;157;191;4;11;11;157;16;191;4;157;4;11;4;4;99;191;54;11;157,191;4;157;157,156;157,191;157;157;191,192;157;157;51,178;157,156;4;157,191;4;157;191;157,191;157;4;157;157,191,192;157;157;157;192;157;157,191;81;130,131;157,191;157,191;157;157;157,156;157,191;157;4;4;64;157;4;191;157,156;157;157;191,192;60;157;63;41;157;15;156;4;4;4;4;4;156;157,156;157,156;157,156;157;157;4;157,156;157,191;157;11;157,191;157,191;27;150,151,152;69;4;157,156;157,191;157;157,191;157,191;4;157;157;136;157;11;157,191;4;157,191,192,193;4;15;191;151,156,157,158;151,156,157,158;157,192,193;157,191;66;191;157,191;4;157;95;15;157,191;3;191;191;157,191;157,156;157;191;157,191;157,191,192;191;75;4,5;156;157;157,191;157,191;156;77;157,191;11;4;99;157,191;167,168;4;104;94;4;11;93;4;4;4;191;191;157;4;157,191;157;157,191;157;11;191;157,191;11;-2;44;15;157;157;157;157,156;157;157,156;157,191,192;157;144,145,146,147;144,145,146,147;144,145,146,147;157;157;157,188,189,190;118;157,156;42;11;157,191;54;105;4;73;157;157,156;157,193;102;157;157,191;157;157;135;157;157,156;114;4;157;157,156,191;157;4;157,191,192;157,191;157,191,192,193;64;157;11;4;191;191;191;89;77;133;185,186;4;4;11;157,191;157;185,186;157,191;157;15;157,156;157,191,192;157;133;193;157,193;157;157;191;157;15;157;156;157,156,191;167,168;191;157;167,168;157,191;4;54;73;19;4;157;170;157;157;191,192;157;157;169;157;157;191;157,191,192;157;157,192,193;4;157,191;157,191;157;157,191;157,191;157;157,191;191;157;66;4;157,191;157,191;4;4;167,168;4;157,191;24;4;11;157;157;4;157;157;157;157;54;157,191;4;157,191;157,191;157,156,191;157,191;4;4;157;157,191;157,191;4;157;157,191;191,192;157;157;144,145,146,147;157,191,192;157,191;157,191,192;157;157;157,191;157,191;4;115;4;157,191;4;157,156;159;157;4;4;8;157;157;157,191;157,191;157,191;97;157;157,192,193;157,156;191;157;157,191;157;157,191;157,191;181;4;157;157;157,191;157,191,192;157,191,192;157,191;157,156;4,5;157,156;157;157,191,192;40;191;157,156;49;157;11;157,191;157,191;209;15;157,191;157;157;157;4,5;88;4;110,111;157;157,191,192;157,156;4;191;4,5;157,156;157,156,191;157;157,191;157,156;157;68;157,191;191;156;157;157,193;157;157,156;157;191;174;66;28;157,191;157;4;157,156;157;151,156,157,158;157;157,191;157,156;210,211;66;157;157;191;31;157;54;191;157,156,191;191;191,192;157,156;157,156;157,191;157;157,191;167,168;157,156;191;149;4;157,191;157;15;157,191;15;157;120;157,156,191;157,156;4;157,156;157;144,145,146,147;156;157;157,156;157;157;157,191;167,168;4;157,156,191;4;139;157;15;167,168;4;157,156;54;4;157;157;157,191;157;157,191;157,191;157;157,191,192;157;156;43;4;63;157,156;157,156;183;4;50;167,168;157,191;4,5;63;148;157,191;157;66;157;157,156;191;157,191;4;157,191,192;36;157;167,168;157,156;4;157;109;4,5;157,191;157;157,191,192;117;4;4;191;157;140;35;157;191;191;157,191,192;4;4;157,191;157,156;4;157;157;157,191;157;176;157,191;157,191;4;157,191;157,191;4;4;63;157,156;37;157,191;157;157;138;191;157,156;157,156;108;191;157,191;157;157,191;157,156;157,156;157,191;157;45;4;4;4;144,145,146,147;144,145,146,147;156;134;157,191;157,156;157;157;118;7;157,191;157;4;86;191;157,191;157;4;4;157;157;157,191;4;4;9,10,157;157,191;4;3;157;113;4;4;11;157;157,156;191;157,191;191;157,191;157;109;112;157,191;73;157;4,5;11;33;71;167,168;101;167,168;4;157,156;157;157;154,155,157;157;167,168;128;125;4;157,191;15;99;157;4;157;157,191;157;192;11;4;157,191;191;157,191;191,192;157,191;157;157;157,191;157,156;15;74;4;157;4;4;157,156;63;63;157,191;157,191,192;157;157,191;33;157;4;157,191;11;191;11;119;157;167,168;157;28;4;157;4;157;191;15;167,168;54;4;4;66;15;157,156;191;90;4;167,168;167,168;157,191;48;4;24;157,156,191;15;157;167,168;157;4;191;157,191,192;157,156;157;15;157,191,192,193;70;4;156;191,192;191;15;4;4;4;15;4;4;157,156;4;157,191;157;157,156;4;4;32;181;157;157;157;191;191;4;65;4;191;4;11;157,191;157;167,168;125;4;157,191;157;191;4;191;177;129;54;157,192,193;191;157,156;4;148;63;157;157,156;79;167,168;20;167,168;17;100;4;157,191;157,191;157,191;15;157,156;15,67;26;4;11;157;57;11;43;47;4;4;157,156;157;42;181;157,191;157;157;4;85;157;157;34;66;212;4;157;157,191;192;4;4;4;11;157,191;157;4;31;157;11;157;157,191;4;157;4;157;4;4;15;4;157;103;157,191;24;157";
        const arglistRefs = $scriptletArglistRefs$.split(';');
        for ( const i of todoIndices ) {
            for ( const ref of JSON.parse(`[${arglistRefs[i]}]`) ) {
                todo.add(ref);
            }
        }
    }
}

if ( $hasRegexes$ ) {
    const $scriptletFromRegexes$ = /* 1 */ ["http","^https?:\\/\\/[a-z]{8,15}\\.(com|xyz)\\/$","191"];
    const { hns } = entries[0];
    for ( let i = 0, n = $scriptletFromRegexes$.length; i < n; i += 3 ) {
        const needle = $scriptletFromRegexes$[i+0];
        let regex;
        for ( const hn of hns ) {
            if ( hn.includes(needle) === false ) { continue; }
            if ( regex === undefined ) {
                regex = new RegExp($scriptletFromRegexes$[i+1]);
            }
            if ( regex.test(hn) === false ) { continue; }
            for ( const ref of JSON.parse(`[${$scriptletFromRegexes$[i+2]}]`) ) {
                todo.add(ref);
            }
        }
    }
}

// Execute scriptlets
if ( todo.size && todo.has(0) === false ) {
    const $scriptletFunctions$ = /* 18 */
[setConstant,preventXhr,noEvalIf,preventFetch,abortOnPropertyWrite,abortOnPropertyRead,abortCurrentScript,preventSetTimeout,preventAddEventListener,zeta_8echnktd,preventSetInterval,abortOnStackTrace,noWindowOpenIf,noWebrtc,removeAttr,preventBab,jsonPrune,jsonPruneXhrResponse];
    const $scriptletArgs$ = /* 208 */ ["send_recommendation_event","noopFunc","discord.com/api/v9/science","/chp_?ad/","tie.ad_blocker_detector","","tie.ad_blocker_disallow_images_placeholder","fwmrm","navigator.clipboard","navigator.connection","{}","atob","decodeURIComponent","tmx_post_session_params_fixed","hasAdblock","false","__cmpGdprAppliesGlobally","uxGuid","warning_widget.check_ad_block_status","CheckAdLoad","adsAreBlocked","blazemedia_adBlock","checkForAds","check","100","nebula.session.flags.adblock","undefined","addLink","_adBlockCheck","true","ads","2000","$","AdBlock","adBlockDetected","ADBdetected","fuckAdBlock","_sp_._networkListenerData","document.getElementById","ad-blocker","ABDSettings",".ab_detected","adMessage","adBlockEnabled","$adframe","adblock","BIA.ADBLOCKER","Adblocker","10000","jQuery","samDetected","adBlockFunction","trueFunc","DOMContentLoaded",".js-popup-adblock","checkAds","google_jobrunner","#advert-tracker","500","isAdblockDisabled","adsAreShown","abd","aoezone_adchecker","adsBlocked","adsbygoogle","null","NoAd","8000","ads_not_blocked","can_i_run_ads","warning","hideBannerBlockedMessage","abStyle","eval","ai_adb","ABD","_sp_.mms.startMsg","better_ads_adblock","0","document.createElement","adBlock","adtoniq","adblocker","ads_enabled","offsetHeight","5000","bait","adblockerdetected","juicyads","btoa","checkFeed","1000","FuckAdBlock","adStillHere","adb","canRunAds","Adblock","document.oncontextmenu","abp","blocked","pgblck","admrlWpJsonP","initAdBlockerPanel","pop","String.prototype.charCodeAt","ai_","AdB","&adslot","ab","document.querySelector","test","Promise","showAdblockerModal","dfgh-adsbygoogle","kan_vars.adblock","attachToDom","ad-fallback","adsok","sneakerGoogleTag","checkAdblockBait","AdBlocker","modal","ad","console.clear","mtGlobal.disabledAds","ANN.ads.adblocked","googlesyndication","2","nitroAds","getComputedStyle","load","ad-wrap","&disp=popup","1","adb-enabled","/^/","0x","visibility","sadbl","startCheckingAdblock","_pop","break;case $.","JSON.parse","parseInt","AaDetector","=>","/appendChild|e\\(\"/","String.fromCharCode","/btoa|break/","check_adblock","blueConicPreListeners","Object.defineProperty","trafficjunky","page_params.holiday_promo","_0x","IS_ADBLOCK","shift","open","PopAds","AdBDetected","count","navigator.brave","isAdBlockActive",".style.display=","AdBlockerCheck","advanced_ads_check_adblocker","ads_toegestaan","send","anOptions","adBlockStatus","isAdBlockEnabled","class",".ads-not-loaded","stay","Math","inlineScript","data-leaderboard-is-fixed","html","Blocks","Object.prototype.getPlaceSelectorByBannerId","bootbox.alert","xRds","cRAds","__Y","method:HEAD","EventTarget.prototype.addEventListener","delete window","showTrkURL","/window\\['(?:\\\\x[0-9a-f]{2}){2}/","/popunder/i","document.documentElement","Adcash","//","path","10","*","*.adserverDomain","navigator","FingerprintJS","admc","runAdblock","getAdcrUrl","adBreaks.[-].adSources.[].withRemindAd ads.[-].eventTracking.ackImpressions","propsToMatch","url:api.chzzk.naver.com/service/t/","window.webpackJsonpSSPjs","webpackJsonpSSPjs","adBlockBlock"];
    const $scriptletArglists$ = /* 213 */ ";0,0,1;1,2;2,3;0,4,5;0,6,5;3,7;4,8;0,9,10;5,11;6,11,12;6,13;4,14;5,14;0,14,15;5,16;5,17;0,18,1;4,19;0,20,15;5,21;7,22;7,23,24;0,25,26;5,27;0,28,29;7,30,31;6,32,33;4,34;0,35,1;5,36;5,37;6,38,39;5,40;6,38,41;4,42;4,43;4,44;0,45,15;0,46,15;7,47,48;6,49,26;0,50,29;6,49,30;0,51,52;8,53,54;0,55,52;4,40;0,56,29;7,57,58;0,59,29;0,60,29;0,61,15;0,62,29;7,63;0,64,65;7,66,67;0,68,29;5,69;7,70;0,71,29;5,72;6,73,61;6,49,74;7,45;4,75;5,76;0,77,78;6,79,45;0,80,15;7,65;5,75;8,5,30;5,34;5,81;7,82;0,83,29;6,32,84;7,64,85;7,56;7,86;0,77,65;6,38,87;6,32,88;7,84;6,32,89;7,90,91;4,92;7,93;7,94;5,95;6,32,96;4,97;7,34;9;0,98,15;7,99,91;6,32,80;7,100;4,101;5,102;7,103;6,104,105;7,30;8,5,106;7,107;10,64;0,108,15;6,109,45;6,32,110;7,32;6,32,111;6,112;10,113;11,104,105;7,105;7,98;5,114;6,115,116;7,117;5,118;6,119;2,120;7,121;7,122;3,30;7,64;0,123,1;0,124,29;0,125,15;8,53,30;10,30;1,126;3,126;7,64,31;0,45,127;5,128;10,129;1,30;8,130,131;6,38,45;12,132,133;5,92;7,134;8,135,136;10,137,91;13;7,138;4,139;4,140;8,5,141;6,142,141;6,143,141;5,144;7,145;7,146;6,147,148;12;0,149,29;4,150;6,151,152;0,153,29;8,5,154;4,155;6,147,156;5,157;5,158;4,159;0,160,78;5,161;0,161,26;0,162,15;6,38,163;7,164;4,165;0,166,29;6,38,167;5,168;0,169,15;0,170,15;0,45,78;14,171,172,173;11,174,175;15;14,176,177,173;16,178;4,179;5,180;0,181,29;0,182,15;5,183;3,184;1,184;6,185,186;6,142,187;6,174,188;2,189;6,190,141;5,191;12,192;0,193,5;12,5,194;6,142,11;16,195,196;6,197,198;6,79,199;7,199;5,200;0,201,5;17,202,5,203,204;5,205;5,206;0,207,133";
    const arglists = $scriptletArglists$.split(';');
    const args = $scriptletArgs$;
    for ( const ref of todo ) {
        if ( ref < 0 ) { continue; }
        if ( todo.has(~ref) ) { continue; }
        const arglist = JSON.parse(`[${arglists[ref]}]`);
        const fn = $scriptletFunctions$[arglist[0]];
        try { fn(...arglist.slice(1).map(a => args[a])); }
        catch { }
    }
}

/******************************************************************************/

// End of local scope
})();

void 0;
