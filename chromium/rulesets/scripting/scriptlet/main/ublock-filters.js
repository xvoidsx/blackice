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

// ruleset: ublock-filters

// Important!
// Isolate from global scope

// Start of local scope
(function uBOL_scriptlets() {

/******************************************************************************/

class ArglistParser {
    constructor(separatorChar = ',', mustQuote = false) {
        this.separatorChar = this.actualSeparatorChar = separatorChar;
        this.separatorCode = this.actualSeparatorCode = separatorChar.charCodeAt(0);
        this.mustQuote = mustQuote;
        this.quoteBeg = 0; this.quoteEnd = 0;
        this.argBeg = 0; this.argEnd = 0;
        this.separatorBeg = 0; this.separatorEnd = 0;
        this.transform = false;
        this.failed = false;
        this.reWhitespaceStart = /^\s+/;
        this.reWhitespaceEnd = /(?:^|\S)(\s+)$/;
        this.reOddTrailingEscape = /(?:^|[^\\])(?:\\\\)*\\$/;
        this.reTrailingEscapeChars = /\\+$/;
    }
    nextArg(pattern, beg = 0) {
        const len = pattern.length;
        this.quoteBeg = beg + this.leftWhitespaceCount(pattern.slice(beg));
        this.failed = false;
        const qc = pattern.charCodeAt(this.quoteBeg);
        if ( qc === 0x22 /* " */ || qc === 0x27 /* ' */ || qc === 0x60 /* ` */ ) {
            this.indexOfNextArgSeparator(pattern, qc);
            if ( this.argEnd !== len ) {
                this.quoteEnd = this.argEnd + 1;
                this.separatorBeg = this.separatorEnd = this.quoteEnd;
                this.separatorEnd += this.leftWhitespaceCount(pattern.slice(this.quoteEnd));
                if ( this.separatorEnd === len ) { return this; }
                if ( pattern.charCodeAt(this.separatorEnd) === this.separatorCode ) {
                    this.separatorEnd += 1;
                    return this;
                }
            }
        }
        this.indexOfNextArgSeparator(pattern, this.separatorCode);
        this.separatorBeg = this.separatorEnd = this.argEnd;
        if ( this.separatorBeg < len ) {
            this.separatorEnd += 1;
        }
        this.argEnd -= this.rightWhitespaceCount(pattern.slice(0, this.separatorBeg));
        this.quoteEnd = this.argEnd;
        if ( this.mustQuote ) {
            this.failed = true;
        }
        return this;
    }
    normalizeArg(s, char = '') {
        if ( char === '' ) { char = this.actualSeparatorChar; }
        let out = '';
        let pos = 0;
        while ( (pos = s.lastIndexOf(char)) !== -1 ) {
            out = s.slice(pos) + out;
            s = s.slice(0, pos);
            const match = this.reTrailingEscapeChars.exec(s);
            if ( match === null ) { continue; }
            const tail = (match[0].length & 1) !== 0
                ? match[0].slice(0, -1)
                : match[0];
            out = tail + out;
            s = s.slice(0, -match[0].length);
        }
        if ( out === '' ) { return s; }
        return s + out;
    }
    leftWhitespaceCount(s) {
        const match = this.reWhitespaceStart.exec(s);
        return match === null ? 0 : match[0].length;
    }
    rightWhitespaceCount(s) {
        const match = this.reWhitespaceEnd.exec(s);
        return match === null ? 0 : match[1].length;
    }
    indexOfNextArgSeparator(pattern, separatorCode) {
        this.argBeg = this.argEnd = separatorCode !== this.separatorCode
            ? this.quoteBeg + 1
            : this.quoteBeg;
        this.transform = false;
        if ( separatorCode !== this.actualSeparatorCode ) {
            this.actualSeparatorCode = separatorCode;
            this.actualSeparatorChar = String.fromCharCode(separatorCode);
        }
        while ( this.argEnd < pattern.length ) {
            const pos = pattern.indexOf(this.actualSeparatorChar, this.argEnd);
            if ( pos === -1 ) {
                return (this.argEnd = pattern.length);
            }
            if ( this.reOddTrailingEscape.test(pattern.slice(0, pos)) === false ) {
                return (this.argEnd = pos);
            }
            this.transform = true;
            this.argEnd = pos + 1;
        }
    }
}

class JSONPath {
    static create(query) {
        const jsonp = new JSONPath();
        jsonp.compile(query);
        return jsonp;
    }
    static toJSON(obj, stringifier, ...args) {
        return (stringifier || JSON.stringify)(obj, ...args)
            .replace(/\//g, '\\/');
    }
    static keys = Object.keys;
    static entries = Object.entries;
    static hasOwn = Object.hasOwn;
    static Regex = RegExp;
    get value() {
        return this.#compiled && this.#compiled.rval;
    }
    set value(v) {
        if ( this.#compiled === undefined ) { return; }
        this.#compiled.rval = v;
    }
    get valid() {
        return this.#compiled !== undefined;
    }
    compile(query) {
        this.#compiled = undefined;
        this.v2 = query.startsWith('v2:');
        if ( this.v2 ) { query = query.slice(3); }
        const r = this.#compile(query, 0);
        if ( r === undefined ) { return; }
        if ( r.i !== query.length ) {
            let val;
            if ( query.startsWith('=', r.i) ) {
                const match = this.#reRval.exec(query.slice(r.i));
                if ( match ) {
                    r.modify = match[1];
                    val = match[2];
                } else {
                    val = query.slice(r.i+1);
                }
            } else if ( query.startsWith('+=', r.i) ) {
                r.modify = '+';
                val = query.slice(r.i+2);
            }
            try { r.rval = JSON.parse(val); }
            catch { return; }
        }
        r.v2 = this.v2;
        this.#compiled = r;
    }
    evaluate(root) {
        if ( this.valid === false ) { return []; }
        this.#root = { '$': root };
        const paths = this.#evaluate(this.#compiled.steps, []);
        this.#root = null;
        return paths;
    }
    apply(root) {
        if ( this.valid === false ) { return; }
        const { rval } = this.#compiled;
        this.#root = { '$': root };
        const paths = this.#evaluate(this.#compiled.steps, []);
        let i = paths.length
        if ( i === 0 ) { this.#root = null; return; }
        while ( i-- ) {
            const { obj, key } = this.#resolvePath(paths[i]);
            if ( obj === undefined ) { continue; }
            if ( rval !== undefined ) {
                this.#modifyVal(obj, key);
            } else if ( Array.isArray(obj) && typeof key === 'number' ) {
                obj.splice(key, 1);
            } else {
                delete obj[key];
            }
        }
        const result = this.#root['$'] ?? null;
        this.#root = null;
        return result;
    }
    dump() {
        return JSON.stringify(this.#compiled);
    }
    toJSON(obj, ...args) {
        return JSONPath.toJSON(obj, null, ...args)
    }
    get [Symbol.toStringTag]() {
        return 'JSONPath';
    }
    #UNDEFINED = 0;
    #ROOT = 1;
    #CURRENT = 2;
    #CHILDREN = 3;
    #DESCENDANTS = 4;
    #QUANTIFIER = 5;
    #reUnquotedIdentifier = /^[A-Za-z_][\w]*|^\*/;
    #reExpr = /^\s*([!=^$*]=|[<>]=?)\s*(.+?)\]/;
    #reIndice = /^-?\d+/;
    #reRval = /^=([a-z]+)\((.+)\)$/;
    #reQuantifier = /^\{(\d+|\d+,\d+|\d+,|,\d+)\};\$/;
    #root;
    #compiled;
    #compile(query, i) {
        if ( query.length === 0 ) { return; }
        const steps = [];
        let c = query.charCodeAt(i);
        if ( c === 0x24 /* $ */ ) {
            steps.push({ mv: this.#ROOT });
            i += 1;
        } else if ( c === 0x40 /* @ */ ) {
            steps.push({ mv: this.#CURRENT });
            i += 1;
        } else {
            steps.push({ mv: i === 0 ? this.#ROOT : this.#CURRENT });
        }
        let mv = this.#UNDEFINED;
        for (;;) {
            if ( i === query.length ) { break; }
            c = query.charCodeAt(i);
            if ( c === 0x20 /* whitespace */ ) {
                i += 1;
                continue;
            }
            // Dot accessor syntax
            if ( c === 0x2E /* . */ ) {
                if ( mv !== this.#UNDEFINED ) { return; }
                if ( query.startsWith('..', i) ) {
                    mv = this.#DESCENDANTS;
                    i += 2;
                } else {
                    mv = this.#CHILDREN;
                    i += 1;
                }
                continue;
            }
            if ( c === 0x3B /* ; */ ) {
                if ( query.startsWith(';$', i) === false ) { return; }
                steps.push(
                    { mv: this.#QUANTIFIER, min: 1, max: 1e6 },
                    { mv: this.#ROOT }
                );
                i += 2;
                mv = this.#UNDEFINED;
                continue;
            }
            if ( c === 0x7B /* { */ ) {
                const match = this.#reQuantifier.exec(query.slice(i));
                if ( match === null ) { return; }
                const comma = match[1].indexOf(',');
                let min, max;
                if ( comma === -1 ) {
                    min = max = parseInt(match[1]);
                } else {
                    min = parseInt(match[1].slice(0, comma)) || 0;
                    max = parseInt(match[1].slice(comma+1)) || 1e6;
                }
                steps.push(
                    { mv: this.#QUANTIFIER, min, max },
                    { mv: this.#ROOT }
                );
                i += match[0].length;
                mv = this.#UNDEFINED;
                continue;
            }
            if ( c !== 0x5B /* [ */ ) {
                if ( mv === this.#UNDEFINED ) {
                    const step = steps.at(-1);
                    if ( step === undefined ) { return; }
                    const j = this.#compileExpr(query, step, i);
                    if ( j ) { i = j; }
                    break;
                }
                const r = this.#consumeUnquotedIdentifier(query, i);
                if  ( r === undefined ) { return; }
                steps.push({ mv, k: r.s });
                i = r.i;
                mv = this.#UNDEFINED;
                continue;
            }
            // Bracket accessor syntax
            if ( mv === this.#CHILDREN ) { return; }
            if ( query.startsWith('[?', i) ) {
                const not = query.charCodeAt(i+2) === 0x21 /* ! */ ? 1 : 0;
                const j = i + 2 + not;
                const r = this.#compile(query, j);
                if ( r === undefined ) { return; }
                if ( query.startsWith(']', r.i) === false ) { return; }
                if ( not ) { r.steps.at(-1).not = true; }
                steps.push({ mv: mv || this.#CHILDREN, steps: r.steps });
                i = r.i + 1;
                mv = this.#UNDEFINED;
                continue;
            }
            if ( query.startsWith('[*]', i) ) {
                mv ||= this.#CHILDREN;
                steps.push({ mv, k: '*' });
                i += 3;
                mv = this.#UNDEFINED;
                continue;
            }
            const r = this.#consumeIdentifier(query, i+1);
            if ( r === undefined ) { return; }
            mv ||= this.#CHILDREN;
            steps.push({ mv, k: r.s });
            i = r.i + 1;
            mv = this.#UNDEFINED;
        }
        if ( steps.length === 0 ) { return; }
        if ( mv !== this.#UNDEFINED ) { return; }
        return { steps, i };
    }
    #evaluate(steps, pathin) {
        let resultset = [];
        if ( Array.isArray(steps) === false ) { return resultset; }
        for ( const step of steps ) {
            switch ( step.mv ) {
            case this.#ROOT:
                resultset = [ [ '$' ] ];
                break;
            case this.#CURRENT:
                if ( step.op ) {
                    const { obj, key } = this.#resolvePath(pathin);
                    if ( obj === undefined ) { return []; }
                    const outcome = this.#evaluateExpr(step, obj, key);
                    if ( outcome !== true ) { break; }
                }
                resultset = [ pathin ];
                break;
            case this.#CHILDREN:
            case this.#DESCENDANTS: {
                if ( resultset.length === 0 ) { break; }
                resultset = this.#getMatches(resultset, step);
                break;
            }
            case this.#QUANTIFIER: {
                const { length } = resultset;
                if ( length < step.min || length > step.max ) { return []; }
                resultset = [];
                break;
            }
            default:
                break;
            }
        }
        return resultset;
    }
    #getMatches(listin, step) {
        const listout = [];
        for ( const pathin of listin ) {
            const { value: owner } = this.#resolvePath(pathin);
            if ( owner === undefined ) { continue; }
            if ( step.steps ) {
                this.#getMatchesFromExpr(pathin, step, owner, listout);
                continue;
            }
            const iter = this.#expandKey(owner, step.k);
            if ( iter ) {
                for ( const k of iter ) {
                    const outcome = this.#evaluateExpr(step, owner, k);
                    if ( outcome !== true ) { continue; }
                    listout.push([ ...pathin, k ]);
                }
            }
            if ( step.mv !== this.#DESCENDANTS ) { continue; }
            for ( const { obj, key, path } of this.#getDescendants(owner, true) ) {
                const iter = this.#expandKey(obj[key], step.k);
                if ( iter === undefined ) { continue; }
                for ( const k of iter ) {
                    const outcome = this.#evaluateExpr(step, obj[key], k);
                    if ( outcome !== true ) { continue; }
                    listout.push([ ...pathin, ...path, k ]);
                }
            }
        }
        return listout;
    }
    #expandKey(owner, k) {
        if ( typeof owner !== 'object' || owner === null ) { return; }
        if ( Array.isArray(k) ) {
            const out = [];
            for ( const a of k ) {
                const iter = this.#expandKey(owner, a);
                if ( iter === undefined ) { continue; }
                out.push(...iter);
            }
            return out;
        }
        if ( typeof k === 'number' ) {
            if ( Array.isArray(owner) === false ) { return; }
            return [ k >= 0 ? k : owner.length + k ];
        }
        if ( k === '*' ) {
            if ( Array.isArray(owner) ) { return owner.keys(); }
            return JSONPath.keys(owner);
        }
        if ( k instanceof JSONPath.Regex ) {
            const out = [];
            for ( const key of JSONPath.keys(owner) ) {
                if ( k.test(key) === false ) { continue; }
                out.push(key);
            }
            return out;
        }
        return [ k ];
    }
    #getMatchesFromExpr(pathin, step, owner, out) {
        const recursive = step.mv === this.#DESCENDANTS;
        const v2 = this.#compiled.v2 || recursive || Array.isArray(owner);
        for ( const { path } of this.#getDescendants(owner, recursive) ) {
            const q = v2 ? [ ...pathin, ...path ] : pathin;
            const r = this.#evaluate(step.steps, q);
            if ( Boolean(r?.length) === false ) { continue; }
            out.push(q);
            if ( v2 === false ) { break; }
        }
    }
    #getDescendants(v, recursive) {
        const iterator = {
            next() {
                const n = this.stack.length;
                if ( n === 0 ) {
                    this.value = undefined;
                    this.done = true;
                    return this;
                }
                const details = this.stack[n-1];
                const entry = details.keys.next();
                if ( entry.done ) {
                    this.stack.pop();
                    this.path.pop();
                    return this.next();
                }
                this.path[n-1] = entry.value;
                this.value = {
                    obj: details.obj,
                    key: entry.value,
                    path: this.path.slice(),
                };
                const v = this.value.obj[this.value.key];
                if ( recursive ) {
                    if ( Array.isArray(v) ) {
                        this.stack.push({ obj: v, keys: v.keys() });
                    } else if ( typeof v === 'object' && v !== null ) {
                        this.stack.push({ obj: v, keys: JSONPath.keys(v).values() });
                    }
                }
                return this;
            },
            path: [],
            value: undefined,
            done: false,
            stack: [],
            [Symbol.iterator]() { return this; },
        };
        if ( Array.isArray(v) ) {
            iterator.stack.push({ obj: v, keys: v.keys() });
        } else if ( typeof v === 'object' && v !== null ) {
            iterator.stack.push({ obj: v, keys: JSONPath.keys(v).values() });
        }
        return iterator;
    }
    #consumeIdentifier(query, i) {
        const keys = [];
        let needIdentifier = true;
        while ( i < query.length ) {
            const c0 = query.charCodeAt(i);
            if ( c0 === 0x5D /* ] */ ) { break; }
            if ( c0 === 0x20 /* SPACE */ ) {
                i += 1;
                continue;
            }
            if ( c0 === 0x2C /* , */ ) {
                if ( needIdentifier ) { return; }
                i += 1;
                needIdentifier = true;
                continue;
            }
            if ( c0 === 0x22 /* " */ || c0 === 0x27 /* ' */ ) {
                const r = this.#untilChar(query, c0, i+1);
                if ( r === undefined ) { return; }
                keys.push(r.s);
                i = r.i;
                needIdentifier = false;
                continue;
            }
            if ( c0 === 0x2D /* - */ || c0 >= 0x30 && c0 <= 0x39 ) {
                const match = this.#reIndice.exec(query.slice(i));
                if ( match === null ) { return; }
                const indice = parseInt(query.slice(i), 10);
                keys.push(indice);
                i += match[0].length;
                needIdentifier = false;
                continue;
            }
            if ( this.v2 ) { return; }
            const r = this.#consumeUnquotedIdentifier(query, i);
            if ( r === undefined ) { return; }
            keys.push(r.s);
            i = r.i;
        }
        if ( needIdentifier ) { return; }
        return { s: keys.length === 1 ? keys[0] : keys, i };
    }
    #consumeUnquotedIdentifier(query, i) {
        if ( query.charCodeAt(i) === 0x2F /* / */ ) {
            const r = this.#untilChar(query, 0x2F, i+1);
            if ( r === undefined ) { return; }
            let re;
            try { re = new JSONPath.Regex(r.s); } catch { return; }
            return { s: re, i: r.i };
        }
        const match = this.#reUnquotedIdentifier.exec(query.slice(i));
        if ( match === null ) { return; }
        return { s: match[0], i: i + match[0].length };
    }
    #untilChar(query, targetCharCode, i) {
        const len = query.length;
        const parts = [];
        let beg = i, end = i;
        for (;;) {
            if ( end === len ) { return; }
            const c = query.charCodeAt(end);
            if ( c === targetCharCode ) {
                parts.push(query.slice(beg, end));
                end += 1;
                break;
            }
            if ( c === 0x5C /* \ */ && (end+1) < len ) {
                const d = query.charCodeAt(end+1);
                if ( d === targetCharCode ) {
                    parts.push(query.slice(beg, end));
                    end += 1;
                    beg = end;
                }
            }
            end += 1;
        }
        return { s: parts.join(''), i: end };
    }
    #compileExpr(query, step, i) {
        if ( query.startsWith('=/', i) ) {
            const r = this.#untilChar(query, 0x2F /* / */, i+2);
            if ( r === undefined ) { return i; }
            const match = /^[i]/.exec(query.slice(r.i));
            try {
                step.rval = new JSONPath.Regex(r.s, match && match[0] || undefined);
            } catch { return; }
            step.op = 're';
            if ( match ) { r.i += match[0].length; }
            return r.i;
        }
        const match = this.#reExpr.exec(query.slice(i));
        if ( match === null ) { return; }
        const op = match[1], rval = match[2];
        if ( rval.charCodeAt(0) === 0x27 /* ' */ ) {
            const r = this.#untilChar(rval, 0x27, 1);
            if ( r === undefined ) { return; }
            step.rval = r.s;
            step.op = op;
        } else {
            try {
                step.rval = JSON.parse(rval);
                step.op = op;
            } catch { return; }
        }
        return i + match[0].length - 1;
    }
    #resolvePath(path) {
        if ( path.length === 0 ) { return { value: this.#root }; }
        const key = path.at(-1);
        let obj = this.#root
        for ( let i = 0, n = path.length-1; i < n; i++ ) {
            obj = obj[path[i]];
            if ( obj instanceof Object === false ) { return {}; }
        }
        return { obj, key, value: obj[key] };
    }
    #evaluateExpr(step, owner, k) {
        if ( owner === undefined || owner === null ) { return; }
        const hasOwn = owner[k] !== undefined || JSONPath.hasOwn(owner, k);
        if ( step.op !== undefined && hasOwn === false ) { return; }
        const target = step.not !== true;
        const v = owner[k];
        switch ( step.op ) {
        case '==': return (v === step.rval) === target;
        case '!=': return (v !== step.rval) === target;
        case  '<': return (v < step.rval) === target;
        case '<=': return (v <= step.rval) === target;
        case  '>': return (v > step.rval) === target;
        case '>=': return (v >= step.rval) === target;
        case '^=': return `${v}`.startsWith(step.rval) === target;
        case '$=': return `${v}`.endsWith(step.rval) === target;
        case '*=': return `${v}`.includes(step.rval) === target;
        case 're': return step.rval.test(`${v}`);
        default: break;
        }
        return hasOwn === target;
    }
    #modifyVal(obj, key) {
        let { modify, rval } = this.#compiled;
        if ( typeof rval === 'string' ) {
            rval = rval.replace('${now}', `${Date.now()}`);
        }
        switch ( modify ) {
        case undefined:
            obj[key] = rval;
            break;
        case '+': {
            if ( rval instanceof Object === false ) { return; }
            const lval = obj[key];
            if ( lval instanceof Object === false ) { return; }
            if ( Array.isArray(lval) ) { return; }
            for ( const [ k, v ] of JSONPath.entries(rval) ) {
                lval[k] = v;
            }
            break;
        }
        case 'call': {
            const entries = rval.slice();
            if ( entries.length < 2 ) { break; }
            entries.forEach((a, i, aa) => {
                if ( a === '${obj}' ) { aa[i] = obj; }
                else if ( a === '${key}' ) { aa[i] = key; }
                else if ( a === '${val}' ) { aa[i] = obj[key]; }
            });
            const instance = entries[0] ?? self;
            instance[entries[1]](...entries.slice(2));
            break;
        }
        case 'repl': {
            const lval = obj[key];
            if ( typeof lval !== 'string' ) { return; }
            if ( this.#compiled.re === undefined ) {
                this.#compiled.re = null;
                try {
                    this.#compiled.re = rval.regex !== undefined
                        ? new JSONPath.Regex(rval.regex, rval.flags)
                        : new JSONPath.Regex(rval.pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
                } catch { }
            }
            if ( this.#compiled.re === null ) { return; }
            obj[key] = lval.replace(this.#compiled.re, rval.replacement);
            break;
        }
        default:
            break;
        }
    }
}

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

function adjustSetInterval(
    needleArg = '',
    delayArg = '',
    boostArg = ''
) {
    if ( typeof needleArg !== 'string' ) { return; }
    const safe = safeSelf();
    const reNeedle = safe.patternToRegex(needleArg);
    let delay = delayArg !== '*' ? parseInt(delayArg, 10) : -1;
    if ( isNaN(delay) || isFinite(delay) === false ) { delay = 1000; }
    let boost = parseFloat(boostArg);
    boost = isNaN(boost) === false && isFinite(boost)
        ? Math.min(Math.max(boost, 0.001), 50)
        : 0.05;
    self.setInterval = new Proxy(self.setInterval, {
        apply: function(target, thisArg, args) {
            const [ a, b ] = args;
            if (
                (delay === -1 || b === delay) &&
                reNeedle.test(a.toString())
            ) {
                args[1] = b * boost;
            }
            return target.apply(thisArg, args);
        }
    });
}

function adjustSetTimeout(
    needleArg = '',
    delayArg = '',
    boostArg = ''
) {
    if ( typeof needleArg !== 'string' ) { return; }
    const safe = safeSelf();
    const reNeedle = safe.patternToRegex(needleArg);
    let delay = delayArg !== '*' ? parseInt(delayArg, 10) : -1;
    if ( isNaN(delay) || isFinite(delay) === false ) { delay = 1000; }
    let boost = parseFloat(boostArg);
    boost = isNaN(boost) === false && isFinite(boost)
        ? Math.min(Math.max(boost, 0.001), 50)
        : 0.05;
    self.setTimeout = new Proxy(self.setTimeout, {
        apply: function(target, thisArg, args) {
            const [ a, b ] = args;
            if (
                (delay === -1 || b === delay) &&
                reNeedle.test(a.toString())
            ) {
                args[1] = b * boost;
            }
            return target.apply(thisArg, args);
        }
    });
}

function alertBuster() {
    window.alert = new Proxy(window.alert, {
        apply: function(a) {
            console.info(a);
        },
        get(target, prop) {
            if ( prop === 'toString' ) {
                return target.toString.bind(target);
            }
            return Reflect.get(target, prop);
        },
    });
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

function disableNewtabLinks() {
    document.addEventListener('click', ev => {
        let target = ev.target;
        while ( target !== null ) {
            if ( target.localName === 'a' && target.hasAttribute('target') ) {
                ev.stopPropagation();
                ev.preventDefault();
                break;
            }
            target = target.parentNode;
        }
    }, { capture: true });
}

function editInboundObjectFn(
    trusted = false,
    propChain = '',
    argPosRaw = '',
    jsonq = '',
) {
    if ( propChain === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix(
        `${trusted ? 'trusted-' : ''}edit-inbound-object`,
        propChain,
        jsonq
    );
    const jsonp = JSONPath.create(jsonq);
    if ( jsonp.valid === false || jsonp.value !== undefined && trusted !== true ) {
        return safe.uboLog(logPrefix, 'Bad JSONPath query');
    }
    const argPos = parseInt(argPosRaw, 10);
    if ( isNaN(argPos) ) { return; }
    const getArgPos = args => {
        if ( Array.isArray(args) === false ) { return; }
        if ( argPos >= 0 ) {
            if ( args.length <= argPos ) { return; }
            return argPos;
        }
        if ( args.length < -argPos ) { return; }
        return args.length + argPos;
    };
    const editObj = obj => {
        let clone;
        try {
            clone = safe.JSON_parse(safe.JSON_stringify(obj));
        } catch {
        }
        if ( typeof clone !== 'object' || clone === null ) { return; }
        const objAfter = jsonp.apply(clone);
        if ( objAfter === undefined ) { return; }
        safe.uboLog(logPrefix, 'Edited');
        if ( safe.logLevel > 1 ) {
            safe.uboLog(logPrefix, `After edit:\n${safe.JSON_stringify(objAfter, null, 2)}`);
        }
        return objAfter;
    };
    proxyApplyFn(propChain, function(context) {
        const i = getArgPos(context.callArgs);
        if ( i !== undefined ) {
            const obj = editObj(context.callArgs[i]);
            if ( obj ) {
                context.callArgs[i] = obj;
            }
        }
        return context.reflect();
    });
}

function editObjectOnSetter(...args) {
    editObjectOnSetterFn(false, ...args);
}

function editObjectOnSetterFn(
    trusted = false,
    propChain = '',
    jsonq = '',
) {
    if ( propChain === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix(
        `${trusted ? 'trusted-' : ''}edit-object-on-setter`,
        propChain,
        jsonq
    );
    const jsonp = JSONPath.create(jsonq);
    if ( jsonp.valid === false || jsonp.value !== undefined && trusted !== true ) {
        return safe.uboLog(logPrefix, 'Bad JSONPath query');
    }
    const editObj = objBefore => {
        const objAfter = jsonp.apply(objBefore);
        if ( objAfter === undefined ) { return; }
        safe.uboLog(logPrefix, 'Edited');
        if ( safe.logLevel <= 1 ) { return; }
        safe.uboLog(logPrefix, `After edit:\n${safe.JSON_stringify(objAfter, null, 2)}`);
    };
    let currentValue = trapPropertyFn(propChain, {
        get: function() {
            return currentValue;
        },
        set: function(a) {
            currentValue = a;
            if ( currentValue instanceof Object ) {
                editObj(currentValue);
            }
        }
    });
    if ( currentValue instanceof Object ) {
        editObj(currentValue);
    }
}

function freezeElementProperty(
    property = '',
    selector = '',
    pattern = ''
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('freeze-element-property', property, selector, pattern);
    const matcher = safe.initPattern(pattern, { canNegate: true });
    const owner = (( ) => {
        if ( Object.hasOwn(HTMLScriptElement.prototype, property) ) {
            return HTMLScriptElement.prototype;
        }
        if ( Object.hasOwn(HTMLElement.prototype, property) ) {
            return HTMLElement.prototype;
        }
        if ( Object.hasOwn(Element.prototype, property) ) {
            return Element.prototype;
        }
        if ( Object.hasOwn(Node.prototype, property) ) {
            return Node.prototype;
        }
        return null;
    })();
    if ( owner === null ) { return; }
    const current = safe.Object_getOwnPropertyDescriptor(owner, property);
    if ( current === undefined ) { return; }
    const shouldPreventSet = (elem, a) => {
        if ( selector !== '' ) {
            if ( typeof elem.matches !== 'function' ) { return false; }
            if ( elem.matches(selector) === false ) { return false; }
        }
        return safe.testPattern(matcher, `${a}`);
    };
    Object.defineProperty(owner, property, {
        get: function() {
            return current.get
                ? current.get.call(this)
                : current.value;
        },
        set: function(a) {
            if ( shouldPreventSet(this, a) ) {
                safe.uboLog(logPrefix, 'Assignment prevented');
            } else if ( current.set ) {
                current.set.call(this, a);
            }
            if ( safe.logLevel > 1 ) {
                safe.uboLog(logPrefix, `Assigned:\n${a}`);
            }
            current.value = a;
        },
    });
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

function jsonEdit(jsonq = '', ...varargs) {
    jsonEditFn(false, jsonq, ...varargs);
}

function jsonEditFetchRequest(jsonq = '', ...args) {
    jsonEditFetchRequestFn(false, jsonq, ...args);
}

function jsonEditFetchRequestFn(trusted, jsonq = '', ...varargs) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix(
        `${trusted ? 'trusted-' : ''}json-edit-fetch-request`,
        jsonq
    );
    const jsonp = JSONPath.create(jsonq);
    if ( jsonp.valid === false || jsonp.value !== undefined && trusted !== true ) {
        return safe.uboLog(logPrefix, 'Bad JSONPath query');
    }
    const extraArgs = safe.parseVarargs(varargs);
    const propNeedles = parsePropertiesToMatchFn(extraArgs.propsToMatch, 'url');
    const filterBody = body => {
        if ( typeof body !== 'string' ) { return; }
        let data;
        try { data = safe.JSON_parse(body); }
        catch { }
        if ( data instanceof Object === false ) { return; }
        const objAfter = jsonp.apply(data);
        if ( objAfter === undefined ) { return; }
        return safe.JSON_stringify(objAfter);
    }
    const proxyHandler = context => {
        const args = context.callArgs;
        const [ resource, options ] = args;
        const bodyBefore = options?.body;
        if ( Boolean(bodyBefore) === false ) { return context.reflect(); }
        const bodyAfter = filterBody(bodyBefore);
        if ( bodyAfter === undefined || bodyAfter === bodyBefore ) {
            return context.reflect();
        }
        if ( propNeedles.size !== 0 ) {
            const props = collateFetchArgumentsFn(resource, options);
            const matched = matchObjectPropertiesFn(propNeedles, props);
            if ( matched === undefined ) { return context.reflect(); }
            if ( safe.logLevel > 1 ) {
                safe.uboLog(logPrefix, `Matched "propsToMatch":\n\t${matched.join('\n\t')}`);
            }
        }
        safe.uboLog(logPrefix, 'Edited');
        if ( safe.logLevel > 1 ) {
            safe.uboLog(logPrefix, `After edit:\n${bodyAfter}`);
        }
        options.body = bodyAfter;
        return context.reflect();
    };
    proxyApplyFn('fetch', proxyHandler);
    proxyApplyFn('Request', proxyHandler);
}

function jsonEditFetchResponse(jsonq = '', ...args) {
    jsonEditFetchResponseFn(false, jsonq, ...args);
}

function jsonEditFetchResponseFn(trusted, jsonq = '', ...varargs) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix(
        `${trusted ? 'trusted-' : ''}json-edit-fetch-response`,
        jsonq
    );
    const jsonp = JSONPath.create(jsonq);
    if ( jsonp.valid === false || jsonp.value !== undefined && trusted !== true ) {
        return safe.uboLog(logPrefix, 'Bad JSONPath query');
    }
    const extraArgs = safe.parseVarargs(varargs);
    const propNeedles = parsePropertiesToMatchFn(extraArgs.propsToMatch, 'url');
    proxyApplyFn('fetch', function(context) {
        const args = context.callArgs;
        const fetchPromise = context.reflect();
        if ( propNeedles.size !== 0 ) {
            const props = collateFetchArgumentsFn(...args);
            const matched = matchObjectPropertiesFn(propNeedles, props);
            if ( matched === undefined ) { return fetchPromise; }
            if ( safe.logLevel > 1 ) {
                safe.uboLog(logPrefix, `Matched "propsToMatch":\n\t${matched.join('\n\t')}`);
            }
        }
        return fetchPromise.then(responseBefore => {
            const response = responseBefore.clone();
            return response.json().then(obj => {
                if ( typeof obj !== 'object' ) { return responseBefore; }
                const objAfter = jsonp.apply(obj);
                if ( objAfter === undefined ) { return responseBefore; }
                safe.uboLog(logPrefix, 'Edited');
                const responseAfter = Response.json(objAfter, {
                    status: responseBefore.status,
                    statusText: responseBefore.statusText,
                    headers: responseBefore.headers,
                });
                Object.defineProperties(responseAfter, {
                    ok: { value: responseBefore.ok },
                    redirected: { value: responseBefore.redirected },
                    type: { value: responseBefore.type },
                    url: { value: responseBefore.url },
                });
                return responseAfter;
            }).catch(reason => {
                safe.uboErr(logPrefix, 'Error:', reason);
                return responseBefore;
            });
        }).catch(reason => {
            safe.uboErr(logPrefix, 'Error:', reason);
            return fetchPromise;
        });
    });
}

function jsonEditFn(trusted = false, jsonq = '', ...varargs) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix(
        `${trusted ? 'trusted-' : ''}json-edit`,
        jsonq,
        ...varargs
    );
    const jsonp = JSONPath.create(jsonq);
    if ( jsonp.valid === false || jsonp.value !== undefined && trusted !== true ) {
        return safe.uboLog(logPrefix, 'Bad JSONPath query');
    }
    const extraArgs = safe.parseVarargs(varargs);
    const pattern = extraArgs.matches && safe.initPattern(extraArgs.matches);
    proxyApplyFn('JSON.parse', function(context) {
        const json = context.callArgs[0];
        const obj = context.reflect();
        if ( pattern && safe.testPattern(pattern, json) === false ) { return obj; }
        const objAfter = jsonp.apply(obj);
        if ( objAfter === undefined ) { return obj; }
        safe.uboLog(logPrefix, 'Edited');
        if ( safe.logLevel > 1 ) {
            safe.uboLog(logPrefix, `After edit:\n${safe.JSON_stringify(objAfter, null, 2)}`);
        }
        return objAfter;
    });
}

function jsonEditXhrResponse(jsonq = '', ...args) {
    jsonEditXhrResponseFn(false, jsonq, ...args);
}

function jsonEditXhrResponseFn(trusted, jsonq = '', ...varargs) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix(
        `${trusted ? 'trusted-' : ''}json-edit-xhr-response`,
        jsonq
    );
    const xhrInstances = new WeakMap();
    const jsonp = JSONPath.create(jsonq);
    if ( jsonp.valid === false || jsonp.value !== undefined && trusted !== true ) {
        return safe.uboLog(logPrefix, 'Bad JSONPath query');
    }
    const extraArgs = safe.parseVarargs(varargs);
    const propNeedles = parsePropertiesToMatchFn(extraArgs.propsToMatch, 'url');
    self.XMLHttpRequest = class extends self.XMLHttpRequest {
        open(method, url, ...args) {
            const xhrDetails = { method, url };
            const matched = propNeedles.size === 0 ||
                matchObjectPropertiesFn(propNeedles, xhrDetails);
            if ( matched ) {
                if ( safe.logLevel > 1 && Array.isArray(matched) ) {
                    safe.uboLog(logPrefix, `Matched "propsToMatch":\n\t${matched.join('\n\t')}`);
                }
                xhrInstances.set(this, xhrDetails);
            }
            return super.open(method, url, ...args);
        }
        get response() {
            const innerResponse = super.response;
            const xhrDetails = xhrInstances.get(this);
            if ( xhrDetails === undefined ) { return innerResponse; }
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
            let obj;
            if ( typeof innerResponse === 'object' ) {
                obj = innerResponse;
            } else if ( typeof innerResponse === 'string' ) {
                try { obj = safe.JSON_parse(innerResponse); } catch { }
            }
            if ( typeof obj !== 'object' || obj === null ) {
                return (xhrDetails.response = innerResponse);
            }
            const objAfter = jsonp.apply(obj);
            if ( objAfter === undefined ) {
                return (xhrDetails.response = innerResponse);
            }
            safe.uboLog(logPrefix, 'Edited');
            const outerResponse = typeof innerResponse === 'string'
                ? JSONPath.toJSON(objAfter, safe.JSON_stringify)
                : objAfter;
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

function jsonPruneFetchResponse(
    rawPrunePaths = '',
    rawNeedlePaths = '',
    ...varargs
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('json-prune-fetch-response', rawPrunePaths, rawNeedlePaths);
    const extraArgs = safe.parseVarargs(varargs);
    const propNeedles = parsePropertiesToMatchFn(extraArgs.propsToMatch, 'url');
    const stackNeedle = safe.initPattern(extraArgs.stackToMatch || '', { canNegate: true });
    const logall = rawPrunePaths === '';
    const applyHandler = function(target, thisArg, args) {
        const fetchPromise = Reflect.apply(target, thisArg, args);
        if ( propNeedles.size !== 0 ) {
            const props = collateFetchArgumentsFn(...args);
            const matched = matchObjectPropertiesFn(propNeedles, props);
            if ( matched === undefined ) { return fetchPromise; }
            if ( safe.logLevel > 1 ) {
                safe.uboLog(logPrefix, `Matched "propsToMatch":\n\t${matched.join('\n\t')}`);
            }
        }
        return fetchPromise.then(responseBefore => {
            const response = responseBefore.clone();
            return response.json().then(objBefore => {
                if ( typeof objBefore !== 'object' ) { return responseBefore; }
                if ( logall ) {
                    safe.uboLog(logPrefix, safe.JSON_stringify(objBefore, null, 2));
                    return responseBefore;
                }
                const objAfter = objectPruneFn(
                    objBefore,
                    rawPrunePaths,
                    rawNeedlePaths,
                    stackNeedle,
                    extraArgs
                );
                if ( typeof objAfter !== 'object' ) { return responseBefore; }
                safe.uboLog(logPrefix, 'Pruned');
                const responseAfter = Response.json(objAfter, {
                    status: responseBefore.status,
                    statusText: responseBefore.statusText,
                    headers: responseBefore.headers,
                });
                Object.defineProperties(responseAfter, {
                    ok: { value: responseBefore.ok },
                    redirected: { value: responseBefore.redirected },
                    type: { value: responseBefore.type },
                    url: { value: responseBefore.url },
                });
                return responseAfter;
            }).catch(reason => {
                safe.uboErr(logPrefix, 'Error:', reason);
                return responseBefore;
            });
        }).catch(reason => {
            safe.uboErr(logPrefix, 'Error:', reason);
            return fetchPromise;
        });
    };
    self.fetch = new Proxy(self.fetch, {
        apply: applyHandler
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

function jsonlEditFn(jsonp, text = '') {
    const safe = safeSelf();
    const lineSeparator = /\r?\n/.exec(text)?.[0] || '\n';
    const linesBefore = text.split('\n');
    const linesAfter = [];
    for ( const lineBefore of linesBefore ) {
        let obj;
        try { obj = safe.JSON_parse(lineBefore); } catch { }
        if ( typeof obj !== 'object' || obj === null ) {
            linesAfter.push(lineBefore);
            continue;
        }
        const objAfter = jsonp.apply(obj);
        if ( objAfter === undefined ) {
            linesAfter.push(lineBefore);
            continue;
        }
        const lineAfter = safe.JSON_stringify(objAfter);
        linesAfter.push(lineAfter);
    }
    return linesAfter.join(lineSeparator);
}

function jsonlEditXhrResponse(jsonq = '', ...args) {
    jsonlEditXhrResponseFn(false, jsonq, ...args);
}

function jsonlEditXhrResponseFn(trusted, jsonq = '', ...varargs) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix(
        `${trusted ? 'trusted-' : ''}jsonl-edit-xhr-response`,
        jsonq
    );
    const xhrInstances = new WeakMap();
    const jsonp = JSONPath.create(jsonq);
    if ( jsonp.valid === false || jsonp.value !== undefined && trusted !== true ) {
        return safe.uboLog(logPrefix, 'Bad JSONPath query');
    }
    const extraArgs = safe.parseVarargs(varargs);
    const propNeedles = parsePropertiesToMatchFn(extraArgs.propsToMatch, 'url');
    self.XMLHttpRequest = class extends self.XMLHttpRequest {
        open(method, url, ...args) {
            const xhrDetails = { method, url };
            const matched = propNeedles.size === 0 ||
                matchObjectPropertiesFn(propNeedles, xhrDetails);
            if ( matched ) {
                if ( safe.logLevel > 1 && Array.isArray(matched) ) {
                    safe.uboLog(logPrefix, `Matched "propsToMatch":\n\t${matched.join('\n\t')}`);
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
            if ( typeof innerResponse !== 'string' ) {
                return (xhrDetails.response = innerResponse);
            }
            const outerResponse = jsonlEditFn(jsonp, innerResponse);
            if ( outerResponse !== innerResponse ) {
                safe.uboLog(logPrefix, 'Pruned');
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

function m3uPrune(
    m3uPattern = '',
    urlPattern = ''
) {
    if ( typeof m3uPattern !== 'string' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('m3u-prune', m3uPattern, urlPattern);
    const toLog = [];
    const regexFromArg = arg => {
        if ( arg === '' ) { return /^/; }
        const match = /^\/(.+)\/([gms]*)$/.exec(arg);
        if ( match !== null ) {
            let flags = match[2] || '';
            if ( flags.includes('m') ) { flags += 's'; }
            return new RegExp(match[1], flags);
        }
        return new RegExp(
            arg.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*+/g, '.*?')
        );
    };
    const reM3u = regexFromArg(m3uPattern);
    const reUrl = regexFromArg(urlPattern);
    const pruneSpliceoutBlock = (lines, i) => {
        if ( lines[i].startsWith('#EXT-X-CUE:TYPE="SpliceOut"') === false ) {
            return false;
        }
        toLog.push(`\t${lines[i]}`);
        lines[i] = undefined; i += 1;
        if ( lines[i].startsWith('#EXT-X-ASSET:CAID') ) {
            toLog.push(`\t${lines[i]}`);
            lines[i] = undefined; i += 1;
        }
        if ( lines[i].startsWith('#EXT-X-SCTE35:') ) {
            toLog.push(`\t${lines[i]}`);
            lines[i] = undefined; i += 1;
        }
        if ( lines[i].startsWith('#EXT-X-CUE-IN') ) {
            toLog.push(`\t${lines[i]}`);
            lines[i] = undefined; i += 1;
        }
        if ( lines[i].startsWith('#EXT-X-SCTE35:') ) {
            toLog.push(`\t${lines[i]}`);
            lines[i] = undefined; i += 1;
        }
        return true;
    };
    const pruneInfBlock = (lines, i) => {
        if ( lines[i].startsWith('#EXTINF') === false ) { return false; }
        if ( reM3u.test(lines[i+1]) === false ) { return false; }
        toLog.push('Discarding', `\t${lines[i]}, \t${lines[i+1]}`);
        lines[i] = lines[i+1] = undefined; i += 2;
        if ( lines[i].startsWith('#EXT-X-DISCONTINUITY') ) {
            toLog.push(`\t${lines[i]}`);
            lines[i] = undefined; i += 1;
        }
        return true;
    };
    const pruner = text => {
        if ( (/^\s*#EXTM3U/.test(text)) === false ) { return text; }
        if ( m3uPattern === '' ) {
            safe.uboLog(` Content:\n${text}`);
            return text;
        }
        if ( reM3u.multiline ) {
            reM3u.lastIndex = 0;
            for (;;) {
                const match = reM3u.exec(text);
                if ( match === null ) { break; }
                let discard = match[0];
                let before = text.slice(0, match.index);
                if (
                    /^[\n\r]+/.test(discard) === false &&
                    /[\n\r]+$/.test(before) === false
                ) {
                    const startOfLine = /[^\n\r]+$/.exec(before);
                    if ( startOfLine !== null ) {
                        before = before.slice(0, startOfLine.index);
                        discard = startOfLine[0] + discard;
                    }
                }
                let after = text.slice(match.index + match[0].length);
                if (
                    /[\n\r]+$/.test(discard) === false &&
                    /^[\n\r]+/.test(after) === false
                ) {
                    const endOfLine = /^[^\n\r]+/.exec(after);
                    if ( endOfLine !== null ) {
                        after = after.slice(endOfLine.index);
                        discard += discard + endOfLine[0];
                    }
                }
                text = before.trim() + '\n' + after.trim();
                reM3u.lastIndex = before.length + 1;
                toLog.push('Discarding', ...safe.String_split.call(discard, /\n+/).map(s => `\t${s}`));
                if ( reM3u.global === false ) { break; }
            }
            return text;
        }
        const lines = safe.String_split.call(text, /\n\r|\n|\r/);
        for ( let i = 0; i < lines.length; i++ ) {
            if ( lines[i] === undefined ) { continue; }
            if ( pruneSpliceoutBlock(lines, i) ) { continue; }
            if ( pruneInfBlock(lines, i) ) { continue; }
        }
        return lines.filter(l => l !== undefined).join('\n');
    };
    const urlFromArg = arg => {
        if ( typeof arg === 'string' ) { return arg; }
        if ( arg instanceof Request ) { return arg.url; }
        return String(arg);
    };
    proxyApplyFn('fetch', async function fetch(context) {
        const args = context.callArgs;
        const fetchPromise = context.reflect();
        if ( reUrl.test(urlFromArg(args[0])) === false ) { return fetchPromise; }
        const responseBefore = await fetchPromise;
        const responseClone = responseBefore.clone();
        const textBefore = await responseClone.text();
        const textAfter = pruner(textBefore);
        if ( textAfter === textBefore ) { return responseBefore; }
        const responseAfter = new Response(textAfter, {
            status: responseBefore.status,
            statusText: responseBefore.statusText,
            headers: responseBefore.headers,
        });
        Object.defineProperties(responseAfter, {
            url: { value: responseBefore.url },
            type: { value: responseBefore.type },
        });
        if ( toLog.length !== 0 ) {
            toLog.unshift(logPrefix);
            safe.uboLog(toLog.join('\n'));
        }
        return responseAfter;
    })
    self.XMLHttpRequest.prototype.open = new Proxy(self.XMLHttpRequest.prototype.open, {
        apply: async (target, thisArg, args) => {
            if ( reUrl.test(urlFromArg(args[1])) === false ) {
                return Reflect.apply(target, thisArg, args);
            }
            thisArg.addEventListener('readystatechange', function() {
                if ( thisArg.readyState !== 4 ) { return; }
                const type = thisArg.responseType;
                if ( type !== '' && type !== 'text' ) { return; }
                const textin = thisArg.responseText;
                const textout = pruner(textin);
                if ( textout === textin ) { return; }
                Object.defineProperty(thisArg, 'response', { value: textout });
                Object.defineProperty(thisArg, 'responseText', { value: textout });
                if ( toLog.length !== 0 ) {
                    toLog.unshift(logPrefix);
                    safe.uboLog(toLog.join('\n'));
                }
            });
            return Reflect.apply(target, thisArg, args);
        }
    });
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

function modifyXhrResponseFn(
    propsToMatch = '',
    modifierFn = ''
) {
    if ( typeof propsToMatch !== 'string' ) { return; }
    const safe = safeSelf();
    if ( modifyXhrResponseFn.xhrInstances === undefined ) {
        modifyXhrResponseFn.xhrInstances = new WeakMap();
    }
    const propNeedles = parsePropertiesToMatchFn(propsToMatch, 'url');
    const NativeXMLHttpRequest = self.XMLHttpRequest;
    const TrappedXMLHttpRequest = class XMLHttpRequest extends NativeXMLHttpRequest {
        open(method, url, ...args) {
            const haystack = { method, url };
            if ( propsToMatch === '' ) {
                safe.uboLog(`modifyXhrResponseFn() / Called: ${safe.JSON_stringify(haystack, null, 2)}`);
            } else if ( matchObjectPropertiesFn(propNeedles, haystack) ) {
                modifyXhrResponseFn.xhrInstances.set(this, modifierFn);
            }
            return super.open(method, url, ...args);
        }
        get response() {
            const modifierFn = modifyXhrResponseFn.xhrInstances.get(this);
            return modifierFn
                ? modifierFn(this, super.response)
                : super.response;
        }
        get responseText() {
            const modifierFn = modifyXhrResponseFn.xhrInstances.get(this);
            return modifierFn
                ? modifierFn(this, super.responseText)
                : super.responseText;
        }
        get responseXML() {
            const modifierFn = modifyXhrResponseFn.xhrInstances.get(this);
            return modifierFn
                ? modifierFn(this, super.responseXML)
                : super.responseXML;
        }
    };
    proxyToStringFn(TrappedXMLHttpRequest.prototype.open, NativeXMLHttpRequest.prototype.open);
    proxyToStringFn(TrappedXMLHttpRequest, NativeXMLHttpRequest);
    self.XMLHttpRequest = TrappedXMLHttpRequest;
}

function mpegdashPrune(
    selector = '',
    propsToMatch = ''
) {
    if ( typeof selector !== 'string' ) { return; }
    if ( selector === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('mpegdash-prune', selector, propsToMatch);
    const queryAll = (xmlDoc, selector) => {
        if ( selector.startsWith('xpath:') === false ) {
            return Array.from(xmlDoc.querySelectorAll(selector));
        }
        const xpr = xmlDoc.evaluate(
            selector.slice(6),
            xmlDoc,
            null,
            XPathResult.UNORDERED_NODE_SNAPSHOT_TYPE,
            null
        );
        const out = [];
        for ( let i = 0; i < xpr.snapshotLength; i++ ) {
            const node = xpr.snapshotItem(i);
            out.push(node);
        }
        return out;
    };
    const rePTparse = /^PT(\d+D)?(\d+H)?(\d+M)?([\d.]+S)?$/;
    const secondsPerDay = 24 * 60 * 60;
    const secondsPerHour = 60 * 60;
    const secondsPerMinute = 60;
    const secondsFromPT = pt => {
        const match = rePTparse.exec(pt);
        if ( match === null ) { return; }
        let seconds = 0;
        if ( match[1] ) {
            const d = parseFloat(match[1].slice(0, -1));
            if ( isNaN(d) ) { return; }
            seconds += d * secondsPerDay;
        }
        if ( match[2] ) {
            const h = parseFloat(match[2].slice(0, -1));
            if ( isNaN(h) ) { return; }
            seconds += h * secondsPerHour;
        }
        if ( match[3] ) {
            const m = parseFloat(match[3].slice(0, -1));
            if ( isNaN(m) ) { return; }
            seconds += m * secondsPerMinute;
        }
        if ( match[4] ) {
            const s = parseFloat(match[4].slice(0, -1));
            if ( isNaN(s) ) { return; }
            seconds += s;
        }
        return seconds;
    };
    const ptFromSeconds = seconds => {
        const parts = [ 'PT' ];
        const d = Math.floor(seconds / secondsPerDay);
        if ( d ) {
            parts.push(`${d}D`);
            seconds -= d * secondsPerDay;
        }
        const h = Math.floor(seconds / secondsPerHour);
        if ( h ) {
            parts.push(`${h}H`);
            seconds -= h * secondsPerHour;
        }
        const m = Math.floor(seconds / secondsPerMinute);
        if ( m ) {
            parts.push(`${m}M`);
            seconds -= m * secondsPerMinute;
        }
        parts.push(`${seconds}S`);
        return parts.join('');
    };
    const fixTimeAttributes = xmlDoc => {
        try {
            const periods = queryAll(xmlDoc, 'MPD > Period');
            if ( periods.length === 0 ) { return; }
            let seconds = 0;
            for ( const period of periods ) {
                const startAttrBefore = period.getAttribute('start');
                const durAttr = period.getAttribute('duration');
                if ( startAttrBefore === null || durAttr === null ) { continue; }
                const startAttrAfter = ptFromSeconds(seconds);
                period.setAttribute('start', startAttrAfter);
                if ( period.hasAttribute('id') ) {
                    const idAttr = period.getAttribute('id');
                    period.setAttribute('id', idAttr.replace(startAttrBefore, startAttrAfter));
                }
                seconds += secondsFromPT(durAttr);
            }
            const mpds = queryAll(xmlDoc, 'MPD[mediaPresentationDuration]');
            if ( mpds.length !== 1 ) { return; }
            mpds[0].setAttribute('mediaPresentationDuration', ptFromSeconds(seconds));
        } catch {
        }
    };
    const pruneFromDoc = xmlDoc => {
        try {
            if ( selector === '' ) {
                const serializer = new XMLSerializer();
                safe.uboLog(logPrefix, `Document is\n\t${serializer.serializeToString(xmlDoc)}`);
            }
            const items = queryAll(xmlDoc, selector);
            if ( items.length === 0 ) { return xmlDoc; }
            safe.uboLog(logPrefix, `Patching ${items.length} items`);
            for ( const item of items ) {
                if ( item.nodeType !== 1 ) { continue; }
                item.setAttribute('duration', 'PT0S');
            }
            fixTimeAttributes(xmlDoc);
        } catch(ex) {
            safe.uboErr(logPrefix, `Error: ${ex}`);
        }
        return xmlDoc;
    };
    const pruneFromText = text => {
        if ( (/^\s*</.test(text) && />\s*$/.test(text)) === false ) {
            return text;
        }
        try {
            const xmlParser = new DOMParser();
            const xmlDoc = xmlParser.parseFromString(text, 'text/xml');
            pruneFromDoc(xmlDoc);
            const serializer = new XMLSerializer();
            text = serializer.serializeToString(xmlDoc);
        } catch {
        }
        return text;
    };
    modifyXhrResponseFn(propsToMatch, (xhr, before) => {
        if ( before instanceof XMLDocument ) {
            return pruneFromDoc(before);
        }
        if ( typeof before === 'string' ) {
            return pruneFromText(before);
        }
        return before;
    });
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

function parseReplaceFn(s) {
    if ( s.charCodeAt(0) !== 0x2F /* / */ ) { return; }
    const parser = new ArglistParser('/');
    parser.nextArg(s, 1);
    let pattern = s.slice(parser.argBeg, parser.argEnd);
    if ( parser.transform ) {
        pattern = parser.normalizeArg(pattern);
    }
    if ( pattern === '' ) { return; }
    parser.nextArg(s, parser.separatorEnd);
    let replacement = s.slice(parser.argBeg, parser.argEnd);
    if ( parser.separatorEnd === parser.separatorBeg ) { return; }
    if ( parser.transform ) {
        replacement = parser.normalizeArg(replacement);
    }
    const flags = s.slice(parser.separatorEnd);
    try {
        return { re: new RegExp(pattern, flags), replacement };
    } catch {
    }
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

function preventCanvas(
    contextType = ''
) {
    const safe = safeSelf();
    const pattern = safe.initPattern(contextType, { canNegate: true });
    const proto = globalThis.HTMLCanvasElement.prototype;
    proto.getContext = new Proxy(proto.getContext, {
        apply(target, thisArg, args) {
            if ( safe.testPattern(pattern, args[0]) ) { return null; }
            return Reflect.apply(target, thisArg, args);
        }
    });
}

function preventClipboardWrite(matches = '', ...varargs) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('prevent-clipboard-write');
    const pattern = safe.initPattern(matches);
    const extraArgs = safe.parseVarargs(varargs);
    const excludePattern = extraArgs.excludeMatches &&
        safe.initPattern(extraArgs.excludeMatches);
    const htmlTemplate = [
        '<div style="background-color:beige;color:black;border:1px solid black;display:flex;font-family:sans-serif;font-size:medium;margin:0;position:fixed;top:0;white-space:pre-wrap;width:100%;z-index:2147483647">',
            '<span style="flex-grow:1;padding:0.5em 0 0.5em 0.5em;">${warning}</span>\n',
            '<button style="background-color:#8880;border:0;font-size:24px;padding:0.5em;">×</button>',
        '</div>',
    ].join('');
    const domAlert = clipboardText => {
        const doc = document;
        const domAlert = extraArgs.domAlert.replace(/\\n/g, '\n');
        let html;
        if ( domAlert.includes('${text}') ) {
            const code = doc.createElement('code');
            const styles = [
                'background-color: #ddc',
                'display: inline-block',
                'font-family: monospace',
                'font-size: 100%',
                'max-height: 8em',
                'overflow: auto',
                'padding: 0.25em',
                'user-select: all',
                'width: 100%;',
                'word-break: break-all'
            ];
            if ( Boolean(extraArgs.selectable ?? true) === false ) {
                styles.push('user-select: none');
            }
            code.style = styles.join(';');
            code.textContent = clipboardText;
            html = htmlTemplate.replace('${warning}',
                domAlert.replace('${text}', code.outerHTML)
            );
        } else {
            html = htmlTemplate.replace('${warning}', domAlert);
        }
        if ( currentAlert ) { currentAlert.remove(); }
        const domParser = new DOMParser();
        const fragment = domParser.parseFromString(html, 'text/html');
        currentAlert = fragment.querySelector('div');
        const button = currentAlert.querySelector('button');
        button.addEventListener('click', ( ) => {
            if ( currentAlert === null ) { return; }
            currentAlert.remove();
            currentAlert = null;
        });
        currentAlert.setAttribute('popover', 'manual');
        doc.documentElement.append(currentAlert);
        if ( typeof currentAlert.showPopover === 'function' ) {
            currentAlert.showPopover();
        }
    };
    let currentAlert = null;
    const prevent = text => {
        if ( typeof text !== 'string' ) { return; }
        text = text.trim();
        if ( safe.testPattern(pattern, text) !== true ) { return; }
        if ( extraArgs.excludeMatches ) {
            if ( safe.testPattern(excludePattern, text) ) { return; }
        }
        if ( extraArgs.domAlert ) {
            domAlert(text);
        }
        safe.uboLog(logPrefix, 'Prevented:\n\t', text);
        return true;
    };
    const installTraps = ( ) => {
        proxyApplyFn('navigator.clipboard.writeText', async function(context) {
            const text = `${context.callArgs[0]}`;
            if ( prevent(text) ) { return; }
            return context.reflect();
        }, { skipToString: true });
        proxyApplyFn('document.execCommand', function(context) {
            const { callArgs } = context;
            if ( callArgs[0] === 'copy' || callArgs[0] === 'cut' ) {
                const text = document.getSelection()?.toString();
                if ( prevent(text) ) { return true; }
            }
            return context.reflect();
        }, { skipToString: true });
    };
    runAt(( ) => {
        self.document.addEventListener('mousemove', installTraps, {
            once: true,
            capture: true,
        });
    }, 'interactive')
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

function preventInnerHTML(
    selector = '',
    pattern = ''
) {
    freezeElementProperty('innerHTML', selector, pattern);
}

function preventRequestAnimationFrame(
    needleRaw = ''
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('prevent-requestAnimationFrame', needleRaw);
    const needleNot = needleRaw.charAt(0) === '!';
    const reNeedle = safe.patternToRegex(needleNot ? needleRaw.slice(1) : needleRaw);
    proxyApplyFn('requestAnimationFrame', function(context) {
        const { callArgs } = context;
        const a = callArgs[0] instanceof Function
            ? safe.String(safe.Function_toString(callArgs[0]))
            : safe.String(callArgs[0]);
        if ( needleRaw === '' ) {
            safe.uboLog(logPrefix, `Called:\n${a}`);
        } else if ( reNeedle.test(a) !== needleNot ) {
            callArgs[0] = function(){};
            safe.uboLog(logPrefix, `Prevented:\n${a}`);
        }
        return context.reflect();
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

function proxyApplyConfig(config = '') {
    try {
        if ( typeof proxyApplyFn !== 'function' ) { return; }
        config = JSON.parse(config);
        if ( typeof config !== 'object' ) { return; }
        Object.assign(proxyApplyFn, config);
    } catch {
    }
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

function proxyToStringFn(proxiedFn, nativeFn) {
    if ( proxyToStringFn.proxies === undefined ) {
        proxyToStringFn.proxies = new WeakMap();
        proxyToStringFn.nativeToString = Function.prototype.toString;
        const proxiedToString = new Proxy(Function.prototype.toString, {
            apply(target, thisArg) {
                let proxied = thisArg;
                for(;;) {
                    const fn = proxyToStringFn.proxies.get(proxied);
                    if ( fn === undefined ) { break; }
                    proxied = fn;
                }
                return proxyToStringFn.nativeToString.call(proxied);
            }
        });
        proxyToStringFn.proxies.set(proxiedToString, proxyToStringFn.nativeToString);
        Function.prototype.toString = proxiedToString;
    }
    proxyToStringFn.proxies.set(proxiedFn, nativeFn);
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

function replaceFetchResponseFn(
    trusted = false,
    pattern = '',
    replacement = '',
    propsToMatch = '',
    ...varargs
) {
    if ( trusted !== true ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('replace-fetch-response', pattern, replacement, propsToMatch);
    if ( pattern === '*' ) { pattern = '.*'; }
    const rePattern = safe.patternToRegex(pattern);
    const propNeedles = parsePropertiesToMatchFn(propsToMatch, 'url');
    const extraArgs = safe.parseVarargs(varargs);
    const reIncludes = extraArgs.includes ? safe.patternToRegex(extraArgs.includes) : null;
    self.fetch = new Proxy(self.fetch, {
        apply: function(target, thisArg, args) {
            const fetchPromise = Reflect.apply(target, thisArg, args);
            if ( pattern === '' ) { return fetchPromise; }
            if ( propNeedles.size !== 0 ) {
                const props = collateFetchArgumentsFn(...args);
                const matched = matchObjectPropertiesFn(propNeedles, props);
                if ( matched === undefined ) { return fetchPromise; }
                if ( safe.logLevel > 1 ) {
                    safe.uboLog(logPrefix, `Matched "propsToMatch":\n\t${matched.join('\n\t')}`);
                }
            }
            return fetchPromise.then(responseBefore => {
                const response = responseBefore.clone();
                return response.text().then(textBefore => {
                    if ( reIncludes && reIncludes.test(textBefore) === false ) {
                        return responseBefore;
                    }
                    const textAfter = textBefore.replace(rePattern, replacement);
                    if ( textAfter === textBefore ) { return responseBefore; }
                    safe.uboLog(logPrefix, 'Replaced');
                    const responseAfter = new Response(textAfter, {
                        status: responseBefore.status,
                        statusText: responseBefore.statusText,
                        headers: responseBefore.headers,
                    });
                    Object.defineProperties(responseAfter, {
                        ok: { value: responseBefore.ok },
                        redirected: { value: responseBefore.redirected },
                        type: { value: responseBefore.type },
                        url: { value: responseBefore.url },
                    });
                    return responseAfter;
                }).catch(reason => {
                    safe.uboErr(logPrefix, reason);
                    return responseBefore;
                });
            }).catch(reason => {
                safe.uboErr(logPrefix, reason);
                return fetchPromise;
            });
        }
    });
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

function spoofCSS(
    selector,
    ...args
) {
    if ( typeof selector !== 'string' ) { return; }
    if ( selector === '' ) { return; }
    const toCamelCase = s => s.replace(/-[a-z]/g, s => s.charAt(1).toUpperCase());
    const propToValueMap = new Map();
    const privatePropToValueMap = new Map();
    for ( let i = 0; i < args.length; i += 2 ) {
        const prop = toCamelCase(args[i+0]);
        if ( prop === '' ) { break; }
        const value = args[i+1];
        if ( typeof value !== 'string' ) { break; }
        if ( prop.charCodeAt(0) === 0x5F /* _ */ ) {
            privatePropToValueMap.set(prop, value);
        } else {
            propToValueMap.set(prop, value);
        }
    }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('spoof-css', selector, ...args);
    const instanceProperties = [ 'cssText', 'length', 'parentRule' ];
    const spoofStyle = (prop, real) => {
        const normalProp = toCamelCase(prop);
        const shouldSpoof = propToValueMap.has(normalProp);
        const value = shouldSpoof ? propToValueMap.get(normalProp) : real;
        if ( shouldSpoof ) {
            safe.uboLog(logPrefix, `Spoofing ${prop} to ${value}`);
        }
        return value;
    };
    const cloackFunc = (fn, thisArg, name) => {
        const trap = fn.bind(thisArg);
        Object.defineProperty(trap, 'name', { value: name });
        Object.defineProperty(trap, 'toString', {
            value: ( ) => `function ${name}() { [native code] }`
        });
        return trap;
    };
    self.getComputedStyle = new Proxy(self.getComputedStyle, {
        apply: function(target, thisArg, args) {
            // eslint-disable-next-line no-debugger
            if ( privatePropToValueMap.has('_debug') ) { debugger; }
            const style = Reflect.apply(target, thisArg, args);
            const targetElements = new WeakSet(document.querySelectorAll(selector));
            if ( targetElements.has(args[0]) === false ) { return style; }
            const proxiedStyle = new Proxy(style, {
                get(target, prop) {
                    if ( typeof target[prop] === 'function' ) {
                        if ( prop === 'getPropertyValue' ) {
                            return cloackFunc(function getPropertyValue(prop) {
                                return spoofStyle(prop, target[prop]);
                            }, target, 'getPropertyValue');
                        }
                        return cloackFunc(target[prop], target, prop);
                    }
                    if ( instanceProperties.includes(prop) ) {
                        return Reflect.get(target, prop);
                    }
                    return spoofStyle(prop, Reflect.get(target, prop));
                },
                getOwnPropertyDescriptor(target, prop) {
                    if ( propToValueMap.has(prop) ) {
                        return {
                            configurable: true,
                            enumerable: true,
                            value: propToValueMap.get(prop),
                            writable: true,
                        };
                    }
                    return Reflect.getOwnPropertyDescriptor(target, prop);
                },
            });
            return proxiedStyle;
        },
        get(target, prop) {
            if ( prop === 'toString' ) {
                return target.toString.bind(target);
            }
            return Reflect.get(target, prop);
        },
    });
    Element.prototype.getBoundingClientRect = new Proxy(Element.prototype.getBoundingClientRect, {
        apply: function(target, thisArg, args) {
            // eslint-disable-next-line no-debugger
            if ( privatePropToValueMap.has('_debug') ) { debugger; }
            const rect = Reflect.apply(target, thisArg, args);
            const targetElements = new WeakSet(document.querySelectorAll(selector));
            if ( targetElements.has(thisArg) === false ) { return rect; }
            let { x, y, height, width } = rect;
            if ( privatePropToValueMap.has('_rectx') ) {
                x = parseFloat(privatePropToValueMap.get('_rectx'));
            }
            if ( privatePropToValueMap.has('_recty') ) {
                y = parseFloat(privatePropToValueMap.get('_recty'));
            }
            if ( privatePropToValueMap.has('_rectw') ) {
                width = parseFloat(privatePropToValueMap.get('_rectw'));
            } else if ( propToValueMap.has('width') ) {
                width = parseFloat(propToValueMap.get('width'));
            }
            if ( privatePropToValueMap.has('_recth') ) {
                height = parseFloat(privatePropToValueMap.get('_recth'));
            } else if ( propToValueMap.has('height') ) {
                height = parseFloat(propToValueMap.get('height'));
            }
            return new self.DOMRect(x, y, width, height);
        },
        get(target, prop) {
            if ( prop === 'toString' ) {
                return target.toString.bind(target);
            }
            return Reflect.get(target, prop);
        },
    });
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

function trustedEditInboundObject(propChain = '', argPos = '', jsonq = '') {
    editInboundObjectFn(true, propChain, argPos, jsonq);
}

function trustedJsonEdit(jsonq = '', ...varargs) {
    jsonEditFn(true, jsonq, ...varargs);
}

function trustedJsonEditFetchResponse(jsonq = '', ...args) {
    jsonEditFetchResponseFn(true, jsonq, ...args);
}

function trustedJsonEditXhrResponse(jsonq = '', ...args) {
    jsonEditXhrResponseFn(true, jsonq, ...args);
}

function trustedOverrideElementMethod(
    methodPath = '',
    selector = '',
    disposition = '',
    ...varargs
) {
    if ( methodPath === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('trusted-override-element-method', methodPath, selector, disposition);
    const extraArgs = safe.parseVarargs(varargs);
    proxyApplyFn(methodPath, function(context) {
        let override = selector === '';
        if ( override === false ) {
            const { thisArg } = context;
            try {
                override = thisArg.closest(selector) === thisArg;
            } catch {
            }
        }
        if ( override === false ) {
            return context.reflect();
        }
        safe.uboLog(logPrefix, 'Overridden');
        if ( disposition === '' ) { return; }
        if ( disposition === 'debug' && safe.logLevel !== 0 ) {
            debugger; // eslint-disable-line no-debugger
        }
        if ( disposition === 'throw' ) {
            throw new ReferenceError();
        }
        return validateConstantFn(true, disposition, extraArgs);
    });
}

function trustedPreventDomBypass(
    methodPath = '',
    targetProp = ''
) {
    if ( methodPath === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('trusted-prevent-dom-bypass', methodPath, targetProp);
    proxyApplyFn(methodPath, function(context) {
        const elems = new Set(context.callArgs.filter(e => e instanceof HTMLElement));
        const r = context.reflect();
        if ( elems.length === 0 ) { return r; }
        for ( const elem of elems ) {
            try {
                if ( `${elem.contentWindow}` !== '[object Window]' ) { continue; }
                if ( elem.contentWindow.location.href !== 'about:blank' ) {
                    if ( elem.contentWindow.location.href !== self.location.href ) {
                        continue;
                    }
                }
                if ( targetProp !== '' ) {
                    let me = self, it = elem.contentWindow;
                    let chain = targetProp;
                    for (;;) {
                        const pos = chain.indexOf('.');
                        if ( pos === -1 ) { break; }
                        const prop = chain.slice(0, pos);
                        me = me[prop]; it = it[prop];
                        chain = chain.slice(pos+1);
                    }
                    it[chain] = me[chain];
                } else {
                    Object.defineProperty(elem, 'contentWindow', { value: self });
                }
                safe.uboLog(logPrefix, 'Bypass prevented');
            } catch {
            }
        }
        return r;
    });
}

function trustedPreventFetch(...args) {
    preventFetchFn(true, ...args);
}

function trustedPreventXhr(...args) {
    preventXhrFn(true, ...args);
}

function trustedReplaceArgument(
    propChain = '',
    argposRaw = '',
    argraw = '',
    ...varargs
) {
    if ( propChain === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('trusted-replace-argument', propChain, argposRaw, argraw);
    const argoffset = parseInt(argposRaw, 10) || 0;
    const extraArgs = safe.parseVarargs(varargs);
    let replacer;
    if ( argraw.startsWith('repl:/') ) {
        const parsed = parseReplaceFn(argraw.slice(5));
        if ( parsed === undefined ) { return; }
        replacer = arg => `${arg}`.replace(replacer.re, replacer.replacement);
        Object.assign(replacer, parsed);
    } else if ( argraw.startsWith('add:') ) {
        const delta = parseFloat(argraw.slice(4));
        if ( isNaN(delta) ) { return; }
        replacer = arg => Number(arg) + delta;
    } else {
        const value = validateConstantFn(true, argraw, extraArgs);
        replacer = ( ) => value;
    }
    const reCondition = extraArgs.condition
        ? safe.patternToRegex(`${extraArgs.condition}`)
        : /^/;
    const getArg = context => {
        if ( argposRaw === 'this' ) { return context.thisArg; }
        const { callArgs } = context;
        const argpos = argoffset >= 0 ? argoffset : callArgs.length - argoffset;
        if ( argpos < 0 || argpos >= callArgs.length ) { return; }
        context.private = { argpos };
        return callArgs[argpos];
    };
    const setArg = (context, value) => {
        if ( argposRaw === 'this' ) {
            if ( value !== context.thisArg ) {
                context.thisArg = value;
            }
        } else if ( context.private ) {
            context.callArgs[context.private.argpos] = value;
        }
    };
    proxyApplyFn(propChain, function(context) {
        if ( argposRaw === '' ) {
            safe.uboLog(logPrefix, `Arguments:\n${context.callArgs.join('\n')}`);
            return context.reflect();
        }
        const argBefore = getArg(context);
        if ( extraArgs.condition !== undefined ) {
            if ( safe.RegExp_test(reCondition, argBefore) === false ) {
                return context.reflect();
            }
        }
        const argAfter = replacer(argBefore);
        if ( argAfter !== argBefore ) {
            setArg(context, argAfter);
            safe.uboLog(logPrefix, `Replaced argument:\nBefore: ${JSON.stringify(argBefore)}\nAfter: ${argAfter}`);
        }
        return context.reflect();
    });
}

function trustedReplaceFetchResponse(...args) {
    replaceFetchResponseFn(true, ...args);
}

function trustedReplaceOutboundText(
    propChain = '',
    rawPattern = '',
    rawReplacement = '',
    ...varargs
) {
    if ( propChain === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('trusted-replace-outbound-text', propChain, rawPattern, rawReplacement, ...varargs);
    const rePattern = safe.patternToRegex(rawPattern);
    const replacement = rawReplacement.startsWith('json:')
        ? safe.JSON_parse(rawReplacement.slice(5))
        : rawReplacement;
    const extraArgs = safe.parseVarargs(varargs);
    const reCondition = safe.patternToRegex(extraArgs.condition || '');
    proxyApplyFn(propChain, function(context) {
        const encodedTextBefore = context.reflect();
        let textBefore = encodedTextBefore;
        if ( extraArgs.encoding === 'base64' ) {
            try { textBefore = self.atob(encodedTextBefore); }
            catch { return encodedTextBefore; }
        }
        if ( rawPattern === '' ) {
            safe.uboLog(logPrefix, 'Decoded outbound text:\n', textBefore);
            return encodedTextBefore;
        }
        reCondition.lastIndex = 0;
        if ( reCondition.test(textBefore) === false ) { return encodedTextBefore; }
        const textAfter = textBefore.replace(rePattern, replacement);
        if ( textAfter === textBefore ) { return encodedTextBefore; }
        safe.uboLog(logPrefix, 'Matched and replaced');
        if ( safe.logLevel > 1 ) {
            safe.uboLog(logPrefix, 'Modified decoded outbound text:\n', textAfter);
        }
        let encodedTextAfter = textAfter;
        if ( extraArgs.encoding === 'base64' ) {
            encodedTextAfter = self.btoa(textAfter);
        }
        return encodedTextAfter;
    });
}

function trustedReplaceXhrResponse(
    pattern = '',
    replacement = '',
    propsToMatch = '',
    ...varargs
) {
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('trusted-replace-xhr-response', pattern, replacement, propsToMatch);
    const xhrInstances = new WeakMap();
    if ( pattern === '*' ) { pattern = '.*'; }
    const rePattern = safe.patternToRegex(pattern);
    const propNeedles = parsePropertiesToMatchFn(propsToMatch, 'url');
    const extraArgs = safe.parseVarargs(varargs);
    const reIncludes = extraArgs.includes ? safe.patternToRegex(extraArgs.includes) : null;
    self.XMLHttpRequest = class extends self.XMLHttpRequest {
        open(method, url, ...args) {
            const outerXhr = this;
            const xhrDetails = { method, url };
            let outcome = 'match';
            if ( propNeedles.size !== 0 ) {
                if ( matchObjectPropertiesFn(propNeedles, xhrDetails) === undefined ) {
                    outcome = 'nomatch';
                }
            }
            if ( outcome === 'match' ) {
                if ( safe.logLevel > 1 ) {
                    safe.uboLog(logPrefix, `Matched "propsToMatch"`);
                }
                xhrInstances.set(outerXhr, xhrDetails);
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
            if ( typeof innerResponse !== 'string' ) {
                return (xhrDetails.response = innerResponse);
            }
            if ( reIncludes && reIncludes.test(innerResponse) === false ) {
                return (xhrDetails.response = innerResponse);
            }
            const textBefore = innerResponse;
            const textAfter = textBefore.replace(rePattern, replacement);
            if ( textAfter !== textBefore ) {
                safe.uboLog(logPrefix, 'Match');
            }
            return (xhrDetails.response = textAfter);
        }
        get responseText() {
            const response = this.response;
            if ( typeof response !== 'string' ) {
                return super.responseText;
            }
            return response;
        }
    };
}

function trustedSetConstant(
    ...args
) {
    setConstantFn(true, ...args);
}

function trustedSuppressNativeMethod(
    methodPath = '',
    signature = '',
    how = '',
    stack = ''
) {
    if ( methodPath === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('trusted-suppress-native-method', methodPath, signature, how, stack);
    const signatureArgs = safe.String_split.call(signature, /\s*\|\s*/).map(v => {
        if ( /^".*"$/.test(v) ) {
            return { type: 'pattern', re: safe.patternToRegex(v.slice(1, -1)) };
        }
        if ( /^\/.+\/$/.test(v) ) {
            return { type: 'pattern', re: safe.patternToRegex(v) };
        }
        if ( v === 'false' ) {
            return { type: 'exact', value: false };
        }
        if ( v === 'true' ) {
            return { type: 'exact', value: true };
        }
        if ( v === 'null' ) {
            return { type: 'exact', value: null };
        }
        if ( v === 'undefined' ) {
            return { type: 'exact', value: undefined };
        }
    });
    const stackNeedle = safe.initPattern(stack, { canNegate: true });
    proxyApplyFn(methodPath, function(context) {
        const { callArgs } = context;
        if ( signature === '' ) {
            safe.uboLog(logPrefix, `Arguments:\n${callArgs.join('\n')}`);
            return context.reflect();
        }
        for ( let i = 0; i < signatureArgs.length; i++ ) {
            const signatureArg = signatureArgs[i];
            if ( signatureArg === undefined ) { continue; }
            const targetArg = i < callArgs.length ? callArgs[i] : undefined;
            if ( signatureArg.type === 'exact' ) {
                if ( targetArg !== signatureArg.value ) {
                    return context.reflect();
                }
            }
            if ( signatureArg.type === 'pattern' ) {
                if ( safe.RegExp_test(signatureArg.re, targetArg) === false ) {
                    return context.reflect();
                }
            }
        }
        if ( stackNeedle.matchAll !== true ) {
            const logLevel = safe.logLevel > 1 ? 'all' : '';
            if ( matchesStackTraceFn(stackNeedle, logLevel) === false ) {
                return context.reflect();
            }
        }
        if ( how === 'debug' ) {
            debugger; // eslint-disable-line no-debugger
            return context.reflect();
        }
        safe.uboLog(logPrefix, `Suppressed:\n${callArgs.join('\n')}`);
        if ( how === 'abort' ) {
            throw new ReferenceError();
        }
    });
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

function xmlPrune(
    selector = '',
    selectorCheck = '',
    urlPattern = '',
    ...varargs
) {
    if ( typeof selector !== 'string' ) { return; }
    if ( selector === '' ) { return; }
    const safe = safeSelf();
    const logPrefix = safe.makeLogPrefix('xml-prune', selector, selectorCheck, urlPattern);
    const reUrl = safe.patternToRegex(urlPattern);
    const extraArgs = safe.parseVarargs(varargs);
    const queryAll = (xmlDoc, selector) => {
        const isXpath = /^xpath\(.+\)$/.test(selector);
        if ( isXpath === false ) {
            return Array.from(xmlDoc.querySelectorAll(selector));
        }
        const xpr = xmlDoc.evaluate(
            selector.slice(6, -1),
            xmlDoc,
            null,
            XPathResult.UNORDERED_NODE_SNAPSHOT_TYPE,
            null
        );
        const out = [];
        for ( let i = 0; i < xpr.snapshotLength; i++ ) {
            const node = xpr.snapshotItem(i);
            out.push(node);
        }
        return out;
    };
    const pruneFromDoc = xmlDoc => {
        try {
            if ( selectorCheck !== '' && xmlDoc.querySelector(selectorCheck) === null ) {
                return xmlDoc;
            }
            if ( extraArgs.logdoc ) {
                const serializer = new XMLSerializer();
                safe.uboLog(logPrefix, `Document is\n\t${serializer.serializeToString(xmlDoc)}`);
            }
            const items = queryAll(xmlDoc, selector);
            if ( items.length === 0 ) { return xmlDoc; }
            safe.uboLog(logPrefix, `Removing ${items.length} items`);
            for ( const item of items ) {
                if ( item.nodeType === 1 ) {
                    item.remove();
                } else if ( item.nodeType === 2 ) {
                    item.ownerElement.removeAttribute(item.nodeName);
                }
                safe.uboLog(logPrefix, `${item.constructor.name}.${item.nodeName} removed`);
            }
        } catch(ex) {
            safe.uboErr(logPrefix, `Error: ${ex}`);
        }
        return xmlDoc;
    };
    const pruneFromText = text => {
        if ( (/^\s*</.test(text) && />\s*$/.test(text)) === false ) {
            return text;
        }
        try {
            const xmlParser = new DOMParser();
            const xmlDoc = xmlParser.parseFromString(text, 'text/xml');
            pruneFromDoc(xmlDoc);
            const serializer = new XMLSerializer();
            text = serializer.serializeToString(xmlDoc);
        } catch {
        }
        return text;
    };
    const urlFromArg = arg => {
        if ( typeof arg === 'string' ) { return arg; }
        if ( arg instanceof Request ) { return arg.url; }
        return String(arg);
    };
    self.fetch = new Proxy(self.fetch, {
        apply: function(target, thisArg, args) {
            const fetchPromise = Reflect.apply(target, thisArg, args);
            if ( reUrl.test(urlFromArg(args[0])) === false ) {
                return fetchPromise;
            }
            return fetchPromise.then(responseBefore => {
                const response = responseBefore.clone();
                return response.text().then(text => {
                    const responseAfter = new Response(pruneFromText(text), {
                        status: responseBefore.status,
                        statusText: responseBefore.statusText,
                        headers: responseBefore.headers,
                    });
                    Object.defineProperties(responseAfter, {
                        ok: { value: responseBefore.ok },
                        redirected: { value: responseBefore.redirected },
                        type: { value: responseBefore.type },
                        url: { value: responseBefore.url },
                    });
                    return responseAfter;
                }).catch(( ) =>
                    responseBefore
                );
            });
        }
    });
    modifyXhrResponseFn(urlPattern, (xhr, before) => {
        if ( before instanceof XMLDocument ) {
            return pruneFromDoc(before);
        }
        if ( typeof before === 'string' ) {
            return pruneFromText(before);
        }
        return before;
    });
}

function zeta_2brklsgs() { // popads.js
(function() {
    'use strict';
    const magic = String.fromCharCode(Date.now() % 26 + 97) +
                  Math.floor(Math.random() * 982451653 + 982451653).toString(36);
    const oe = window.onerror;
    window.onerror = function(msg, src, line, col, error) {
        if ( typeof msg === 'string' && msg.indexOf(magic) !== -1 ) { return true; }
        if ( oe instanceof Function ) {
            return oe(msg, src, line, col, error);
        }
    }.bind();
    const throwMagic = function() { throw new ReferenceError(magic); };
    delete window.PopAds;
    delete window.popns;
    Object.defineProperties(window, {
        PopAds: { set: throwMagic },
        popns: { set: throwMagic }
    });
})();
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

function zeta_djbdt5ns() { // popads-dummy.js
(function() {
    'use strict';
    delete window.PopAds;
    delete window.popns;
    Object.defineProperties(window, {
        PopAds: { value: {} },
        popns: { value: {} }
    });
})();
}

function zeta_j7s0f4ys() { // google-ima.js
'use strict';





if (!window.google || !window.google.ima || !window.google.ima.VERSION) {
  const VERSION = "3.764.0";
  const ima = {};

  class AdDisplayContainer {
    constructor(containerElement) {
      const divElement = document.createElement("div");
      divElement.style.setProperty("display", "none", "important");
      divElement.style.setProperty("visibility", "collapse", "important");
      containerElement.appendChild(divElement);
    }
    destroy() {}
    initialize() {}
  }

  class ImaSdkSettings {
    constructor() {
      this.c = true;
      this.f = {};
      this.i = false;
      this.l = "";
      this.p = "";
      this.r = 0;
      this.t = "";
      this.v = "";
    }
    getCompanionBackfill() {}
    getDisableCustomPlaybackForIOS10Plus() {
      return this.i;
    }
    getFeatureFlags() {
      return this.f;
    }
    getLocale() {
      return this.l;
    }
    getNumRedirects() {
      return this.r;
    }
    getPlayerType() {
      return this.t;
    }
    getPlayerVersion() {
      return this.v;
    }
    getPpid() {
      return this.p;
    }
    isCookiesEnabled() {
      return this.c;
    }
    setAutoPlayAdBreaks() {}
    setCompanionBackfill() {}
    setCookiesEnabled(c) {
      this.c = !!c;
    }
    setDisableCustomPlaybackForIOS10Plus(i) {
      this.i = !!i;
    }
    setFeatureFlags(f) {
      this.f = f;
    }
    setLocale(l) {
      this.l = l;
    }
    setNumRedirects(r) {
      this.r = r;
    }
    setPlayerType(t) {
      this.t = t;
    }
    setPlayerVersion(v) {
      this.v = v;
    }
    setPpid(p) {
      this.p = p;
    }
    setSessionId() {}
    setVpaidAllowed() {}
    setVpaidMode() {}

    // https://github.com/uBlockOrigin/uBlock-issues/issues/2265#issuecomment-1637094149
    getDisableFlashAds() {
    }
    setDisableFlashAds() {
    }
  }
  ImaSdkSettings.CompanionBackfillMode = {
    ALWAYS: "always",
    ON_MASTER_AD: "on_master_ad",
  };
  ImaSdkSettings.VpaidMode = {
    DISABLED: 0,
    ENABLED: 1,
    INSECURE: 2,
  };

  class EventHandler {
    constructor() {
      this.listeners = new Map();
    }

    _dispatch(e) {
      let listeners = this.listeners.get(e.type);
      listeners = listeners ? Array.from(listeners.values()) : [];
      for (const listener of listeners) {
        try {
          listener(e);
        } catch (r) {
          console.error(r);
        }
      }
    }

    addEventListener(types, c, options, context) {
      if (!Array.isArray(types)) {
        types = [types];
      }

      for (const t of types) {
        if (!this.listeners.has(t)) {
          this.listeners.set(t, new Map());
        }
        this.listeners.get(t).set(c, c.bind(context || this));
      }
    }

    removeEventListener(types, c) {
      if (!Array.isArray(types)) {
        types = [types];
      }

      for (const t of types) {
        const typeSet = this.listeners.get(t);
        if (typeSet) {
          typeSet.delete(c);
        }
      }
    }
  }

  class AdsLoader extends EventHandler {
    constructor() {
      super();
      this.settings = new ImaSdkSettings();
    }
    contentComplete() {}
    destroy() {}
    getSettings() {
      return this.settings;
    }
    getVersion() {
      return VERSION;
    }
    requestAds(_r, _c) {
      requestAnimationFrame(() => {
        const { ADS_MANAGER_LOADED } = AdsManagerLoadedEvent.Type;
        const event = new ima.AdsManagerLoadedEvent(ADS_MANAGER_LOADED, _r, _c);
        this._dispatch(event);
      });
      const error = new ima.AdError(
        "adPlayError",
        1205, 1205,
        "The browser prevented playback initiated without user interaction.",
        _r, _c
      );
      requestAnimationFrame( () => {
        this._dispatch(new ima.AdErrorEvent(error));
      });
    }
  }

  class AdsManager extends EventHandler {
    constructor() {
      super();
      this.volume = 1;
      this._enablePreloading = false;
    }
    collapse() {}
    configureAdsManager() {}
    destroy() {}
    discardAdBreak() {}
    expand() {}
    focus() {}
    getAdSkippableState() {
      return false;
    }
    getCuePoints() {
      return [0];
    }
    getCurrentAd() {
      return currentAd;
    }
    getCurrentAdCuePoints() {
      return [];
    }
    getRemainingTime() {
      return 0;
    }
    getVolume() {
      return this.volume;
    }
    init() {
      if (this._enablePreloading) {
        this._dispatch(new ima.AdEvent(AdEvent.Type.LOADED));
      }
    }
    isCustomClickTrackingUsed() {
      return false;
    }
    isCustomPlaybackUsed() {
      return false;
    }
    pause() {}
    requestNextAdBreak() {}
    resize() {}
    resume() {}
    setVolume(v) {
      this.volume = v;
    }
    skip() {}
    start() {
      requestAnimationFrame(() => {
        for (const type of [
          AdEvent.Type.LOADED,
          AdEvent.Type.STARTED,
          AdEvent.Type.CONTENT_PAUSE_REQUESTED,
          AdEvent.Type.AD_BUFFERING,
          AdEvent.Type.FIRST_QUARTILE,
          AdEvent.Type.MIDPOINT,
          AdEvent.Type.THIRD_QUARTILE,
          AdEvent.Type.COMPLETE,
          AdEvent.Type.ALL_ADS_COMPLETED,
          AdEvent.Type.CONTENT_RESUME_REQUESTED,
        ]) {
          try {
            this._dispatch(new ima.AdEvent(type));
          } catch (e) {
            console.error(e);
          }
        }
      });
    }
    stop() {}
    updateAdsRenderingSettings() {}
  }

  class AdsRenderingSettings {}

  class AdsRequest {
    setAdWillAutoPlay() {}
    setAdWillPlayMuted() {}
    setContinuousPlayback() {}
  }

  class AdPodInfo {
    getAdPosition() {
      return 1;
    }
    getIsBumper() {
      return false;
    }
    getMaxDuration() {
      return -1;
    }
    getPodIndex() {
      return 1;
    }
    getTimeOffset() {
      return 0;
    }
    getTotalAds() {
      return 1;
    }
  }

  class Ad {
    constructor() {
      this._pi = new AdPodInfo();
    }
    getAdId() {
      return "";
    }
    getAdPodInfo() {
      return this._pi;
    }
    getAdSystem() {
      return "";
    }
    getAdvertiserName() {
      return "";
    }
    getApiFramework() {
      return null;
    }
    getCompanionAds() {
      return [];
    }
    getContentType() {
      return "";
    }
    getCreativeAdId() {
      return "";
    }
    getCreativeId() {
      return "";
    }
    getDealId() {
      return "";
    }
    getDescription() {
      return "";
    }
    getDuration() {
      return 8.5;
    }
    getHeight() {
      return 0;
    }
    getMediaUrl() {
      return null;
    }
    getMinSuggestedDuration() {
      return -2;
    }
    getSkipTimeOffset() {
      return -1;
    }
    getSurveyUrl() {
      return null;
    }
    getTitle() {
      return "";
    }
    getTraffickingParameters() {
      return {};
    }
    getTraffickingParametersString() {
      return "";
    }
    getUiElements() {
      return [""];
    }
    getUniversalAdIdRegistry() {
      return "unknown";
    }
    getUniversalAdIds() {
      return [new UniversalAdIdInfo()];
    }
    getUniversalAdIdValue() {
      return "unknown";
    }
    getVastMediaBitrate() {
      return 0;
    }
    getVastMediaHeight() {
      return 0;
    }
    getVastMediaWidth() {
      return 0;
    }
    getWidth() {
      return 0;
    }
    getWrapperAdIds() {
      return [""];
    }
    getWrapperAdSystems() {
      return [""];
    }
    getWrapperCreativeIds() {
      return [""];
    }
    isLinear() {
      return true;
    }
    isSkippable() {
      return true;
    }
  }

  class CompanionAd {
    getAdSlotId() {
      return "";
    }
    getContent() {
      return "";
    }
    getContentType() {
      return "";
    }
    getHeight() {
      return 1;
    }
    getWidth() {
      return 1;
    }
  }

  class AdError {
    constructor(type, code, vast, message, request, context) {
      this.errorCode = code;
      this.message = message;
      this.type = type;
      this.adsRequest = request;
      this.userRequestContext = context;
      this.vastErrorCode = vast;
    }
    getErrorCode() {
      return this.errorCode;
    }
    getInnerError() {
        return null;
    }
    getMessage() {
      return this.message;
    }
    getType() {
      return this.type;
    }
    getVastErrorCode() {
      return this.vastErrorCode;
    }
    toString() {
      return `AdError ${this.errorCode}: ${this.message}`;
    }
  }
  AdError.ErrorCode = {};
  AdError.Type = {};

  const isEngadget = () => {
    try {
      for (const ctx of Object.values(window.vidible._getContexts())) {
        const player = ctx.getPlayer();
        if (!player) { continue;}
        const div = player.div;
        if (!div) { continue; }
        if (div.innerHTML.includes("www.engadget.com")) {
          return true;
        }
      }
    } catch {
    }
    return false;
  };

  const currentAd = isEngadget() ? undefined : new Ad();

  class AdEvent {
    constructor(type) {
      this.type = type;
    }
    getAd() {
      return currentAd;
    }
    getAdData() {
      return {};
    }
  }
  AdEvent.Type = {
    AD_BREAK_READY: "adBreakReady",
    AD_BUFFERING: "adBuffering",
    AD_CAN_PLAY: "adCanPlay",
    AD_METADATA: "adMetadata",
    AD_PROGRESS: "adProgress",
    ALL_ADS_COMPLETED: "allAdsCompleted",
    CLICK: "click",
    COMPLETE: "complete",
    CONTENT_PAUSE_REQUESTED: "contentPauseRequested",
    CONTENT_RESUME_REQUESTED: "contentResumeRequested",
    DURATION_CHANGE: "durationChange",
    EXPANDED_CHANGED: "expandedChanged",
    FIRST_QUARTILE: "firstQuartile",
    IMPRESSION: "impression",
    INTERACTION: "interaction",
    LINEAR_CHANGE: "linearChange",
    LINEAR_CHANGED: "linearChanged",
    LOADED: "loaded",
    LOG: "log",
    MIDPOINT: "midpoint",
    PAUSED: "pause",
    RESUMED: "resume",
    SKIPPABLE_STATE_CHANGED: "skippableStateChanged",
    SKIPPED: "skip",
    STARTED: "start",
    THIRD_QUARTILE: "thirdQuartile",
    USER_CLOSE: "userClose",
    VIDEO_CLICKED: "videoClicked",
    VIDEO_ICON_CLICKED: "videoIconClicked",
    VIEWABLE_IMPRESSION: "viewable_impression",
    VOLUME_CHANGED: "volumeChange",
    VOLUME_MUTED: "mute",
  };

  class AdErrorEvent {
    constructor(error) {
      this.type = "adError";
      this.error = error;
    }
    getError() {
      return this.error;
    }
    getUserRequestContext() {
      return this.error?.userRequestContext || {};
    }
  }
  AdErrorEvent.Type = {
    AD_ERROR: "adError",
  };

  const manager = new AdsManager();

  class AdsManagerLoadedEvent {
    constructor(type, request, context) {
      this.type = type;
      this.adsRequest = request;
      this.userRequestContext = context;
    }
    getAdsManager(c, settings) {
      if (settings && settings.enablePreloading) {
        manager._enablePreloading = true;
      }
      return manager;
    }
    getUserRequestContext() {
      return this.userRequestContext || {};
    }
  }
  AdsManagerLoadedEvent.Type = {
    ADS_MANAGER_LOADED: "adsManagerLoaded",
  };

  class CustomContentLoadedEvent {}
  CustomContentLoadedEvent.Type = {
    CUSTOM_CONTENT_LOADED: "deprecated-event",
  };

  class CompanionAdSelectionSettings {}
  CompanionAdSelectionSettings.CreativeType = {
    ALL: "All",
    FLASH: "Flash",
    IMAGE: "Image",
  };
  CompanionAdSelectionSettings.ResourceType = {
    ALL: "All",
    HTML: "Html",
    IFRAME: "IFrame",
    STATIC: "Static",
  };
  CompanionAdSelectionSettings.SizeCriteria = {
    IGNORE: "IgnoreSize",
    SELECT_EXACT_MATCH: "SelectExactMatch",
    SELECT_NEAR_MATCH: "SelectNearMatch",
  };

  class AdCuePoints {
    getCuePoints() {
      return [];
    }
  }

  class AdProgressData {}

  class UniversalAdIdInfo {
    getAdIdRegistry() {
      return "";
    }
    getAdIdValue() {
      return "";
    }
  }

  Object.assign(ima, {
    AdCuePoints,
    AdDisplayContainer,
    AdError,
    AdErrorEvent,
    AdEvent,
    AdPodInfo,
    AdProgressData,
    AdsLoader,
    AdsManager: manager,
    AdsManagerLoadedEvent,
    AdsRenderingSettings,
    AdsRequest,
    CompanionAd,
    CompanionAdSelectionSettings,
    CustomContentLoadedEvent,
    gptProxyInstance: {},
    ImaSdkSettings,
    OmidAccessMode: {
      DOMAIN: "domain",
      FULL: "full",
      LIMITED: "limited",
    },
    OmidVerificationVendor: {
      1: "OTHER",
      2: "GOOGLE",
      GOOGLE: 2,
      OTHER: 1
    },
    settings: new ImaSdkSettings(),
    UiElements: {
      AD_ATTRIBUTION: "adAttribution",
      COUNTDOWN: "countdown",
    },
    UniversalAdIdInfo,
    VERSION,
    ViewMode: {
      FULLSCREEN: "fullscreen",
      NORMAL: "normal",
    },
  });

  if (!window.google) {
    window.google = {};
  }

  window.google.ima = ima;
}
}

function zeta_mb58kw52() { // fingerprint2.js
// Reference:
// https://github.com/fingerprintjs/fingerprintjs/tree/v2

(function() {
    'use strict';
    const hex32 = len => {
        return Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)
            .toString(16)
            .slice(-len)
            .padStart(len, '0');
    };
    const browserId = `${hex32(8)}${hex32(8)}${hex32(8)}${hex32(8)}`;
    const fp2 = function(){};
    fp2.get = function(opts, cb) {
        if ( !cb  ) { cb = opts; }
        setTimeout(( ) => { cb([]); }, 1);
    };
    fp2.getPromise = function() {
        return Promise.resolve([]);
    };
    fp2.getV18 = function() {
        return browserId;
    };
    fp2.x64hash128 = function() {
        return browserId;
    };
    fp2.prototype = {
        get: function(opts, cb) {
            if ( !cb  ) { cb = opts; }
            setTimeout(( ) => { cb(browserId, []); }, 1);
        },
    };
    self.Fingerprint2 = self.Fingerprint = fp2;
})();
}

function zeta_movh4xh5() { // noeval.js
(function() {
    'use strict';
    const log = console.log.bind(console);
    window.eval = new Proxy(window.eval, {          // jshint ignore: line
        apply: function(target, thisArg, args) {
            log(`Document tried to eval... ${args[0]}\n`);
        }
    });
})();
}

/******************************************************************************/

const scriptletGlobals = {}; // eslint-disable-line

const $hasHostnames$ = true;
const $hasEntities$ = true;
const $hasAncestors$ = true;
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
    const $scriptletHostnames$ = /* 13997 */ ["*","edu","g.pl","j.gs","s.to","3sk.*","al.ly","asd.*","bc.vc","br.de","bs.to","clk.*","di.fm","fc.lc","fr.de","fzm.*","g3g.*","gmx.*","hqq.*","kat.*","lz.de","m4u.*","mt.de","nn.de","nw.de","o2.pl","ok.ru","op.gg","ouo.*","oxy.*","pnd.*","qmh.*","rp5.*","sh.st","sn.at","th.gl","tpb.*","tu.no","tz.de","ur.ly","vev.*","vz.lt","wa.de","wn.de","wp.de","wp.pl","wr.de","x.com","ytc.*","yts.*","za.gl","ze.tt","00m.in","1hd.to","2ddl.*","33sk.*","4br.me","4j.com","538.nl","9tsu.*","a8ix.*","agf.nl","aii.sh","al.com","as.com","av01.*","bab.la","bbf.lt","bcvc.*","bde4.*","btdb.*","btv.bg","c2g.at","cap3.*","cbc.ca","crn.pl","djs.sk","dlhd.*","dna.fr","dnn.de","dodz.*","dood.*","ebay.*","edu.cn","eio.io","epe.es","ettv.*","ew.com","exe.io","eztv.*","fbgo.*","fnp.de","ft.com","geo.de","geo.fr","goo.st","gra.pl","haz.de","hd21.*","hdss.*","hna.de","iir.ai","iiv.pl","imx.to","ioe.vn","jav.re","jav.sb","jav.si","javx.*","kaa.lt","kaa.mx","kat2.*","kio.ac","kkat.*","kmo.to","kwik.*","la7.it","lne.es","lnk.lt","lvz.de","m5g.it","mel.fm","met.bz","mexa.*","mmm.dk","mtv.fi","nj.com","nnn.de","nos.nl","now.gg","now.us","noz.de","npo.nl","nrz.de","nto.pl","ntv.cx","och.to","oii.io","oii.la","ok.xxx","oke.io","oko.sh","ovid.*","pahe.*","pe.com","pnn.de","poop.*","qub.ca","ran.de","rgb.vn","rgl.vn","rtl.de","rtv.de","s.to>>","sab.bz","sfr.fr","shz.de","siz.tv","srt.am","svz.de","tek.no","tf1.fr","tfp.is","tii.la","tio.ch","tny.so","top.gg","tpi.li","tv2.no","tvn.pl","tvtv.*","txxx.*","uii.io","upns.*","vido.*","vip.de","vod.pl","voe.sx","vox.de","vsd.fr","waaw.*","waz.de","wco.tv","web.de","xnxx.*","xup.in","xxnx.*","yts2.*","zoro.*","0xxx.ws","10gb.vn","1337x.*","1377x.*","1ink.cc","24pdd.*","5278.cc","5play.*","7mmtv.*","7xm.xyz","8tm.net","a-ha.io","adn.com","adsh.cc","adsrt.*","adsy.pw","adyou.*","adzz.in","ahri8.*","ak4eg.*","akoam.*","akw.cam","akwam.*","an1.com","an1me.*","app.com","arbsd.*","atdhe.*","atv.com","babla.*","bbc.com","bgr.com","bgsi.gg","bhg.com","bild.de","biqle.*","brew.sh","bunkr.*","car.com","cbox.ws","cbr.com","cbs.com","chip.de","cine.to","clik.pw","cnn.com","crn.com","ctrlv.*","dbna.de","dciuu.*","deco.fr","delo.bg","dict.cc","digi.no","dirp.me","dlhd.sx","dnj.com","docer.*","doods.*","doood.*","duck.ai","elixx.*","enit.in","eska.pl","exe.app","exey.io","f6s.com","fakt.pl","faz.net","ffcv.es","filmy.*","fomo.id","fox.com","fpo.xxx","gala.de","gala.fr","gats.io","gdtot.*","giga.de","gk24.pl","gntai.*","gnula.*","goku.sx","gomo.to","gotxx.*","govid.*","gp24.pl","grid.id","gs24.pl","gsurl.*","haps.pl","hdvid.*","hdzog.*","hftg.co","igram.*","inc.com","inra.bg","itv.com","j5z.xyz","javhd.*","jizz.us","jmty.jp","joyn.at","joyn.ch","joyn.de","jpg2.su","jpg6.su","k1nk.co","k511.me","kaas.ro","kfc.com","khsm.io","kijk.nl","kino.de","kinox.*","kinoz.*","koyso.*","ksl.com","ksta.de","lato.sx","laut.de","leak.sx","link.tl","linkz.*","linx.cc","litv.tv","lnbz.la","lnk2.cc","logi.im","lulu.st","m4uhd.*","mail.de","mdn.lol","mega.nz","mlb.com","mlfbd.*","mlsbd.*","mlwbd.*","moin.de","mopo.de","more.tv","moto.it","moto.pl","movi.pk","mtv.com","myegy.*","n-tv.de","nba.com","nbc.com","netu.ac","news.at","news.bg","news.de","nfl.com","nmac.to","noxx.to","ntvs.cx","nuvid.*","odum.cl","oe24.at","oggi.it","oload.*","onle.co","onvid.*","opvid.*","oxy.edu","oyohd.*","pelix.*","pes6.es","pfps.gg","pngs.gg","pnj.com","pobre.*","prad.de","qmh.sex","rabo.no","rat.xxx","raw18.*","rgj.com","rmcmv.*","sat1.de","sbot.cf","seehd.*","send.cm","sflix.*","sixx.de","sms24.*","songs.*","spy.com","stape.*","stfly.*","swfr.tv","szbz.de","tj.news","tlin.me","tr.link","ttks.tw","tuba.pl","tube8.*","tune.pk","tvhay.*","tvply.*","tvtv.ca","tvtv.us","u.co.uk","ujav.me","uns.bio","upi.com","upn.one","upvid.*","vcp.xxx","veev.to","vidd.se","vidhd.*","vidoo.*","vidop.*","vids.st","vidup.*","vipr.im","viu.com","vix.com","viz.com","vkmp3.*","vods.tv","vox.com","vozz.vn","vpro.nl","vsrc.su","vudeo.*","waaaw.*","waaw1.*","welt.de","wgod.co","wiwo.de","wwd.com","xtits.*","ydr.com","yiv.com","ymix.to","yout.pw","ytmp3.*","zeit.de","zeiz.me","zien.pl","0deh.com","123mkv.*","15min.lt","18jav.tv","1flix.to","1mov.lol","20min.ch","2embed.*","2ix2.com","2tencb.*","3prn.com","4anime.*","4cash.me","4khd.com","519.best","58n1.com","7mmtv.sx","85po.com","9gag.com","9mod.com","9n8o.com","9xflix.*","a2zapk.*","aalah.me","actvid.*","adbull.*","adeth.cc","adfloz.*","adfoc.us","adsup.lk","aetv.com","afly.pro","agefi.fr","al4a.com","alpin.de","amazon.*","anigo.to","anoboy.*","arcor.de","ariva.de","asd.pics","asiaon.*","atxtv.co","auone.jp","ayo24.id","azsoft.*","babia.to","bbw6.com","bdiptv.*","bdix.app","bif24.pl","bigfm.de","bilan.ch","bing.com","binged.*","bjhub.me","blick.ch","blick.de","bmovie.*","bombuj.*","booru.eu","brato.bg","brevi.eu","bsky.app","bunkr.la","bunkrr.*","bzzhr.co","bzzhr.to","canna.to","capshd.*","cataz.to","cety.app","cgaa.org","chd4.com","cima4u.*","cineb.gg","cineb.rs","cinen9.*","citi.com","clk.asia","cnbc.com","cnet.com","comix.to","crichd.*","crone.es","cuse.com","cwtv.com","cybar.to","cykf.net","dahh.net","dazn.com","dbna.com","deano.me","dewimg.*","dfiles.*","dlhd.*>>","doods.to","doodss.*","dooood.*","dosya.co","duden.de","dump.xxx","ecac.org","eee1.lat","egolf.jp","eldia.es","emoji.gg","ervik.as","espn.com","exee.app","exeo.app","exyi.net","f75s.com","fastt.gg","fembed.*","files.cx","files.fm","files.im","filma1.*","finya.de","fir3.net","firmy.cz","flixhq.*","fmovie.*","focus.de","friv.com","fupa.net","fxmag.pl","fyxxr.to","fzlink.*","g9r6.com","game8.jp","ganool.*","garaz.cz","gaygo.tv","gdflix.*","ggjav.tv","gload.to","glodls.*","gogohd.*","gokutv.*","gol24.pl","golem.de","gtavi.pl","gusto.at","hackr.io","haho.moe","hd44.com","hd44.net","hdbox.ws","hdfull.*","heftig.*","heise.de","hidan.co","hidan.sh","hilaw.vn","hk01.com","hltv.org","howdy.id","hoyme.jp","hpjav.in","hqtv.biz","html.net","huim.com","hulu.com","hydrax.*","hyhd.org","iade.com","ibbs.pro","icelz.to","idnes.cz","imgdew.*","imgsen.*","imgsto.*","imgviu.*","index.hr","isi7.net","its.porn","j91.asia","janjua.*","javgg.me","jmanga.*","jmmv.dev","jotea.cl","kagane.*","kagi.com","kaido.to","katbay.*","kcra.com","kduk.com","keepv.id","kick.com","kimi.com","kizi.com","kloo.com","km77.com","kmed.com","kmhd.net","kmnt.com","kpnw.com","ktee.com","ktmx.pro","kukaj.io","kukni.to","kwro.com","l8e8.com","l99j.com","la3c.com","lablue.*","lared.cl","lejdd.fr","levif.be","lin-ks.*","link1s.*","linkos.*","live.com","liveon.*","lnk.news","ma-x.org","magesy.*","mail.com","mazpic.*","mcloud.*","mgeko.cc","miro.com","miruro.*","missav.*","mitly.us","mixdrp.*","mixed.de","mkvhub.*","mlsbd.co","mmsbee.*","moms.com","money.bg","money.pl","movidy.*","movs4u.*","mxdrop.*","my1ink.*","my4w.com","myad.biz","mycima.*","n.fcd.su","ncaa.com","net77.cc","newdmn.*","nhl66.ir","nick.com","nohat.cc","nola.com","notube.*","ogario.*","orsm.net","oui.sncf","pa1n.xyz","pahe.ink","pasend.*","payt.com","pctnew.*","piano.io","picks.my","picrok.*","pingit.*","pirate.*","pixlev.*","pluto.tv","plyjam.*","plyvdo.*","pogo.com","pons.com","porn.com","porn0.tv","pornid.*","pornx.to","qa2h.com","quins.us","quoka.de","r2sa.net","racaty.*","radio.at","radio.de","radio.dk","radio.es","radio.fr","radio.it","radio.pl","radio.pt","radio.se","ralli.ee","ranoz.gg","rargb.to","rasoi.me","rdxhd1.*","rintor.*","rootz.so","roshy.tv","saint.to","sanet.lc","sanet.st","sbchip.*","sbflix.*","sbplay.*","sbrulz.*","scmp.com","seeeed.*","self.com","senda.pl","senpa.io","seriu.jp","sex3.com","sexvid.*","shopr.tv","short.pe","shtab.su","shtms.co","shush.se","sj-r.com","slant.co","sms24.me","so1.asia","splay.id","sport.de","sport.es","sport.pl","spox.com","sptfy.be","stern.de","stfly.me","strtpe.*","svapo.it","swdw.net","swzz.xyz","sxsw.com","sxyprn.*","t20cup.*","t7meel.*","tasma.ru","tbib.org","tele5.de","thegay.*","thekat.*","thoptv.*","tirexo.*","tmearn.*","tobys.dk","today.it","toggo.de","tokfm.pl","trakt.tv","trend.at","trrs.pro","tubeon.*","tubidy.*","turbo.cr","turbo.fr","tv.wp.pl","tv247.us","tvepg.eu","tvn24.pl","tvnet.lv","txst.com","udvl.com","uiil.ink","upapk.io","uproxy.*","uqload.*","urbia.de","uvnc.com","v.qq.com","vanime.*","vapley.*","vedbam.*","vedbom.*","vembed.*","venge.io","vibe.com","vid4up.*","vidlo.us","vidlox.*","vidsrc.*","vidup.to","viki.com","vipbox.*","viper.to","viprow.*","virpe.cc","vlive.tv","voe.sx>>","voici.fr","voxfm.pl","vozer.io","vozer.vn","vtbe.net","vtmgo.be","vtube.to","vumoo.cc","vxxx.com","wat32.tv","watch.ug","wcofun.*","wcvb.com","webbro.*","weloma.*","wepc.com","wetter.*","wfmz.com","wkyc.com","woman.at","work.ink","wowtv.de","wp.solar","wplink.*","wttw.com","wykop.pl","wyze.com","x1337x.*","xcum.com","xh.video","xo7c.com","xvide.me","xxf.mobi","xxr.mobi","xxu.mobi","y2mate.*","yacht.de","yandex.*","yelp.com","yepi.com","youx.xxx","yporn.tv","yt1s.com","yt5s.com","ytapi.cc","ythd.org","z4h4.com","zbporn.*","zdrz.xyz","zee5.com","zooqle.*","zovo.ink","zshort.*","0vg9r.com","10.com.au","10short.*","123av.com","123link.*","123mf9.my","127.0.0.1","18xxx.xyz","1milf.com","1stream.*","2024tv.ru","26efp.com","2conv.com","2glho.org","2kmovie.*","2ndrun.tv","3dzip.org","3movs.com","49ers.com","4share.vn","4stream.*","4tube.com","51sec.org","5flix.top","5mgz1.com","5movies.*","6jlvu.com","7bit.link","7mm003.cc","7starhd.*","9-gld.net","9anime.pe","9hentai.*","9xbuddy.*","9xmovie.*","a-o.ninja","a2zapk.io","aagag.com","aagmaal.*","abcya.com","acortar.*","adcorto.*","adobe.com","adsfly.in","adshort.*","adurly.cc","aduzz.com","afk.guide","agar.live","ah-me.com","aikatu.jp","airtel.in","alphr.com","ameblo.jp","ampav.com","andyday.*","anidl.org","animekb.*","animesa.*","anitube.*","aniwave.*","anizm.net","apkmb.com","apkmody.*","apl373.me","apl374.me","apl375.me","appdoze.*","apple.com","appvn.com","aram.zone","arc018.to","arcai.com","art19.com","artru.net","asd.homes","astral.sh","atlaq.com","atomohd.*","avtub.*>>","awafim.tv","aylink.co","azel.info","azmen.com","azrom.net","azure.com","bakai.org","bdlink.pw","beeg.fund","befap.com","bflix.*>>","bhplay.me","bibme.org","bigwarp.*","biqle.com","bitfly.io","bitlk.com","blackd.de","blkom.com","blog24.me","blogk.com","bmovies.*","boerse.de","bolly4u.*","boost.ink","brainly.*","btdig.com","buffed.de","busuu.com","c1z39.com","cambabe.*","cambb.xxx","cambro.io","cambro.tv","camcam.cc","camcaps.*","camhub.cc","canela.tv","canoe.com","canva.com","ccurl.net","cda-hd.cc","cdn1.site","cdn77.org","cdrab.com","cfake.com","chatta.it","chess.com","chyoa.com","cinema.de","cinetux.*","cl1ca.com","clamor.pl","claude.ai","clksz.com","cloudy.pk","cmovies.*","colts.com","comunio.*","ctrl.blog","curto.win","cutdl.xyz","cybar.xyz","czxxx.org","d000d.com","d0o0d.com","daddyhd.*","daybuy.tw","debgen.fr","dfast.app","dfiles.eu","dflinks.*","dhd24.com","djmaza.my","djstar.in","djx10.org","dlgal.com","do0od.com","do7go.com","dom.wp.pl","domaha.tv","doods.pro","doooood.*","doply.net","dotflix.*","doviz.com","dropmms.*","dropzy.io","drrtyr.mx","drtuber.*","drzna.com","dumpz.net","dvdplay.*","dx-tv.com","dz4soft.*","dzapk.com","eater.com","echoes.gr","efukt.com","eg4link.*","egybest.*","egydead.*","eltern.de","embedme.*","embedy.me","embtaku.*","emovies.*","enorme.tv","entano.jp","eodev.com","erogen.su","erome.com","eroxxx.us","europix.*","evaki.fun","evo.co.uk","exego.app","expres.cz","eyalo.com","f16px.com","fap16.net","fapnado.*","faps.club","fapxl.com","faselhd.*","fast-dl.*","fbsbx.com","fc-lc.com","feet9.com","femina.ch","ffjav.com","fifojik.*","file4go.*","fileq.net","filma24.*","filmex.to","finfang.*","flixhd.cc","flixhq.ru","flixhq.to","flixhub.*","flixtor.*","flvto.biz","fmj.co.uk","fmovies.*","fooak.com","forsal.pl","foundit.*","foxhq.com","freep.com","freewp.io","frembed.*","frprn.com","fshost.me","ftopx.com","ftuapps.*","fuqer.com","furher.in","fx-22.com","gahag.net","gayck.com","gayfor.us","gayxx.net","gazeta.pl","gazeta.ru","gdirect.*","ggjav.com","gifhq.com","giize.com","gitea.com","glodls.to","gm-db.com","gmanga.me","gofile.to","gojo2.com","gomov.bio","gomoviz.*","goplay.ml","goplay.su","gosemut.*","goshow.tv","gototub.*","goved.org","gowyo.com","goyabu.us","gplinks.*","gry.wp.pl","gsdn.live","gsm1x.xyz","guum5.com","gvnvh.net","hanime.tv","happi.com","haqem.com","hax.co.id","hd-xxx.me","hdfilme.*","hdgay.net","hdhub4u.*","hdrez.com","hdss-to.*","heavy.com","hellnaw.*","hentai.tv","hh3dhay.*","hhesse.de","hianime.*","hideout.*","hitomi.la","hmt6u.com","hoca2.com","hoca6.com","hoerzu.de","hojii.net","hokej.net","hothit.me","hotmovs.*","hugo3c.tw","huyamba.*","hxfile.co","i-bits.io","ibooks.to","icdrama.*","iceporn.*","idpvn.com","ihow.info","ihub.live","ikaza.net","ilinks.in","imeteo.sk","img4fap.*","imgmaze.*","imgrock.*","imgtown.*","imgur.com","imgview.*","imslp.org","ingame.de","intest.tv","inwepo.co","iobit.com","iprima.cz","iqiyi.com","ireez.com","isohunt.*","janjua.tv","jappy.com","jasmr.net","javboys.*","javcl.com","javct.net","javdoe.sh","javfor.tv","javfun.me","javhat.tv","javhd.*>>","javmix.tv","javpro.cc","javsub.my","javup.org","javwide.*","javxxx.me","jkanime.*","job.mt.de","job.nw.de","jootc.com","kagane.to","kali.wiki","karwan.tv","katfile.*","keepvid.*","ki24.info","kick4ss.*","kickass.*","kicker.de","kinob.net","kinoger.*","kissjav.*","klmanga.*","koora.vip","krx18.com","kuyhaa.me","kzjou.com","l2db.info","l455o.com","lecker.de","legia.net","lenkino.*","lep.co.uk","lesoir.be","linkfly.*","liveru.sx","ljcam.net","lkc21.net","lmtos.com","lnk.parts","loader.fo","loader.to","loawa.com","localhost","lodynet.*","lohud.com","lookcam.*","lootup.me","los40.com","m.kuku.lu","m1xdrop.*","m4ufree.*","magma.com","magmix.jp","mamadu.pl","mangaku.*","manhwas.*","maniac.de","mapple.tv","marca.com","mavplay.*","mboost.me","mc-at.org","mcrypto.*","mega4up.*","merkur.de","messen.de","mfw09.org","mgnet.xyz","mgread.io","mhn.quest","milfnut.*","miniurl.*","mitele.es","mixdrop.*","mkvcage.*","mkvpapa.*","mlbbox.me","mlive.com","mmo69.com","mobile.de","mod18.com","momzr.com","mov2day.*","mp3clan.*","mp3fy.com","mp3spy.cc","mp3y.info","mrgay.com","mrjav.net","multi.xxx","mxcity.mx","myaew.com","mynet.com","mz-web.de","nbabox.co","ncdnstm.*","nekopoi.*","netcine.*","neuna.net","news38.de","nhentai.*","niadd.com","nikke.win","nkiri.com","nknews.jp","notion.so","nowgg.lol","noxx.to>>","nozomi.la","npodoc.nl","nxxn.live","nyaa.land","nydus.org","oatuu.org","obsev.com","ocala.com","ocnpj.com","ofiii.com","ofppt.net","ohmymag.*","ok-th.com","okanime.*","okblaz.me","omavs.com","oosex.net","opjav.com","orunk.com","owlzo.com","oxxfile.*","pahe.plus","palabr.as","palimas.*","pasteit.*","pastes.io","pcwelt.de","pelis28.*","pepar.net","pferde.de","phodoi.vn","phois.pro","picrew.me","pixhost.*","pkembed.*","player.pl","plotek.pl","plylive.*","pogga.org","popjav.in","porn720.*","porner.tv","pornfay.*","pornhat.*","pornhub.*","pornj.com","pornlib.*","porno18.*","pornuj.cz","powvdeo.*","premio.io","profil.at","proton.me","psarips.*","publio.pl","pugam.com","pussy.org","pynck.com","q1003.com","qcheng.cc","qcock.com","qlinks.eu","qoshe.com","quizz.biz","radio.net","rarbg.how","rdembed.*","readm.org","redd.tube","redisex.*","redtube.*","redwap.me","remaxhd.*","rentry.co","rexporn.*","rexxx.org","rfiql.com","ridge.com","rjno1.com","rock.porn","rokni.xyz","rooter.gg","rophimz.*","rphost.in","rshrt.com","ruhr24.de","rytmp3.io","s2dfree.*","saint2.cr","samfw.com","sat24.com","satdl.com","sbnmp.bar","sbplay2.*","sbplay3.*","sbsun.com","scat.gold","seazon.fr","seelen.io","seexh.com","series9.*","seulink.*","sexmv.com","sexsq.com","sextb.*>>","sezia.com","sflix.pro","shape.com","shlly.com","shmapp.ca","shorten.*","shrdsk.me","shrib.com","shrinke.*","shrtfly.*","skardu.pk","skpb.live","skysetx.*","slate.com","slink.bid","smutr.com","son.co.za","songspk.*","spcdn.xyz","sport1.de","srnky.com","sssam.com","ssstik.io","staige.tv","stly.link","strms.net","strmup.cc","strmup.to","strmup.ws","strtape.*","study.com","stvid.com","sulasok.*","swame.com","syosetu.*","sythe.org","szene1.at","talaba.su","tamilmv.*","taming.io","tatli.biz","tech5s.co","teensex.*","terabox.*","tfly.link","themw.com","thesun.ie","thgss.com","thothd.to","thothub.*","tinhte.vn","tnp98.xyz","to.com.pl","today.com","todaypk.*","tojav.net","topflix.*","topjav.tv","torlock.*","tpaste.io","tpayr.xyz","tpz6t.com","trutv.com","tubev.sex","tubexo.tv","tukoz.com","turbo1.co","tvguia.es","tvinfo.de","tvlogy.to","tvporn.cc","twitch.tv","txori.com","txxx.asia","ucptt.com","udebut.jp","ufacw.com","uflash.tv","ujszo.com","ulsex.net","unicum.de","upbam.org","upbolt.to","upfiles.*","upiapi.in","uplod.net","uporn.icu","upornia.*","uppit.com","uproxy2.*","upxin.net","upzone.cc","uqload.co","uqozy.com","urlcero.*","ustream.*","uxjvp.pro","v1kkm.com","vdtgr.com","vebo1.com","veedi.com","vg247.com","vid2faf.*","vidara.so","vidara.to","vidbm.com","vidbox.vc","vide0.net","videobb.*","vidfast.*","vidmoly.*","vidneo.cc","vidplay.*","vidzy.org","vienna.at","vimeo.com","vinaurl.*","vinovo.to","vipurl.in","vladan.fr","vnuki.net","vogue.com","voodc.com","vplink.in","vsembed.*","vtlinks.*","vttpi.com","vvid30c.*","vvvvid.it","w3cub.com","webex.com","webmaal.*","webtor.io","wecast.to","weebee.me","wetter.de","wildwap.*","winporn.*","wiour.com","wired.com","woiden.id","world4.eu","wpteq.org","wvt24.top","www.wp.pl","x-tg.tube","x24.video","xbaaz.com","xbabe.com","xca.cymru","xcafe.com","xcity.org","xcoic.com","xcums.com","xecce.com","xexle.com","xfeed.com","xhand.com","xhbig.com","xmovies.*","xpaja.net","xtapes.me","xvideos.*","xvipp.com","xxx24.vip","xxxhub.cc","xxxxxx.hu","y2down.cc","yahoo.com","yeptube.*","yeshd.net","ygosu.com","yjiur.xyz","ymovies.*","youku.com","younetu.*","youporn.*","yt2mp3s.*","ytmp3s.nu","ytpng.net","ytsaver.*","yu2be.com","zataz.com","zdnet.com","zedge.net","zefoy.com","zhihu.com","zjet7.com","zojav.com","zokaj.com","zovo2.top","zrozz.com","0gogle.com","0gomovie.*","10starhd.*","123anime.*","123chill.*","13tv.co.il","141jav.com","18tube.sex","1apple.xyz","1bit.space","1kmovies.*","1link.club","1stream.eu","1tamilmv.*","1todaypk.*","2best.club","2the.space","2umovies.*","3dzip.info","3fnews.com","3hiidude.*","3kmovies.*","3xyaoi.com","4-liga.com","444.coffee","4kporn.xxx","4porn4.com","4tests.com","4tube.live","5ggyan.com","5xmovies.*","720pflix.*","8boobs.com","8muses.xxx","8xmovies.*","91porn.com","96ar.com>>","9908ww.com","9anime.vip","9animes.ru","9kmovies.*","9monate.de","9xmovies.*","9xupload.*","a1movies.*","acefile.co","acortalo.*","adshnk.com","adslink.pw","aeonax.com","aether.mom","afdah2.com","akmcloud.*","all3do.com","allfeeds.*","alphatv.gr","amboss.com","ameede.com","amindi.org","anchira.to","andani.net","anime4up.*","animedb.in","animeflv.*","animeid.tv","animesup.*","animetak.*","animez.org","anitube.us","aniwatch.*","aniwave.uk","anodee.com","anon-v.com","anroll.net","ansuko.net","antenne.de","anysex.com","apkhex.com","apkmaven.*","apkmody.io","arabseed.*","archive.fo","archive.is","archive.li","archive.md","archive.ph","archive.vn","arcjav.com","areadvd.de","aruble.net","asiansex.*","asiaon.top","asmroger.*","ate9ni.com","atishmkv.*","atomixhq.*","atomtt.com","av01.media","avjosa.com","avtub.cx>>","awpd24.com","axporn.com","ayuka.link","aznude.com","babeporn.*","baikin.net","bakotv.com","balbums.st","bandle.app","bang14.com","bayimg.com","bblink.com","bbw.com.es","bdjobs.com","bdokan.com","bdsmx.tube","bdupload.*","beatree.cn","beeg.party","beeimg.com","bembed.net","bestcam.tv","bigten.org","bildirim.*","bloooog.it","bluetv.xyz","bnnvara.nl","boards.net","boombj.com","borwap.xxx","bos21.site","boyfuck.me","brd.edu.pl","brian70.tw","brides.com","brillen.de","brmovies.*","brstej.com","btvplus.bg","byrdie.com","bztube.com","caller.com","calvyn.com","camflow.tv","camfox.com","camhoes.tv","camseek.tv","canada.com","capital.de","capital.fr","cashkar.in","cavallo.de","cboard.net","cdn256.xyz","ceesty.com","cekip.site","cerdas.com","cgtips.org","chad.co.uk","chiefs.com","chrome.com","ciberdvd.*","cimanow.cc","cinehd.app","cinemar.cc","cityam.com","citynow.it","ckxsfm.com","claude.com","cluset.com","codare.fun","code.world","cola16.app","colearn.id","comtasq.ca","connect.de","cookni.net","costco.com","cpscan.xyz","creatur.io","cricfree.*","cricfy.net","crictime.*","crohasit.*","csrevo.com","cuatro.com","cubshq.com","cuckold.it","cuevana.is","cuevana3.*","cutnet.net","cuttty.com","cwseed.com","d0000d.com","ddownr.com","deezer.com","demooh.com","depedlps.*","desiflix.*","desimms.co","desired.de","destyy.com","dev2qa.com","dfbplay.tv","diaobe.net","dilar.tube","disqus.com","djamix.net","djxmaza.in","dloady.com","dnevnik.hr","do-xxx.com","dogecoin.*","dojing.net","domahi.net","donk69.com","doodle.com","dopebox.to","dorkly.com","downev.com","dpstream.*","drakkar.st","drivebot.*","driveup.in","driving.ca","drphil.com","ds.163.com","dtmaga.com","dvm360.com","dz4up1.com","eadt.co.uk","earncash.*","earnload.*","easysky.in","ebc.com.br","ebony8.com","ebookmed.*","ebuxxx.net","edmdls.com","egyup.live","elmundo.es","embed.casa","embedv.net","emsnow.com","emurom.net","epainfo.pl","eplayvid.*","eplsite.uk","erofus.com","erotom.com","eroxia.com","evileaks.*","evojav.pro","ewybory.eu","exeygo.com","exnion.com","express.de","f1livegp.*","f1stream.*","f2movies.*","f4scdn.com","fabmx1.com","fakaza.com","fake-it.ws","falpus.com","familie.de","fandom.com","fapcat.com","fapdig.com","fapeza.com","fapset.com","faqwiki.us","fastly.net","fautsy.com","fboxtv.com","fbstream.*","festyy.com","ffmovies.*","fhedits.in","fikfak.net","fikiri.net","fikper.com","filedown.*","filemoon.*","fileone.tv","filesq.net","filester.*","film.wp.pl","film1k.com","film4e.com","filmi7.net","filmo.to>>","filmovi.ws","filmweb.pl","filmyfly.*","filmygod.*","filmyhit.*","filmypur.*","filmywap.*","finanzen.*","finclub.in","fitbook.de","flickr.com","flixbaba.*","flixhub.co","flybid.net","fmembed.cc","forgee.xyz","formel1.de","foxnxx.com","freeload.*","freenet.de","freevpn.us","friars.com","frogogo.ru","fsplayer.*","fstore.biz","fuckdy.com","fullreal.*","fulltube.*","fullxh.com","funzen.net","funztv.com","fuxnxx.com","fxporn69.*","fzmovies.*","gadgets.es","game5s.com","gamenv.net","gamepro.de","gamezop.io","gatcha.org","gawbne.com","gaydam.net","gcinee.com","gcloud.cfd","gdfile.org","gdmax.site","gdplayer.*","gentside.*","gestyy.com","giants.com","gifans.com","giff.cloud","gigaho.com","github.com","gitlab.com","givee.club","gkbooks.in","gkgsca.com","gleaks.pro","gledaitv.*","gmenhq.com","gnomio.com","go.tlc.com","gocast.pro","gochyu.com","goduke.com","goeags.com","goegoe.net","goerie.com","gofilmes.*","goflix.sbs","gogodl.com","gogoplay.*","gogriz.com","gomovies.*","google.com","gopack.com","gostream.*","goutsa.com","gozags.com","gozips.com","gplinks.co","grasta.net","gtaall.com","gunauc.net","haddoz.net","hamburg.de","hamzag.com","hanauer.de","hanime.xxx","hao123.com","hardsex.cc","hartico.tv","haustec.de","haxina.com","hcbdsm.com","hclips.com","hd-tch.com","hdfriday.*","hdporn.net","hdtoday.cc","hdtoday.tv","hdzone.org","health.com","hechos.net","hentaihd.*","hentaisd.*","hextank.io","hhkungfu.*","hianime.to","himovies.*","hitprn.com","hivelr.com","hl-live.de","hoca4u.com","hoca4u.xyz","hochi.news","hostxy.com","hotmasti.*","hotovs.com","house.porn","how2pc.com","howifx.com","hqbang.com","huavod.com","huavod.net","huavod.top","hub2tv.com","hubcdn.vip","hubdrive.*","huoqwk.com","hydracdn.*","icegame.ro","iceporn.tv","idevice.me","idlixvip.*","igay69.com","illink.net","ilmeteo.it","imag-r.com","imgair.net","imgbox.com","imgbqb.sbs","imginn.com","imgmgf.sbs","imgpke.sbs","imguee.sbs","indeed.com","indoav.app","indoav.com","indobo.com","inertz.org","infulo.com","ingles.com","ipamod.com","iplark.com","ironysub.*","isbn.co.in","isgfrm.com","issuya.com","itdmusic.*","iumkit.net","iusm.co.kr","iwcp.co.uk","jakondo.ru","japgay.com","japscan.ws","jav-fun.cc","jav.direct","jav247.top","jav380.com","javbee.vip","javbix.com","javboys.tv","javbull.tv","javdo.cc>>","javembed.*","javfan.one","javfav.com","javfc2.xyz","javgay.com","javhdz.*>>","javhub.net","javhun.com","javlab.net","javmix.app","javmvp.com","javneon.tv","javnew.net","javopen.co","javpan.net","javpas.com","javplay.me","javqis.com","javrip.net","javroi.com","javseen.tv","javsek.net","jnews5.com","jobsbd.xyz","joktop.com","joolinks.*","josemo.com","jpgames.de","jpvhub.com","jrlinks.in","kaamuu.cfd","kaliscan.*","kamelle.de","kaotic.com","kaplog.com","katlinks.*","kedoam.com","keepvid.pw","kejoam.com","kelaam.com","kendam.com","kenzato.uk","kerapoxy.*","keroseed.*","key-hub.eu","kiaclub.cz","kickass2.*","kickasst.*","kickassz.*","kickbd.org","king-pes.*","kinobox.cz","kinoger.re","kinoger.ru","kinoger.to","kjmx.rocks","kkickass.*","klooam.com","klyker.com","kochbar.de","kompas.com","kompiko.pl","kotaku.com","kropic.com","kvador.com","kxbxfm.com","labgame.io","lacrima.jp","larazon.es","lasisa.net","ldnews.com","leakav.com","leeapk.com","leechall.*","leet365.cc","leolist.cc","lewd.ninja","lglbmm.com","lidovky.cz","likecs.com","line25.com","link1s.com","linkbin.me","linkpoi.me","linkshub.*","linkskat.*","linksly.co","linkspy.cc","linkz.wiki","liquor.com","listatv.pl","live7v.com","livehere.*","livetvon.*","lollty.pro","lookism.me","lootdest.*","lopers.com","love4u.net","loveroms.*","lulust.com","lumens.com","lustich.de","lxmanga.my","m2list.com","macwelt.de","magnetdl.*","mahfda.com","mandai.com","mangago.me","mangaraw.*","mangceh.cc","manwan.xyz","mascac.org","mat6tube.*","mathdf.com","maths.news","maxicast.*","mdplay.top","medibok.se","megadb.net","megadede.*","megaflix.*","megalink.*","megaup.net","megaxh.com","meltol.net","meong.club","merinfo.se","meteox.com","mhdtvmax.*","miixdrop.*","milfzr.com","mistral.ai","mitaku.net","mixdroop.*","mlbb.space","mma-core.*","mmnm.store","mmopeon.ru","mmtv01.xyz","molotov.tv","mongri.net","motchill.*","moto.wp.pl","movie123.*","movie4me.*","moviegan.*","moviehdf.*","moviemad.*","movies07.*","movies2k.*","movies4u.*","movies7.to","moviflex.*","movix.blog","mozkra.com","mp3cut.net","mp3guild.*","mp3juice.*","mpnnow.com","mreader.co","mrpiracy.*","mtlurb.com","mult34.com","multics.eu","multiup.eu","multiup.io","musichq.cc","my-subs.co","mydaddy.cc","myjest.com","mykhel.com","mylust.com","myplexi.fr","myqqjd.com","myvideo.ge","myviid.com","naasongs.*","nackte.com","naijal.com","nakiny.com","namasce.pl","namemc.com","napmap.net","natalie.mu","natfrp.com","nbabite.to","nbaup.live","ncdnx3.xyz","negumo.com","neonmag.fr","neoteo.com","neowin.net","netfree.cc","newhome.de","newpelis.*","news18.com","newser.com","nexdrive.*","nflbite.to","ngelag.com","ngomek.com","ngomik.net","nhentai.io","nickles.de","ninguno.cc","niyaniya.*","nmovies.cc","noanyi.com","nocfsb.com","nohost.one","nosteam.ro","note1s.com","notube.com","novinky.cz","noz-cdn.de","nsfw247.to","ntucgm.com","nudes7.com","nullpk.com","nuroflix.*","nxbrew.net","nxprime.in","nypost.com","odporn.com","odtmag.com","ofwork.net","ohorse.com","ohueli.net","okleak.com","okmusi.com","okteve.com","onehack.us","oneotv.com","onepace.co","onepunch.*","onezoo.net","onloop.pro","onmovies.*","onvista.de","openload.*","oploverz.*","origami.me","orirom.com","otomoto.pl","owsafe.com","paminy.com","papafoot.*","parade.com","parents.at","pbabes.com","pc-guru.it","pcbeta.com","pcgames.de","pctfenix.*","pcworld.es","pdfaid.com","peetube.cc","people.com","petbook.de","phc.web.id","phim85.com","picmsh.sbs","pictoa.com","pidlio.com","pilsner.nu","pingit.com","pinkun.com","pirlotv.mx","pitube.net","pixelio.de","pixvid.org","pjstar.com","plaion.com","planeta.pl","planhub.ca","playboy.de","playfa.com","playgo1.cc","plc247.com","plejada.pl","poapan.xyz","pondit.xyz","poophq.com","popcdn.day","poplinks.*","poranny.pl","porn00.org","porndr.com","pornfd.com","porngo.com","porngq.com","pornhd.com","pornhd8k.*","pornky.com","porntb.com","porntn.com","pornve.com","pornwex.tv","pornx.tube","pornxp.com","pornxp.org","pornxs.com","pouvideo.*","povvideo.*","povvldeo.*","povw1deo.*","povwideo.*","powder.com","powlideo.*","powv1deo.*","powvibeo.*","powvideo.*","powvldeo.*","premid.app","progfu.com","prosongs.*","proxybit.*","proxytpb.*","prydwen.gg","psychic.de","ptztv.live","pudelek.pl","puhutv.com","putlog.net","qqxnxx.com","qrixpe.com","qthang.net","quicomo.it","radio.zone","raenonx.cc","rakuten.tv","rambler.ru","ranker.com","rawinu.com","rawlazy.si","realgm.com","rebahin.pw","reddit.com","redfea.com","redgay.net","reeell.com","regio7.cat","rencah.com","reshare.pm","rgeyyddl.*","rgmovies.*","riazor.org","rlxoff.com","rmdown.com","roblox.com","rodude.com","romsget.io","ronorp.net","roshy.tv>>","rrstar.com","rsrlink.in","rule34.art","rule34.xxx","rule34.xyz","rule34ai.*","rumahit.id","s1p1cd.com","s2dfree.to","s3taku.com","sakpot.com","salina.com","samash.com","sanblo.com","savego.org","sawwiz.com","sbrity.com","sbs.com.au","scribd.com","sctoon.net","scubidu.eu","seeflix.to","serien.cam","seriesly.*","sevenst.us","sexato.com","sexjobs.es","sexkbj.com","sexlist.tv","sexodi.com","sexpin.net","sexpox.com","sexrura.pl","sextor.org","sextvx.com","sfile.mobi","shahid4u.*","shinden.pl","shineads.*","shlink.net","sholah.net","shophq.com","shorttey.*","shortx.net","shortzzy.*","showflix.*","shrink.icu","shrinkme.*","shrt10.com","sibtok.com","sikwap.xyz","silive.com","simpcity.*","skinmc.net","skmedix.pl","smoner.com","smsget.net","snbc13.com","snopes.com","snowmtl.ru","soap2day.*","socebd.com","sohot.cyou","sokobj.com","solewe.com","sourds.net","soy502.com","spaste.com","spiegel.de","spielen.de","sportal.de","sportbar.*","sports24.*","srvy.ninja","ssdtop.com","sshkit.com","ssyou.tube","stardima.*","stemplay.*","stiletv.it","stpm.co.uk","strcloud.*","streamsb.*","streamta.*","strefa.biz","stripe.com","suaurl.com","sunhope.it","surfer.com","szene38.de","tapetus.pl","target.com","taxi69.com","tcpalm.com","tcpvpn.com","tech.wp.pl","tech8s.net","techhx.com","telerium.*","texte.work","th-cam.com","thatav.net","theacc.com","thecut.com","thedaddy.*","theproxy.*","thevidhd.*","thosa.info","thothd.com","thripy.com","tickzoo.tv","tiktok.com","tiscali.it","tmnews.com","tokuvn.com","tokuzl.net","toorco.com","topito.com","toppng.com","torlock2.*","torrent9.*","tranny.one","trust.zone","trzpro.com","tsubasa.im","tsz.com.np","tubesex.me","tubous.com","tubsexer.*","tubtic.com","tugaflix.*","tulink.org","tumblr.com","tunein.com","turbovid.*","tutelehd.*","tutsnode.*","tutwuri.id","tuxnews.it","tv0800.com","tvline.com","tvnz.co.nz","tvtoday.de","twatis.com","twihub.net","uctnew.com","uindex.org","uiporn.com","unito.life","uol.com.br","up-load.io","upbaam.com","updato.com","updown.cam","updown.fun","updown.icu","upfion.com","upicsz.com","uplinkto.*","uploadev.*","uploady.io","uporno.xxx","uprafa.com","ups2up.fun","upskirt.tv","uptobhai.*","uptomega.*","urlpay.net","usagoals.*","userload.*","usgate.xyz","usnews.com","ustimz.com","ustream.to","utreon.com","uupbom.com","vadbam.com","vadbam.net","vadbom.com","vcloud.lol","vcstar.com","vdbtm.shop","vecloud.eu","veganab.co","veplay.top","vevioz.com","vgames.fun","vgmlinks.*","vidapi.xyz","vidbam.org","vidbox.dev","vidcloud.*","vidcorn.to","vidembed.*","videyx.cam","videzz.net","vidlii.com","vidnest.io","vidohd.com","vidomo.xyz","vidoza.net","vidply.com","viduro.top","viduyy.com","viewfr.com","vipboxtv.*","vipotv.com","vipstand.*","vivatube.*","vizcloud.*","vod.tvp.pl","vortez.net","vrporn.com","vscode.dev","vstream.id","vvide0.com","vvtlinks.*","wapkiz.com","warezcdn.*","warps.club","watch32.sx","watch4hd.*","watcho.com","watchug.to","watchx.top","wawacity.*","weather.us","web1s.asia","webcafe.bg","weshare.is","weszlo.com","wetter.com","wetter3.de","wikwiki.cv","wintub.com","woiden.com","wooflix.tv","worder.cat","woxikon.de","ww9g.com>>","www.cc.com","x-x-x.tube","xanimu.com","xasiat.com","xberuang.*","xhamster.*","xhopen.com","xhspot.com","xhtree.com","xhvid1.com","xiaopan.co","xmorex.com","xmovie.pro","xmovies8.*","xnxx.party","xpicse.com","xprime4u.*","xprivo.com","xrares.com","xsober.com","xspiel.com","xsz-av.com","xszav.club","xvideis.cc","xxgasm.com","xxmovz.com","xxxdan.com","xxxfiles.*","xxxmax.net","xxxrip.net","xxxsex.pro","xxxtik.com","xxxtor.com","xxxxsx.com","y-porn.com","y2mate.com","y2tube.pro","ymknow.xyz","yomovies.*","youapk.net","youmath.it","youpit.xyz","youwatch.*","yseries.tv","ystream.id","ytanime.tv","ytboob.com","ytjar.info","ytmp4.live","yts-subs.*","yumacs.com","yuppow.com","yuvutu.com","yy1024.net","z12z0vla.*","zeefiles.*","zilinak.sk","zillow.com","zoechip.cc","zoechip.gg","zpaste.net","zthots.com","0123movie.*","0gomovies.*","0rechner.de","10alert.com","111watcho.*","11xmovies.*","123animes.*","123movies.*","12thman.com","141tube.com","173.249.8.3","17track.net","18comic.vip","1movieshd.*","2gomovies.*","2rdroid.com","3bmeteo.com","3d-porn.org","3dyasan.com","3hentai.net","3xfaktor.hu","423down.com","4funbox.com","4gousya.net","4players.de","4pornhd.com","4shared.com","4spaces.org","4tymode.win","5j386s9.sbs","69games.xxx","7review.com","7starmv.com","80-talet.se","8tracks.com","9animetv.to","9goals.live","9jarock.org","a-hentai.tv","aagmaal.com","abs-cbn.com","abstream.to","ad-doge.com","ad4msan.com","adictox.com","adisann.com","adshrink.it","afilmywap.*","africue.com","afrodity.sk","ahmedmode.*","aiailah.com","aipebel.com","akirabox.to","allkpop.com","almofed.com","almursi.com","altcryp.com","alttyab.net","analdin.com","anavidz.com","and-more.co","andiim3.com","anibatch.me","anichin.top","anigogo.net","anihq.org>>","animahd.com","anime-i.com","anime3d.xyz","animeblix.*","animecix.tv","animehay.tv","animehub.ac","animepahe.*","animesex.me","anisaga.org","anitube.vip","aniwixi.xyz","aniworld.to","anomize.xyz","anonymz.com","anxcinema.*","anyporn.com","anysex.club","aofsoru.com","aosmark.com","apkdink.com","apkhihe.com","apkshrt.com","apksvip.com","aplus.my.id","app.plex.tv","apritos.com","aquipelis.*","arabstd.com","arabxnx.com","arakpop.net","arbweb.info","area51.porn","arenabg.com","arkadmin.fr","artnews.com","asia2tv.com","asianal.xyz","asiangay.tv","asianload.*","asianplay.*","ask4movie.*","asmr18.fans","asmwall.com","asumesi.com","ausfile.com","auszeit.bio","autobild.de","autokult.pl","automoto.it","autopixx.de","autoroad.cz","autosport.*","avanti24.pl","avcesar.com","avitter.net","axomtube.in","ayatoon.com","azmath.info","azmovies.to","b2bhint.com","b4ucast.com","babaktv.com","babeswp.com","babyclub.de","badjojo.com","badtaste.it","barfuck.com","batcave.biz","batman.city","bbwfest.com","bcmanga.com","bdcraft.net","bdmusic23.*","bdmusic28.*","bdsmporn.cc","beelink.pro","beinmatch.*","bengals.com","berich8.com","berklee.edu","bfclive.com","bg-gledai.*","bi-girl.net","bigconv.com","bigojav.com","bigshare.io","bigwank.com","bikemag.com","bitco.world","bitlinks.pw","bitzite.com","blavity.com","blogue.tech","blu-ray.com","blurayufr.*","bokepxv.com","bolighub.dk","bollyflix.*","book18.fans","bootdey.com","botrix.live","bowfile.com","boxporn.net","braflix.win","brbeast.com","brbushare.*","brigitte.de","bristan.com","browser.lol","bsierad.com","btcbitco.in","btvsport.bg","btvsports.*","buondua.com","buzzfeed.at","buzzfeed.de","buzzpit.net","bx-zone.com","bypass.city","bypass.link","cafenau.com","camclips.tv","camsclips.*","camslib.com","camwhores.*","canaltdt.es","carbuzz.com","ch-play.com","chatgbt.one","chatgpt.com","chefkoch.de","chicoer.com","chochox.com","cima-club.*","cinecloud.*","cinefreak.*","civicxi.com","civitai.com","civitai.red","claimrbx.gg","clapway.com","clkmein.com","cloubix.com","cloudfam.io","club386.com","cocorip.net","coinclix.co","coldfrm.org","collater.al","colnect.com","comicxxx.eu","commands.gg","comnuan.com","comohoy.com","converto.io","coomer1.net","corneey.com","corriere.it","cpmlink.net","cpmlink.pro","crackle.com","crazydl.net","crdroid.net","criczop.com","crvsport.ru","csurams.com","cubuffs.com","cuevana.pro","cupra.forum","cut-fly.com","cutearn.net","cutlink.net","cutpaid.com","cutyion.com","daddyhd.*>>","daddylive.*","daftsex.biz","daftsex.net","daftsex.org","daij1n.info","daily.co.jp","dailyweb.pl","damitv.live","daozoid.com","datadoghq.*","ddlvalley.*","decider.com","decrypt.day","deltabit.co","devotag.com","dexerto.com","digit77.com","digitask.ru","direct-dl.*","discord.com","disheye.com","diudemy.com","divxtotal.*","dj-figo.com","djqunjab.in","dlpanda.com","dlstreams.*","dma-upd.org","dogdrip.net","donlego.com","dotycat.com","doumura.com","douploads.*","downsub.com","dozarte.com","dramacool.*","dramamate.*","dramanice.*","drawize.com","droplink.co","ds2play.com","dsharer.com","dstat.space","dsvplay.com","duboku.info","dudefilms.*","dz4link.com","dziennik.pl","e-glossa.it","earnbee.xyz","earnhub.net","easy-coin.*","easybib.com","ebookdz.com","echiman.com","echodnia.eu","ecomento.de","edjerba.com","edp24.co.uk","eductin.com","edziecko.pl","einthusan.*","elahmad.com","embasic.pro","embedhd.org","embedmoon.*","embedpk.net","embedtv.net","empflix.com","emuenzen.de","enagato.com","eoreuni.com","eporner.com","eroasmr.com","erothots.co","erowall.com","esgeeks.com","eshentai.tv","eskarock.pl","eslfast.com","europixhd.*","everand.com","everia.club","everyeye.it","exalink.fun","exeking.top","exeporn.net","ezmanga.net","f51rm.com>>","facet.wp.pl","fapdrop.com","fapguru.com","faptube.com","farescd.com","fastdokan.*","fastream.to","fastssh.com","fbstream.is","fbstreams.*","fchopin.net","feedzop.com","fembedx.top","feyorra.top","fffmovies.*","figtube.com","file-me.top","file-up.org","file4go.com","file4go.net","filecloud.*","filecrypt.*","filelions.*","filemooon.*","filepress.*","fileq.games","filesamba.*","filmcdn.top","filmez.club","filmisub.cc","films5k.com","filmy-hit.*","filmy4web.*","filmydown.*","filmygod6.*","findjav.com","firefile.cc","fit4art.com","flixrave.me","flixsix.com","fluentu.com","fluvore.com","fmovies0.cc","fmoviesto.*","folkmord.se","foodxor.com","footybite.*","forumdz.com","fosters.com","foumovies.*","foxtube.com","freenem.com","freepik.com","frpgods.com","fseries.org","fsx.monster","ftuapps.dev","fuckfuq.com","futemax.zip","g-porno.com","gal-dem.com","gamcore.com","game-2u.com","game3rb.com","gameblog.in","gameblog.jp","gamedrive.*","gamehub.cam","gamelab.com","gamer18.net","gamestar.de","gameswelt.*","gametop.com","gamewith.jp","gamezone.de","gamezop.com","garaveli.de","gaytail.com","gayvideo.me","gazzetta.gr","gazzetta.it","gcloud.live","gedichte.ws","genialne.pl","genpick.app","get-to.link","getmega.net","getthit.com","gevestor.de","gezondnu.nl","ggbases.com","girlmms.com","girlshd.xxx","gisarea.com","gitizle.vip","gizmodo.com","glianec.com","globetv.app","go.fakta.id","go.zovo.ink","goalup.live","gobison.com","gocards.com","gocast2.com","godeacs.com","godmods.com","godtube.com","goducks.com","gofilms4u.*","gofrogs.com","gogifox.com","gogoanime.*","goheels.com","gojacks.com","gokerja.net","gold-24.net","golobos.com","gomovies.pk","gomoviesc.*","goodporn.to","gooplay.net","gorating.in","gosexy.mobi","gostyn24.pl","goto.com.np","gotocam.net","gotporn.com","govexec.com","grafikos.cz","gsmware.com","guhoyas.com","gulf-up.com","gumtree.com","gupload.xyz","h-flash.com","haaretz.com","hagalil.com","hagerty.com","hardgif.com","hartziv.org","haxmaps.com","haxnode.net","hblinks.pro","hdbraze.com","hdeuropix.*","hdmotori.it","hdonline.co","hdpicsx.com","hdpornt.com","hdtodayz.to","hdtube.porn","helmiau.com","hentai20.io","hentaila.tv","herexxx.com","herzporno.*","hes-goals.*","hexload.com","hhdmovies.*","himovies.sx","hindi.trade","hiphopa.net","history.com","hitokin.net","hmanga.asia","holavid.com","hoofoot.net","hoporno.net","hornpot.net","hornyfap.tv","hornyhill.*","hotabis.com","hotbabes.tv","hotcars.com","hotfm.audio","hotgirl.biz","hotleak.vip","hotleaks.tv","hotscope.tv","hotscopes.*","hotshag.com","hotstar.com","htrnews.com","htsport.org","huaren.live","hubdrive.de","hubison.com","hubstream.*","hubzter.com","hurawatch.*","huskers.com","huurshe.com","hwreload.it","hygiena.com","hypesol.com","icgaels.com","idlixku.com","iegybest.co","iframejav.*","iggtech.com","igorslab.de","iimanga.com","iklandb.com","imageweb.ws","imgbvdf.sbs","imgcloud.pw","imgjjtr.sbs","imgnngr.sbs","imgoebn.sbs","imgoutlet.*","imgtaxi.com","imgyhq.shop","in91vip.win","infocorp.io","infokik.com","inkapelis.*","instyle.com","inverse.com","ipa-apps.me","iporntv.net","iptvbin.com","irunfar.com","isaimini.ca","isosite.org","ispunlock.*","itavisen.no","itpro.co.uk","itudong.com","iv-soft.com","jaguars.com","jaiefra.com","japanfuck.*","japanporn.*","japansex.me","japscan.lol","javbake.com","javball.com","javbobo.com","javboys.com","javcock.com","javdock.com","javdoge.com","javfull.net","javgrab.com","javhoho.com","javideo.net","javlion.xyz","javmenu.com","javmeta.com","javmilf.xyz","javpool.com","javsex.guru","javstor.com","javx357.com","javynow.com","jcutrer.com","jeep-cj.com","jetanimes.*","jetpunk.com","jezebel.com","jkanime.net","jnovels.com","jobnoid.net","jobsibe.com","jocooks.com","jotapov.com","jpg.fishing","jra.jpn.org","jungyun.net","jxoplay.xyz","kaembed.net","karanpc.com","kashtanka.*","kb.arlo.com","khohieu.com","kiaporn.com","kickassgo.*","kiemlua.com","kimoitv.com","kinoking.cc","kissanime.*","kissasia.cc","kissasian.*","kisscos.net","kissmanga.*","kjanime.net","klettern.de","kmansin09.*","kochamjp.pl","kodaika.com","kolyoom.com","komikcast.*","kompoz2.com","kpkuang.org","kppk983.com","ksuowls.com","kumaraw.com","l23movies.*","l2crypt.com","labstory.in","laposte.net","lapresse.ca","lastampa.it","latimes.com","latitude.to","lbprate.com","leaknud.com","letras2.com","lewdweb.net","lewebde.com","lfpress.com","lgcnews.com","lgwebos.com","libertyvf.*","lichess.org","lifeline.de","liflix.site","ligaset.com","likemag.com","linclik.com","link-to.net","linkmake.in","linkrex.net","links-url.*","linksfire.*","linkshere.*","linksmore.*","lite-link.*","loanpapa.in","lokalo24.de","lookimg.com","lookmovie.*","losmovies.*","losporn.org","lostineu.eu","lovefap.com","lscomic.com","luluvdo.com","luluvid.com","luxmovies.*","m.akkxs.net","m.iqiyi.com","m1xdrop.com","m1xdrop.net","m4maths.com","made-by.org","madoohd.com","madouqu.com","magesy.blog","magesypro.*","mamastar.jp","mandiner.hu","manga1000.*","manga1001.*","mangahub.io","mangasail.*","mangatv.net","mangayy.org","manhwa18.cc","maths.media","mature4.net","mavanimes.*","mavavid.com","maxstream.*","mcdlpit.com","mchacks.net","mcloud.guru","mcxlive.org","medisite.fr","mega1080p.*","megafile.io","megavideo.*","mein-mmo.de","melodelaa.*","mephimtv.cc","mercari.com","messitv.net","messitv.org","metavise.in","mgoblue.com","mhdsports.*","mhscans.com","miiixdrop.*","miklpro.com","mirrorace.*","mirrored.to","mlbstream.*","mmfenix.com","mmsmaza.com","mobifuq.com","moenime.com","momomesh.tv","momondo.com","momvids.com","moonembed.*","moonmov.pro","motohigh.pl","motphimr.io","moviebaaz.*","movied.link","movieku.ink","movieon21.*","movieplay.*","movieruls.*","movierulz.*","movies123.*","movies4me.*","movies4u3.*","moviesda4.*","moviesden.*","movieshub.*","moviesjoy.*","moviesmod.*","moviesmon.*","moviesub.is","moviesx.org","moviewr.com","moviezwap.*","movizland.*","mozilla.org","mp3-now.com","mp3juices.*","mp3yeni.org","mp4moviez.*","mpo-mag.com","mr9soft.com","mrexcel.com","mrunblock.*","mtb-news.de","mtlblog.com","muchfap.com","multiup.org","muthead.com","muztext.com","mycloudz.cc","myflixerz.*","mygalls.com","mymp3song.*","mytoolz.net","myunity.dev","myvalley.it","myvidmate.*","myxclip.com","narcity.com","nbabox.co>>","nbastream.*","nbch.com.ar","nbcnews.com","needbux.com","needrom.com","nekopoi.*>>","nelomanga.*","nemenlake.*","neopets.com","netfapx.com","netflix.com","netfuck.net","netplayz.ru","netxwatch.*","netzwelt.de","newscon.org","newsmax.com","nextgov.com","nflbite.com","nflstream.*","nhentai.net","nhlstream.*","nicekkk.com","nichapk.com","nimegami.id","nkreport.jp","notandor.cn","novelism.jp","novohot.com","novojoy.com","nowiny24.pl","nowmovies.*","nrj-play.fr","nsfwr34.com","ntriver.org","nudevista.*","nulakers.ca","nunflix.org","nyahentai.*","nysainfo.pl","odiasia.sbs","ofilmywap.*","ogomovies.*","ohentai.org","ohmymag.com","okstate.com","olarila.com","omuzaani.me","onhockey.tv","onifile.com","onlyfans.to","onneddy.com","ontools.net","onworks.net","optimum.net","ortograf.pl","osxinfo.net","otakudesu.*","otakuindo.*","oubghas.xyz","outletpic.*","overgal.com","overtake.gg","ovester.com","oxanime.com","p2pplay.pro","packers.com","pagesix.com","paketmu.com","papahd.club","papalah.com","paradisi.de","parents.com","parispi.net","pasokau.com","payskip.org","pcbolsa.com","pcgamer.com","pdfdrive.to","pdfsite.net","pelisplus.*","peppe8o.com","perelki.net","pesktop.com","pewgame.com","pezporn.com","phim1080.in","pianmanga.*","picbqqa.sbs","picnft.shop","picngt.shop","picuenr.sbs","pilot.wp.pl","pinkporno.*","pinterest.*","piratebay.*","pistona.xyz","pitiurl.com","pixjnwe.sbs","pixsera.net","pksmovies.*","pkspeed.net","play.tv3.ee","play.tv3.lt","play.tv3.lv","playmate.to","playrust.io","playtamil.*","playtube.tv","plus.rtl.de","pngitem.com","pngreal.com","pogolinks.*","pokopow.com","polygon.com","pomorska.pl","pooembed.eu","porcore.com","porn3dx.com","porn77.info","porn78.info","porndaa.com","porndex.com","porndig.com","porndoe.com","porndude.tv","porngem.com","porngun.net","pornhex.com","pornhub.com","pornkai.com","pornken.com","pornkino.cc","pornktube.*","pornmam.com","pornmom.net","porno-365.*","pornoman.pl","pornomoll.*","pornone.com","pornovka.cz","pornoxo.com","pornpaw.com","pornsai.com","porntin.com","porntry.com","pornult.com","poscitech.*","povvvideo.*","powstream.*","powstreen.*","ppatour.com","primesrc.me","primewire.*","prisjakt.no","promobil.de","pronpic.org","pulpo69.com","pupuweb.com","purplex.app","putlocker.*","pvip.gratis","pxtech.site","qdembed.com","quizack.com","quizlet.com","quizzop.com","radamel.icu","radiozet.pl","raiders.com","rainanime.*","rakuten.com","raw1001.net","rawkuma.com","rawkuma.net","rawkuro.net","readfast.in","readmore.de","realbbc.xyz","recorder.ca","redding.com","redgifs.com","redlion.net","redporno.cz","redtub.live","redwap2.com","redwap3.com","reifporn.de","rekogap.xyz","repelis.net","repelisgt.*","repelishd.*","repelisxd.*","repicsx.com","resetoff.pl","rethmic.com","retrotv.org","reuters.com","reverso.net","riedberg.tv","rimondo.com","rl6mans.com","rlshort.com","roadbike.de","rocklink.in","rogoyume.jp","romfast.com","romsite.org","romviet.com","rphangx.net","rpmplay.xyz","rpupdate.cc","rubystm.com","rubyvid.com","rugby365.fr","rule34h.com","runmods.com","runpane.com","rvguide.com","ryxy.online","s0ft4pc.com","saekita.com","safelist.eu","sandrives.*","sankaku.app","sansat.link","sararun.net","sat1gold.de","satcesc.com","savelinks.*","savemedia.*","savetub.com","sbbrisk.com","sbchill.com","scenedl.org","scenexe2.io","schadeck.eu","sciagnij.pl","scripai.com","sctimes.com","sdefx.cloud","seclore.com","secuhex.com","see-xxx.com","semawur.com","sembunyi.in","sendvid.com","seoworld.in","serengo.net","serially.it","seriemega.*","seriesflv.*","seselah.com","sexavgo.com","sexdiaryz.*","sexemix.com","sexetag.com","sexmoza.com","sexpuss.org","sexrura.com","sexsaoy.com","sexuhot.com","sexygirl.cc","shaheed4u.*","sharclub.in","sharedisk.*","sharing.wtf","shavetape.*","shikotch.in","shortearn.*","shrinkus.tk","shrlink.top","simsdom.com","siteapk.net","sitepdf.com","sixsave.com","smarturl.it","smplace.com","snaptik.app","socks24.org","soft112.com","softrop.com","solobari.it","soninow.com","sonyliv.com","sosuroda.pl","soundpark.*","souqsky.net","southpark.*","spambox.xyz","spankbang.*","speedporn.*","spinbot.com","sporcle.com","sport365.fr","sportbet.gr","sportcast.*","sportlive.*","sportshub.*","spotify.com","spycock.com","srcimdb.com","sreality.cz","ssoap2day.*","ssrmovies.*","staaker.com","stagatv.com","starmusiq.*","steamgg.net","steamplay.*","steanplay.*","sterham.net","stickers.gg","stmruby.com","strcloud.in","streamcdn.*","streamed.su","streamers.*","streamhoe.*","streamhub.*","streamix.so","streamm4u.*","streamup.ws","strikeout.*","strp2p.site","subdivx.com","subedlc.com","submilf.com","subsvip.com","sukuyou.com","sundberg.ws","sushiscan.*","swatalk.com","swtimes.com","t-online.de","tabootube.*","tagblatt.ch","takimag.com","tamilyogi.*","tandess.com","taodung.com","tattle.life","tcheats.com","tdtnews.com","teachoo.com","teamkong.tk","techbook.de","techforu.in","technews.tw","tecnomd.com","telenord.it","teltarif.de","tempr.email","terabox.fun","teralink.me","testedich.*","thapcam.net","thaript.com","the-sun.com","thelanb.com","therams.com","theroot.com","thespun.com","thestar.com","thewhig.com","thisvid.com","thotcity.su","thotporn.tv","thotsbay.tv","threads.com","threads.net","tikmate.app","timeful.app","titantv.com","titulky.com","tmailor.com","tnaflix.com","todaypktv.*","tonspion.de","toolxox.com","toonanime.*","toonily.com","topgear.com","topmovies.*","topshare.in","topsport.bg","totally.top","toxicwap.us","trahino.net","tranny6.com","trgtkls.org","tribuna.com","trickms.com","trilog3.net","tromcap.com","trxking.xyz","tryvaga.com","ttsfree.com","tubator.com","tube18.sexy","tuberel.com","tubsxxx.com","tukoz.com>>","tunebat.com","turkmmo.com","tutflix.org","tutvlive.ru","tv-media.at","tv.bdix.app","tvableon.me","tvseries.in","tw-calc.net","twitchy.com","twitter.com","ubbulls.com","ucanwatch.*","ufcstream.*","uhdmovies.*","uiiumovie.*","uknip.co.uk","umterps.com","unblockit.*","uozzart.com","updown.link","upfiles.app","uploadbaz.*","uploadhub.*","uploadrar.*","upns.online","uproxy2.biz","uprwssp.org","upstore.net","upstream.to","uptime4.com","uptobox.com","urdubolo.pk","usfdons.com","usgamer.net","ustvgo.live","uticaod.com","uyeshare.cc","v2movies.me","v6embed.xyz","vague.style","variety.com","vaughn.live","vectorx.top","vedshar.com","vegamovie.*","ver-pelis.*","verizon.com","veronica.uk","vexfile.com","vexmovies.*","vf-film.net","vgamerz.com","vidavra.com","vidbeem.com","vidcloud9.*","videezy.com","vidello.net","videovard.*","videoxxx.cc","videplay.us","videq.cloud","vidfast.pro","vidlink.pro","vidload.net","vidnest.fun","vidshar.org","vidshare.tv","vidspeed.cc","vidsrcme.ru","vidstream.*","vidtube.one","vikatan.com","vikings.com","vikuy.click","vip-box.app","vipifsa.com","vipleague.*","vipracing.*","vipshort.in","vipstand.se","viptube.com","virabux.com","visalist.io","visible.com","viva100.com","vixcloud.co","vizcloud2.*","vkprime.com","voirfilms.*","voyeurhit.*","vrcmods.com","vstdrive.in","vulture.com","vvtplayer.*","vw-page.com","w.grapps.me","waploaded.*","watchfree.*","watchporn.*","wayfair.com","wcostream.*","weadown.com","weather.com","webcras.com","webfail.com","webtoon.xyz","weerslag.nl","weights.com","wetsins.com","weviral.org","wgzimmer.ch","why-tech.it","wideo.wp.pl","wildwap.com","winshell.de","wintotal.de","wmovies.xyz","woffxxx.com","wonporn.com","wowroms.com","wupfile.com","wvt.free.nf","www.msn.com","wyborcza.pl","x-x-x.video","x.ag2m2.cfd","xbokeps.com","xcandid.vip","xemales.com","xflixbd.com","xforum.live","xfreehd.com","xgroovy.com","xhamster.fm","xhamster1.*","xhamster2.*","xhamster3.*","xhamster4.*","xhamster5.*","xhamster7.*","xhamster8.*","xhmoon5.com","xhreal2.com","xhreal3.com","xhtotal.com","xhwide5.com","xmateur.com","xmovies08.*","xnxxcom.xyz","xozilla.xxx","xpicu.store","xpornzo.com","xpshort.com","xsanime.com","xubster.com","xvideos.com","xx.knit.bid","xxxmomz.com","xxxmovies.*","xxxshut.com","xztgl.com>>","y-2mate.com","y2meta.mobi","yamsoti.com","yesmovies.*","yesporn.vip","yestech.xyz","yifysub.net","ymovies.vip","yomovies1.*","yoshare.net","youjizz.com","youshort.me","youtube.com","yoxplay.xyz","yt2conv.com","ytmp3cc.net","ytsubme.com","yumeost.net","yurn.online","zedporn.com","zeilink.net","zemporn.com","zerioncc.pl","zerogpt.com","zetporn.com","ziperto.com","zlpaste.net","zoechip.com","zyromod.com","0123movies.*","0cbcq8mu.com","0l23movies.*","0ochi8hp.com","10-train.com","1024tera.com","103.74.5.104","123-movies.*","1234movies.*","123animes.ru","123moviesc.*","123moviess.*","123unblock.*","1340kbbr.com","16honeys.com","185.53.88.15","18tubehd.com","1fichier.com","1madrasdub.*","1primewire.*","2017tube.com","2cf0xzdu.com","2fb9tsgn.fun","2madrasdub.*","398fitus.com","3gaytube.com","45.86.86.235","456movie.com","4archive.org","4bct9.live>>","4edtcixl.xyz","4fansites.de","4k2h4w04.xyz","4live.online","4movierulz.*","5moviess.com","720pstream.*","7hitmovies.*","8teenxxx.com","a6iqb4m8.xyz","ablefast.com","aboedman.com","absoluporn.*","abysscdn.com","acapellas.eu","adbypass.org","adcrypto.net","addonbiz.com","addtoany.com","adsurfle.com","adultfun.net","aegeanews.gr","afl3ua5u.xyz","afreesms.com","afrotech.com","airflix1.com","airliners.de","akinator.com","akirabox.com","alcasthq.com","alexsports.*","aliancapes.*","allcalidad.*","alliptvs.com","allmusic.com","allosurf.net","alotporn.com","alphatron.tv","alrincon.com","alternet.org","amarillo.com","amateur8.com","amestrib.com","amnaymag.com","amtil.com.au","androidaba.*","anhdep24.com","animalia.bio","anime-jl.net","anime3rb.com","animefire.io","animeflv.net","animefreak.*","animelok.xyz","animesanka.*","animeunity.*","animexin.vip","animixplay.*","aninami.site","aninavi.blog","anisubindo.*","anmup.com.np","annabelle.ch","anonmp4.help","antiadtape.*","antonimos.de","anybunny.com","apetube.asia","apkcombo.com","apkdrill.com","apkmodhub.in","apkprime.org","apkship.shop","apnablogs.in","app.vaia.com","apps2app.com","appsbull.com","appsmodz.com","aranzulla.it","arcaxbydz.id","arkadium.com","arolinks.com","aroratr.club","artforum.com","asiaflix.net","asianporn.li","askim-bg.com","astrozop.com","atglinks.com","atgstudy.com","atozmath.com","audiotools.*","audizine.com","autoblog.com","autodime.com","autoembed.cc","autonews.com","autorevue.at","az-online.de","azoranov.com","azores.co.il","b-hentai.com","babesexy.com","babiato.tech","babygaga.com","bagpipe.news","baithak.news","bamgosu.site","bandstand.ph","banned.video","baramjak.com","barchart.com","baritoday.it","batchkun.com","batporno.com","bbyhaber.com","bceagles.com","bclikeqt.com","beemtube.com","beingtek.com","benchmark.pl","bestlist.top","bestwish.lol","bike-news.jp","biletomat.pl","bilibili.com","biopills.net","biovetro.net","birdurls.com","bitchute.com","bitssurf.com","bittools.net","blog-dnz.com","blogmado.com","blogmura.com","bloground.ro","blwideas.com","bobolike.com","bollydrive.*","bollyshare.*","boltbeat.com","bookfrom.net","bookriot.com","boredbat.com","boundhub.com","boysfood.com","br0wsers.com","braflix.tube","brainzaps.tv","brawlify.com","bright-b.com","brobokep.org","bronco6g.com","bsmaurya.com","bubraves.com","buffsports.*","buffstream.*","bugswave.com","bullfrag.com","burakgoc.com","burbuja.info","burnbutt.com","buyjiocoin.*","bysebuho.com","bysekoze.com","bysewihe.com","byswiizen.fr","bz-berlin.de","calbears.com","callfuck.com","camaro7g.com","camhub.world","camlovers.tv","camporn.tube","camwhores.tv","camwhorez.tv","capoplay.net","cardiagn.com","cariskuy.com","carnewz.site","cashbux.work","casperhd.com","casthill.net","cataz.stream","catcrave.com","catholic.com","cbt-tube.net","cctvwiki.com","cdn.vifey.de","celebmix.com","celibook.com","cesoirtv.com","channel4.com","chargers.com","chatango.com","chibchat.com","chillizet.pl","chopchat.com","choralia.net","chzzkban.xyz","cinedetodo.*","cinemabg.net","cinemaxxl.de","cjonline.com","claimbits.io","claimtrx.com","clickapi.net","clicporn.com","clix4btc.com","clockskin.us","closermag.fr","cocogals.com","cocoporn.net","codeberg.org","coderblog.in","codesnse.com","coindice.win","coingraph.us","coinsrev.com","collider.com","compsmag.com","compu-pc.com","cool-etv.net","cosmicapp.co","couchtuner.*","coursera.org","cracking.org","crazyblog.in","cricwatch.io","cryptowin.io","cuevana8.com","cuts-url.com","cwc.utah.gov","cyberdrop.me","cyberleaks.*","cyclones.com","cyprus.co.il","czechsex.net","da-imnetz.de","daddylive1.*","dafideff.com","dafontvn.com","daftporn.com","dailydot.com","dailysport.*","daizurin.com","daotekno.com","darkibox.com","datacheap.io","datanodes.to","datawav.club","dawntube.com","ddlvalley.me","deadline.com","deadspin.com","deckshop.pro","decorisi.com","deepbrid.com","deephot.link","delvein.tech","derwesten.de","descarga.xyz","desi.upn.bio","desihoes.com","desiupload.*","desivideos.*","deviants.com","digimanie.cz","dikgames.com","dir-tech.com","dirproxy.com","dirtyfox.net","dirtyporn.cc","dispatch.com","distanta.net","divicast.com","divxtotal1.*","djpunjab2.in","dl-protect.*","dlolcast.pro","dlupload.com","dndsearch.in","dokumen.tips","domahatv.com","doodstream.*","dotabuff.com","doujindesu.*","downloadr.in","drakecomic.*","dreamdth.com","dredyson.com","drivefire.co","drivemoe.com","drivers.plus","dropbang.net","dropgalaxy.*","drsnysvet.cz","drublood.com","ds2video.com","dukeofed.org","dumovies.com","duolingo.com","dutchycorp.*","dvd-flix.com","dwlinks.buzz","eastream.net","ecamrips.com","eclypsia.com","edukaroo.com","egram.com.ng","egyanime.com","ehotpics.com","elcultura.pl","electsex.com","elvocero.com","embed4me.com","embedtv.best","emporda.info","endbasic.dev","eng-news.com","engvideo.net","epson.com.cn","eroclips.org","erofound.com","erogarga.com","eropaste.net","eroticmv.com","esportivos.*","estrenosgo.*","estudyme.com","et-invest.de","etonline.com","eurogamer.de","eurogamer.es","eurogamer.it","eurogamer.pt","euronews.com","eurostream.*","evernia.site","evfancy.link","ex-foary.com","examword.com","exceljet.net","exe-urls.com","expertvn.com","eymockup.com","ezeviral.com","f1livegp.net","facebook.com","factable.com","fairyhorn.cc","faiviral.com","fansided.com","fansmega.com","fapality.com","fapfappy.com","fastilinks.*","fat-bike.com","fbsquadx.com","fc2stream.tv","fedscoop.com","feed2all.org","fehmarn24.de","femdomtb.com","ferdroid.net","fileguard.cc","fileguru.net","filemoon.*>>","filerice.com","filescdn.com","filessrc.com","filezipa.com","filmifen.com","filmisongs.*","filmizip.com","filmizletv.*","filmy4wap1.*","filmygod13.*","filmyone.com","filmyzilla.*","financid.com","finevids.xxx","firstonetv.*","fitforfun.de","fivemdev.org","flaticon.com","flexy.stream","flexyhit.com","flightsim.to","flixbaba.com","flowsnet.com","flstv.online","flvto.com.co","fm-arena.com","fmoonembed.*","focus4ca.com","footybite.to","forexrw7.com","forogore.com","forplayx.ink","fotopixel.es","freejav.guru","freemovies.*","freemp3.tube","freeshib.biz","freetron.top","freewsad.com","fremdwort.de","freshbbw.com","fruitlab.com","fsileaks.com","fuckmilf.net","fullboys.com","fullcinema.*","fullhd4k.com","fuskator.com","futemais.net","fxpornhd.com","galaxyos.net","game-owl.com","gamebrew.org","gamefast.org","gamekult.com","gamer.com.tw","gamerant.com","gamerxyt.com","games.get.tv","games.wkb.jp","gameslay.net","gameszap.com","gametter.com","gamezizo.com","gamingsym.in","gatagata.net","gay4porn.com","gaystream.pw","gayteam.club","gazeta.press","gculopes.com","gekkonen.net","gelbooru.com","gentside.com","gerbeaud.com","getcopy.link","getitfree.cn","getmodsapk.*","gifcandy.net","gioialive.it","gksansar.com","glo-n.online","globes.co.il","globfone.com","gniewkowo.eu","gnusocial.jp","go2share.net","goanimes.vip","gobadgers.ca","gocast123.me","godzcast.com","gogoanimes.*","gogriffs.com","golancers.ca","gomuraw.blog","gonzoporn.cc","goracers.com","gosexpod.com","gottanut.com","goxavier.com","gplastra.com","grazymag.com","greekfun.net","grigtube.com","grosnews.com","gseagles.com","gsmarena.com","gsmhamza.com","guidetnt.com","gurusiana.id","h-game18.xyz","habuteru.com","hachiraw.net","hackshort.me","hackstore.me","halloporno.*","hanime24.com","harbigol.com","hbnews24.com","hbrfrance.fr","hcaptcha.com","hdfcfund.com","hdhub4u.fail","hdmoviehub.*","hdmovies23.*","hdmovies4u.*","hdmovies50.*","hdpopcorns.*","hdporn92.com","hdpornos.net","hdvideo9.com","hellmoms.com","helpdice.com","hentai2w.com","hentai4k.com","hentaicube.*","hentaigo.com","hentaila.com","hentaimoe.me","hentais.tube","hentaitk.net","hentaizm.fun","heqviral.com","hi0ti780.fun","highporn.net","hiperdex.com","hipsonyc.com","hispajav.com","hivetoon.com","hktvmall.com","hmanga.world","hometalk.com","hostmath.com","hotmilfs.pro","hqporner.com","hubdrive.com","huffpost.com","hurawatch.cc","hwzone.co.il","hyderone.com","hydrogen.lat","hypnohub.net","ibradome.com","icutlink.com","icyporno.com","idealight.it","idesign.wiki","idntheme.com","iguarras.com","ihdstreams.*","ilovephd.com","ilpescara.it","imagefap.com","imdpu9eq.com","imgadult.com","imgbaron.com","imgblaze.net","imgbnwe.shop","imgbyrev.sbs","imgclick.net","imgdrive.net","imgflare.com","imgfrost.net","imggune.shop","imgjajhe.sbs","imgmffmv.sbs","imgnbii.shop","imgolemn.sbs","imgprime.com","imgqbbds.sbs","imgshots.com","imgspark.com","imgthbm.shop","imgtorrnt.in","imgxabm.shop","imgxxbdf.sbs","imintweb.com","indian-tv.cz","indianxxx.us","indystar.com","infodani.net","infofuge.com","informer.com","instamod.app","interssh.com","intro-hd.net","ipacrack.com","ipatriot.com","iptvapps.net","iptvspor.com","iputitas.net","iqksisgw.xyz","isaidub6.net","itainews.com","itz-fast.com","iwanttfc.com","izzylaif.com","jaktsidan.se","jalopnik.com","japanporn.tv","japteenx.com","jav-asia.top","javboys.tv>>","javbraze.com","javguard.xyz","javhahaha.us","javhdz.today","javindo.site","javjavhd.com","javmelon.com","javplaya.com","javplayer.cc","javplayer.me","javprime.net","javquick.com","javrave.club","javtiful.com","javturbo.xyz","jconline.com","jenpornuj.cz","jeshoots.com","jmzkzesy.xyz","jobfound.org","jobsheel.com","jockantv.com","joymaxtr.net","joziporn.com","jsfiddle.net","jsonline.com","juba-get.com","jujmanga.com","kabeleins.de","kafeteria.pl","kakitengah.*","kamehaus.net","kaoskrew.org","karanapk.com","katmoviehd.*","kattracker.*","kaystls.site","khaddavi.net","khatrimaza.*","khsn1230.com","kickasskat.*","kinisuru.com","kinkyporn.cc","kino-zeit.de","kiss-anime.*","kisstvshow.*","klubsports.*","knowstuff.in","knoxnews.com","kolcars.shop","kollhong.com","konten.co.id","koramaup.com","kpopjams.com","kr18plus.com","kreisbote.de","kstreaming.*","kubo-san.com","kumapoi.info","kungfutv.net","kunmanga.com","kurazone.net","kusonime.com","ladepeche.fr","landwirt.com","lanjutkeun.*","leaktube.net","learnmany.in","lectormh.com","lecturel.com","leechall.com","leprogres.fr","lesbenhd.com","lesbian8.com","lewdzone.com","liddread.com","lifestyle.bg","lifewire.com","likemanga.io","likuoo.video","lineup11.net","linfoweb.com","linkedin.com","linkjust.com","linksaya.com","linkshorts.*","linkvoom.com","lionsfan.net","livegore.com","livemint.com","livesport.ws","ln-online.de","lokerwfh.net","longporn.xyz","lookmovie.pn","lookmovie2.*","looopings.nl","lootdest.com","lover937.net","lrepacks.net","lucidcam.com","lulustream.*","luluvdoo.com","luluvido.com","luluvids.top","luscious.net","lusthero.com","luxuretv.com","m-hentai.net","mac2sell.net","macsite.info","mamahawa.com","manga18.club","mangadna.com","mangafire.to","mangagun.net","mangakita.id","mangakoma.ac","mangalek.com","mangamanga.*","manganato.gg","manganelo.tv","mangarawjp.*","mangasco.com","mangoporn.co","mangovideo.*","manhuaga.com","manhuascan.*","manhwa68.com","manhwass.com","manhwaus.net","manpeace.org","manyakan.com","manytoon.com","maqal360.com","marmiton.org","masahub2.com","masengwa.com","mashtips.com","masslive.com","mat6tube.com","mathaeser.de","maturell.com","mavanimes.co","maxgaming.fi","mazakony.com","mc-hacks.net","mcfucker.com","mcrypto.club","mdbekjwqa.pw","mdtaiwan.com","mealcold.com","medscape.com","medytour.com","meetimgz.com","mega-mkv.com","mega-p2p.net","megafire.net","megatube.xxx","megaupto.com","meilblog.com","meloradio.pl","metabomb.net","meteolive.it","miaandme.org","micmicidol.*","microify.com","midis.com.ar","miixdrop.net","mikohub.blog","milftoon.xxx","mirror.co.uk","missavtv.com","missyusa.com","mitsmits.com","mixloads.com","mjukb26l.fun","mkvcinemas.*","mlbstream.tv","mmsbee27.com","mmsbee47.com","mobitool.net","modcombo.com","moddroid.com","modhoster.de","modsbase.com","modsfire.com","modyster.com","mom4real.com","momo-net.com","momon-ga.com","momspost.com","momxxx.video","monaco.co.il","moretvtime.*","moshahda.net","motofakty.pl","movie4u.live","moviedokan.*","movieffm.net","moviefreak.*","moviekids.tv","movielair.cc","movierulzs.*","movierulzz.*","movies123.pk","movies18.net","movies4us.co","moviesapi.to","moviesbaba.*","moviesflix.*","moviesland.*","moviespapa.*","moviesrulz.*","moviesshub.*","moviesxxx.cc","movieweb.com","movstube.net","mp3fiber.com","mp3juices.su","mp4-porn.net","mpg.football","mrscript.net","multporn.net","musictip.net","mutigers.com","mxdrop.click","myesports.gg","myflixerz.to","myfxbook.com","mylinkat.com","naniplay.com","nanolinks.in","napiszar.com","nar.k-ba.net","natgeotv.com","nbastream.tv","nemumemo.com","nephobox.com","netmovies.to","netoff.co.jp","netuplayer.*","newatlas.com","news.now.com","newsammo.com","newsextv.com","newslive.com","newsmondo.it","nextdoor.com","nextorrent.*","neymartv.net","nflscoop.xyz","nflstream.tv","nicetube.one","nicknight.de","nicovideo.jp","nifteam.info","niganpro.com","nilesoft.org","niu-pack.com","niyaniya.moe","njherald.com","nkunorse.com","nonktube.com","nosubapp.com","novelasesp.*","novelbob.com","novelread.co","novoglam.com","novoporn.com","nowmaxtv.com","nowsports.me","nowsportv.nl","nowtv.com.tr","nptsr.live>>","nsfwgify.com","nsfwzone.xyz","nudecams.xxx","nudedxxx.com","nudistic.com","nudogram.com","nudostar.com","nueagles.com","nugglove.com","nusports.com","nwzonline.de","nyaa.iss.ink","nzbstars.com","oaaxpgp3.xyz","of-model.com","oimsmosy.fun","oklivetv.com","okulsoru.com","oldcamera.pl","olutposti.fi","olympics.com","oncehelp.com","ondebola.com","oneupload.to","onlinexxx.cc","onlytech.com","onscreens.me","onyxfeed.com","op-online.de","openload.mov","opinie.wp.pl","opomanga.com","optifine.net","orangeink.pk","oricon.co.jp","osuskins.net","otakukan.com","otakuraw.net","ottverse.com","ottxmaza.com","ovagames.com","ovnihoje.com","oyungibi.com","pagalworld.*","pak-mcqs.net","paktech2.com","pal-item.com","pandadoc.com","pandamovie.*","panthers.com","papunika.com","parenting.pl","parzibyte.me","paste.bin.sx","pastepvp.org","pastetot.com","patriots.com","pay4fans.com","pc-hobby.com","pcgamesn.com","pdfindir.net","peachify.top","peekvids.com","pelimeli.com","pelis182.net","pelisflix2.*","pelishouse.*","pelispedia.*","pelisplus2.*","pennlive.com","pentruea.com","perisxxx.com","petguide.com","phimmoiaz.cc","photooxy.com","photopea.com","picbaron.com","picjbet.shop","picnwqez.sbs","picyield.com","pietsmiet.de","pig-fuck.com","pilibook.com","pinayflix.me","piratebayz.*","pisatoday.it","pittband.com","pixbnab.shop","pixdfdj.shop","piximfix.com","pixkfkf.shop","pixnbrqw.sbs","pixrqqz.shop","pkw-forum.de","platinmods.*","play.1188.lv","play.max.com","play.nova.bg","play1002.com","player4u.xyz","playerfs.com","playertv.net","playfront.de","playmogo.com","playstore.pw","playvids.com","plaza.chu.jp","plc4free.com","plusupload.*","pmvhaven.com","pogoda.wp.pl","poki-gdn.com","politico.com","polygamia.pl","pomofocus.io","ponsel4g.com","porn4fans.me","pornabcd.com","pornachi.com","porncomics.*","pornditt.com","pornfeel.com","pornfeet.xyz","pornflip.com","porngames.tv","porngrey.com","pornhat.asia","pornhdin.com","pornhits.com","pornhost.com","pornicom.com","pornleaks.in","pornlift.com","pornlore.com","pornluck.com","pornmoms.org","porno-tour.*","pornoaid.com","pornobae.com","pornoente.tv","pornohd.blue","pornotom.com","pornozot.com","pornpapa.com","porntape.net","porntrex.com","pornvibe.org","pornwatch.ws","pornyeah.com","pornyfap.com","pornzone.com","poscitechs.*","postazap.com","postimees.ee","powcloud.org","prensa.click","pressian.com","pricemint.in","prime4you.de","produsat.com","programme.tv","promipool.de","proplanta.de","prothots.com","proxyorb.com","ps2-bios.com","pugliain.net","pupupul.site","pussyspace.*","putlocker9.*","putlockerc.*","putlockers.*","px-cloud.net","pysznosci.pl","q1-tdsge.com","qashbits.com","qpython.club","quizrent.com","qvzidojm.com","r3owners.net","raidrush.net","rail-log.net","rajtamil.org","ranger5g.com","ranger6g.com","ranjeet.best","rapelust.com","rarepike.com","raulmalea.ro","rawmanga.top","rawstory.com","razzball.com","rbs.ta36.com","recipahi.com","recipenp.com","recording.de","reddflix.com","redecanais.*","redretti.com","remilf.xyz>>","repelisgoo.*","repretel.com","reqlinks.net","resplace.com","retire49.com","richhioon.eu","riotbits.com","ritzysex.com","rockmods.net","rolltide.com","romatoday.it","rome2rio.com","roms-hub.com","ronaldo7.pro","root-top.com","rosasidan.ws","rosefile.net","rot-blau.com","rotowire.com","royalkom.com","rp-online.de","rtilinks.com","rubias19.com","rue89lyon.fr","ruidrive.com","rushporn.xxx","s2watch.link","salidzini.lv","samfirms.com","samovies.net","satkurier.pl","savefrom.net","savegame.pro","savesubs.com","savevideo.me","scamalot.com","scjhg5oh.fun","scotsman.com","seahawks.com","seeklogo.com","seireshd.com","seirsanduk.*","seksrura.net","senimovie.co","senmanga.com","senzuri.tube","servustv.com","sethphat.com","seuseriado.*","sex-pic.info","sexgames.xxx","sexgay18.com","sexroute.net","sexy-games.*","sexyhive.com","sfajacks.com","sgxnifty.org","shanurdu.com","sharedrive.*","sharetext.me","shemale6.com","shemedia.com","sheshaft.com","shorteet.com","shrtslug.biz","sieradmu.com","silkengirl.*","sinonimos.de","siteflix.org","sitekeys.net","skinnyhq.com","skinnyms.com","slawoslaw.pl","slreamplay.*","slutdump.com","slutmesh.net","smailpro.com","smallpdf.com","smcgaels.com","smgplaza.com","snlookup.com","sobatkeren.*","sodomojo.com","solarmovie.*","sonixgvn.net","sortporn.com","sound-park.*","southfreak.*","sp-today.com","sp500-up.com","speedrun.com","spielfilm.de","spinoff.link","sport-97.com","sportico.com","sporting77.*","sportlemon.*","sportlife.es","sportnews.to","sportshub.to","sportskart.*","starcima.com","stardeos.com","stardima.com","stayglam.com","stbturbo.xyz","steelers.com","stevivor.com","stimotion.pl","stre4mplay.*","stream18.net","streamango.*","streambee.to","streameast.*","streampiay.*","streamtape.*","streamwish.*","strikeout.im","stylebook.de","subtaboo.com","sunbtc.space","sunporno.com","superapk.org","superpsx.com","supervideo.*","supramkv.com","surfline.com","surrit.store","sushi-scan.*","sussytoons.*","suzihaza.com","suzylu.co.uk","svipvids.com","swiftload.io","synonyms.com","syracuse.com","system32.ink","tabering.net","tabooporn.tv","tacobell.com","tacoma4g.com","tagecoin.com","tajpoint.com","tamilprint.*","tamilyogis.*","tampabay.com","tanfacil.net","tapchipi.com","tapepops.com","tatabrada.tv","team-rcv.xyz","tech24us.com","tech4auto.in","techably.com","techmuzz.com","technons.com","technorj.com","techstage.de","techstwo.com","techtobo.com","techyinfo.in","techzed.info","teczpert.com","teencamx.com","teenhost.net","teensark.com","teensporn.tv","teknorizen.*","telecinco.es","telegraaf.nl","telegram.com","teleriumtv.*","teluguflix.*","teraearn.com","terashare.co","terashare.me","tesbox.my.id","tespedia.com","testious.com","th-world.com","theblank.net","thecomet.net","theconomy.me","thedaddy.*>>","thefmovies.*","thegamer.com","theherta.com","thehindu.com","thekickass.*","thelinkbox.*","themezon.net","theonion.com","theproxy.app","thertstv.com","thesleak.com","thesukan.net","thesun.co.uk","thevalley.fm","theverge.com","threezly.com","thuglink.com","thurrott.com","tieulam.info","tigernet.com","tik-tok.porn","timestamp.fr","tinypass.com","tioanime.com","tipranks.com","tnaflix.asia","tnhitsda.net","tntdrama.com","tokuzl.net>>","topeuropix.*","topfaucet.us","topkickass.*","topspeed.com","topstreams.*","torture1.net","trahodom.com","traingon.top","trendyol.com","tresdaos.com","trustnet.com","truthnews.de","truyenvn.dev","tryboobs.com","ts-mpegs.com","tsmovies.com","tubedupe.com","tubewolf.com","tubxporn.com","tucinehd.com","turbobit.net","turbovid.vip","turkdown.com","turkrock.com","tusfiles.com","tv3monde.com","tvappapk.com","tvasports.ca","tvdigital.de","tvnow247.top","tvpclive.com","tvtropes.org","tweakers.net","twister.porn","tz7z9z0h.com","u-s-news.com","u26bekrb.fun","udoyoshi.com","ugreen.autos","uhdwalls.com","ukchat.co.uk","ukdevilz.com","ukigmoch.com","ultraten.net","umagame.info","umogames.com","unitystr.com","up-4ever.net","upload18.com","uploadbox.io","uploadmx.com","uploads.mobi","uploadvr.com","upshrink.com","uptomega.net","ur-files.com","usatoday.com","usaxtube.com","userupload.*","usp-forum.de","utahutes.com","utaitebu.com","utakmice.net","utsports.com","uur-tech.net","uwatchfree.*","veganinja.hu","vegas411.com","vibehubs.com","videofilms.*","videojav.com","videos-xxx.*","videovak.com","vidnest.live","vidsaver.net","vidsonic.net","vidsrc.click","viidshar.com","vijviral.com","vikiporn.com","violablu.net","vipporns.com","viralxns.com","visorsmr.com","vivasexe.com","vocalley.com","voirseries.*","volokit2.com","voznovel.com","vr.pornhat.*","walftech.com","warddogs.com","warezcdn.lat","wargamer.com","watchmovie.*","watchmygf.me","watchnow.fun","watchop.live","watchporn.cc","watchporn.to","watchtvchh.*","way2movies.*","web2.0calc.*","webcams.casa","webnovel.com","webxmaza.com","weerplaza.nl","westword.com","whatgame.xyz","whatsapp.com","whyvpn.my.id","wikifeet.com","wikirise.com","wildsnow.com","winboard.org","winfuture.de","winlator.com","wishfast.top","withukor.com","wohngeld.org","wolfstream.*","worldaide.fr","worldsex.com","writedroid.*","wspinanie.pl","www.google.*","wyborcza.biz","x-video.tube","xemphim1.top","xfantazy.com","xfantazy.org","xhaccess.com","xhadult2.com","xhadult3.com","xhamster.com","xhamster10.*","xhamster11.*","xhamster12.*","xhamster13.*","xhamster14.*","xhamster15.*","xhamster16.*","xhamster17.*","xhamster18.*","xhamster19.*","xhamster20.*","xhamster42.*","xhamster46.*","xhdate.world","xpornium.net","xsexpics.com","xteensex.net","xvideos.name","xvideos2.com","xxporner.com","xxxfiles.com","xxxhdvideo.*","xxxonline.cc","xxxpicss.com","xxxputas.net","xxxshake.com","xxxstream.me","yabiladi.com","yaoiscan.com","yggtorrent.*","yhocdata.com","ynk-blog.com","yogranny.com","you-porn.com","yourlust.com","yts-subs.com","yts-subs.net","ytube2dl.com","yuatools.com","yurudori.com","zealtyro.com","zehnporn.com","zenradio.com","zhlednito.cz","zilla-xr.xyz","zimabdko.com","zone.msn.com","zootube1.com","zplayer.live","zpserver.com","zvision.link","zxcprime.icu","01234movies.*","01fmovies.com","10convert.com","10play.com.au","10starhub.com","111.90.150.10","111.90.151.26","111movies.com","123gostream.*","123movies.net","123moviesgo.*","123movieshd.*","123moviesla.*","123moviesme.*","123movieweb.*","123multihub.*","185.53.88.104","185.53.88.204","190.115.18.20","1bitspace.com","1qwebplay.xyz","1xxx-tube.com","247sports.com","2girls1cup.ca","30kaiteki.com","360news4u.net","38.242.194.12","3dhentai.club","4download.net","4drumkits.com","4filmyzilla.*","4horlover.com","4meplayer.com","4movierulz1.*","4runner6g.com","560pmovie.com","5movierulz2.*","6hiidude.gold","7fractals.icu","7misr4day.com","7movierulz1.*","7moviesrulz.*","7vibelife.com","94.103.83.138","9filmyzilla.*","9ketsuki.info","abczdrowie.pl","abendblatt.de","abseits-ka.de","acusports.com","acutetube.net","adblocktape.*","advantien.com","advertape.net","aha-music.com","ainonline.com","aitohuman.org","ajt.xooit.org","akcartoons.in","albania.co.il","alexbacher.fr","alimaniac.com","allitebooks.*","allmomsex.com","alltstube.com","allusione.org","alohatube.xyz","alueviesti.fi","ambonkita.com","angelfire.com","angelgals.com","anihdplay.com","animecast.net","animefever.cc","animeflix.ltd","animefreak.to","animeheaven.*","animenexus.in","animesite.net","animesup.info","animetoast.cc","animeunity.so","animeworld.ac","animeworld.tv","animeyabu.net","animeyabu.org","animeyubi.com","anitube22.vip","aniwatchtv.to","aniworld.to>>","anonyviet.com","anusling.info","aogen-net.com","aparttent.com","appteka.store","archive.today","archivebate.*","archlinux.org","archpaper.com","areabokep.com","areamobile.de","areascans.net","areatopik.com","arenascan.com","arenavision.*","arhplyrics.in","ariestube.com","ark-unity.com","arldeemix.com","artesacro.org","arti-flora.nl","articletz.com","artribune.com","asianboy.fans","asianhdplay.*","asianlbfm.net","asiansex.life","asiaontop.com","askattest.com","asssex-hd.com","astroages.com","astronews.com","at.wetter.com","audiotag.info","audiotrip.org","austiblox.net","auto-data.net","auto-swiat.pl","autobytel.com","autoembed.app","autoextrem.de","autofrage.net","autoguide.com","autoscout24.*","autosport.com","autotrader.nl","autotrader.pl","avnsgames.com","avpgalaxy.net","azcentral.com","b-bmovies.com","babakfilm.com","babepedia.com","babestube.com","babytorrent.*","baddiehub.com","beasttips.com","beegsexxx.com","besargaji.com","bestgames.com","beverfood.com","biftutech.com","bikeradar.com","bikerszene.de","bikerumor.com","bilasport.net","bilinovel.com","billboard.com","bimshares.com","bingsport.xyz","bitcosite.com","bitfaucet.net","bitlikutu.com","bitview.cloud","bitwarden.com","bizdustry.com","blasensex.com","blog.40ch.net","blogesque.net","blograffo.net","blurayufr.cam","bobs-tube.com","bokugents.com","bolly2tolly.*","bollymovies.*","boobgirlz.com","bootyexpo.net","boxylucha.com","boystube.link","bravedown.com","bravoporn.com","brawlhalla.fr","breitbart.com","breznikar.com","brighteon.com","brocoflix.com","brocoflix.xyz","bshifast.live","buffsports.io","buffstreams.*","buienalarm.be","buienalarm.nl","bustyfats.com","buydekhke.com","bymichiby.com","call4cloud.nl","camarchive.tv","camdigest.com","camgoddess.tv","camvideos.org","camwhorestv.*","camwhoria.com","canlikolik.my","cantonrep.com","capo5play.com","capo6play.com","caravaning.de","cardshare.biz","carryflix.com","carryflix.icu","carscoops.com","cat-a-cat.net","cat3movie.org","cbsnews.com>>","ccthesims.com","cdiscount.com","celeb.gate.cc","celemusic.com","ceramic.or.kr","ceylonssh.com","cg-method.com","cgcosplay.org","chapteria.com","chataigpt.org","cheatcloud.cc","cheater.ninja","cheatsquad.gg","chevalmag.com","chieftain.com","chihouban.com","chikonori.com","chimicamo.org","chloeting.com","cima100fm.com","cinecalidad.*","cinefreak.net","cinema.com.my","cinemabaz.com","cinemitas.org","civitai.green","claimbits.net","claudelog.com","claydscap.com","clickhole.com","cloudvideo.tv","cloudwish.xyz","cmsdetect.com","cmtracker.net","cnnamador.com","cockmeter.com","cocomanga.com","code2care.org","codeastro.com","codesnail.com","codewebit.top","coinbaby8.com","coinfaucet.io","coinlyhub.com","coinsbomb.com","comedyshow.to","comexlive.org","comparili.net","computer76.ru","condorsoft.co","configspc.com","cooksinfo.com","coolcast2.com","coolporno.net","corrector.app","cotemaison.fr","crackcodes.in","crackevil.com","crackfree.org","crazyporn.xxx","crazyshit.com","crazytoys.xyz","cricket12.com","criollasx.com","criticker.com","crocotube.com","crotpedia.net","crypto4yu.com","cryptonor.xyz","cryptorank.io","cuisineaz.com","cumlouder.com","cuttlinks.com","cybermania.ws","cyklobazar.cz","czterykaty.pl","daddylive.*>>","daddylivehd.*","dailymail.com","dailynews.com","dailypaws.com","dailyrevs.com","dandanzan.top","dankmemer.lol","datavaults.co","daveockop.com","dbusports.com","dcleakers.com","ddd-smart.net","decmelfot.xyz","deepfucks.com","deichstube.de","deluxtube.com","demae-can.com","dengarden.com","denofgeek.com","depvailon.com","derusblog.com","descargasok.*","desertsun.com","desicinema.se","desifakes.com","desijugar.net","desimmshd.com","devsoftwr.com","dfilmizle.com","dic.pixiv.net","dickclark.com","dinnerexa.com","dipprofit.com","dirtyship.com","diskizone.com","dl-protect1.*","dlapk4all.com","dldokan.store","dlhe-videa.sk","dlstreams.*>>","doctoraux.com","dongknows.com","donkparty.com","doofree88.com","doomovie-hd.*","dooodster.com","doramasyt.com","dorawatch.net","douxporno.com","downfile.site","downloader.is","downloadhub.*","dr-farfar.com","dragontea.ink","dramafren.com","dramafren.org","dramavideo.se","dramaviki.com","drivelinks.me","drivenime.com","driveup.space","drop.download","dropnudes.com","dropshipin.id","dubaitime.net","durtypass.com","e-monsite.com","eatsmarter.de","ebonybird.com","ebook-hell.to","ebook3000.com","ebooksite.org","edealinfo.com","edukamer.info","egitim.net.tr","elespanol.com","embdproxy.xyz","embed.scdn.to","embedgram.com","embedplayer.*","embedrise.com","embedseek.xyz","embedwish.com","empleo.com.uy","emueagles.com","encurtads.net","encurtalink.*","enjoyfuck.com","ensenchat.com","entenpost.com","entireweb.com","ephoto360.com","epochtimes.de","eporner.video","eramuslim.com","erospots.info","eroticity.net","erreguete.gal","eurogamer.net","ev3forums.com","exe-links.com","expansion.com","extratipp.com","f150gen14.com","familyporn.tv","fanfiktion.de","fangraphs.com","fantasiku.com","fapomania.com","faresgame.com","farodevigo.es","fastcars1.com","fbstream.is>>","fclecteur.com","fembed9hd.com","fetish-tv.com","fetishtube.cc","file-upload.*","filegajah.com","filehorse.com","filemooon.top","filmeseries.*","filmibeat.com","filmlinks4u.*","filmy4wap.uno","filmyporno.tv","filmyworlds.*","finanse.wp.pl","findheman.com","firescans.xyz","firestream.to","firmwarex.net","firstpost.com","fitness.wp.pl","fivemturk.com","flexamens.com","flexxporn.com","flix-wave.lol","flixlatam.com","flyplayer.xyz","fmoviesfree.*","fontyukle.net","footeuses.com","footyload.com","forexforum.co","forlitoday.it","forum.dji.com","fossbytes.com","fosslinux.com","fotoblogia.pl","foxaholic.com","foxsports.com","foxtel.com.au","frauporno.com","free.7hd.club","freedom3d.art","freeflix.info","freegames.com","freeiphone.fr","freeomovie.to","freeporn8.com","freesex-1.com","freeshot.live","freexcafe.com","freexmovs.com","freshscat.com","freyalist.com","fromwatch.com","fsicomics.com","fsl-stream.lu","fsportshd.net","fuck-beeg.com","fuck-xnxx.com","fuckingfast.*","fucksporn.com","fullassia.com","fullhdxxx.com","funandnews.de","fussball.news","futurezone.de","fzmovies.info","fztvseries.ng","galesburg.com","gamearter.com","gamefront.com","gamelopte.com","gamereactor.*","games.bnd.com","games.qns.com","gamesider.com","gamesite.info","gamesmain.xyz","gamezhero.com","gamovideo.com","garoetpos.com","gatasdatv.com","gayboyshd.com","gaysearch.com","geekering.com","generate.plus","gesundheit.de","getintopc.com","getpaste.link","getpczone.com","gfsvideos.com","ghscanner.com","gigmature.com","gipfelbuch.ch","girlnude.link","girlydrop.com","globalnews.ca","globalrph.com","globalssh.net","globlenews.in","go.linkify.ru","gobobcats.com","gogoanimetv.*","gogoplay1.com","gogoplay2.com","gohuskies.com","gol245.online","goldderby.com","gomaainfo.com","gomoviestv.to","goodriviu.com","goupstate.com","govandals.com","grabpussy.com","grantorrent.*","graphicux.com","greatnass.com","greensmut.com","gry-online.pl","gsmturkey.net","guardaserie.*","guessthe.game","gutefrage.net","gutekueche.at","gwiazdy.wp.pl","gwusports.com","haaretz.co.il","hailstate.com","hairytwat.org","hamhigh.co.uk","hancinema.net","haonguyen.top","haoweichi.com","harimanga.com","harzkurier.de","hb-nippon.com","hdgayporn.net","hdmoviefair.*","hdmoviehubs.*","hdmovieplus.*","hdmovies2.org","hdtubesex.net","heatworld.com","heimporno.com","hellabyte.one","hellenism.net","hellporno.com","hentai-ia.com","hentaicop.com","hentaihaven.*","hentaikai.com","hentaimama.tv","hentaipaw.com","hentaiporn.me","hentairead.io","hentaiyes.com","hertsad.co.uk","herzporno.net","heutewelt.com","hexupload.net","hiddenleaf.to","hifi-forum.de","hihihaha1.xyz","hihihaha2.xyz","hikvision.com","hilites.today","hillsdale.net","hindimovies.*","hindinest.com","hindishri.com","hindisink.com","hindisite.net","hispasexy.org","hitsports.pro","hlsplayer.top","hobbykafe.com","hogtiehub.com","holaporno.xxx","holymanga.net","hornbunny.com","hornyfanz.com","hosttbuzz.com","hostzteam.com","hotntubes.com","hotpress.info","howtogeek.com","hqmaxporn.com","hqpornero.com","hqsex-xxx.com","htmlgames.com","hulkshare.com","hurawatchz.to","hutchnews.com","hydraxcdn.biz","hypebeast.com","hyperdebrid.*","iammagnus.com","iceland.co.uk","ichberlin.com","icy-veins.com","ievaphone.com","iflixmovies.*","ifreefuck.com","igg-games.com","ignboards.com","iiyoutube.com","ikarianews.gr","ikz-online.de","ilpiacenza.it","imagehaha.com","imagenpic.com","imgbbnhi.shop","imgbncvnv.sbs","imgcredit.xyz","imghqqbg.shop","imgkkabm.shop","imgmyqbm.shop","imgouskel.sbs","imgwallet.com","imgwwqbm.shop","imleagues.com","indiafree.net","indianyug.com","indiewire.com","ineedskin.com","inextmovies.*","infidrive.net","inhabitat.com","instagram.com","instalker.org","interfans.org","investing.com","iogames.space","ipalibrary.me","iptvpulse.top","italpress.com","itdmusics.com","itdmusicy.com","itmaniatv.com","itopmusic.com","itsguider.com","jadijuara.com","jagoanssh.com","jameeltips.us","japanxxx.asia","jav101.online","javenglish.cc","javguard.club","javhdporn.com","javhdporn.net","javleaked.com","javmobile.net","javplayer.com","javporn18.com","javsaga.ninja","javstream.com","javstream.top","javsubbed.xyz","javsunday.com","jaysndees.com","jazzradio.com","jellynote.com","jennylist.xyz","jesseporn.xyz","jetbrains.com","jiocinema.com","jipinsoft.com","jizzberry.com","jk-market.com","jkdamours.com","jlaforums.com","jncojeans.com","jobzhub.store","joongdo.co.kr","jpscan-vf.com","jptorrent.org","juegos.as.com","jumboporn.xyz","jurukunci.net","justjared.com","justpaste.top","justwatch.com","juventusfc.hu","k12reader.com","kacengeng.com","kakiagune.com","kalileaks.com","kanald.com.tr","kangkimin.com","katdrive.link","katestube.com","katmoviefix.*","kayoanime.com","kckingdom.com","kenta2222.com","kfapfakes.com","kfrfansub.com","kicaunews.com","kickcharm.com","kissasian.*>>","kitsapsun.com","klaustube.com","klikmanga.com","kllproject.lv","klykradio.com","kobieta.wp.pl","komunikaty.pl","koreanbj.club","korsrt.eu.org","kotanopan.com","kpopjjang.com","ksiazki.wp.pl","ksusports.com","kuchnia.wp.pl","kumascans.com","kupiiline.com","kurashiru.com","kuronavi.blog","kurosuen.live","lamorgues.com","laptrinhx.com","latinabbw.xyz","latinlucha.es","laurasia.info","lavoixdux.com","law101.org.za","learn-cpp.org","learnclax.com","lecceprima.it","leccotoday.it","leermanga.net","leinetal24.de","letmejerk.com","letras.mus.br","lewdstars.com","liberation.fr","liiivideo.com","likemanga.ink","lilymanga.net","ling-online.*","link4rev.site","linkfinal.com","linkshortx.in","linkskibe.com","linkspaid.com","linovelib.com","linuxhint.com","lippycorn.com","listeamed.net","litecoin.host","litonmods.com","liveonsat.com","livestreams.*","liveuamap.com","loanbixby.com","lolcalhost.ru","lolhentai.net","longfiles.com","lookmovie2.to","loot-link.com","lootlemon.com","loptelink.com","lordpremium.*","love4porn.com","lovetofu.cyou","lowellsun.com","lrtrojans.com","lsusports.net","ludigames.com","lulacloud.com","lustesthd.lat","lustholic.com","lusttaboo.com","lustteens.net","lustylist.com","lustyspot.com","m.viptube.com","m.youtube.com","maccanismi.it","macrumors.com","macserial.com","magesypro.com","mailnesia.com","mailocal2.xyz","mainbabes.com","mainlinks.xyz","mainporno.com","makeuseof.com","mamochki.info","manga-tube.me","manga18fx.com","mangabats.com","mangacrab.com","mangacrab.org","mangadass.com","mangafreak.me","mangahere.onl","mangakoma01.*","mangalist.org","mangarawjp.me","mangaread.org","mangasite.org","mangoporn.net","manhastro.com","manhastro.net","manhuatop.org","manhwatop.com","manofadan.com","map.naver.com","massgrave.dev","math-aids.com","mathcrave.com","mathebibel.de","mathsspot.com","matomeiru.com","maxegatos.net","maz-online.de","mconverter.eu","md3b0j6hj.com","mdfx9dc8n.net","mdy48tn97.com","medebooks.xyz","mediafire.com","mediamarkt.be","mediamarkt.de","mediapason.it","medihelp.life","mega-dvdrip.*","megagames.com","megane.com.pl","megawarez.org","megawypas.com","meineorte.com","meinestadt.de","memedroid.com","menshealth.de","metalflirt.de","meteocity.com","meteopool.org","meteovista.be","metrolagu.cam","mettablog.com","meuanime.info","mexicogob.com","mh.baxoi.buzz","mhdsportstv.*","mhdtvsports.*","microsoft.com","miiixdrop.net","milfnut.com>>","minhatela.xyz","miohentai.com","mirrorace.com","missav123.com","missav888.com","mitedrive.com","mixdrop21.net","mixdrop23.net","mixdropjmk.pw","mjakmama24.pl","mmastreams.me","mmorpg.org.pl","mobdi3ips.com","mobdropro.com","modelisme.com","mom-pussy.com","momxxxass.com","momxxxsex.com","moneyhouse.ch","monstream.org","monzatoday.it","moonquill.com","moovitapp.com","moozpussy.com","moregirls.org","morencius.com","morgenpost.de","mosttechs.com","motive213.com","motofan-r.com","motor-talk.de","motorbasar.de","motortests.de","moutogami.com","moviedekho.in","moviefone.com","moviehaxx.pro","moviejones.de","movielinkbd.*","moviepilot.de","movieping.com","movierulzhd.*","moviesdaweb.*","moviesite.app","moviesverse.*","moviexxx.mobi","mp3-gratis.it","mp3fusion.net","mp3juices.icu","mp4mania1.net","mp4upload.com","mrpeepers.net","mtech4you.com","mtg-print.com","mtvuutiset.fi","multicanais.*","musicsite.biz","musikradar.de","mustang6g.com","mustang7g.com","myadslink.com","mydomaine.com","myfernweh.com","myflixertv.to","myhindigk.com","myhomebook.de","myicloud.info","myrecipes.com","myshopify.com","mysostech.com","mythvista.com","myvidplay.com","myvidster.com","myviptuto.com","myyouporn.com","naijahits.com","nakastream.tv","nakenprat.com","napolipiu.com","nastybulb.com","nation.africa","natomanga.com","naturalbd.com","nbcsports.com","ncdexlive.org","needrombd.com","neilpatel.com","nekolink.site","nekopoi.my.id","nelomanga.net","neoseeker.com","nesiaku.my.id","netcinebs.lat","netfilmes.org","netnaijas.com","nettiauto.com","neuepresse.de","neurotray.com","nevcoins.club","neverdims.com","newportri.com","newschief.com","newstopics.in","newyorker.com","newzjunky.com","nexusgames.to","nexusmods.com","nflstreams.me","nhvnovels.com","nicematin.com","nicomanga.com","nihonkuni.com","nin10news.com","nklinks.click","nlcosplay.com","noblocktape.*","noikiiki.info","noob4cast.com","noor-book.com","nordbayern.de","notevibes.com","nousdecor.com","nouvelobs.com","novamovie.net","novelcrow.com","novelroom.net","novizer.com>>","nsfwalbum.com","nsfwhowto.xyz","nudegista.com","nudistube.com","nuhuskies.com","nukibooks.com","nulledmug.com","nupload.top>>","nuviatoon.com","nvimfreak.com","nwemail.co.uk","nwusports.com","oakridger.com","odiadance.com","odiafresh.com","officedepot.*","ogoplayer.xyz","ohmybrush.com","ojogos.com.br","okhatrimaza.*","oklahoman.com","onemanhua.com","onlinegdb.com","onlyssh.my.id","onlystream.tv","op-marburg.de","openloadmov.*","openlua.cloud","openrouter.ai","ostreaming.tv","otakuliah.com","otakuporn.com","otonanswer.jp","ottawasun.com","ovcsports.com","owlsports.com","ozulscans.com","padovaoggi.it","pagalfree.com","pagalmovies.*","pagalworld.us","paidnaija.com","paipancon.com","panuvideo.com","paolo9785.com","parisporn.org","parmatoday.it","pasteboard.co","pastelink.net","patchsite.net","pawastreams.*","pc-builds.com","pc-magazin.de","pclicious.net","peacocktv.com","peladas69.com","peliculas24.*","pelisflix20.*","pelisgratis.*","pelismart.com","pelisplusgo.*","pelisplushd.*","pelisplusxd.*","pelisstar.com","perplexity.ai","pervclips.com","pg-wuming.com","phimfun.net>>","pianokafe.com","pic-upload.de","picbcxvxa.sbs","pichaloca.com","pics-view.com","pienovels.com","pinterest.com","piraproxy.app","pirateproxy.*","pitchfork.com","pixbkghxa.sbs","pixbryexa.sbs","pixnbrqwg.sbs","pixtryab.shop","pkbiosfix.com","pkproject.net","plattformj.ch","play.aetv.com","player.stv.tv","player4me.vip","playfmovies.*","playpaste.com","plugincim.com","pocketnow.com","poco.rcccn.in","pokemundo.com","polska-ie.com","popcorntime.*","porn4fans.com","pornbaker.com","pornbimbo.com","pornblade.com","pornborne.com","pornchaos.org","pornchimp.com","porncomics.me","porncoven.com","porndollz.com","porndrake.com","pornfelix.com","pornfuzzy.com","pornloupe.com","pornmonde.com","pornoaffe.com","pornobait.com","pornocomics.*","pornoeggs.com","pornohaha.com","pornohans.com","pornohelm.com","pornokeep.com","pornoleon.com","pornomico.com","pornonline.cc","pornonote.pro","pornoplum.com","pornproxy.app","pornproxy.art","pornretro.xyz","pornslash.com","porntopic.com","porntube18.cc","posterify.net","pourcesoir.in","povaddict.com","powforums.com","pravda.com.ua","pregledaj.net","pressplay.cam","pressplay.top","prignitzer.de","primeflix.*>>","primewire.*>>","proappapk.com","proboards.com","produktion.de","promiblogs.de","prostoporno.*","protestia.com","protopage.com","pureleaks.net","pussy-hub.com","pussyspot.net","putlockertv.*","puzzlefry.com","pvpoke-re.com","pygodblog.com","quesignifi.ca","quicasting.it","quickporn.net","rainytube.com","rakuten.co.jp","ranourano.xyz","rbscripts.net","read.amazon.*","readingbd.com","realbooru.com","realmadryt.pl","recaptcha.net","rechtslupe.de","recordnet.com","redhdtube.xxx","redsexhub.com","reliabletv.me","repelisgooo.*","restorbio.com","reviewdiv.com","rexdlfile.com","ridvanmau.com","riggosrag.com","ritzyporn.com","rocdacier.com","rockradio.com","rojadirecta.*","romsgames.net","romspedia.com","rossoporn.com","rottenlime.pw","roystream.com","rufiiguta.com","rule34.jp.net","rumbunter.com","ruyamanga.com","s.sseluxx.com","sagewater.com","sarapbabe.com","sassytube.com","savefiles.com","scatkings.com","scimagojr.com","scrapywar.com","scrolller.com","selfhostt.com","sendspace.com","seneporno.com","sensacine.com","seriesite.net","set.seturl.in","sex-babki.com","sexbixbox.com","sexbox.online","sexdicted.com","sexmazahd.com","sexmutant.com","sexphimhd.net","sextube-6.com","sexyscope.net","sexytrunk.com","sfastwish.com","sfirmware.com","shameless.com","share.hntv.tv","share1223.com","sharemods.com","sharkfish.xyz","sharphindi.in","shemaleup.net","short-fly.com","short1ink.com","shortlinkto.*","shortnest.com","shortpaid.com","shorttrick.in","shownieuws.nl","shroomers.app","siimanga.cyou","simana.online","simplebits.io","simpmusic.org","sissytube.net","sitefilme.com","sitegames.net","sk8therapy.fr","skymovieshd.*","smartworld.it","smashkarts.io","snapwordz.com","socigames.com","softcobra.com","softfully.com","sohohindi.com","solarmovie.id","solarmovies.*","solotrend.net","songfacts.com","sosovalue.com","spankbang.com","spankbang.mov","speedporn.net","speedtest.net","speedweek.com","spfutures.org","spokesman.com","spontacts.com","sportbar.live","sportlemons.*","sportlemonx.*","sportowy24.pl","sportsbite.cc","sportsembed.*","sportsnest.co","sportsrec.com","sportweb.info","spotsaver.net","spring.org.uk","ssyoutube.com","stagemilk.com","stalkface.com","starsgtech.in","startseite.to","statesman.com","ster-blog.xyz","stereogum.com","stock-rom.com","str8ongay.com","stre4mpay.one","stream-69.com","stream4free.*","streambtw.com","streamcash.to","streamcloud.*","streamfree.to","streamhd247.*","streamobs.net","streampoi.com","streamporn.cc","streamsport.*","streamta.site","streamtp1.com","streamvid.dev","streamvid.net","strefaagro.pl","stripecdn.com","striptube.net","stylist.co.uk","subtitles.cam","subtorrents.*","suedkurier.de","sulleiman.com","sunporno.club","superstream.*","supervideo.tv","supforums.com","sweetgirl.org","swisscows.com","switch520.com","sylverkat.com","sysguides.com","szexkepek.net","szexvideok.hu","t-rocforum.de","tab-maker.com","taboodude.com","taigoforum.de","talksport.com","tamilarasan.*","tamilguns.org","tamilhit.tech","tapenoads.com","tatsublog.com","techacode.com","techclips.net","techdriod.com","techilife.com","technofino.in","techradar.com","techrecur.com","techtrim.tech","techybuff.com","techyrick.com","teenvogue.com","tehnotone.com","teknisitv.com","temp-mail.lol","temp-mail.org","tempumail.com","tennis.stream","ternitoday.it","terrylove.com","testsieger.de","texastech.com","theintell.com","thejournal.ie","thelayoff.com","theledger.com","thememypc.net","thenation.com","thespruce.com","thestar.co.uk","thestreet.com","thetemp.email","thethings.com","thetravel.com","theuser.cloud","theweek.co.uk","thichcode.net","thiepmung.com","thotpacks.xyz","thotslife.com","thoughtco.com","tierfreund.co","tierlists.com","timescall.com","tinyzonetv.cc","tinyzonetv.se","tiz-cycling.*","tmohentai.com","to-travel.net","tok-thots.com","tokopedia.com","tokuzilla.net","topwwnews.com","torgranate.de","torrentz2eu.*","torupload.com","totalcsgo.com","totaldebrid.*","tourporno.com","towerofgod.me","trade2win.com","trailerhg.xyz","trangchu.news","transfaze.com","transflix.net","transtxxx.com","travelbook.de","tremamnon.com","tribeclub.com","tricksplit.io","trigonevo.com","trilltrill.jp","tripsavvy.com","tsubasatr.org","tubehqxxx.com","tubemania.org","tubereader.me","tudigitale.it","tudotecno.com","tukipasti.com","tunabagel.net","tunemovie.fun","turkleech.com","tutcourse.com","tvfutbol.info","twink-hub.com","twitchcdn.net","twojeip.wp.pl","twstalker.com","txxxporn.tube","uberhumor.com","ubuntudde.com","udemyking.com","udinetoday.it","uhcougars.com","uicflames.com","uniqueten.net","unlockapk.com","unlockxh4.com","unnuetzes.com","unterhalt.net","up4stream.com","upfilesgo.com","uploadgig.com","uptoimage.com","urgayporn.com","utrockets.com","uwbadgers.com","vectorizer.io","vegamoviese.*","veoplanet.com","verhentai.top","vermoegen.org","vibestreams.*","vibraporn.com","vid-guard.com","vidaextra.com","videoplayer.*","vidora.stream","vidspeeds.com","vidstream.pro","viefaucet.com","villanova.com","vintagetube.*","vipergirls.to","vipserije.com","vipstand.pm>>","visionias.net","visnalize.com","vixenless.com","vkrovatku.com","voidtruth.com","voiranime1.fr","voirseries.io","vosfemmes.com","vpntester.org","vpzserver.com","vstplugin.net","vuinsider.com","w3layouts.com","waploaded.com","warezsite.net","watch.plex.tv","watchdirty.to","watchluna.com","watchmovies.*","watchseries.*","watchsite.net","watchtv24.com","wdpglobal.com","weatherwx.com","weeronline.nl","weirdwolf.net","wendycode.com","westmanga.org","wetpussy.sexy","wg-gesucht.de","whoreshub.com","whtimes.co.uk","widewifes.com","wikipedia.org","wikipekes.com","wikitechy.com","willcycle.com","windowspro.de","wkusports.com","wlz-online.de","wmagazine.com","wmoviesfree.*","wonderapk.com","wordshake.com","workink.click","world4ufree.*","worldfree4u.*","worldsports.*","worldstar.com","worldtop2.com","wowescape.com","wunderweib.de","wvusports.com","www.amazon.de","www.seznam.cz","www.twitch.tv","www.yahoo.com","x-fetish.tube","x-videos.name","xanimehub.com","xhbranch5.com","xhchannel.com","xhlease.world","xhplanet1.com","xhplanet2.com","xhvictory.com","xhwebsite.com","xmovies08.org","xnxxjapon.com","xoxocomic.com","xrivonet.info","xsportbox.com","xsportshd.com","xxvideoss.org","xxx-image.com","xxxbunker.com","xxxcomics.org","xxxfree.watch","xxxhothub.com","xxxscenes.net","xxxvideo.asia","xxxvideor.com","y2meta-uk.com","yachtrevue.at","yamiisoku.com","yandexcdn.com","yaoiotaku.com","ycongnghe.com","yesmovies.*>>","yesmovies4u.*","yeswegays.com","ymp4.download","yogitimes.com","youjizzz.club","youlife24.com","youngleak.com","youpornfm.com","youtubeai.com","yoyofilmeys.*","yt1s.com.co>>","yumekomik.com","zamundatv.com","zekamashi.net","zerotopay.com","zigforums.com","zinkmovies.in","zmamobile.com","zoompussy.com","zorroplay.xyz","0dramacool.net","111.90.141.252","111.90.150.149","111.90.159.132","1111fullwise.*","123animehub.cc","123moviefree.*","123movierulz.*","123movies4up.*","123moviesd.com","123movieshub.*","185.193.17.214","188.166.182.72","18girlssex.com","1cloudfile.com","1pack1goal.com","1primewire.com","1shortlink.com","1stkissmanga.*","3gpterbaru.com","3rabsports.com","4everproxy.com","69hoshudaana.*","69teentube.com","absolugirl.com","absolutube.com","admiregirls.su","adnan-tech.com","adsafelink.com","afilmywapi.biz","agedvideos.com","airsextube.com","akumanimes.com","akutsu-san.com","alexsports.*>>","alimaniacky.cz","allbbwtube.com","allcalidad.app","allcelebs.club","allmovieshub.*","allosoccer.com","allpremium.net","allrecipes.com","alluretube.com","allwpworld.com","almezoryae.com","alphaporno.com","amanguides.com","amateurfun.net","amateurporn.co","amigosporn.top","ancensored.com","anconatoday.it","androgamer.org","ani-stream.com","anime4mega.net","animeblkom.net","animefire.info","animefire.plus","animeheaven.ru","animeindo.asia","animeshqip.org","animespank.com","animesvision.*","anonymfile.com","anyxvideos.com","aozoraapps.net","app.cekresi.me","appsfree4u.com","arab4media.com","arabincest.com","arabxforum.com","arealgamer.org","ariversegl.com","arlinadzgn.com","armyranger.com","articlebase.pk","artoffocas.com","ashemaletube.*","ashemaletv.com","asianporn.sexy","asianwatch.net","askpaccosi.com","askushowto.com","assesphoto.com","astro-seek.com","atlantic10.com","autocentrum.pl","autopareri.com","av1encodes.com","b3infoarena.in","balkanteka.net","bamahammer.com","bantenexis.com","batmanstream.*","battleboats.io","bbwfuckpic.com","bcanepaltu.com","bcsnoticias.mx","bdsmstreak.com","bdsomadhan.com","bdstarshop.com","beegvideoz.com","belloporno.com","benzinpreis.de","bergwelten.com","best18porn.com","bestofarea.com","betaseries.com","bgmiesports.in","bharian.com.my","bidersnotu.com","bildderfrau.de","bingotingo.com","bit-shares.com","bitcotasks.com","bitcrypto.info","bittukitech.in","blackcunts.org","blackteen.link","blocklayer.com","blowjobgif.net","bluedollar.net","boersennews.de","bolly-tube.com","bollywoodx.org","bonappetit.com","bonstreams.net","boobieblog.com","boobsradar.com","boobsrealm.com","boredgiant.com","boxaoffrir.com","brainknock.net","bravoteens.com","bravotube.asia","brightpets.org","brulosophy.com","btcadspace.com","btvnovinite.bg","buccaneers.com","buchstaben.com","businessua.com","bustmonkey.com","bustybloom.com","bysefujedu.com","bysejikuar.com","byseqekaho.com","byseraguci.com","bysesukior.com","bysetayico.com","cacfutures.org","cadenadial.com","calculate.plus","calgarysun.com","camgirlbay.net","camgirlfap.com","camsstream.com","canalporno.com","caracol.com.co","cardscanner.co","carrnissan.com","casertanews.it","celebjihad.com","celebretea.com","celebwhore.com","cellmapper.net","cesenatoday.it","cg-gamespc.net","chachocool.com","chanjaeblog.jp","chart.services","chatgptfree.ai","chaturflix.cam","cheatermad.com","chietitoday.it","christitus.com","cincinnati.com","cine-calidad.*","cinelatino.net","cinemalibero.*","cinepiroca.com","claimcrypto.cc","claimlite.club","clasicotas.org","clicknupload.*","clipartmax.com","cloudflare.com","cloudhostt.com","cloudvideotv.*","club-flank.com","cntraveler.com","codeandkey.com","coinadpro.club","coloradoan.com","comdotgame.com","comicsarmy.com","comingsoon.net","comixzilla.com","commanders.com","compromath.com","comunio-cl.com","convert2mp3.cx","coolrom.com.au","copyseeker.net","courseboat.com","coverapi.space","coverapi.store","cpu-monkey.com","crackshash.com","cracksports.me","crazygames.com","crazyvidup.com","creebhills.com","crichdplays.ru","cricwatch.io>>","croq-kilos.com","crunchyscan.fr","crypt.cybar.to","cryptoforu.org","cryptonetos.ru","cryptstream.de","csgo-ranks.com","cuckoldsex.net","curseforge.com","cwtvembeds.com","cyberscoop.com","czechvideo.org","daddylive.link","dafreeporn.com","dagensnytt.com","daily-jeff.com","dailycomet.com","dailylocal.com","dailyworld.com","dallasnews.com","dansmovies.com","daotranslate.*","daxfutures.org","dayuploads.com","ddwloclawek.pl","decompiler.com","defenseone.com","delcotimes.com","derstandard.at","derstandard.de","desicinema.org","desicinemas.pk","designbump.com","desiremovies.*","desktophut.com","devdrive.cloud","deviantart.com","devuploads.com","diampokusy.com","dicariguru.com","dieblaue24.com","digipuzzle.net","direct-cloud.*","dirtytamil.com","disneyplus.com","dobletecno.com","dodgersway.com","dogsexporn.net","donegallive.ie","doseofporn.com","dotesports.com","dotfreesex.com","dotfreexxx.com","doujinnote.com","dowfutures.org","downloadming.*","drakecomic.com","dreamfancy.org","duniailkom.com","dvdgayporn.com","dvdporngay.com","e123movies.com","easytodoit.com","eatingwell.com","ebooksyard.com","ecacsports.com","echo-online.de","ed-protect.org","eddiekidiw.com","eftacrypto.com","elaoffcial.com","elcorreoweb.es","electomania.es","elitegoltv.org","elitetorrent.*","elmalajeno.com","elnacional.cat","emailnator.com","embedsports.me","embedstream.me","empire-anime.*","emturbovid.com","emugameday.com","enryumanga.com","ensuretips.com","epicstream.com","epicurious.com","ericdraken.com","erinsakura.com","erokomiksi.com","eroprofile.com","esgentside.com","esportivos.fun","este-walks.net","estrenosflix.*","estrenosflux.*","ethiopia.co.il","euronews.com>>","eveningsun.com","examscisco.com","exbulletin.com","expertplay.net","exteenporn.com","extratorrent.*","extreme-down.*","eztvtorrent.co","f123movies.com","faaduindia.com","fairyanime.com","faitsfizzle.fr","fakazagods.com","fakedetail.com","fanatik.com.tr","fantacalcio.it","fap-nation.org","faperplace.com","faselhdwatch.*","fastdour.store","fatxxxtube.com","faucetdump.com","fduknights.com","fetishburg.com","fettspielen.de","fhmemorial.com","fibwatch.store","filemirage.com","fileplanet.com","filesharing.io","filesupload.in","film-adult.com","filme-bune.biz","filmifen.com>>","filmpertutti.*","filmy4waps.org","filmypoints.in","filmyzones.com","filtercams.com","finanztreff.de","finderporn.com","findtranny.com","fine-wings.com","firefaucet.win","fitdynamos.com","fleamerica.com","flostreams.xyz","flycutlink.com","fmoonembed.pro","foodgustoso.it","foodiesjoy.com","foodtechnos.in","football365.fr","fooxybabes.com","forex-trnd.com","freeforums.net","freegayporn.me","freehqtube.com","freeltc.online","freemodsapp.in","freepasses.org","freepreset.net","freesoccer.net","freesolana.top","freetubetv.net","freiepresse.de","freshplaza.com","freshremix.net","frostytube.com","fu-4u3omzw0.nl","fucktube4k.com","fuckundies.com","fullporner.com","fullvoyeur.com","gadgetbond.com","gamefi-mag.com","gameofporn.com","games.amny.com","games.insp.com","games.metro.us","games.metv.com","games.wtop.com","games2rule.com","games4king.com","gamesgames.com","gamesleech.com","gayforfans.com","gaypornhot.com","gayxxxtube.net","gazettenet.com","gdr-online.com","gdriveplayer.*","gearjunkie.com","gecmisi.com.tr","genovatoday.it","getintopcm.com","getintoway.com","getmaths.co.uk","gettapeads.com","gisvacancy.com","gknutshell.com","gloryshole.com","gobearcats.com","gofirmware.com","goislander.com","golfdigest.com","golightsgo.com","gomoviesfree.*","gomovieshub.io","goodreturns.in","goodstream.one","googlvideo.com","gorecenter.com","gorgeradio.com","gosbagotui.com","goshockers.com","gostanford.com","gostreamon.net","goterriers.com","gotgayporn.com","gotigersgo.com","gourmandix.com","gousfbulls.com","govtportal.org","grannysex.name","grantorrent1.*","grantorrents.*","graphicget.com","growgritly.com","grubstreet.com","guitarnick.com","gujjukhabar.in","gurbetseli.net","guruofporn.com","gutfuerdich.co","gyanitheme.com","gyonlineng.com","haloursynow.pl","hanime1-me.top","hannibalfm.net","hardcorehd.xxx","haryanaalert.*","hausgarten.net","hawtcelebs.com","hdhub4one.pics","hdmovies23.com","hdmoviesfair.*","hdmoviesflix.*","hdmoviesmaza.*","hdpornteen.com","healthelia.com","healthmyst.com","hentai-for.net","hentai-hot.com","hentai-one.com","hentaiasmr.moe","hentaiblue.net","hentaibros.com","hentaicity.com","hentaidays.com","hentaihere.com","hentaipins.com","hentairead.com","hentaisenpai.*","hentaiworld.tv","heraldnews.com","heysigmund.com","hidefninja.com","hilaryhahn.com","hinatasoul.com","hindilinks4u.*","hindimovies.to","hindiporno.pro","hit-erotic.com","hollymoviehd.*","homebooster.de","homeculina.com","horoskop.wp.pl","hortidaily.com","hotcleaner.com","hotgirlhub.com","hotgirlpix.com","houmatoday.com","howtocivil.com","hpaudiobooks.*","huggingface.co","hyogo.ie-t.net","hypershort.com","i123movies.net","iconmonstr.com","idealfollow.in","idlelivelink.*","ilifehacks.com","ilikecomix.com","imagetwist.com","imgjbxzjv.shop","imgjmgfgm.shop","imgjvmbbm.shop","imgnnnvbrf.sbs","in-cumbria.com","inbbotlist.com","indeonline.com","indi-share.com","indiatimes.com","indopanas.cyou","infocycles.com","infokita17.com","infomaniakos.*","informacion.es","inhumanity.com","insidenova.com","instaporno.net","ios.codevn.net","iqksisgw.xyz>>","isekaitube.com","issstories.xyz","itechfever.com","itopmusics.com","itopmusicx.com","iuhoosiers.com","jacksonsun.com","jacksorrell.tv","jalshamoviez.*","janamathaya.lk","japannihon.com","javaguides.net","javbangers.com","javggvideo.xyz","javhdvideo.org","javheroine.com","javplayers.com","javsexfree.com","javsubindo.com","javtsunami.com","javxxxporn.com","jeniusplay.com","jewelry.com.my","jizzbunker.com","join2babes.com","joyousplay.xyz","jpopsingles.eu","juegoviejo.com","jugomobile.com","juicy3dsex.com","justababes.com","justembeds.xyz","justthegays.tv","kaboomtube.com","kahanighar.com","kakarotfoot.ru","kannadamasti.*","kashtanka2.com","keepkoding.com","kendralist.com","kgs-invest.com","khabarbyte.com","kickassanime.*","kickasshydra.*","kiddyshort.com","kindergeld.org","kingofdown.com","kiradream.blog","kisahdunia.com","kits4beats.com","klartext-ne.de","kokostream.net","komikmanhwa.me","kompasiana.com","kongregate.com","kordramass.com","kurakura21.com","kuruma-news.jp","ladkibahin.com","lampungway.com","laprovincia.es","laradiobbs.net","laser-pics.com","latinatoday.it","lauradaydo.com","layardrama21.*","lcsun-news.com","leaderpost.com","leakedzone.com","leakshaven.com","learnospot.com","lebahmovie.com","ledauphine.com","lenconnect.com","lesboluvin.com","lesfoodies.com","letmejerk2.com","letmejerk3.com","letmejerk4.com","letmejerk5.com","letmejerk6.com","letmejerk7.com","lewdcorner.com","lifehacker.com","ligainsider.de","limetorrents.*","linemarlin.com","link.vipurl.in","linkconfig.com","livecamrips.to","livenewsof.com","lizardporn.com","login.asda.com","lokhung888.com","lookmovie186.*","ludwig-van.com","lulustream.com","m.liputan6.com","macheforum.com","mactechnews.de","macworld.co.uk","mad4wheels.com","madchensex.com","madmaxworld.tv","mahitimanch.in","mail.yahoo.com","main-spitze.de","maliekrani.com","manga4life.com","mangamovil.net","manganatos.com","mangaraw18.net","mangarawad.fit","mangareader.to","mangatrend.org","manhuarmtl.com","manhuascan.com","manhwaclub.net","manhwalist.com","manhwaread.com","marionstar.com","marketbeat.com","masteranime.tv","mathepower.com","maths101.co.za","matureworld.ws","mcafee-com.com","mega-debrid.eu","megacanais.com","megalinks.info","megamovies.org","megapastes.com","mehr-tanken.de","mejortorrent.*","mercato365.com","merkmal-biz.jp","meteologix.com","mewingzone.com","miiiixdrop.net","milanotoday.it","milanworld.net","milffabrik.com","minecraft.buzz","minorpatch.com","mixmods.com.br","mixrootmod.com","mjsbigblog.com","mkv-pastes.com","mobileporn.cam","mockupcity.com","modapkfile.com","moddedguru.com","modenatoday.it","moegirl.org.cn","mommybunch.com","mommysucks.com","momsextube.pro","monroenews.com","mortaltech.com","motchill29.com","motherless.com","motogpstream.*","motorcycle.com","motorgraph.com","motorsport.com","motscroises.fr","movearnpre.com","moviefree2.com","movies2watch.*","moviesapi.club","movieshd.watch","moviesjoy-to.*","moviesjoyhd.to","moviesnation.*","movisubmalay.*","mprogaming.com","mtsproducoes.*","multiplayer.it","mummumtime.com","musketfire.com","mxpacgroup.com","mycoolmoviez.*","mydesibaba.com","myforecast.com","myglamwish.com","myinstants.com","mylifetime.com","mynewsmedia.co","mypornhere.com","myporntape.com","mysexgamer.com","mysexgames.com","myshrinker.com","mytectutor.com","naasongsfree.*","naijauncut.com","nammakalvi.com","naplesnews.com","naszemiasto.pl","navysports.com","nazarickol.com","nensaysubs.net","neonxcloud.top","neservicee.com","netchimp.co.uk","new.lewd.ninja","newmovierulz.*","news-press.com","newsbreak24.de","newscard24.com","newsherald.com","newsleader.com","ngontinh24.com","nicheporno.com","nichetechy.com","nikaplayer.com","ninernoise.com","nirjonmela.com","nishankhatri.*","niteshyadav.in","nitro-link.com","nitroflare.com","niuhuskies.com","nodenspace.com","nosteam.com.ro","notunmovie.net","notunmovie.org","novaratoday.it","novel-gate.com","novelaplay.com","novelgames.com","novostrong.com","nowosci.com.pl","nudebabes.sexy","nudisteens.com","nulledbear.com","nulledteam.com","nullforums.net","nulljungle.com","nurulislam.org","nylondolls.com","ocregister.com","officedepot.fr","oggitreviso.it","okamimiost.com","omegascans.org","onlineatlas.us","onlinekosh.com","onlineporno.cc","openstartup.tm","opentunnel.net","oregonlive.com","organismes.org","orgasmlist.com","orgyxxxhub.com","orovillemr.com","osubeavers.com","osuskinner.com","oteknologi.com","ourenseando.es","overhentai.net","packhacker.com","palapanews.com","palofw-lab.com","pandamovies.me","pandamovies.pw","pandanote.info","pantieshub.net","paradepets.com","paris-tabi.com","paste-drop.com","paylaterin.com","peachytube.com","pekintimes.com","pelismartv.com","pelismkvhd.com","pelispedia24.*","pelispoptv.com","pemersatu.link","perfectgirls.*","perfektdamen.*","pervertium.com","perverzija.com","pethelpful.com","petitestef.com","pherotruth.com","phoneswiki.com","picgiraffe.com","picjgfjet.shop","pickleball.com","pictryhab.shop","picturelol.com","pimylifeup.com","pink-sluts.net","pinterpoin.com","pirate4all.com","pirateblue.com","pirateblue.net","pirateblue.org","piratemods.com","pivigames.blog","planetsuzy.org","platinmods.com","play-games.com","play.xpass.top","playcast.click","player-cdn.com","player.rtl2.de","player.sbnmp.*","playermeow.com","playertv24.com","playhydrax.com","podkontrola.pl","polsatsport.pl","polskatimes.pl","pop-player.com","popno-tour.net","porconocer.com","porn0video.com","pornahegao.xyz","pornasians.pro","pornerbros.com","pornflixhd.com","porngames.club","pornharlot.net","pornhd720p.com","pornincest.net","pornissimo.org","pornktubes.net","pornodavid.com","pornodoido.com","pornofelix.com","pornofisch.com","pornojenny.net","pornoperra.com","pornopics.site","pornoreino.com","pornotommy.com","pornotrack.net","pornozebra.com","pornrabbit.com","pornrewind.com","pornsocket.com","porntrex.video","porntube15.com","porntubegf.com","pornvideoq.com","pornvintage.tv","portaldoaz.org","portalyaoi.com","poscitechs.lol","powerover.site","powershell.org","premierftp.com","prepostseo.com","pressemedie.dk","primagames.com","primemovies.pl","primevid.click","primevideo.com","printables.com","proapkdown.com","pruefernavi.de","purediablo.com","purepeople.com","pussyspace.com","pussyspace.net","pussystate.com","put-locker.com","putingfilm.com","puzzleship.com","queerdiary.com","querofilmehd.*","questloops.com","rabbitsfun.com","radiopogoda.pl","radiotimes.com","radiotunes.com","rahim-soft.com","ramblinfan.com","rankersadda.in","ravenscans.com","rbxscripts.net","rcostation.xyz","realbbwsex.com","realgfporn.com","realmoasis.com","realmomsex.com","realsimple.com","record-bee.com","recordbate.com","redecanaishd.*","redecanaistv.*","redfaucet.site","rednowtube.com","redpornnow.com","redtubemov.com","reggiotoday.it","reisefrage.net","resortcams.com","revealname.com","reviersport.de","reviewrate.net","revivelink.com","richtoscan.com","riminitoday.it","ringelnatz.net","ripplehub.site","rlxtech24h.com","rmacsports.org","roadtrippin.fr","robbreport.com","rokuhentai.com","rollrivers.com","rollstroll.com","romaniasoft.ro","romhustler.org","royaledudes.io","rpmplay.online","rubyvidhub.com","rugbystreams.*","ruinmyweek.com","russland.jetzt","rusteensex.com","ruyashoujo.com","safefileku.com","safemodapk.com","saita-puls.com","samaysawara.in","sanfoundry.com","saratogian.com","sat.technology","sattaguess.com","saveshared.com","savevideo.tube","sciencebe21.in","scoreland.name","scrap-blog.com","screenflash.io","screenrant.com","scriptsomg.com","scriptsrbx.com","scriptzhub.com","section215.com","seeitworks.com","seekplayer.vip","seirsanduk.com","seksualios.com","selfhacked.com","serienstream.*","series2watch.*","seriesonline.*","seriesperu.com","seriesyonkis.*","serijehaha.com","severeporn.com","sex-empire.org","sex-movies.biz","sexcams-24.com","sexgamescc.com","sexgayplus.com","sextubedot.com","sextubefun.com","sextubeset.com","sexvideos.host","sexyaporno.com","sexybabes.club","sexybabesz.com","sexynakeds.com","sgvtribune.com","shahid.mbc.net","sharedwebs.com","shazysport.pro","sheamateur.com","shegotass.info","sheikhmovies.*","shelbystar.com","shemalesin.com","shesfreaky.com","shinobijawi.id","shooshtime.com","shop123.com.tw","short-url.link","shorterall.com","shrinkearn.com","shueisharaw.tv","shupirates.com","sieutamphim.me","siliconera.com","singjupost.com","sitarchive.com","siusalukis.com","skat-karten.de","slickdeals.net","slidesaver.app","slideshare.net","smartinhome.pl","smarttrend.xyz","smiechawatv.pl","snhupenmen.com","solidfiles.com","soranews24.com","soundboards.gg","spaziogames.it","speedostream.*","speisekarte.de","spiele.bild.de","spieletipps.de","spiritword.net","spoilerplus.tv","sporteurope.tv","sportsdark.com","sportsonline.*","sportsurge.net","sproutgigs.com","spy-x-family.*","stadelahly.net","stahnivideo.cz","standard.co.uk","stardewids.com","starzunion.com","stbemuiptv.com","steamverde.net","stireazilei.eu","storiesig.info","storyblack.com","stownrusis.com","straemplay.org","stream2watch.*","streamdesi.com","streamlord.com","streamruby.com","streamxtv.tech","stripehype.com","studydhaba.com","subtitleone.cc","subtorrents1.*","super-games.cz","superanimes.in","suvvehicle.com","svetserialu.io","svetserialu.to","swatchseries.*","swordalada.org","tainhanhvn.com","talkceltic.net","talkjarvis.com","tamilnaadi.com","tamilprint29.*","tamilprint30.*","tamilprint31.*","tamilprinthd.*","taradinhos.com","tarnkappe.info","taschenhirn.de","tech-blogs.com","tech-story.net","techcrunch.com","techhelpbd.com","techiestalk.in","techkeshri.com","techmyntra.net","techperiod.com","techsignin.com","techsslash.com","tecnoaldia.net","tecnobillo.com","tecnoscann.com","tecnoyfoto.com","teenager365.to","teenextrem.com","teenhubxxx.com","teensexass.com","tekkenmods.com","telemagazyn.pl","teleshow.wp.pl","telesrbija.com","temp.modpro.co","tennessean.com","tennisactu.net","testserver.pro","textograto.com","textovisia.com","texturecan.com","the-leader.com","the-review.com","theargus.co.uk","theavtimes.com","thefantazy.com","theflixertv.to","thegleaner.com","thehesgoal.com","theinertia.com","themeslide.com","thenetnaija.co","thepiratebay.*","theporngod.com","therichest.com","thesextube.net","thetakeout.com","thethothub.com","thetimes.co.uk","thevideome.com","thewambugu.com","thotchicks.com","titsintops.com","tojimangas.com","tomshardware.*","topcartoons.tv","topsporter.net","topwebgirls.eu","torinotoday.it","tormalayalam.*","torontosun.com","torovalley.net","torrentmac.net","totalsportek.*","tournguide.com","tous-sports.ru","towerofgod.top","toyokeizai.net","tpornstars.com","tradingref.com","trafficnews.jp","trancehost.com","trannyline.com","trashbytes.net","traumporno.com","travelhost.com","treehugger.com","trendflatt.com","trentonian.com","trentotoday.it","tribunnews.com","tronxminer.com","truckscout24.*","trustpilot.com","tuberzporn.com","tubesafari.com","tubexxxone.com","tukangsapu.net","turbocloud.xyz","turkish123.com","tv-films.co.uk","tv.youtube.com","tvspielfilm.de","twincities.com","u123movies.com","ucfknights.com","uciteljica.net","uclabruins.com","ufreegames.com","uiuxsource.com","uktvplay.co.uk","unblocked.name","unblocksite.pw","uncpbraves.com","uncwsports.com","unlvrebels.com","uoflsports.com","uploadbank.com","uploadking.net","uploadmall.com","uploadraja.com","upnewsinfo.com","uptostream.com","urlbluemedia.*","urldecoder.org","usctrojans.com","usdtoreros.com","usersdrive.com","utepminers.com","uyduportal.net","v2movies.click","vanityfair.com","vavada5com.com","vbox7-mp3.info","vegamovies4u.*","vegamovvies.to","veo-hentai.com","vestimage.site","video-seed.xyz","video1tube.com","videogamer.com","videolyrics.in","videos1002.com","videoseyred.in","videosgays.net","vidguardto.xyz","vidhidepre.com","vidhidevip.com","vidquickly.com","vidstreams.net","view.ceros.com","viewmature.com","vikistream.com","viralpedia.pro","virustotal.com","visortecno.com","vmorecloud.com","voiceloves.com","voipreview.org","voltupload.com","voyeurblog.net","vscode-cdn.net","vulgarmilf.com","vviruslove.com","wantmature.com","warefree01.com","watch-series.*","watchasians.cc","watchomovies.*","watchpornx.com","watchseries1.*","watchseries9.*","wawalove.wp.pl","wcoanimedub.tv","wcoanimesub.tv","wcoforever.net","webseries.club","weihnachten.me","wenxuecity.com","westmanga.info","wetteronline.*","whatfontis.com","whatismyip.com","whats-new.cyou","whatshowto.com","whodatdish.com","whoisnovel.com","wiacsports.com","wifi4games.com","wigantoday.net","willyweather.*","windbreaker.me","wizhdsports.fi","wkutickets.com","wmubroncos.com","womennaked.net","world4ufree1.*","worldofbin.com","worthcrete.com","wow-mature.com","wowxxxtube.com","wspolczesna.pl","wsucougars.com","www-y2mate.com","www.amazon.com","www.lenovo.com","www.reddit.com","www.tiktok.com","x2download.com","xanimeporn.com","xclusivejams.*","xdld.pages.dev","xerifetech.com","xfrenchies.com","xhofficial.com","xhomealone.com","xhwebsite5.com","xiaomi-miui.gr","xmegadrive.com","xnxxporn.video","xxx-videos.org","xxxbfvideo.net","xxxblowjob.pro","xxxdessert.com","xxxextreme.org","xxxtubedot.com","xxxtubezoo.com","xxxvideohd.net","xxxxselfie.com","xxxymovies.com","xxxyoungtv.com","yabaisub.cloud","yakisurume.com","yelitzonpc.com","yomucomics.com","yottachess.com","youngbelle.net","youporngay.com","youtubetomp3.*","yoututosjeff.*","yuki0918kw.com","yumstories.com","yunakhaber.com","zazzybabes.com","zentralplus.ch","zertalious.xyz","zippyshare.day","zona-leros.com","zonebourse.com","zooredtube.com","0123movie.space","10hitmovies.com","123movies-org.*","123moviesfree.*","123moviesfun.is","18-teen-sex.com","18asiantube.com","18porncomic.com","18teen-tube.com","1direct-cloud.*","1vid1shar.space","3xamatorszex.hu","4allprograms.me","5masterzzz.site","6indianporn.com","abyssplayer.com","adhs-zentrum.de","admediaflex.com","adminreboot.com","adrianoluis.net","adrinolinks.com","advicefunda.com","aeroxplorer.com","aflizmovies.com","agrarwetter.net","ai.hubtoday.app","aitoolsfree.org","alanyapower.com","aliezstream.pro","allclassic.porn","alldeepfake.ink","alldownplay.xyz","allotech-dz.com","allpussynow.com","alltechnerd.com","allucanheat.com","amazon-love.com","amritadrino.com","anallievent.com","androidapks.biz","androidsite.net","androjungle.com","anime-sanka.com","anime7.download","animedao.com.ru","animenew.com.br","animesexbar.com","animesultra.net","animexxxsex.com","antenasports.ru","aoashimanga.com","apfelpatient.de","apkmagic.com.ar","app.blubank.com","arabshentai.com","arcadepunks.com","archivebate.com","archiwumalle.pl","argio-logic.net","argusleader.com","arstechnica.com","asia.5ivttv.vip","asiangaysex.net","asianhdplay.net","askcerebrum.com","astrumscans.xyz","atemporal.cloud","atleticalive.it","atresplayer.com","au-di-tions.com","auto-service.de","autoindustry.ro","automat.systems","automothink.com","autoshieldd.com","avoiderrors.com","awdescargas.com","azcardinals.com","babesaround.com","babesinporn.com","babesxworld.com","badgehungry.com","bangpremier.com","baylorbears.com","bdsmkingdom.xyz","bdsmporntub.com","bdsmwaytube.com","beammeup.com.au","bedavahesap.org","beingmelody.com","bellezashot.com","bengalisite.com","bengalxpress.in","bentasker.co.uk","best-shopme.com","best18teens.com","bestensuree.com","bestialporn.com","bestjavporn.com","beurettekeh.com","bgmateriali.com","bgsufalcons.com","bibliopanda.com","big12sports.com","bigboobs.com.es","bigtitslust.com","bike-magazin.de","bike-urious.com","bintangplus.com","biologianet.com","bizjournals.com","blackavelic.com","blackpornhq.com","blacksexmix.com","blogenginee.com","blogpascher.com","blowxxxtube.com","bluebuddies.com","bluedrake42.com","bluemanhoop.com","bluemediafile.*","bluemedialink.*","bluemediaurls.*","bokepsin.in.net","bolly4umovies.*","boobs-mania.com","boobsforfun.com","bookpraiser.com","boosterx.stream","boxingstream.me","boxingvideo.org","boyfriendtv.com","braziliannr.com","bresciatoday.it","brieffreunde.de","brother-usa.com","buffsports.io>>","buffstreamz.com","buickforums.com","bulbagarden.net","bunkr-albums.io","burningseries.*","burytimes.co.uk","buzzheavier.com","caminteresse.fr","camwhoreshd.com","camwhorespy.com","camwhorez.video","captionpost.com","carbonite.co.za","casutalaurei.ro","cataniatoday.it","catchthrust.net","celticway.co.uk","cempakajaya.com","cerberusapp.com","chatropolis.com","cheatglobal.com","check-imei.info","cheese-cake.net","cheezburger.com","cherrynudes.com","chromeready.com","cieonline.co.uk","cinemakottaga.*","cineplus123.org","citibank.com.sg","ciudadgamer.com","claimclicks.com","classicoder.com","classifarms.com","cloud9obits.com","cloudnestra.com","code-source.net","codeitworld.com","codemystery.com","codeproject.com","coloringpage.eu","comicsporno.xxx","comoinstalar.me","compucalitv.com","computerbild.de","consoleroms.com","convertcase.net","coromon.wiki.gg","cosplaynsfw.xyz","cpomagazine.com","cracking-dz.com","crackthemes.com","crazyashwin.com","crazydeals.live","crunchyroll.com","crunchytech.net","cryptoearns.com","cta-fansite.com","cubbiescrib.com","cumshotlist.com","cutiecomics.com","cybertechng.com","cyclingnews.com","cycraracing.com","daemonanime.net","daily-times.com","dailyangels.com","dailybreeze.com","dailycaller.com","dailycamera.com","dailyecho.co.uk","dailyknicks.com","dailymail.co.uk","dailymotion.com","dailypost.co.uk","dailyrecord.com","dailystar.co.uk","dark-gaming.com","dawindycity.com","db-creation.net","dbupatriots.com","dbupatriots.org","decomaniacos.es","definitions.net","delmarvanow.com","desbloqueador.*","descargas2020.*","desirenovel.com","desixxxtube.org","detikbangka.com","detroitnews.com","deutschsex.mobi","devonlife.co.uk","dhankasamaj.com","digiztechno.com","diminimalis.com","direct-cloud.me","dirtybadger.com","discoveryplus.*","diversanews.com","dlouha-videa.cz","dobleaccion.xyz","docs.google.com","dollarindex.org","domainwheel.com","donnaglamour.it","donnerwetter.de","dopomininfo.com","dota2freaks.com","dotadostube.com","drake-scans.com","drakerelays.org","drama-online.tv","dramanice.video","dreamcheeky.com","drinksmixer.com","driveplayer.net","droidmirror.com","dtbps3games.com","duplex-full.lol","eaglesnovel.com","easylinkref.com","ebaticalfel.com","echo-news.co.uk","editorsadda.com","edmontonsun.com","edumailfree.com","eksporimpor.com","elektrikmen.com","elpasotimes.com","elperiodico.com","embed.acast.com","embed.meomeo.pw","embedcanais.com","embedplayer.xyz","embedsports.top","embedstreams.me","emperorscan.com","empire-stream.*","engstreams.shop","enryucomics.com","erotikclub35.pw","esportsmonk.com","esportsnext.com","exactpay.online","exam-results.in","explorecams.com","explorosity.net","exporntoons.net","exposestrat.com","extratorrents.*","fabioambrosi.it","fapfapgames.com","farmeramania.de","farminglife.com","faselhd-watch.*","fastcompany.com","faucetbravo.fun","fayobserver.com","fcportables.com","fdlreporter.com","fellowsfilm.com","femdomworld.com","femjoybabes.com","feral-heart.com","fidlarmusic.com","fifetoday.co.uk","file-upload.net","file-upload.org","file.gocmod.com","filecrate.store","filehost9.com>>","filespayout.com","filmesonlinex.*","filmoviplex.com","filmy4wap.co.in","filmyzilla5.com","finalnews24.com","financebolo.com","financemonk.net","financewada.com","financeyogi.net","finanzfrage.net","findnewjobz.com","fingerprint.com","firmenwissen.de","fitnesstipz.com","fitpractise.com","fizzlefacts.com","fizzlefakten.de","flashsports.org","flordeloto.site","flyanimes.cloud","flygbussarna.se","flywareagle.com","fmradiofree.com","folgenporno.com","foodandwine.com","footyhunter.lol","forex-yours.com","foxseotools.com","freebitcoin.win","freebnbcoin.com","freecardano.com","freecourse.tech","freecricket.net","freegames44.com","freemockups.org","freeomovie.info","freepornjpg.com","freepornsex.net","freethemesy.com","freevpshere.com","freewebcart.com","french-stream.*","ftsefutures.org","fuckedporno.com","fullxxxporn.net","fztvseries.live","g-streaming.com","gadgetspidy.com","gadzetomania.pl","gainesville.com","game.digitap.eu","gamecopyworld.*","gameplayneo.com","gamersglobal.de","games.macon.com","games.word.tips","gamesaktuell.de","gamestorrents.*","gaminginfos.com","gamingvital.com","gartendialog.de","gayboystube.top","gaypornhdfree.*","gaypornlove.net","gaypornwave.com","gayvidsclub.com","gazetaprawna.pl","geiriadur.ac.uk","geissblog.koeln","gendatabase.com","georgiadogs.com","germanvibes.org","gesund-vital.de","getexploits.com","gewinnspiele.tv","gfx-station.com","girlssexxxx.com","givemeaporn.com","givemesport.com","glavmatures.com","globaldjmix.com","go.babylinks.in","gocreighton.com","goexplorers.com","gofetishsex.com","gofile.download","gogoanime.co.in","goislanders.com","gokushiteki.com","golderotica.com","golfchannel.com","gomacsports.com","gomarquette.com","gopsusports.com","gosanangelo.com","goxxxvideos.com","goyoungporn.com","gradehgplus.com","grandmatube.pro","grannyfucko.com","grasshopper.com","greattopten.com","grootnovels.com","gsmfirmware.net","gsmfreezone.com","gsmmessages.com","guidetechly.com","gut-erklaert.de","hacksnation.com","halohangout.com","handypornos.net","hanimesubth.com","hardcoreluv.com","hardwareluxx.de","hardxxxmoms.com","harshfaucet.com","hd-analporn.com","hd-easyporn.com","hdjavonline.com","hds-streaming.*","healthfatal.com","heavyfetish.com","heidelberg24.de","helicomicro.com","hentai-moon.com","hentai-senpai.*","hentai2read.com","hentaiarena.com","hentaibatch.com","hentaibooty.com","hentaicloud.com","hentaicovid.org","hentaifreak.org","hentaigames.app","hentaihaven.com","hentaihaven.red","hentaihaven.vip","hentaihaven.xxx","hentaiocean.com","hentaiporno.xxx","hentaipulse.com","hentaitube1.lol","heroine-xxx.com","hesgoal-live.io","hiddencamhd.com","hogtiehub.com>>","hokiesports.com","hollymoviehd.cc","hollywoodpq.com","hookupnovel.com","hostserverz.com","hot-cartoon.com","hotgameplus.com","hotmediahub.com","hotpornfile.org","hotsexstory.xyz","hotstunners.com","hotxxxpussy.com","hqxxxmovies.com","hscprojects.com","huntspost.co.uk","iban-rechner.de","ibcomputing.com","ibeconomist.com","ideal-teens.com","ikramlar.online","ilbassoadige.it","ilgazzettino.it","illicoporno.com","ilmessaggero.it","ilsole24ore.com","imagelovers.com","imgqnnnebrf.sbs","incgrepacks.com","indiakablog.com","infrafandub.com","inside-handy.de","instabiosai.com","insuredhome.org","interracial.com","inyatrust.co.in","iptvjournal.com","irvinetimes.com","italianoxxx.com","itsonsitetv.com","iwantmature.com","januflix.expert","japangaysex.com","japansporno.com","japanxxxass.com","jastrzabpost.pl","javcensored.net","javenglish.cc>>","javindosub.site","javmoviexxx.com","javpornfull.com","javraveclub.com","javteentube.com","javtrailers.com","jaysjournal.com","jetztspielen.de","jnvharidwar.org","jobslampung.net","jokerscores.com","kabarportal.com","karaoketexty.cz","kasvekuvvet.net","katmoviehd4.com","kattannonser.se","kawarthanow.com","keezmovies.surf","kent-life.co.uk","ketoconnect.net","ketubanjiwa.com","kickass-anime.*","kickassanime.ch","kiddyearner.com","kingsleynyc.com","kisshentaiz.com","kitabmarkaz.xyz","kittycatcam.com","kodewebsite.com","komikdewasa.art","komorkomania.pl","krakenfiles.com","kreiszeitung.de","krktcountry.com","kstorymedia.com","kurierverlag.de","kyoto-kanko.net","la123movies.org","langitmovie.com","laptechinfo.com","latinluchas.com","lavozdigital.es","ldoceonline.com","leakgallery.com","learnedclub.com","lecrabeinfo.net","legionscans.com","lendrive.web.id","lesbiansex.best","levante-emv.com","libertycity.net","librasol.com.br","liga3-online.de","lightsnovel.com","link.3dmili.com","link.asiaon.top","link.cgtips.org","link.codevn.net","linksheild.site","linkvertise.com","linux-talks.com","live.arynews.tv","livescience.com","livesport24.net","livestreames.us","livestreamtv.pk","livexscores.com","livingathome.de","livornotoday.it","lombardiave.com","londonworld.com","lookmoviess.com","looptorrent.org","lotusgamehd.xyz","lovelynudez.com","lovingsiren.com","luchaonline.com","lucrebem.com.br","lukesitturn.com","lulustream.live","lustesthd.cloud","lycee-maroc.com","lyrics-jpop.net","macombdaily.com","macrotrends.net","magdownload.org","mais.sbt.com.br","maisonbrico.com","mangahentai.xyz","mangahere.today","mangakakalot.gg","mangaonline.fun","mangaraw1001.cc","mangarawjp.asia","mangarussia.com","manhuarmmtl.com","manhwahentai.me","manoramamax.com","mantrazscan.com","marie-claire.es","marimo-info.net","marketmovers.it","maskinbladet.dk","mastakongo.info","mathsstudio.com","mathstutor.life","maxcheaters.com","maxjizztube.com","maxstream.video","maxtubeporn.net","me-encantas.com","medeberiya.site","medeberiya1.com","medeberiyaa.com","medeberiyas.com","medeberiyax.com","mediacast.click","mega4upload.com","mega4upload.net","mejortorrento.*","mejortorrents.*","mejortorrentt.*","memoriadatv.com","mensfitness.com","mensjournal.com","mentalfloss.com","mercerbears.com","mercurynews.com","messinatoday.it","metal-hammer.de","miiiiixdrop.net","milliyet.com.tr","miniminiplus.pl","minutolivre.com","mirrorpoi.my.id","mixrootmods.com","mmsmasala27.com","mobility.com.ng","mockuphunts.com","modelviewer.lol","modporntube.com","moflix-stream.*","molbiotools.com","mommy-pussy.com","momtubeporn.xxx","monhan-soku.com","motherporno.com","mov18plus.cloud","moviemaniak.com","movierulzfree.*","movierulzlink.*","movies2watch.tv","moviescounter.*","moviesonline.fm","moviessources.*","moviessquad.com","movieuniverse.*","mp3fromyou.tube","mrdeepfakes.com","mscdroidlabs.es","msdos-games.com","msonglyrics.com","msuspartans.com","muchohentai.com","multifaucet.org","musiclutter.xyz","musikexpress.de","myanimelist.net","mybestxtube.com","mydesiboobs.com","myfreeblack.com","mysexybabes.com","mywatchseries.*","myyoungbabe.com","mzansinudes.com","naijanowell.com","naijaray.com.ng","nakedbabes.club","nangiphotos.com","nativesurge.net","nativesurge.top","naughtyza.co.za","nbareplayhd.com","nbcolympics.com","necksdesign.com","needgayporn.com","nekopoicare.*>>","nemzetisport.hu","netflixlife.com","networkhint.com","news-herald.com","news-leader.com","newstechone.com","newyorkjets.com","nflspinzone.com","nicexxxtube.com","nissanzclub.com","nizarstream.com","noindexscan.com","noithatmyphu.vn","nokiahacking.pl","northjersey.com","nosteamgames.ro","notebookcheck.*","notesformsc.org","noteshacker.com","notunmovie.link","novelssites.com","nsbtmemoir.site","nsfwmonster.com","nsfwyoutube.com","nswdownload.com","nu6i-bg-net.com","nudeslegion.com","nudismteens.com","nukedpacks.site","nullscripts.net","nursexfilme.com","nyaatorrent.com","oceanofmovies.*","okiemrolnika.pl","olympustaff.com","omgexploits.com","online-smss.com","onlinekosten.de","open3dmodel.com","openculture.com","openloading.com","order-order.com","orgasmatrix.com","oromedicine.com","otokukensaku.jp","otomi-games.com","ourcoincash.xyz","oyundunyasi.net","ozulscansen.com","pacersports.com","pageflutter.com","pakkotoisto.com","palermotoday.it","panda-novel.com","pandamovies.org","pandasnovel.com","paperzonevn.com","paste4free.site","pawastreams.org","pawastreams.pro","pcgameszone.com","pdftoshokan.com","peliculas8k.com","peliculasmx.net","pelisflix20.*>>","pelismarthd.com","pelisxporno.net","pendekarsubs.us","pepperlive.info","perezhilton.com","perfektdamen.co","persianhive.com","perugiatoday.it","pewresearch.org","pflege-info.net","phillyburbs.com","phonerotica.com","pianetalecce.it","pics4upload.com","picxnkjkhdf.sbs","pimpandhost.com","pinoyalbums.com","pinoyrecipe.net","piratehaven.xyz","pisshamster.com","pixdfdjkkr.shop","pixkfjtrkf.shop","planetfools.com","platinporno.com","play.hbomax.com","player.msmini.*","plugincrack.com","pocket-lint.com","polenjournal.de","popcornstream.*","popdaily.com.tw","porhubvideo.com","porn-monkey.com","pornexpanse.com","pornfactors.com","porngameshd.com","pornhegemon.com","pornhoarder.net","porninblack.com","porno-porno.net","porno-rolik.com","pornohammer.com","pornohirsch.net","pornoklinge.com","pornomanoir.com","pornrusskoe.com","portable4pc.com","powergam.online","premiumporn.org","privatemoviez.*","projectfreetv.*","promimedien.com","proxydocker.com","punishworld.com","purelyceleb.com","pussy3dporn.com","pussyhothub.com","qatarstreams.me","quiltfusion.com","quotesshine.com","r1.richtoon.top","rackusreads.com","radio-norge.org","radionatale.com","radionylive.com","radiorockon.com","railwebcams.net","rajssoid.online","ramdomlives.com","rangerboard.com","ravennatoday.it","rctechsworld.in","readhunters.xyz","readingpage.fun","redpornblog.com","remodelista.com","rennrad-news.de","renoconcrete.ca","rentbyowner.com","reportera.co.kr","restegourmet.de","retroporn.world","risingapple.com","ritacandida.com","robot-forum.com","rojadirectatv.*","rollingstone.de","romaierioggi.it","romfirmware.com","root-nation.com","route-fifty.com","rule34vault.com","rule34video.com","runnersworld.de","rushuploads.com","ryansharich.com","saabcentral.com","salernotoday.it","samapkstore.com","sampledrive.org","samuraiscan.org","santhoshrcf.com","savannahnow.com","savealoonie.com","scan-hentai.net","scatnetwork.com","schwaebische.de","sdmoviespoint.*","sekaikomik.live","serienstream.to","seriesmetro.net","seriesonline.sx","seriouseats.com","serverbd247.com","serviceemmc.com","setfucktube.com","sex-torrent.net","sexanimesex.com","sexoverdose.com","sexseeimage.com","sexwebvideo.com","sexxxanimal.com","sexy-parade.com","sexyerotica.net","seznamzpravy.cz","sfmcompile.club","shadagetech.com","shadowrangers.*","sharegdrive.com","sharinghubs.com","shemalegape.net","shomareh-yab.ir","shopkensaku.com","short-jambo.ink","showcamrips.com","showrovblog.com","shrugemojis.com","shugraithou.com","siamfishing.com","sieutamphim.org","singingdalong.*","siriusfiles.com","sitetorrent.com","sivackidrum.net","slapthesign.com","slateforums.com","sleazedepot.com","sleazyneasy.com","smartcharts.net","sms-anonyme.net","sms-receive.net","smsonline.cloud","smumustangs.com","soconsports.com","software-on.com","softwaresde.com","solarchaine.com","sommerporno.com","sondriotoday.it","souq-design.com","sourceforge.net","spanishdict.com","spardhanews.com","sport890.com.uy","sports-stream.*","sportsblend.net","sportsonline.si","sportsonline.so","sportsplays.com","sportsseoul.com","sportstiger.com","sportstreamtv.*","ssdhostting.com","starcourier.com","stargazette.com","starstreams.pro","start-to-run.be","staugustine.com","sterkinekor.com","stream.bunkr.ru","streamnoads.com","stronakobiet.pl","studybullet.com","subtitlecat.com","sueddeutsche.de","sulasokvids.net","sullacollina.it","sumirekeiba.com","suneelkevat.com","superdeporte.es","superembeds.com","supermarches.ca","supermovies.org","surf-magazin.de","svethardware.cz","swift4claim.com","syracusefan.com","tabooanime.club","tagesspiegel.de","tallahassee.com","tamilanzone.com","tamilultra.team","tapeantiads.com","tapeblocker.com","taycanforum.com","techacrobat.com","techadvisor.com","techastuces.com","techedubyte.com","techinferno.com","technichero.com","technorozen.com","techoreview.com","techprakash.com","techsbucket.com","techyhigher.com","techymedies.com","tedenglish.site","teen-hd-sex.com","teenfucksex.com","teenpornjpg.com","teensextube.xxx","teenxxxporn.pro","telegraph.co.uk","telepisodes.org","temporeale.info","tenbaiquest.com","tenies-online.*","tennisonline.me","tennisstreams.*","teracourses.com","texassports.com","textreverse.com","thaiairways.com","the-mystery.org","the2seasons.com","theappstore.org","thebarchive.com","thebigblogs.com","theclashify.com","thedilyblog.com","thegrowthop.com","thejetpress.com","thejoblives.com","themoviesflix.*","thenewsstar.com","theprovince.com","thereporter.com","thespectrum.com","thestreameast.*","theterrace.scot","thetoneking.com","thetowntalk.com","theusaposts.com","thewebflash.com","theyarehuge.com","thingiverse.com","thingstomen.com","thisisrussia.io","thueringen24.de","thumpertalk.com","ticketmaster.sg","tickhosting.com","ticonsiglio.com","tieba.baidu.com","tienganhedu.com","timesonline.com","tires.costco.ca","today-obits.com","todopolicia.com","toeflgratis.com","tokuzilla.net>>","tokyomotion.com","tokyomotion.net","tophostdeal.com","topnewsshow.com","topperpoint.com","topstarnews.net","torascripts.org","tornadomovies.*","torrentgalaxy.*","torrentgame.org","torrentstatus.*","torresette.news","tour-magazin.de","tradingview.com","transfermarkt.*","travelnoire.com","trendohunts.com","trevisotoday.it","triesteprima.it","true-gaming.net","truyenhentaiz.*","trytutorial.com","tubegaytube.com","tubepornnow.com","tudongnghia.com","tuktukcinma.com","turbovidhls.com","turkeymenus.com","turystyka.wp.pl","tusachmanga.com","tvanouvelles.ca","tvsportslive.fr","twistedporn.com","twitchnosub.com","tyler-brown.com","u6lyxl0w.skin>>","ukathletics.com","ukaudiomart.com","ultramovies.org","undeniable.info","underhentai.net","unipanthers.com","updateroj24.com","uploadbeast.com","uploadcloud.pro","uppercutmma.com","usaudiomart.com","user.guancha.cn","vectogravic.com","veekyforums.com","vegamovies3.org","veneziatoday.it","verpelis.gratis","verywellfit.com","vfxdownload.net","vicenzatoday.it","viciante.com.br","vidcloudpng.com","video.genyt.net","videodidixx.com","videosputas.xxx","vidsrc-embed.ru","vik1ngfile.site","ville-ideale.fr","viralharami.com","viralxvideos.es","virtuavixen.com","voyageforum.com","vtplayer.online","wantedbabes.com","warmteensex.com","watch-my-gf.com","watch.sling.com","watchf1full.com","watchfreexxx.pw","watchhentai.net","watchmovieshd.*","watchporn4k.com","watchpornfree.*","watchseries8.to","watchserieshd.*","watchtvseries.*","watchxxxfree.pw","wealthcatal.com","weatherzone.com","web.epalovo.com","webmatrices.com","webtoonscan.com","wegotcookies.co","weltfussball.at","wemakesites.net","wheelofgold.com","wholenotism.com","wholevideos.com","wieistmeineip.*","wikipooster.com","wikisharing.com","windowslite.net","windsorstar.com","winnipegsun.com","witcherhour.com","womenshealth.de","wordfinderx.com","world-iptv.club","worldgyan18.com","worldofiptv.com","worldsports.*>>","wowpornlist.xyz","wowyoungsex.com","wpgdadatong.com","wristreview.com","writeprofit.org","wvv-fmovies.com","www.youtube.com","xfuckonline.com","xhardhempus.net","xianzhenyuan.cn","xiaomitools.com","xkeezmovies.com","xmoviesforyou.*","xn--31byd1i.net","xnudevideos.com","xnxxhamster.net","xterraforum.com","xxxindianporn.*","xxxparodyhd.net","xxxpornmilf.com","xxxtubegain.com","xxxtubenote.com","xxxtubepass.com","xxxwebdlxxx.top","yandexcloud.net","yanksgoyard.com","yazilidayim.net","yesmovies123.me","yeutienganh.com","yogablogfit.com","yomoviesnow.com","yorkpress.co.uk","youlikeboys.com","youmedemblik.nl","young-pussy.com","youranshare.com","yourporngod.com","youtubekids.com","yrtourguide.com","ytconverter.app","yuramanga.my.id","zeroradio.co.uk","zonavideosx.com","zone-annuaire.*","zoominar.online","007stockchat.com","123movies-free.*","18-teen-porn.com","18-teen-tube.com","18adultgames.com","18comic-gquu.vip","1movielinkbd.com","1movierulzhd.pro","24pornvideos.com","2kspecialist.net","4fingermusic.com","8-ball-magic.com","9now.nine.com.au","aberdeennews.com","about-drinks.com","account.bhvr.com","activevoyeur.com","activistpost.com","actresstoday.com","adblockstrtape.*","adblockstrtech.*","adonisfansub.com","adult-empire.com","adultporn.com.es","advertafrica.net","agedtubeporn.com","aghasolution.com","ajaxshowtime.com","ajkalerbarta.com","alleveilingen.be","alleveilingen.nl","alliptvlinks.com","allporncomic.com","alphagames4u.com","alphapolis.co.jp","alphasource.site","altselection.com","anakteknik.co.id","analsexstars.com","analxxxvideo.com","androidadult.com","androidfacil.org","androidgreek.com","androidspill.com","anime-odcinki.pl","animesexclip.com","animetwixtor.com","animixstream.com","antennasports.ru","antiphishing.biz","aopathletics.org","apkandroidhub.in","app.khaddavi.net","app.simracing.gp","applediagram.com","aquariumgays.com","arezzonotizie.it","articlesmania.me","asianimage.co.uk","asianmassage.xyz","asianpornjav.com","assettoworld.com","asyaanimeleri.pw","athlonsports.com","atlantisscan.com","auburntigers.com","audiofanzine.com","audycje.tokfm.pl","augustacrime.com","autotrader.co.uk","avellinotoday.it","azby.fmworld.net","baby-vornamen.de","backfirstwo.site","backyardboss.net","bangyourwife.com","barrheadnews.com","barrier-free.net","base64decode.org","bcuathletics.com","beaddiagrams.com","beritabangka.com","berlin-teltow.de","bestasiansex.pro","bestblackgay.com","bestcash2020.com","bestgamehack.top","bestgrannies.com","besthdmovies.com","bestpornflix.com","bestsextoons.com","beta.plus.rtl.de","biblegateway.com","bigbuttshub2.top","bikeportland.org","birdswatcher.com","bisceglielive.it","bitchesgirls.com","blackandteal.com","blog.livedoor.jp","blowjobfucks.com","bloxinformer.com","bloxyscripts.com","bluemediafiles.*","bluerabbitrx.com","blueridgenow.com","bmw-scooters.com","boardingarea.com","boerse-online.de","bollywoodfilma.*","bondagevalley.cc","book.trivago.com","booksbybunny.com","boolwowgirls.com","boote-magazin.de","bootstrample.com","bostonherald.com","boysxclusive.com","brandbrief.co.kr","bravoerotica.com","bravoerotica.net","breatheheavy.com","breedingmoms.com","bristolworld.com","buffalobills.com","buffalowdown.com","businesstrend.jp","butlersports.com","butterpolish.com","bysedikamoum.com","bysesayeveum.com","call2friends.com","cambstimes.co.uk","caminspector.net","campusfrance.org","camvideoshub.com","camwhoresbay.com","caneswarning.com","capecodtimes.com","cartoonporno.xxx","catmovie.website","ccnworldtech.com","celtadigital.com","cervezaporno.com","championdrive.co","charexempire.com","chattanoogan.com","cheatography.com","chelsea24news.pl","chicagobears.com","chieflyoffer.com","choiceofmods.com","chubbyelders.com","cizzyscripts.com","claimsatoshi.xyz","clever-tanken.de","clickforhire.com","clickndownload.*","clipconverter.cc","cloudgallery.net","cmumavericks.com","coin-profits.xyz","collegehdsex.com","colliersnews.com","coloredmanga.com","comeletspray.com","cometogliere.com","comicspornos.com","comicspornow.com","comicsvalley.com","computerpedia.in","convert2mp3.club","convertinmp4.com","courierpress.com","courseleader.net","cr7-soccer.store","cracksports.me>>","criptologico.com","cryptoclicks.net","cryptofaucet.xyz","cryptojunkie.net","cryptomonitor.in","culturequizz.com","cybercityhelp.in","cyberstumble.com","cydiasources.net","dailyboulder.com","dailypudding.com","dailytips247.com","dailyuploads.net","dakotaforums.com","darknessporn.com","darkwanderer.net","dasgelbeblatt.de","dataunlocker.com","dattebayo-br.com","davewigstone.com","dayoftheweek.org","daytonflyers.com","ddl-francais.com","deepfakeporn.net","deepswapnude.com","demonicscans.org","derbyworld.co.uk","derryjournal.com","designparty.sx>>","desikamababa.com","detroitlions.com","devaccellabs.com","diariodeibiza.es","dirtytubemix.com","discoveryplus.in","divicast.watch>>","doanhnghiepvn.vn","dobrapogoda24.pl","dobreprogramy.pl","donghuaworld.com","dorsetecho.co.uk","downloadapk.info","downloadbatch.me","downloadsite.org","downloadsoft.net","dpscomputing.com","dryscalpgone.com","dualshockers.com","dudleynews.co.uk","duplichecker.com","dvdgayonline.com","earncrypto.co.in","eartheclipse.com","eastbaytimes.com","easymilftube.net","ebook-hunter.org","ecom.wixapps.net","edufileshare.com","einfachschoen.me","eleceedmanhwa.me","eletronicabr.com","elevationmap.net","eliobenedetto.it","embedseek.online","embedstreams.top","empire-anime.com","emulatorsite.com","english101.co.za","eslauthority.com","esportstales.com","everysextube.com","ewrc-results.com","exclusivomen.com","explorersweb.com","fallbrook247.com","familyporner.com","famousnipple.com","fastdownload.top","fattelodasolo.it","fatwhitebutt.com","faucetcrypto.com","faucetcrypto.net","favefreeporn.com","favoyeurtube.net","femmeactuelle.fr","fernsehserien.de","fetishshrine.com","filecatchers.com","filespayouts.com","filmestorrent.tv","filmyhitlink.xyz","filmyhitt.com.in","financacerta.com","financeehelp.com","financeguidz.com","fineasiansex.com","finofilipino.org","fitnessholic.net","fitnessscenz.com","flatpanelshd.com","floridatoday.com","footwearnews.com","footymercato.com","foreverquote.xyz","forexcracked.com","forextrader.site","forgepattern.net","forum-xiaomi.com","foxsports.com.au","freegetcoins.com","freehardcore.com","freehdvideos.xxx","freelitecoin.vip","freemcserver.net","freemomstube.com","freemoviesu4.com","freeporncave.com","freevstplugins.*","freshersgold.com","fullxcinema1.com","fullxxxmovies.me","fumettologica.it","fussballdaten.de","gadgetxplore.com","gadsdentimes.com","game-repack.site","gamemodsbase.com","gamers-haven.org","games.boston.com","games.kansas.com","games.modbee.com","games.puzzles.ca","games.sacbee.com","games.sltrib.com","games.usnews.com","gamesrepacks.com","gamingbeasts.com","gamingdeputy.com","gaminglariat.com","ganstamovies.com","gartenlexikon.de","gaydelicious.com","gazetalubuska.pl","gbmwolverine.com","gdrivelatino.net","gdrivemovies.xyz","gemiadamlari.org","genialetricks.de","genshin-soku.com","gentlewasher.com","getdatgadget.com","getdogecoins.com","getfreegames.net","getworkation.com","gezegenforum.com","ghettopearls.com","ghostsfreaks.com","gidplayer.online","gigemgazette.com","girlschannel.net","glasgowworld.com","globelempire.com","go.discovery.com","go.gociwidey.com","go.shortnest.com","goblackbears.com","godstoryinfo.com","goetbutigers.com","gogetadoslinks.*","gomcpanthers.com","gometrostate.com","goodyoungsex.com","gophersports.com","gopornindian.com","greasygaming.com","greenarrowtv.com","gruene-zitate.de","gruporafa.com.br","gsm-solution.com","gtamaxprofit.com","guncelkaynak.com","gutesexfilme.com","hadakanonude.com","handelsblatt.com","happyinshape.com","hard-tubesex.com","hardfacefuck.com","harpersbazaar.fr","hausbau-forum.de","hayatarehber.com","hd-tube-porn.com","healthylifez.com","hechosfizzle.com","heilpraxisnet.de","helpdeskgeek.com","hemeltoday.co.uk","hentaicomics.pro","hentaiseason.com","hentaistream.com","hentaivideos.net","hometalkpaid.com","hotcopper.com.au","hotdreamsxxx.com","hotpornyoung.com","hotpussyhubs.com","houstonpress.com","hqpornstream.com","huskercorner.com","id.condenast.com","idmextension.xyz","ignoustudhelp.in","ikindlebooks.com","imagereviser.com","imageshimage.com","imagetotext.info","imperiofilmes.co","infinityfree.com","inprogrammer.com","intelligencer.ca","intellischool.id","interviewgig.com","investopedia.com","investorveda.com","isekaibrasil.com","isekaipalace.com","jacksonville.com","jalshamoviezhd.*","japaneseasmr.com","japanesefuck.com","japanfuck.com.es","javenspanish.com","javfullmovie.com","journalduweb.org","justblogbaby.com","justswallows.net","kakarotfoot.ru>>","katiescucina.com","kawaii-anime.com","kayifamilytv.com","khatrimazafull.*","kingdomfiles.com","kingstreamz.site","kireicosplay.com","kitchennovel.com","kitraskimisi.com","knowyourmeme.com","kodibeginner.com","kokosovoulje.com","komikstation.com","komputerswiat.pl","kshowsubindo.org","kstatesports.com","ksuathletics.com","kurakura21.space","kuttymovies1.com","lakeshowlife.com","lampungkerja.com","larvelfaucet.com","lascelebrite.com","latesthdmovies.*","latinohentai.com","lavanguardia.com","lawyercontact.us","leaderlive.co.uk","lectormangaa.com","leechpremium.net","legionjuegos.org","lehighsports.com","lesbiantube.club","letmewatchthis.*","lettersolver.com","levelupalone.com","lg-firmwares.com","libramemoria.com","lifesurance.info","lightxxxtube.com","limetorrents.lol","linkneverdie.net","linux-magazin.de","linuxexplain.com","live.vodafone.de","livenewsflix.com","lk21official.*>>","logofootball.net","london-now.co.uk","lookmovie.studio","loudountimes.com","ltpcalculator.in","luminatedata.com","lumpiastudio.com","lustaufsleben.at","lustesthd.makeup","lutontoday.co.uk","macrocreator.com","magicseaweed.com","mahobeachcam.com","mammaebambini.it","manga-scantrad.*","mangacanblog.com","mangaforfree.com","mangaindo.web.id","mangakuri.online","masstamilans.com","mastaklomods.com","masterplayer.xyz","matshortener.xyz","mature-tube.sexy","maxisciences.com","meconomynews.com","mee-cccdoz45.com","meetdownload.com","megafilmeshd20.*","megajapansex.com","mejortorrents1.*","merlinshoujo.com","meteoetradar.com","meteoradar.co.uk","metin2alerts.com","milanreports.com","milfxxxpussy.com","milkporntube.com","misterdonghua.in","mlookalporno.com","mockupgratis.com","mockupplanet.com","moto-station.com","mountaineast.org","movielinkhub.xyz","movierulz2free.*","movierulzwatch.*","movieshdwatch.to","movieshubweb.com","moviesnipipay.me","moviesrulzfree.*","moviestowatch.tv","mrproblogger.com","msmorristown.com","msumavericks.com","multimovies.tech","musiker-board.de","my-ford-focus.de","myair.resmed.com","mycivillinks.com","mydownloadtube.*","myfitnesspal.com","mylegalporno.com","mylivestream.pro","mymotherlode.com","mypapercraft.net","myproplugins.com","myradioonline.pl","nakedbbw-sex.com","namethatporn.com","naruldonghua.com","nationalpost.com","nativesurge.info","nauathletics.com","naughtyblogs.xyz","neatfreeporn.com","neatpornodot.com","netflixporno.net","netizensbuzz.com","newanimeporn.com","newsinlevels.com","newsletter.co.uk","newsobserver.com","newstvonline.com","nghetruyenma.net","nguyenvanbao.com","nhentaihaven.org","niftyfutures.org","nikkansports.com","nintendolife.com","nl.hardware.info","nocsummer.com.br","nontonhentai.net","norfolkmag.co.uk","notebookchat.com","notiziemusica.it","novablogitalia.*","nude-teen-18.com","nudemomshots.com","null-scripts.net","nwfdailynews.com","officecoach24.de","older-mature.net","oldgirlsporn.com","onestringlab.com","onlineathens.com","onlineporn24.com","onlyfanvideo.com","onlygangbang.com","onlygayvideo.com","onlyindianporn.*","open.spotify.com","openloadmovies.*","optimizepics.com","oranhightech.com","orenoraresne.com","oswegolakers.com","otakuanimess.net","outlook.live.com","overtakefans.com","oxfordmail.co.uk","ozbargain.com.au","pagalworld.video","pandaatlanta.com","pandafreegames.*","paradoxscans.com","parentcircle.com","parking-map.info","pdfstandards.net","pedroinnecco.com","penis-bilder.com","personefamose.it","petoskeynews.com","phinphanatic.com","physics101.co.za","pigeonburger.xyz","pilotsglobal.com","pinsexygirls.com","play.history.com","player.gayfor.us","player.hdgay.net","player.pop.co.uk","player4me.online","playsexgames.xxx","pleasuregirl.net","plumperstube.com","plumpxxxtube.com","poconorecord.com","pokeca-chart.com","police.community","ponselharian.com","porn-hd-tube.com","pornclassic.tube","pornclipshub.com","pornforrelax.com","porngayclips.com","pornhub-teen.com","pornobengala.com","pornoborshch.com","pornoteensex.com","pornsex-pics.com","pornstargold.com","pornuploaded.net","pornvideotop.com","pornwatchers.com","pornxxxplace.com","pornxxxxtube.net","portnywebcam.com","portsmouth.co.uk","post-gazette.com","postcrescent.com","postermockup.com","powerover.site>>","practicequiz.com","prajwaldesai.com","praveeneditz.com","printedwaste.com","privacy-mgmt.com","privatenudes.com","programme-tv.net","programsolve.com","prosiebenmaxx.de","purduesports.com","purposegames.com","puzzles.nola.com","pythonjobshq.com","qrcodemonkey.net","rabbitstream.net","radio-danmark.dk","radio-deejay.com","realityblurb.com","realjapansex.com","receptyonline.cz","recordonline.com","redbirdrants.com","rendimentibtp.it","repack-games.com","reportbangla.com","reporternews.com","ribbelmonster.de","rimworldbase.com","ringsidenews.com","ripplestream4u.*","rivianforums.com","riwayat-word.com","rocketrevise.com","rollingstone.com","royale-games.com","rule34hentai.net","rv-ecommerce.com","sabishiidesu.com","safehomefarm.com","sainsburys.co.uk","saradahentai.com","sarugbymag.co.za","satoshifaucet.io","savethevideo.com","savingadvice.com","schaken-mods.com","schildempire.com","schoolcheats.net","scoutevforum.com","search.brave.com","seattletimes.com","secretsdujeu.com","semuanyabola.com","sensualgirls.org","serienjunkies.de","seriesflixhd.*>>","serieslandia.com","sesso-escort.com","sexanimetube.com","sexfilmkiste.com","sexflashgame.org","sexhardtubes.com","sexjapantube.com","sexlargetube.com","sexmomvideos.com","sexontheboat.xyz","sexpornasian.com","sextingforum.net","sexybabesart.com","sexyoungtube.com","sharelink-1.site","sheepesports.com","shelovesporn.com","shemalemovies.us","shemalepower.xyz","shemalestube.com","shimauma-log.com","shoot-yalla.live","short.croclix.me","shortenlinks.top","showbizbites.com","shrinkforearn.in","shrinklinker.com","signupgenius.com","sikkenscolore.it","simpleflying.com","simplyvoyage.com","sites.google.com","sitesunblocked.*","skidrowcodex.net","skidrowcrack.com","skintagsgone.com","smallseotools.ai","smart-wohnen.net","smartermuver.com","smashyplayer.top","soccershoes.blog","softdevelopp.com","softwaresite.net","solution-hub.com","soonersports.com","soundpark-club.*","southpark.cc.com","soyoungteens.com","space-faucet.com","spigotunlocked.*","splinternews.com","sportpiacenza.it","sports.yahoo.com","sportshub.stream","sportsloverz.xyz","sportstream.live","spotifylists.com","ss.randomkzn.com","sshconect.com.br","sssinstagram.com","stablerarena.com","stagatvfiles.com","stalowemiasto.pl","stiflersmoms.com","stileproject.com","stillcurtain.com","stockhideout.com","stopstreamtv.net","storieswatch.com","stream.nflbox.me","stream4free.live","streamblasters.*","streamcenter.xyz","streamextreme.cc","streamingnow.mov","streamingworld.*","streamloverx.com","strefabiznesu.pl","strtapeadblock.*","suamusica.com.br","suffolkmag.co.uk","sukidesuost.info","sunshine-live.de","supremebabes.com","sussexlife.co.uk","swiftuploads.com","sxmislandcam.com","synoniemboek.com","tamarindoyam.com","tapelovesads.org","taroot-rangi.com","tatsumi-crew.net","teachmemicro.com","techgeek.digital","techkhulasha.com","technewslive.org","tecnotutoshd.net","teensexvideos.me","telegratuita.com","tempatwisata.pro","text-compare.com","the1security.com","thecozyapron.com","thecustomrom.com","thefappening.pro","thegadgetking.in","thehiddenbay.com","theinventory.com","thejobsmovie.com","thelandryhat.com","thelosmovies.com","thelovenerds.com","thematurexxx.com","thenational.scot","thenerdstash.com","thenewsdrill.com","thenewsglobe.net","thenextplanet1.*","theorie-musik.de","thepiratebay.org","thepoorcoder.com","thesportster.com","thesportsupa.com","thestarpress.com","thesundevils.com","thetrendverse.in","thevikingage.com","thisisfutbol.com","timesnownews.com","timesofindia.com","timminspress.com","tipsenweetjes.nl","tires.costco.com","tiroalpaloes.net","titansonline.com","tnstudycorner.in","todays-obits.com","todoandroid.live","tonanmedia.my.id","topvideosgay.com","toramemoblog.com","torrentkitty.one","totallyfuzzy.net","totalsportek.app","toureiffel.paris","towsontigers.com","tptvencore.co.uk","tradersunion.com","travelerdoor.com","trendytalker.com","trucosonline.com","truetrophies.com","tube-teen-18.com","tube.shegods.com","tuotromedico.com","turbogvideos.com","turboplayers.xyz","turtleviplay.xyz","tutorialsaya.com","tweakcentral.net","twobluescans.com","typinggames.zone","uconnhuskies.com","unfriend-app.com","unionpayintl.com","uniquestream.net","universegunz.net","unrealengine.com","upfiles-urls.com","upgradedhome.com","upstyledaily.com","urlgalleries.net","ustrendynews.com","uvmathletics.com","uwlathletics.com","vancouversun.com","vandaaginside.nl","vegamoviese.blog","veryfreeporn.com","verywellmind.com","vichitrainfo.com","videocdnal24.xyz","videosection.com","vikingf1le.us.to","villettt.kitchen","vinstartheme.com","viralvideotube.*","viralxxxporn.com","vivrebordeaux.fr","vodkapr3mium.com","voiranime.stream","voyeur-house.org","voyeurfrance.net","voyeurxxxsex.com","vrporngalaxy.com","vvdailypress.com","vzrosliedamy.com","watchanime.video","watchfreekav.com","watchfreexxx.net","watchmovierulz.*","watchmovies2.com","wbschemenews.com","wearehunger.site","wearevoice.co.uk","web.facebook.com","webcamsdolls.com","webcheats.com.br","webdesigndev.com","webdeyazilim.com","webseriessex.com","websitesball.com","werkzeug-news.de","whentostream.com","whitexxxtube.com","wiadomosci.wp.pl","wildpictures.net","willow.arlen.icu","windowsonarm.org","wolfgame-ar.site","womenreality.com","woodmagazine.com","word-grabber.com","workxvacation.jp","worldhistory.org","worldjournal.com","wrestlinginc.com","wrzesnia.info.pl","wunderground.com","wvuathletics.com","www.amazon.co.jp","www.amazon.co.uk","www.facebook.com","wysokieobcasy.pl","xhamster-art.com","xhamsterporno.mx","xhamsterteen.com","xvideos-full.com","xxxanimefuck.com","xxxlargeporn.com","xxxlesvianas.com","xxxretrofuck.com","xxxteenyporn.com","xxxvideos247.com","yellowbridge.com","yesjavplease.fun","yona-yethu.co.za","youngerporn.mobi","youtubetoany.com","youtubetowav.net","youwatch.monster","ysokuhou.blog.jp","zdravenportal.eu","zecchino-doro.it","ziggogratis.site","ziminvestors.com","ziontutorial.com","zippyshare.cloud","zwergenstadt.com","123moviesonline.*","123strippoker.com","12thmanrising.com","1337x.unblocked.*","1337x.unblockit.*","19-days-manga.com","1movierulzhd.hair","1teentubeporn.com","2japaneseporn.com","3addedminutes.com","acapellas4u.co.uk","acdriftingpro.com","adblockplustape.*","adffdafdsafds.sbs","adrenaline.com.br","alaskananooks.com","allcelebspics.com","alternativeto.net","altyazitube22.lat","amateur-twink.com","amateurfapper.com","amsmotoresllc.com","ancient-origins.*","andhrafriends.com","androidonepro.com","androidpolice.com","animalwebcams.net","anime-torrent.com","animecenterbr.com","animeidhentai.com","animelatinohd.com","animeonline.ninja","animepornfilm.com","animesonlinecc.us","animexxxfilms.com","anonymousemail.me","apostoliclive.com","arabshentai.com>>","arcade.lemonde.fr","armypowerinfo.com","asianfucktube.com","asiansexcilps.com","assignmentdon.com","atalantini.online","autoexpress.co.uk","ayradvertiser.com","babyjimaditya.com","badassoftcore.com","badgerofhonor.com","bafoeg-aktuell.de","bandyforbundet.no","bargainbriana.com","beaconjournal.com","beargoggleson.com","bebasbokep.online","beritasulteng.com","bestanime-xxx.com","besthdgayporn.com","besthugecocks.com","bestpussypics.net","beyondtheflag.com","bgmiupdate.com.in","bigdickwishes.com","bigtitsxxxsex.com","black-matures.com","blackhatworld.com","bladesalvador.com","blizzboygames.net","blog.linksfire.co","blog.textpage.xyz","blogcreativos.com","blogtruyenmoi.com","bollywoodchamp.in","bostoncommons.net","bracontece.com.br","bradleybraves.com","brazzersbabes.com","brindisireport.it","brokensilenze.net","browncrossing.net","brushednickel.biz","bryantenunder.com","bucksherald.co.uk","burymercury.co.uk","calgaryherald.com","camchickscaps.com","cameronaggies.com","candyteenporn.com","catatanonline.com","cavalierstream.fr","cdn.gledaitv.live","celebritablog.com","charbelnemnom.com","chat.tchatche.com","cheat.hax4you.net","cheboygannews.com","checkfiletype.com","chicksonright.com","cinecalidad5.site","cinema-sketch.com","citethisforme.com","citizen-times.com","citpekalongan.com","ciudadblogger.com","claplivehdplay.ru","clarionledger.com","classicreload.com","clickjogos.com.br","cloudhostingz.com","coatingsworld.com","codingshiksha.com","coempregos.com.br","compota-soft.work","computercrack.com","computerfrage.net","computerhilfen.de","comunidadgzone.es","conferenceusa.com","consoletarget.com","cool-style.com.tw","coolmath4kids.com","coolmathgames.com","costcoinsider.com","countypress.co.uk","countytimes.co.uk","crichd-player.top","cruisingearth.com","cryptednews.space","cryptoblog24.info","cryptowidgets.net","crystalcomics.com","cumbrialife.co.uk","curiosidadtop.com","daemon-hentai.com","dailyamerican.com","dailybulletin.com","dailydemocrat.com","dailyfreebits.com","dailygeekshow.com","dailytech-news.eu","dallascowboys.com","damndelicious.net","darts-scoring.com","dawnofthedawg.com","dealsfinders.blog","dearcreatives.com","deine-tierwelt.de","deinesexfilme.com","dejongeturken.com","denverbroncos.com","descarga-animex.*","design4months.com","designtagebuch.de","desitelugusex.com","developer.arm.com","diamondfansub.com","diaridegirona.cat","diariocordoba.com","diencobacninh.com","dirtbikerider.com","dirtyindianporn.*","dissmercury.co.uk","doctor-groups.com","dodi-repacks.site","dorohedoro.online","downloadapps.info","downloadtanku.org","downloadudemy.com","downloadwella.com","duellinksmeta.com","dynastyseries.com","dzienniklodzki.pl","e-hausaufgaben.de","ealingtimes.co.uk","earninginwork.com","easyjapanesee.com","easyvidplayer.com","ebonyassclips.com","eczpastpapers.net","editions-actu.org","einfachtitten.com","elamigosgames.net","elamigosgamez.com","elamigosgamez.net","elystandard.co.uk","empire-streamz.fr","emulatorgames.net","encurtandourl.com","encurtareidog.top","engel-horoskop.de","enormousbabes.net","entertubeporn.com","epsilonakdemy.com","eromanga-show.com","estrepublicain.fr","eternalmangas.org","etownbluejays.com","euro2024direct.ru","eurotruck2.com.br","extreme-board.com","extremotvplay.com","faceittracker.net","fansonlinehub.com","fantasticporn.net","fastconverter.net","fatgirlskinny.net","fattubevideos.net","femalefirst.co.uk","fgcuathletics.com","fightinghawks.com","file.magiclen.org","fileditchfiles.me","financefernly.com","financialpost.com","finanzas-vida.com","fineretroporn.com","finexxxvideos.com","fitnakedgirls.com","fitnessplanss.com","flight-report.com","floridagators.com","foguinhogames.net","foodtalkdaily.com","footballstream.tv","footfetishvid.com","footstockings.com","fordownloader.com","formatlibrary.com","forum.blu-ray.com","fplstatistics.com","free-wargamer.com","freeboytwinks.com","freecodezilla.net","freecourseweb.com","freemagazines.top","freeoseocheck.com","freepdf-books.com","freepornrocks.com","freepornstream.cc","freepornvideo.sex","freepornxxxhd.com","freerealvideo.com","freethesaurus.com","freex2line.online","freexxxvideos.pro","french-streams.cc","freshstuff4u.info","friendproject.net","frkn64modding.com","frosinonetoday.it","fuerzasarmadas.eu","fuldaerzeitung.de","fullfreeimage.com","fullxxxmovies.net","futbolsayfasi.net","games-manuals.com","games.puzzler.com","games.thestar.com","gamesofdesire.com","gaminggorilla.com","gastongazette.com","gay-streaming.com","gaypornhdfree.com","gebrauchtwagen.at","getwallpapers.com","gewinde-normen.de","girlsofdesire.org","girlswallowed.com","globalstreams.xyz","gobigtitsporn.com","goblueraiders.com","godriveplayer.com","gogetapast.com.br","gogueducation.com","goltelevision.com","googleapis.com.de","googleapis.com.do","gothunderbirds.ca","gowatchseries.net","grannyfuckxxx.com","grannyxxxtube.net","graphicgoogle.com","grsprotection.com","gwiazdatalkie.com","hakunamatata5.org","hallo-muenchen.de","happy-otalife.com","hardcoregamer.com","hardwaretimes.com","harrowtimes.co.uk","hbculifestyle.com","hdfilmizlesen.com","hdvintagetube.com","headlinerpost.com","healbot.dpm15.net","healthcheckup.com","hegreartnudes.com","help.cashctrl.com","hentaibrasil.info","hentaienglish.com","hentaitube.online","heraldtribune.com","herefordtimes.com","hideandseek.world","hikarinoakari.com","hollywoodlife.com","hostingunlock.com","hotkitchenbag.com","hotmaturetube.com","hotspringsofbc.ca","houseandgarden.co","houstontexans.com","howtoconcepts.com","hunterscomics.com","hyperosthemes.org","iedprivatedqu.com","igniteseurope.com","imgdawgknuttz.com","imperialstudy.com","independent.co.uk","indianporn365.net","indofirmware.site","indojavstream.com","infinityscans.net","infinityscans.org","infinityscans.xyz","inside-digital.de","insidermonkey.com","instantcloud.site","insurancepost.xyz","integraforums.com","ipswichstar.co.uk","ironwinter6m.shop","isabihowto.com.ng","isekaisubs.web.id","isminiunuttum.com","ithacajournal.com","jamesbornmain.com","jamiesamewalk.com","janammusic.in.net","japaneseholes.com","japanpornclip.com","japanxxxworld.com","jardiner-malin.fr","jeechallenger.com","jokersportshd.org","juegos.elpais.com","k-statesports.com","k-statesports.net","k-statesports.org","kandisvarlden.com","kenshi.fandom.com","kh-pokemon-mc.com","khabardinbhar.net","kickasstorrents.*","kill-the-hero.com","kimcilonlyofc.com","kiuruvesilehti.fi","know-how-tree.com","kontenterabox.com","kontrolkalemi.com","koreanbeauty.club","korogashi-san.org","kreis-anzeiger.de","kurierlubelski.pl","lachainemeteo.com","lacuevadeguns.com","laksa19.github.io","lavozdegalicia.es","lebois-racing.com","lecanalauditif.ca","lectormangass.net","lecturisiarome.ro","leechpremium.link","leechyscripts.net","lheritierblog.com","libertestreamvf.*","limerickleader.ie","limontorrents.com","line-stickers.com","link.snipcash.com","link.turkdown.com","linuxsecurity.com","liverpoolworld.uk","locatedinfain.com","lonely-mature.com","lovegrowswild.com","lubbockonline.com","lucagrassetti.com","luciferdonghua.in","luckypatchers.com","lycoathletics.com","macanevowners.com","madhentaitube.com","malaysiastock.biz","mangakakalove.com","maps4study.com.br","marthastewart.com","mature-chicks.com","maturepussies.pro","mdzsmutpcvykb.net","media.cms.nova.cz","megajapantube.com","meltontimes.co.uk","metaforespress.gr","mfmfinancials.com","miamidolphins.com","miaminewtimes.com","milfpussy-sex.com","minecraftwild.com","mizugigurabia.com","mlbpark.donga.com","mlbstreaming.live","mmorpgplay.com.br","mobilanyheter.net","modelsxxxtube.com","modescanlator.net","mommyporntube.com","momstube-porn.com","moonblinkwifi.com","motorradfrage.net","motorradonline.de","moviediskhd.cloud","movielinkbd4u.com","moviezaddiction.*","mp3cristianos.net","mundovideoshd.com","murtonroofing.com","music.youtube.com","muyinteresante.es","myabandonware.com","myair2.resmed.com","myfunkytravel.com","mynakedwife.video","mzansixporn.co.za","nasdaqfutures.org","national-park.com","nationalworld.com","negative.tboys.ro","nepalieducate.com","networklovers.com","new-xxxvideos.com","newryreporter.com","newsandstar.co.uk","newsshopper.co.uk","nextchessmove.com","ngin-mobility.com","nieuwsvandedag.nl","nightlifeporn.com","nikkeifutures.org","njwildlifecam.com","nobodycancool.com","nonsensediamond.*","nzpocketguide.com","oceanof-games.com","oceanoffgames.com","odekake-spots.com","officedepot.co.cr","officialpanda.com","olemisssports.com","ondemandkorea.com","onepiecepower.com","onlinemschool.com","onlinesextube.com","onlineteenhub.com","ontariofarmer.com","openspeedtest.com","opensubtitles.com","oportaln10.com.br","osmanonline.co.uk","osthessen-news.de","ottawacitizen.com","ottrelease247.com","outdoorchannel.de","overwatchporn.xxx","pahaplayers.click","palmbeachpost.com","pandaznetwork.com","panel.skynode.pro","pantyhosepink.com","paramountplus.com","paraveronline.org","patriotledger.com","pghk.blogspot.com","phimlongtieng.net","phoenix-manga.com","phonefirmware.com","piazzagallura.org","pistonpowered.com","plantatreenow.com","play.aidungeon.io","playembedapi.site","player.glomex.com","player.kinoton.cc","playerflixapi.com","playerjavseen.com","playmyopinion.com","playporngames.com","playstreaming.win","pleated-jeans.com","pockettactics.com","popcornmovies.org","porn-sexypics.com","pornanimetube.com","porngirlstube.com","pornoenspanish.es","pornoschlange.com","pornxxxvideos.net","practicalkida.com","prague-blog.co.il","premiumporn.org>>","prensaesports.com","prescottenews.com","press-citizen.com","pressconnects.com","presstelegram.com","primeanimesex.com","primeflix.website","progameguides.com","project-free-tv.*","projectfreetv.one","promisingapps.com","promo-visits.site","protege-liens.com","publicananker.com","publicdomainq.net","publicdomainr.net","publicflashing.me","punisoku.blogo.jp","pussytorrents.org","qatarstreams.me>>","queenofmature.com","radiolovelive.com","radiosymphony.com","ragnarokmanga.com","rancheroforum.com","randomarchive.com","rateyourmusic.com","rawindianporn.com","readallcomics.com","readcomiconline.*","readfireforce.com","realvoyeursex.com","redesigndaily.com","registerguard.com","reloadedsteam.com","reporterpb.com.br","reprezentacija.rs","retrosexfilms.com","reviewjournal.com","rhyljournal.co.uk","richieashbeck.com","robloxscripts.com","rojadirectatvhd.*","roms-download.com","roznamasiasat.com","rule34.paheal.net","samfordsports.com","sanangelolive.com","sanmiguellive.com","sarkarinaukry.com","sayphotobooth.com","scandichotels.com","schoolsweek.co.uk","scontianastro.com","searchnsucceed.in","seasons-dlove.net","send-anywhere.com","series9movies.com","sexmadeathome.com","sexyebonyteen.com","sexyfreepussy.com","shahiid-anime.net","share.filesh.site","shentai-anime.com","shinshi-manga.net","shittokuadult.net","shortencash.click","shrink-service.it","sidearmsocial.com","sideplusleaks.com","sim-kichi.monster","simply-hentai.com","simplyrecipes.com","simplywhisked.com","simulatormods.com","skidrow-games.com","skillheadlines.in","skodacommunity.de","slaughtergays.com","smallseotools.com","soccerworldcup.me","softwaresblue.com","sotemnovinhas.com","south-park-tv.biz","spectrum.ieee.org","speculationis.com","spiritparting.com","sponsorhunter.com","sportanalytic.com","sportingsurge.com","sportlerfrage.net","sportsbuff.stream","sportsgames.today","sportzonline.site","stapadblockuser.*","steam-repacks.net","stellarthread.com","stepsisterfuck.me","storefront.com.ng","stories.los40.com","straatosphere.com","streamadblocker.*","streaming-one.com","streamingunity.to","streamlivetv.site","streamonsport99.*","streamseeds24.com","streamshunters.eu","stringreveals.com","suanoticia.online","super-ethanol.com","superflixapi.best","superherohype.com","surreycomet.co.uk","surreyworld.co.uk","tabele-kalorii.pl","tamaratattles.com","tamilbrahmins.com","tamilsexstory.net","tattoosbeauty.com","tautasdziesmas.lv","techadvisor.co.uk","techiepirates.com","techlog.ta-yan.ai","technewsrooms.com","technewsworld.com","techsolveprac.com","teenpornvideo.sex","teenpornvideo.xxx","testlanguages.com","texture-packs.com","thaihotmodels.com","thangdangblog.com","the-gazette.co.uk","theadvertiser.com","theandroidpro.com","thecelticblog.com","thecubexguide.com","thedailybeast.com","thedigitalfix.com","thefreebieguy.com","thegamearcade.com","thehealthsite.com","theismailiusa.org","thekingavatar.com","theliveupdate.com","theouterhaven.net","theregister.co.uk","theresident.co.uk","thermoprzepisy.pl","thesprucepets.com","theworldobits.com","thousandbabes.com","tichyseinblick.de","tiktokcounter.net","times-gazette.com","timesnowhindi.com","timesreporter.com","timestelegram.com","tippsundtricks.co","titfuckvideos.com","tmail.sys64738.at","tomatespodres.com","toplickevesti.com","topsworldnews.com","torrent-pirat.com","torrentdownload.*","trannylibrary.com","trannyxxxtube.net","truyen-hentai.com","truyenaudiocv.net","tubepornasian.com","tubepornstock.com","tukumo99photo.com","ultimate-catch.eu","ultrateenporn.com","umatechnology.org","undeadwalking.com","unsere-helden.com","uptechnologys.com","urjalansanomat.fi","url.gem-flash.com","utepathletics.com","vanillatweaks.net","venusarchives.com","vide-greniers.org","video.gazzetta.it","videogameszone.de","videos.remilf.com","vietnamanswer.com","viralitytoday.com","virtualnights.com","visualnewshub.com","vitalitygames.com","voiceofdenton.com","voyeurpornsex.com","voyeurspyporn.com","voyeurxxxfree.com","walesfarmer.co.uk","wannafreeporn.com","watchanimesub.net","watchfacebook.com","watchsouthpark.tv","websiteglowgh.com","weknowconquer.com","welcometojapan.jp","wirralglobe.co.uk","wirtualnemedia.pl","wohnmobilforum.de","worldfreeware.com","worldgreynews.com","worthitorwoke.com","wpsimplehacks.com","xfreepornsite.com","xhamsterdeutsch.*","xnxx-sexfilme.com","xxxonlinefree.com","xxxpussyclips.com","xxxvideostrue.com","yesdownloader.com","yongfucknaked.com","yummysextubes.com","zeenews.india.com","zeijakunahiko.com","zeroto60times.com","zippysharecue.com","1001tracklists.com","101soundboards.com","123moviesready.org","123moviestoday.net","1337x.unblock2.xyz","247footballnow.com","7daystodiemods.com","adblockeronstape.*","addictinggames.com","adultasianporn.com","advertisertape.com","afasiaarchzine.com","airportwebcams.net","akuebresources.com","allureamateurs.net","alternativa104.net","amateur-mature.net","angrybirdsnest.com","animesonliner4.com","anothergraphic.org","antenasport.online","arcade.buzzrtv.com","arcadeprehacks.com","arkadiumhosted.com","arsiv.mackolik.com","asian-teen-sex.com","asianbabestube.com","asianpornfilms.com","asiansexdiarys.com","asianstubefuck.com","atlantafalcons.com","atlasstudiousa.com","autocadcommand.com","badasshardcore.com","baixedetudo.net.br","ballexclusives.com","barstoolsports.com","basic-tutorials.de","bdsmslavemovie.com","beamng.wesupply.cx","bearchasingart.com","bedfordtoday.co.uk","beermoneyforum.com","beginningmanga.com","berliner-kurier.de","beruhmtemedien.com","best-xxxvideos.com","bestialitytaboo.tv","bettingexchange.it","bidouillesikea.com","bigdata-social.com","bigdata.rawlazy.si","bigpiecreative.com","bigsouthsports.com","bigtitsxxxfree.com","birdsandblooms.com","birminghamworld.uk","blisseyhusband.net","blogredmachine.com","blogx.almontsf.com","blowjobamateur.net","blowjobpornset.com","bluecoreinside.com","bluemediastorage.*","bombshellbling.com","bonsaiprolink.shop","bosoxinjection.com","bridportnews.co.uk","burnleyexpress.net","businessinsider.de","calculatorsoup.com","camwhorescloud.com","captown.capcom.com","cararegistrasi.com","casos-aislados.com","cayenneevforum.com","cdimg.blog.2nt.com","cehennemstream.xyz","cerbahealthcare.it","cheshirelife.co.uk","chiangraitimes.com","chicagobearshq.com","chicagobullshq.com","chicasdesnudas.xxx","chikianimation.org","cintateknologi.com","clampschoolholic.*","classicalradio.com","classicxmovies.com","climaaovivo.com.br","clothing-mania.com","codingnepalweb.com","coleccionmovie.com","comeumamao.monster","comicspornoxxx.com","comparteunclic.com","consejosytrucos.co","consentmanager.net","contractpharma.com","cornwalllife.co.uk","cotswoldlife.co.uk","couponscorpion.com","cr7-soccer.store>>","cravenherald.co.uk","creditcardrush.com","crimsonscrolls.net","crm.urlwebsite.com","cronachedibirra.it","cronachesalerno.it","cryptonworld.space","dallasobserver.com","datapendidikan.com","dawgpounddaily.com","dcdirtylaundry.com","delawareonline.com","denverpioneers.com","depressionhurts.us","derehamtimes.co.uk","descargaspcpro.net","desifuckonline.com","deutschekanale.com","devicediary.online","dianaavoidthey.com","diariodenavarra.es","digicol.dpm.org.cn","dirtyasiantube.com","dirtygangbangs.com","discover-sharm.com","diyphotography.net","diyprojectslab.com","donghuanosekai.com","doublemindtech.com","downloadcursos.top","downloadgames.info","downloadmusic.info","downloadpirate.com","dragonball-zxk.com","dramathical.stream","dulichkhanhhoa.net","e-mountainbike.com","elconfidencial.com","elearning-cpge.com","embed-player.space","empire-streaming.*","english-dubbed.com","english-topics.com","enterprisenews.com","ericeastweight.com","essexlifemag.co.uk","eugenemakedraw.com","evdeingilizcem.com","eveningtimes.co.uk","eveningtribune.com","exactlyhowlong.com","expressandstar.com","expressbydgoski.pl","extremosports.club","familyhandyman.com","favoyeurtube.net>>","fightingillini.com","financialjuice.com","fireflix.pages.dev","flacdownloader.com","flashgirlgames.com","flashingjungle.com","foodiesgallery.com","foreversparkly.com","formasyonhaber.net","forum.cstalking.tv","francaisfacile.net","free-gay-clips.com","freeadultcomix.com","freeadultvideos.cc","freebiesmockup.com","freecoursesite.com","freefireupdate.com","freegogpcgames.com","freegrannyvids.com","freemockupzone.com","freemoviesfull.com","freepornasians.com","freepublicporn.com","freereceivesms.com","freeviewmovies.com","freevipservers.net","freevstplugins.net","freewoodworking.ca","freex2line.onlinex","freshwaterdell.com","friscofighters.com","fritidsmarkedet.dk","fuckhairygirls.com","fuckingsession.com","fullvideosporn.com","gamerevolution.com","games.arkadium.com","games.kentucky.com","games.mashable.com","games.thestate.com","gamingforecast.com","gaypornmasters.com","gazetakrakowska.pl","gazetazachodnia.eu","gazette-news.co.uk","gdrivelatinohd.net","geniale-tricks.com","geniussolutions.co","girlsgogames.co.uk","glasgowtimes.co.uk","go.bucketforms.com","goafricaonline.com","gobankingrates.com","gocurrycracker.com","godrakebulldog.com","gojapaneseporn.com","golf.rapidmice.com","gorro-4go5b3nj.fun","greeksubsmovies.me","grouppornotube.com","gruenderlexikon.de","gudangfirmwere.com","guessthemovie.name","guessthephrase.xyz","guiafinanceiro.top","hamptonpirates.com","hard-tube-porn.com","healthfirstweb.com","healthnewsreel.com","healthy4pepole.com","heatherdisarro.com","hentaipornpics.net","hentaisexfilms.com","heraldscotland.com","heraldseries.co.uk","hibsobserver.co.uk","hiddencamstube.com","highkeyfinance.com","hindustantimes.com","homeairquality.org","homemoviestube.com","hotanimevideos.com","hotbabeswanted.com","hotxxxjapanese.com","hqamateurtubes.com","huffingtonpost.com","huitranslation.com","humanbenchmark.com","hyundaitucson.info","idedroidsafelink.*","idevicecentral.com","ifreemagazines.com","ilcamminodiluce.it","imagetranslator.io","indecentvideos.com","indesignskills.com","indianbestporn.com","indianpornvideos.*","indiansexbazar.com","infinitehentai.com","infinityblogger.in","infojabarloker.com","informatudo.com.br","informaxonline.com","insidemarketing.it","insidememorial.com","insider-gaming.com","intercelestial.com","investor-verlag.de","iowaconference.com","italianporn.com.es","ithinkilikeyou.net","iusedtobeaboss.com","jacksonguitars.com","japanesemomsex.com","japanesetube.video","jeepreconforum.com","jemontremabite.com","jeux.meteocity.com","johnfullwonder.com","jojolandsmanga.com","joomlabeginner.com","jujustu-kaisen.com","juliewomanwish.com","justfamilyporn.com","justpicsplease.com","justtoysnoboys.com","kawaguchimaeda.com","keighleynews.co.uk","kellywhatcould.com","keralatelecom.info","kickasstorrents2.*","kilburntimes.co.uk","kittyfuckstube.com","knowyourphrase.com","kobitacocktail.com","komisanwamanga.com","kr-weathernews.com","krebs-horoskop.com","kstatefootball.net","kstatefootball.org","laopinioncoruna.es","leagueofgraphs.com","leckerschmecker.me","legiongamesgod.com","leighjournal.co.uk","leo-horoscopes.com","letribunaldunet.fr","leviathanmanga.com","levismodding.co.uk","lib.hatenablog.com","lincolncourier.com","link.get2short.com","link.paid4link.com","linkedmoviehub.top","linux-community.de","listenonrepeat.com","literarysomnia.com","littlebigsnake.com","liveandletsfly.com","localemagazine.com","longbeachstate.com","lotus-tours.com.hk","loyolaramblers.com","luzernerzeitung.ch","lyricsongation.com","m.timesofindia.com","magazyn-kuchnia.pl","maggotdrowning.com","magicgameworld.com","maketecheasier.com","makotoichikawa.net","mallorcazeitung.es","manager-magazin.de","manchesterworld.uk","mangas-origines.fr","manoramaonline.com","maraudersports.com","mathplayground.com","maturetubehere.com","maturexxxclips.com","mcdonoughvoice.com","mctechsolutions.in","mediascelebres.com","megafilmeshd50.com","megahentaitube.com","megapornfreehd.com","mein-wahres-ich.de","melaterevancha.com","memorialnotice.com","merlininkazani.com","mespornogratis.com","mesquitaonline.com","miltonkeynes.co.uk","minddesignclub.org","minecraftskins.com","minhasdelicias.com","mobilelegends.shop","mobiletvshows.site","modele-facture.com","moflix-stream.fans","montereyherald.com","motorcyclenews.com","moviescounnter.com","moviesonlinefree.*","mygardening411.com","myhentaicomics.com","mymusicreviews.com","myneobuxportal.com","mypornstarbook.net","nadidetarifler.com","naijachoice.com.ng","nakedgirlsroom.com","nakedneighbour.com","nauci-engleski.com","nauci-njemacki.com","netaffiliation.com","neueroeffnung.info","nevadawolfpack.com","newarkadvocate.com","newcastleworld.com","newjapanesexxx.com","news-geinou100.com","newyorkupstate.com","nicematureporn.com","niestatystyczny.pl","nightdreambabe.com","nlab.itmedia.co.jp","nontonvidoy.online","noodlemagazine.com","nudebeachpussy.com","nudecelebforum.com","nuevos-mu.ucoz.com","nyharborwebcam.com","o2tvseries.website","oceanbreezenyc.org","officegamespot.com","omnicalculator.com","onemileatatime.com","onepunch-manga.com","onetimethrough.com","onlineradiobox.com","onlinesudoku.games","onlinetutorium.com","onlinework4all.com","onlygoldmovies.com","onscreensvideo.com","openchat-review.me","pakistaniporn2.com","passeportsante.net","passportaction.com","pc-spiele-wiese.de","pcgamedownload.net","pcgameshardware.de","peachprintable.com","peliculas-dvdrip.*","penarthtimes.co.uk","penisbuyutucum.net","pestleanalysis.com","pinayviralsexx.com","plainasianporn.com","play.starsites.fun","player.euroxxx.net","player.vidplus.pro","playeriframe.lol>>","playretrogames.com","pliroforiki-edu.gr","policesecurity.com","policiesreview.com","polskawliczbach.pl","pornhubdeutsch.net","pornmaturetube.com","pornohubonline.com","pornovideos-hd.com","pornvideospass.com","powerthesaurus.org","premiumstream.live","present.rssing.com","printablecrush.com","problogbooster.com","productkeysite.com","progress-index.com","projectfreetv2.com","projuktirkotha.com","proverbmeaning.com","psicotestuned.info","pussytubeebony.com","racedepartment.com","radio-en-direct.fr","radio-hrvatska.com","radioitalylive.com","radionorthpole.com","ratemyteachers.com","realfreelancer.com","realtormontreal.ca","recherche-ebook.fr","record-courier.com","redamateurtube.com","redbubbletools.com","redstormsports.com","replica-watch.info","reporter-times.com","reporterherald.com","resultadostris.com","rightdark-scan.com","rincondelsazon.com","ripcityproject.com","risefromrubble.com","romaniataramea.com","royston-crow.co.uk","ryanagoinvolve.com","sabornutritivo.com","samrudhiglobal.com","samurai.rzword.xyz","sandrataxeight.com","sankakucomplex.com","scarletandgame.com","scarletknights.com","schoener-wohnen.de","sciencechannel.com","scopateitaliane.it","seacoastonline.com","seamanmemories.com","selfstudybrain.com","sethniceletter.com","sexiestpicture.com","sexteenxxxtube.com","sexy-youtubers.com","sexykittenporn.com","sexymilfsearch.com","shadowrangers.live","sheboyganpress.com","shemaletoonsex.com","shieldsgazette.com","shipseducation.com","shrivardhantech.in","shropshirestar.com","shutupandgo.travel","sidelionreport.com","siirtolayhaber.com","simpledownload.net","siteunblocked.info","slowianietworza.pl","smithsonianmag.com","soccerstream100.to","sociallyindian.com","sooeveningnews.com","sosyalbilgiler.net","southernliving.com","southparkstudios.*","spank-and-bang.com","sports-arena.space","sportstohfa.online","stapewithadblock.*","starnewsonline.com","sthelensstar.co.uk","stirlingnews.co.uk","stream.nflbox.me>>","streamelements.com","streaming-french.*","strtapeadblocker.*","sturgisjournal.com","sunderlandecho.com","surgicaltechie.com","sweeteroticart.com","syracusecrunch.com","tamilultratv.co.in","tapeadsenjoyer.com","tauntongazette.com","tcpermaculture.com","technicalviral.com","telefullenvivo.com","telexplorer.com.ar","theblissempire.com","thecalifornian.com","thecelticbhoys.com","theendlessmeal.com","thefirearmblog.com","thegardnernews.com","thegoldendaily.com","thehentaiworld.com","thelesbianporn.com","thepewterplank.com","thepiratebay10.org","theralphretort.com","thestarphoenix.com","thesuperdownload.*","thetimesherald.com","thiagorossi.com.br","thisisourbliss.com","tiervermittlung.de","tiktokrealtime.com","times-series.co.uk","times-standard.com","timesandstar.co.uk","tiny-sparklies.com","tips-and-tricks.co","tokyo-ghoul.online","tonpornodujour.com","topbiography.co.in","torrentdosfilmes.*","torrentdownloads.*","totalsportekhd.com","traductionjeux.com","trannysexmpegs.com","transgirlslive.com","traveldesearch.com","travelplanspro.com","trendyol-milla.com","tribeathletics.com","trovapromozioni.it","truckingboards.com","truyenbanquyen.com","truyenhentai18.net","tuhentaionline.com","tulsahurricane.com","turboimagehost.com","tuscaloosanews.com","tv3play.skaties.lv","tvonlinesports.com","tweaksforgeeks.com","txstatebobcats.com","ucirvinesports.com","ukrainesmodels.com","uncensoredleak.com","universfreebox.com","unlimitedfiles.xyz","urbanmilwaukee.com","urlaubspartner.net","venus-and-mars.com","vermangasporno.com","verywellhealth.com","victor-mochere.com","videos.porndig.com","videosinlevels.com","videosxxxputas.com","vintagepornfun.com","vintagepornnew.com","vintagesexpass.com","waitrosecellar.com","washingtonpost.com","watch.rkplayer.xyz","watch.shout-tv.com","watchadsontape.com","wblaxmibhandar.com","weakstreams.online","weatherzone.com.au","web.livecricket.is","webloadedmovie.com","websitesbridge.com","werra-rundschau.de","wheatbellyblog.com","wildhentaitube.com","windowsmatters.com","winteriscoming.net","wohnungsboerse.net","woman.excite.co.jp","worldofpcgames.com","worldstreams.click","wormser-zeitung.de","www.cloudflare.com","www.primevideo.com","xbox360torrent.com","xda-developers.com","xn--kckzb2722b.com","xpressarticles.com","xxx-asian-tube.com","xxxanimemovies.com","xxxanimevideos.com","yify-subtitles.org","youngpussyfuck.com","youwatch-serie.com","yt-downloaderz.com","ytmp4converter.com","zxi.mytechroad.com","aachener-zeitung.de","abukabir.fawrye.com","abyssplay.pages.dev","academiadelmotor.es","adblockstreamtape.*","addtobucketlist.com","adultgamesworld.com","agrigentonotizie.it","aliendictionary.com","allafricangirls.net","allindiaroundup.com","alloaadvertiser.com","allporncartoons.com","almohtarif-tech.net","altadefinizione01.*","amateur-couples.com","amaturehomeporn.com","amazingtrannies.com","androidrepublic.org","angeloyeo.github.io","animefuckmovies.com","animeonlinefree.org","animesonlineshd.com","annoncesescorts.com","anonymous-links.com","anonymousceviri.com","app.link2unlock.com","app.studysmarter.de","aprenderquechua.com","arabianbusiness.com","ardrossanherald.com","arizonawildcats.com","arnaqueinternet.com","arrowheadaddict.com","artificialnudes.com","asiananimaltube.org","asianfuckmovies.com","asianporntube69.com","audiobooks4soul.com","audiotruyenfull.com","bailbondsfinder.com","baltimoreravens.com","beautypackaging.com","beisbolinvernal.com","berliner-zeitung.de","bestmaturewomen.com","bigcockfreetube.com","bigsouthnetwork.com","blackenterprise.com","blog.cloudflare.com","bluemediadownload.*","bordertelegraph.com","bracknellnews.co.uk","brentwoodlive.co.uk","businessinsider.com","calculascendant.com","cambrevenements.com","canuckaudiomart.com","celebritynakeds.com","celebsnudeworld.com","certificateland.com","chakrirkhabar247.in","championpeoples.com","chawomenshockey.com","chicagosportshq.com","christiantrendy.com","chubbypornmpegs.com","citationmachine.net","civilenggforall.com","classicpornbest.com","classicpornvids.com","clevelandbrowns.com","clydebankpost.co.uk","collegeteentube.com","columbiacougars.com","columbiatribune.com","comicsxxxgratis.com","commande.rhinov.pro","commsbusiness.co.uk","comofuncionaque.com","compilationtube.xyz","comprovendolibri.it","concealednation.org","consigliatodanoi.it","couponsuniverse.com","courier-journal.com","coworkingczerska.pl","crackedsoftware.biz","creativebusybee.com","crossdresserhub.com","crosswordsolver.com","crystal-launcher.pl","custommapposter.com","daddyfuckmovies.com","dailycommercial.com","dailyjobposting.xyz","dailymaverick.co.za","dartmouthsports.com","der-betze-brennt.de","descargaranimes.com","descargatepelis.com","deseneledublate.com","desktopsolution.org","detroitjockcity.com","dev.fingerprint.com","developerinsider.co","diariodemallorca.es","diarioeducacion.com","dichvureviewmap.com","diendancauduong.com","digitalfernsehen.de","digitalseoninja.com","digitalstudiome.com","dignityobituary.com","discordfastfood.com","divinelifestyle.com","divxfilmeonline.net","dktechnicalmate.com","download.megaup.net","dubipc.blogspot.com","dynamicminister.net","dziennikbaltycki.pl","dziennikpolski24.pl","dziennikzachodni.pl","edmontonjournal.com","elamigosedition.com","ellibrepensador.com","embed.nana2play.com","embed.tmp-url.pro>>","en-thunderscans.com","erotaredogaonly.xyz","erotic-beauties.com","eveningnews24.co.uk","eventiavversinews.*","expresskaszubski.pl","fakenhamtimes.co.uk","falkirkherald.co.uk","fansubseries.com.br","fatblackmatures.com","faucetcaptcha.co.in","felicetommasino.com","femdomporntubes.com","fifaultimateteam.it","filmeonline2018.net","filmesonlinehd1.org","firstasianpussy.com","footballfancast.com","footballstreams.lol","footballtransfer.ru","fortnitetracker.com","fplstatistics.co.uk","franceprefecture.fr","free-trannyporn.com","freecoursesites.com","freecoursesonline.*","freegamescasual.com","freeindianporn.mobi","freeindianporn2.com","freeplayervideo.com","freescorespiano.com","freesexvideos24.com","freetarotonline.com","freshsexxvideos.com","frustfrei-lernen.de","fuckmonstercock.com","fuckslutsonline.com","futura-sciences.com","gagaltotal666.my.id","gallant-matures.com","gamecocksonline.com","games.bradenton.com","games.dailymail.com","games.fresnobee.com","games.heraldsun.com","games.sunherald.com","gazetawroclawska.pl","gazetteherald.co.uk","gazetteseries.co.uk","generacionretro.net","gesund-vital.online","gfilex.blogspot.com","global.novelpia.com","gloswielkopolski.pl","goarmywestpoint.com","godrakebulldogs.com","godrakebulldogs.net","goodnewsnetwork.org","hailfloridahail.com","halesowennews.co.uk","hamburgerinsult.com","hardcorelesbian.xyz","hardwarezone.com.sg","hardwoodhoudini.com","hartvannederland.nl","haus-garten-test.de","haveyaseenjapan.com","hawaiiathletics.com","hayamimi-gunpla.com","healthbeautybee.com","helpnetsecurity.com","hentai-mega-mix.com","hentaianimezone.com","hentaisexuality.com","heraldmailmedia.com","hieunguyenphoto.com","highdefdiscnews.com","hindimatrashabd.com","hindimearticles.net","hindimoviesonline.*","historicaerials.com","hmc-id.blogspot.com","hobby-machinist.com","hollandsentinel.com","home-xxx-videos.com","horseshoeheroes.com","hotbeautyhealth.com","hotorientalporn.com","hqhardcoreporno.com","ianrequireadult.com","ilbolerodiravel.org","ilforumdeibrutti.is","ilkleygazette.co.uk","independentmail.com","indianpornvideo.org","individualogist.com","ingyenszexvideok.hu","insidertracking.com","insidetheiggles.com","interculturalita.it","inventionsdaily.com","iptvxtreamcodes.com","itsecuritynews.info","iulive.blogspot.com","jacquieetmichel.net","japanesexxxporn.com","javuncensored.watch","jessicaclearout.com","joguinhosgratis.com","journalstandard.com","justcastingporn.com","justsexpictures.com","k-statefootball.net","k-statefootball.org","kentstatesports.com","kingjamesgospel.com","kingsofkauffman.com","kissmaturestube.com","klettern-magazin.de","kreuzwortraetsel.de","kstateathletics.com","ladypopularblog.com","lawweekcolorado.com","learnchannel-tv.com","legionpeliculas.org","legionprogramas.org","leitesculinaria.com","lemino.docomo.ne.jp","letrasgratis.com.ar","lifeisbeautiful.com","limiteddollqjc.shop","lindalastattack.com","livetv.moviebite.cc","livingstondaily.com","localizaagencia.com","lufkindailynews.com","m.jobinmeghalaya.in","marketrevolution.eu","masashi-blog418.com","massagefreetube.com","maturepornphoto.com","measuringflower.com","mediatn.cms.nova.cz","meeting.tencent.com","megajapanesesex.com","meicho.marcsimz.com","miamiairportcam.com","miamibeachradio.com","midweekherald.co.uk","migliori-escort.com","mikaylaarealike.com","mindmotion93y8.shop","minecraft-forum.net","minecraftraffle.com","minhaconexao.com.br","minutemirror.com.pk","mittelbayerische.de","mobilesexgamesx.com","montrealgazette.com","morinaga-office.net","motherandbaby.co.uk","movies-watch.com.pk","multicanaistt.space","mycentraljersey.com","myhentaigallery.com","mynaturalfamily.com","myreadingmanga.info","norwichbulletin.com","noticiascripto.site","nottinghamworld.com","novelsparadise.site","nude-beach-tube.com","nudeselfiespics.com","nurparatodos.com.ar","obituaryupdates.com","octavestreaming.com","oldgrannylovers.com","onlinefetishporn.cc","onlinepornushka.com","opisanie-kartin.com","orangespotlight.com","outdoor-magazin.com","painting-planet.com","parasportontario.ca","parrocchiapalata.it","pcgamebenchmark.com","peopleenespanol.com","perfectmomsporn.com","petitegirlsnude.com","pharmaguideline.com","phoenixnewtimes.com","phonereviewinfo.com","pickleballclubs.com","picspornamateur.com","planetminecraft.com","platform.autods.com","play.dictionary.com","play.geforcenow.com","play.mylifetime.com","play.playkrx18.site","player.popfun.co.uk","player.uwatchfree.*","pompanobeachcam.com","popularasianxxx.com","poradyiwskazowki.pl","pornjapanesesex.com","pornocolegialas.org","pornocolombiano.net","pornosubtitula2.com","pornstarsadvice.com","portmiamiwebcam.com","porttampawebcam.com","pranarevitalize.com","protege-torrent.com","psychology-spot.com","publicidadtulua.com","quest.to-travel.net","raccontivietati.com","radio-australia.org","radio-osterreich.at","radiosantaclaus.com","radiotormentamx.com","rangersreview.co.uk","readcomicsonline.ru","realitybrazzers.com","redowlanalytics.com","relampagomovies.com","reneweconomy.com.au","richardsignfish.com","richmondspiders.com","ripplestream4u.shop","roberteachfinal.com","rojadirectaenhd.net","rojadirectatvlive.*","rollingglobe.online","romanticlesbian.com","rundschau-online.de","ryanmoore.marketing","rysafe.blogspot.com","samurai.wordoco.com","santoinferninho.com","savingsomegreen.com","scansatlanticos.com","scholarshiplist.org","schrauben-normen.de","secondhandsongs.com","sempredirebanzai.it","sempreupdate.com.br","serieshdpormega.com","seriezloaded.com.ng","setsuyakutoushi.com","sex-free-movies.com","sexyvintageporn.com","shogaisha-shuro.com","shogaisha-techo.com","shreveporttimes.com","sixsistersstuff.com","skidrowreloaded.com","smartkhabrinews.com","soap2day-online.com","soccerfullmatch.com","soccerworldcup.me>>","sociologicamente.it","somerset-life.co.uk","somulhergostosa.com","sourcingjournal.com","sousou-no-frieren.*","southcoasttoday.com","spa.center.ivof.com","sportitalialive.com","sportowefakty.wp.pl","sportzonline.site>>","spotidownloader.com","ssdownloader.online","standardmedia.co.ke","stealthoptional.com","stormininnorman.com","storynavigation.com","stoutbluedevils.com","stream.offidocs.com","stream.pkayprek.com","streamadblockplus.*","streamcasthub.store","streamshunters.eu>>","streamtapeadblock.*","submissive-wife.net","summarynetworks.com","sussexexpress.co.uk","svetatnazdraveto.bg","sweetadult-tube.com","tainio-mania.online","tamilfreemp3songs.*","tapewithadblock.org","teachersupdates.net","technicalline.store","techtrendmakers.com","tekniikanmaailma.fi","telecharger-igli4.*","thebalancemoney.com","theberserkmanga.com","theboltonnews.co.uk","thecrazytourist.com","thedailyjournal.com","theglobeandmail.com","themehospital.co.uk","thenorthwestern.com","theoaklandpress.com","therecordherald.com","thesaltysoldier.com","thesimsresource.com","thesmokingcuban.com","thetorquereport.com","thewatchseries.live","throwsmallstone.com","timesnowmarathi.com","timesrecordnews.com","timmaybealready.com","tiz-cycling-live.io","tophentaicomics.com","toptenknowledge.com","totalfuckmovies.com","totalmaturefuck.com","transexuales.gratis","trendsderzukunft.de","trucs-et-astuces.co","tubepornclassic.com","tubevintageporn.com","turkishseriestv.net","turtleboysports.com","tutorialsduniya.com","tw-hkt.blogspot.com","ukmagazinesfree.com","uktvplay.uktv.co.uk","ultimate-guitar.com","urbandictionary.com","usinger-anzeiger.de","utahstateaggies.com","valleyofthesuns.com","veryfastdownload.pw","vickisaveworker.com","vinylcollective.com","vip.stream101.space","virtual-youtuber.jp","virtualdinerbot.com","vitadacelebrita.com","wallpaperaccess.com","watch-movies.com.pk","watchlostonline.net","watchmonkonline.com","watchmoviesrulz.com","watchonlinemovie.pk","wearesunderland.com","webhostingoffer.org","weneverbeenfree.com","weristdeinfreund.de","windows-7-forum.net","winit.heatworld.com","witneygazette.co.uk","woffordterriers.com","worcesternews.co.uk","worldstarhiphop.com","worldtravelling.com","www2.tmyinsight.net","xhamsterdeutsch.xyz","xn--nbkw38mlu2a.com","xnxx-downloader.net","xnxx-sex-videos.com","xxxhentaimovies.com","xxxpussysextube.com","xxxsexyjapanese.com","yaoimangaonline.com","yellowblissroad.com","yeovilexpress.co.uk","yorkshirelife.co.uk","yorkshirepost.co.uk","your-daily-girl.com","youramateurporn.com","youramateurtube.com","yourlifeupdated.net","youtubedownloader.*","zeeplayer.pages.dev","25yearslatersite.com","27-sidefire-blog.com","2adultflashgames.com","acienciasgalilei.com","adult-sex-gamess.com","adultdvdparadise.com","akatsuki-no-yona.com","allcelebritywiki.com","allcivilstandard.com","allnewindianporn.com","aman-dn.blogspot.com","amateurebonypics.com","amateuryoungpics.com","analysis-chess.io.vn","androidapkmodpro.com","androidauthority.com","androidtunado.com.br","angolopsicologia.com","animalextremesex.com","apenasmaisumyaoi.com","aquiyahorajuegos.net","aroundthefoghorn.com","aspdotnet-suresh.com","augustachronicle.com","ayobelajarbareng.com","ayrshire-today.co.uk","badassdownloader.com","bailiwickexpress.com","banglachotigolpo.xyz","bestmp3converter.com","bestshemaleclips.com","bigtitsporn-tube.com","birmingham-now.co.uk","blackwoodacademy.org","bloggingawaydebt.com","bloggingguidance.com","boainformacao.com.br","bogowieslowianscy.pl","bollywoodshaadis.com","boxofficebusiness.in","br.nacaodamusica.com","broncosportforum.com","browardpalmbeach.com","bucksfreepress.co.uk","bustyshemaleporn.com","cachevalleydaily.com","canberratimes.com.au","captcha-delivery.com","cartoonstvonline.com","cartoonvideos247.com","centralboyssp.com.br","centralfifetimes.com","charlestoughrace.com","chasingthedonkey.com","cienagamagdalena.com","climbingtalshill.com","comandotorrenthd.org","commercialappeal.com","consiglietrucchi.com","coolmath4parents.com","crackstreamsfree.com","crackstreamshd.click","craigretailers.co.uk","creators.nafezly.com","cumnockchronicle.com","dailygrindonline.net","dairylandexpress.com","davidsonbuilders.com","decorativemodels.com","defienietlynotme.com","deliciousmagazine.pl","demonyslowianskie.pl","derbyshirelife.co.uk","descargaseriestv.com","diglink.blogspot.com","divxfilmeonline.tv>>","djsofchhattisgarh.in","docs.fingerprint.com","donna-cerca-uomo.com","dorsetmagazine.co.uk","downloadfilm.website","dunfermlinepress.com","durhamopenhouses.com","ear-phone-review.com","earnfromarticles.com","edivaldobrito.com.br","educationbluesky.com","embed.hideiframe.com","encuentratutarea.com","eroticteensphoto.net","escort-in-italia.com","essen-und-trinken.de","eurostreaming.casino","eveshamjournal.co.uk","exmouthjournal.co.uk","extremereportbot.com","fairforexbrokers.com","falmouthpacket.co.uk","famosas-desnudas.org","fastpeoplesearch.com","filmeserialegratis.*","filmpornofrancais.fr","finanznachrichten.de","finding-camellia.com","fitbook-magazine.com","fle-5r8dchma-moo.com","football-ukraine.com","footballandress.club","foreverconscious.com","forexwikitrading.com","forge.plebmasters.de","forobasketcatala.com","forum.lolesporte.com","forum.thresholdx.net","fotbolltransfers.com","fr.streamon-sport.ru","free-sms-receive.com","freebigboobsporn.com","freelistenonline.com","freemagazinespdf.com","freemedicalbooks.org","freepatternsarea.com","freereadnovel.online","freeromsdownload.com","freestreams-live.*>>","freethailottery.live","freshshemaleporn.com","fullywatchonline.com","funeral-memorial.com","gaget.hatenablog.com","games.abqjournal.com","games.dallasnews.com","games.denverpost.com","games.kansascity.com","games.sixtyandme.com","games.wordgenius.com","gearingcommander.com","gesundheitsfrage.net","getfreesmsnumber.com","ghajini-4urg44yg.lol","giuseppegravante.com","giveawayoftheday.com","givemenbastreams.com","googledrivelinks.com","gourmetsupremacy.com","greatestshemales.com","greenvilleonline.com","griffinathletics.com","hackingwithreact.com","hackneygazette.co.uk","halifaxcourier.co.uk","hampshire-life.co.uk","harboroughmail.co.uk","hartlepoolmail.co.uk","hds-streaming-hd.com","headlinepolitics.com","heartofvicksburg.com","heartrainbowblog.com","heartsstandard.co.uk","heresyoursavings.com","hexham-courant.co.uk","highheelstrample.com","historichorizons.com","hodgepodgehippie.com","hofheimer-zeitung.de","home-made-videos.com","homehobbiesdaily.com","homestratosphere.com","hornyconfessions.com","hostingreviews24.com","hotasianpussysex.com","hotjapaneseshows.com","huffingtonpost.co.uk","hypelifemagazine.com","ilfordrecorder.co.uk","immobilienscout24.de","india.marathinewz.in","inkworldmagazine.com","intereseducation.com","irresistiblepets.net","italiadascoprire.net","itpassportgokaku.com","jemontremonminou.com","jessicayeahcatch.com","jlwranglerforums.com","johnbeyondnation.com","k-stateathletics.com","kachelmannwetter.com","karaoke4download.com","karaokegratis.com.ar","lacronicabadajoz.com","lancashirelife.co.uk","laopiniondemalaga.es","laopiniondemurcia.es","laopiniondezamora.es","largescaleforums.com","latinatemptation.com","laweducationinfo.com","lazytranslations.com","lemonsqueezyhome.com","lempaala.ideapark.fi","lesbianvideotube.com","letemsvetemapplem.eu","letsworkremotely.com","link.djbassking.live","linksdegrupos.com.br","live-tv-channels.org","liveonlinesports.net","lostcoastoutpost.com","luxurydreamhomes.net","main.sportswordz.com","malverngazette.co.uk","mangcapquangvnpt.com","maps.blitzortung.org","maryspecialwatch.com","maturepornjungle.com","maturewomenfucks.com","mauiinvitational.com","medicalstudyzone.com","mein-kummerkasten.de","milforddailynews.com","milfordmercury.co.uk","mkvmoviespoint.autos","monkeyanimalporn.com","morganhillwebcam.com","motorbikecatalog.com","motorcitybengals.com","motorsport-total.com","movieloversworld.com","moviemakeronline.com","moviesubtitles.click","mujeresdesnudas.club","mustardseedmoney.com","mylivewallpapers.com","mypace.sasapurin.com","myperfectweather.com","mypussydischarge.com","myuploadedpremium.de","naughtymachinima.com","newfreelancespot.com","newhamrecorder.co.uk","neworleanssaints.com","newsonthegotoday.com","nibelungen-kurier.de","northernfarmer.co.uk","notebookcheck-cn.com","notebookcheck-hu.com","notebookcheck-ru.com","notebookcheck-tr.com","nudeplayboygirls.com","nuovo.vidplayer.live","nutraingredients.com","nylonstockingsex.net","odkrywamyzakryte.com","onechicagocenter.com","online-xxxmovies.com","onlinegrannyporn.com","oraridiapertura24.it","originalteentube.com","pandadevelopment.net","pasadenastarnews.com","pcgamez-download.com","peeblesshirenews.com","pembrokeobserver.com","pesprofessionals.com","petbook-magazine.com","pipocamoderna.com.br","plagiarismchecker.co","planetaminecraft.com","platform.twitter.com","play.doramasplus.net","player.amperwave.net","player.smashy.stream","playstationhaber.com","popularmechanics.com","porlalibreportal.com","pornhub-sexfilme.net","portnassauwebcam.com","presentation-ppt.com","prismmarketingco.com","pro.iqsmartgames.com","psychologyjunkie.com","pussymaturephoto.com","radiocountrylive.com","ragnarokscanlation.*","ranaaclanhungary.com","readcomicsonline.lol","redensarten-index.de","remotejobzone.online","reviewingthebrew.com","rhein-main-presse.de","rinconpsicologia.com","robertplacespace.com","rockpapershotgun.com","roemische-zahlen.net","rojadirectaenvivo.pl","roms-telecharger.com","salamanca24horas.com","sanadegreecollege.in","sandratableother.com","sarkariresult.social","savespendsplurge.com","schoolgirls-asia.org","schwaebische-post.de","securegames.iwin.com","server-tutorials.net","sexypornpictures.org","sidmouthherald.co.uk","sloughobserver.co.uk","socialmediagirls.com","socket.pearsoned.com","solomaxlevelnewbie.*","southbendtribune.com","spicyvintageporn.com","sportstohfa.online>>","starkroboticsfrc.com","statesmanjournal.com","steamunderground.net","stevenfamilyedge.com","stream.nbcsports.com","streamingcommunity.*","strtapewithadblock.*","sudburymercury.co.uk","superfastrelease.xyz","superpackpormega.com","swietaslowianskie.pl","switchbacktravel.com","tainguyenmienphi.com","tasteandtellblog.com","telephone-soudan.com","teluguonlinemovies.*","telugusexkathalu.com","the-daily-record.com","thedailyreporter.com","thefappeningblog.com","thefastlaneforum.com","thegatewaypundit.com","thekitchenmagpie.com","theleafchronicle.com","theoldhamtimes.co.uk","thepublicopinion.com","thescottishsun.co.uk","thesimplifydaily.com","tienichdienthoai.net","tinyqualityhomes.org","tomb-raider-king.com","totallysnookered.com","totalsportek1000.com","toyoheadquarters.com","tracylocalschool.com","trueachievements.com","tutorialforlinux.com","udemy-downloader.com","unblockedgames.world","underground.tboys.ro","utahsweetsavings.com","utepminermaniacs.com","ver-comics-porno.com","ver-mangas-porno.com","videoszoofiliahd.com","vintageporntubes.com","viralviralvideos.com","virgo-horoscopes.com","visualcapitalist.com","wallstreet-online.de","watchallchannels.com","watchcartoononline.*","watchgameofthrones.*","watchsuitsonline.net","watchtheofficetv.com","weekendletters.store","wegotthiscovered.com","weihnachts-filme.com","wetasiancreampie.com","whats-on-netflix.com","whitehavennews.co.uk","wife-home-videos.com","wiltshiretimes.co.uk","wirtualnynowydwor.pl","worldgirlsportal.com","www.digitalocean.com","yakyufan-asobiba.com","youfreepornotube.com","youngerasiangirl.net","yourhomemadetube.com","youtube-nocookie.com","yummytummyaarthi.com","zakupy-czterykaty.pl","1337x.ninjaproxy1.com","3dassetcollection.com","3dprintersforum.co.uk","ableitungsrechner.net","ad-itech.blogspot.com","airportseirosafar.com","airsoftmilsimnews.com","allgemeine-zeitung.de","ar-atech.blogspot.com","arabamob.blogspot.com","arrisalah-jakarta.com","banburyguardian.co.uk","banglachoti-story.com","bestsellerforaday.com","bibliotecadecorte.com","bigbuttshubvideos.com","blackchubbymovies.com","blackmaturevideos.com","blasianluvforever.com","blog.motionisland.com","bournemouthecho.co.uk","branditechture.agency","brandstofprijzen.info","broncathleticfund.com","brutalanimalsfuck.com","bucetaspeludas.com.br","business-standard.com","calculator-online.net","cancer-horoscopes.com","cantondailyledger.com","celebritydeeplink.com","charlessheimprove.com","chesterstandard.co.uk","collinsdictionary.com","comentariodetexto.com","community-scripts.org","conselhosetruques.com","coolmath4teachers.com","cotswoldjournal.co.uk","courierpostonline.com","course-downloader.com","daddylivestream.com>>","dailyvideoreports.net","daventryexpress.co.uk","davescomputertips.com","derbyshiretimes.co.uk","desitab69.sextgem.com","desmoinesregister.com","destakenewsgospel.com","deutschpersischtv.com","diarioinformacion.com","diplomaexamcorner.com","dirtyyoungbitches.com","disneyfashionista.com","download.yasir252.com","downloadcursos.gratis","dragontranslation.com","dragontranslation.net","dragontranslation.org","dunmowbroadcast.co.uk","easyworldbusiness.com","elcriticodelatele.com","electricalstudent.com","ellwoodcityledger.com","embraceinnerchaos.com","envato-downloader.com","eroticmoviesonline.me","errotica-archives.com","essexcountynews.co.uk","exchangeandmart.co.uk","expressilustrowany.pl","filemoon-59t9ep5j.xyz","filemoon-nv2xl8an.xyz","filmpornoitaliano.org","fitting-it-all-in.com","foodsdictionary.co.il","forestryjournal.co.uk","free-3dtextureshd.com","free-famous-toons.com","freebulksmsonline.com","freefatpornmovies.com","freeindiansextube.com","freepikdownloader.com","freepressseries.co.uk","freshmaturespussy.com","friedrichshainblog.de","froheweihnachten.info","gadgetguideonline.com","games.bostonglobe.com","games.centredaily.com","games.dailymail.co.uk","games.greatergood.com","games.miamiherald.com","games.puzzlebaron.com","games.startribune.com","games.theadvocate.com","games.theolympian.com","games.triviatoday.com","gbadamud.blogspot.com","gemini-horoscopes.com","generalpornmovies.com","gentiluomodigitale.it","gentlemansgazette.com","giantshemalecocks.com","giessener-anzeiger.de","girlfuckgalleries.com","glamourxxx-online.com","gmuender-tagespost.de","googlearth.selva.name","goprincetontigers.com","greatfallstribune.com","greenwichmeantime.com","guardian-series.co.uk","hackedonlinegames.com","halsteadgazette.co.uk","heraldtimesonline.com","hersfelder-zeitung.de","higherorlowergame.com","hillingdontimes.co.uk","hochheimer-zeitung.de","hoegel-textildruck.de","hollywoodreporter.com","hot-teens-movies.mobi","hotmarathistories.com","howtoblogformoney.net","html5.gamemonetize.co","hungarianhardstyle.hu","iamflorianschulze.com","imasdk.googleapis.com","impartialreporter.com","indiansexstories2.net","indratranslations.com","inmatesearchidaho.com","insideeducation.co.za","jacquieetmicheltv.net","jemontremasextape.com","jessicachoosemake.com","journaldemontreal.com","journey.to-travel.net","jsugamecocksports.com","juninhoscripts.com.br","kana-mari-shokudo.com","kstatewomenshoops.com","kstatewomenshoops.net","kstatewomenshoops.org","labelandnarrowweb.com","lapaginadealberto.com","learnodo-newtonic.com","lebensmittelpraxis.de","ledburyreporter.co.uk","lesbianfantasyxxx.com","lincolnshireworld.com","lingeriefuckvideo.com","live-sport.duktek.pro","lycomingathletics.com","majalahpendidikan.com","malaysianwireless.com","mangaplus.shueisha.tv","mavericktruckclub.com","megashare-website.com","meuplayeronlinehd.com","midlandstraveller.com","midwestconference.org","mimaletadepeliculas.*","mmoovvfr.cloudfree.jp","motorsport.uol.com.br","musvozimbabwenews.com","mysflink.blogspot.com","nationalgeographic.fr","netsentertainment.net","niederschlagsradar.de","nobledicion.yoveo.xyz","note.sieuthuthuat.com","notformembersonly.com","oberschwaben-tipps.de","onepiecemangafree.com","onlinetntextbooks.com","onlinewatchmoviespk.*","ovcdigitalnetwork.com","paradiseislandcam.com","partner.nonamejose.sx","pcmap.place.naver.com","pcso-lottoresults.com","peiner-nachrichten.de","pelotalibrevivo.net>>","petersfieldpost.co.uk","philippinenmagazin.de","photovoltaikforum.com","pickleballleagues.com","pisces-horoscopes.com","platform.adex.network","portbermudawebcam.com","primapaginamarsala.it","printablecreative.com","prod.hydra.sophos.com","providencejournal.com","quinnipiacbobcats.com","qul-de.translate.goog","radioitaliacanada.com","radioitalianmusic.com","redbluffdailynews.com","reddit-streams.online","redheaddeepthroat.com","redirect.dafontvn.com","revistaapolice.com.br","romfordrecorder.co.uk","salzgitter-zeitung.de","santacruzsentinel.com","santafenewmexican.com","scotlandrugbynews.com","scriptgrowagarden.com","scrubson.blogspot.com","scrumpoker-online.org","sex-amateur-clips.com","sexybabespictures.com","shortgoo.blogspot.com","showdownforrelief.com","sinnerclownceviri.net","skorpion-horoskop.com","smartwebsolutions.org","snapinstadownload.xyz","softwarecrackguru.com","softwaredescargas.com","solomax-levelnewbie.*","solopornoitaliani.xxx","southsideshowdown.com","southwalesargus.co.uk","southwestfarmer.co.uk","soziologie-politik.de","space.tribuntekno.com","stablediffusionxl.com","startupjobsportal.com","steamcrackedgames.com","stourbridgenews.co.uk","stream.hownetwork.xyz","streaming-community.*","streamingcommunityz.*","studyinghuman6js.shop","supertelevisionhd.com","sweet-maturewomen.com","symboleslowianskie.pl","tapeadvertisement.com","tarjetarojaenvivo.lat","tarjetarojatvonline.*","taurus-horoscopes.com","taurus.topmanhuas.org","tech.trendingword.com","techbook-magazine.com","texteditor.nsspot.net","thecakeboutiquect.com","thedigitaltheater.com","thefightingcock.co.uk","thefreedictionary.com","thegnomishgazette.com","thenews-messenger.com","thenorthernecho.co.uk","theprofoundreport.com","thesavvyexplorers.com","thetruthaboutcars.com","thewebsitesbridge.com","thisiswiltshire.co.uk","thurrockgazette.co.uk","timesheraldonline.com","timesnewsgroup.com.au","tipsandtricksarab.com","torrentdofilmeshd.net","towheaddeepthroat.com","travel-the-states.com","travelingformiles.com","tudo-para-android.com","ukiahdailyjournal.com","unsurcoenlasombra.com","utkarshonlinetest.com","vdl.np-downloader.com","virtualstudybrain.com","visaliatimesdelta.com","voyeur-pornvideos.com","walterprettytheir.com","warwickshireworld.com","watch-movies.com.pk>>","watch.foodnetwork.com","watchcartoonsonline.*","watchfreejavonline.co","watchkobestreams.info","watchonlinemoviespk.*","watchporninpublic.com","watchseriesstream.com","watfordobserver.co.uk","wausaudailyherald.com","weihnachts-bilder.org","wetterauer-zeitung.de","whisperingauroras.com","whittierdailynews.com","wiesbadener-kurier.de","wirtualnelegionowo.pl","wisbechstandard.co.uk","worksopguardian.co.uk","worldwidestandard.net","www.bankofamerica.com","www.dailymotion.com>>","xn--mlaregvle-02af.nu","yoima.hatenadiary.com","yoima2.hatenablog.com","zone-telechargement.*","123movies-official.net","1plus1plus1equals1.net","45er-de.translate.goog","acervodaputaria.com.br","adelaidepawnbroker.com","aimasummd.blog.fc2.com","algodaodocescan.com.br","allevertakstream.space","androidecuatoriano.xyz","anguscountyworld.co.uk","appstore-discounts.com","arbitrarydecisions.com","automobile-catalog.com","batterypoweronline.com","best4hack.blogspot.com","bestialitysextaboo.com","bicesteradvertiser.net","biggleswadetoday.co.uk","blackamateursnaked.com","blackpoolgazette.co.uk","borehamwoodtimes.co.uk","brunettedeepthroat.com","buxtonadvertiser.co.uk","canadianunderwriter.ca","canzoni-per-bambini.it","cartoonporncomics.info","caseyimpactstation.com","celebritymovieblog.com","chillicothegazette.com","clixwarez.blogspot.com","cloudorchestranova.com","comandotorrentshds.org","conceptoweb-studio.com","cosmonova-broadcast.tv","cotravinh.blogspot.com","cpopchanelofficial.com","currencyconverterx.com","currentrecruitment.com","dads-banging-teens.com","databasegdriveplayer.*","dewsburyreporter.co.uk","digitalbeautybabes.com","downloadfreecourse.com","drakorkita73.kita.rest","drop.carbikenation.com","dtupgames.blogspot.com","eastlothiancourier.com","ecommercewebsite.store","einewelteinezukunft.de","electriciansforums.net","elektrobike-online.com","elizabeth-mitchell.org","enciclopediaonline.com","eu-proxy.startpage.com","eurointegration.com.ua","exclusiveasianporn.com","exgirlfriendmarket.com","expatexplorer.hsbc.com","ezaudiobookforsoul.com","f150lightningforum.com","fantasticyoungporn.com","filmeserialeonline.org","freelancerartistry.com","freepic-downloader.com","freepik-downloader.com","ftlauderdalewebcam.com","games.besthealthmag.ca","games.heraldonline.com","games.islandpacket.com","games.journal-news.com","games.readersdigest.ca","garylargeavailable.com","gazetteandherald.co.uk","gdl.freegogpcgames.xyz","gewinnspiele-markt.com","gifhorner-rundschau.de","girlfriendsexphoto.com","golink.bloggerishyt.in","greatbritishlife.co.uk","hentai-cosplay-xxx.com","hentai-vl.blogspot.com","hiraethtranslation.com","hockeyfantasytools.com","hopsion-consulting.com","hotanimepornvideos.com","housethathankbuilt.com","hucknalldispatch.co.uk","illustratemagazine.com","imagetwist.netlify.app","incontri-in-italia.com","indianpornvideo.online","insidekstatesports.com","insidekstatesports.net","insidekstatesports.org","internetradio-horen.de","irasutoya.blogspot.com","islingtongazette.co.uk","jacquieetmicheltv2.net","jeepgladiatorforum.com","juegos.eleconomista.es","juneauharborwebcam.com","k-statewomenshoops.com","k-statewomenshoops.net","k-statewomenshoops.org","kenkou-maintenance.com","kristiesoundsimply.com","lagacetadesalamanca.es","lecourrier-du-soir.com","livefootballempire.com","living-magazines.co.uk","livingincebuforums.com","llanfairpwllgwyngy.com","lonestarconference.org","lowestoftjournal.co.uk","ludlowadvertiser.co.uk","m.bloggingguidance.com","marissasharecareer.com","marketedgeofficial.com","marketplace.nvidia.com","masterpctutoriales.com","megadrive-emulator.com","megankiddifference.com","meteoregioneabruzzo.it","metrowestdailynews.com","mini.surveyenquete.net","moneywar2.blogspot.com","muleriderathletics.com","nathanmichaelphoto.com","newbookmarkingsite.com","news-journalonline.com","nicolehappyoutside.com","nilopolisonline.com.br","northamptonchron.co.uk","northnorfolknews.co.uk","obutecodanet.ig.com.br","oeffnungszeitenbuch.de","onlinetechsamadhan.com","onlinevideoconverter.*","opiniones-empresas.com","oracleerpappsguide.com","originalindianporn.com","osint-info.netlify.app","paginadanoticia.com.br","palmbeachdailynews.com","philadelphiaeagles.com","pianetamountainbike.it","pittsburghpanthers.com","plagiarismdetector.net","play.discoveryplus.com","pontiacdailyleader.com","portstthomaswebcam.com","poweredbycovermore.com","praxis-jugendarbeit.de","principiaathletics.com","puzzles.standard.co.uk","puzzles.sunjournal.com","radioamericalatina.com","readingchronicle.co.uk","redlandsdailyfacts.com","repositoratacadao.cyou","republicain-lorrain.fr","rubyskitchenrecipes.uk","russkoevideoonline.com","salisburyjournal.co.uk","schwarzwaelder-bote.de","scorpio-horoscopes.com","sexyasianteenspics.com","smallpocketlibrary.com","smartfeecalculator.com","sms-receive-online.com","southendstandard.co.uk","stornowaygazette.co.uk","strangernervousql.shop","streamhentaimovies.com","stuttgarter-zeitung.de","supermarioemulator.com","tastefullyeclectic.com","tatacommunications.com","techieway.blogspot.com","teluguhitsandflops.com","thatballsouttahere.com","the-military-guide.com","thecartoonporntube.com","thehouseofportable.com","thewestonmercury.co.uk","tipsandtricksjapan.com","tipsandtrickskorea.com","totalsportek1000.com>>","turkishaudiocenter.com","tutoganga.blogspot.com","tvchoicemagazine.co.uk","unity3diy.blogspot.com","universityequality.com","wakefieldexpress.co.uk","watchdocumentaries.com","webcreator-journal.com","welsh-dictionary.ac.uk","westerntelegraph.co.uk","whitchurchherald.co.uk","xhamster-sexvideos.com","xn--algododoce-j5a.com","xn--gckdevd5myivf.site","youfiles.herokuapp.com","yourdesignmagazine.com","zeeebatch.blogspot.com","aachener-nachrichten.de","adblockeronstreamtape.*","ads-ti9ni4.blogspot.com","adultgamescollector.com","alejandrocenturyoil.com","allschoolboysecrets.com","andoveradvertiser.co.uk","aquarius-horoscopes.com","arcade.dailygazette.com","architecturaldigest.com","asianteenagefucking.com","auto-motor-und-sport.de","barranquillaestereo.com","battlecreekenquirer.com","bestbondagevideos.com>>","bestpuzzlesandgames.com","betterbuttchallenge.com","bikyonyu-bijo-zukan.com","brasilsimulatormods.com","bridgwatermercury.co.uk","buerstaedter-zeitung.de","burlingtonfreepress.com","c--ix-de.translate.goog","careersatcouncil.com.au","cloudapps.herokuapp.com","columbiadailyherald.com","coolsoft.altervista.org","creditcardgenerator.com","dameungrrr.videoid.baby","destinationsjourney.com","dokuo666.blog98.fc2.com","dumbartonreporter.co.uk","edgedeliverynetwork.com","elperiodicodearagon.com","encurtador.postazap.com","entertainment-focus.com","escortconrecensione.com","eservice.directauto.com","eskiceviri.blogspot.com","examiner-enterprise.com","exclusiveindianporn.com","fantasysports.yahoo.com","fightforthealliance.com","financeandinsurance.xyz","footballtransfer.com.ua","fourchette-et-bikini.fr","freefiremaxofficial.com","freemovies-download.com","freepornhdonlinegay.com","funeralmemorialnews.com","gamersdiscussionhub.com","games.mercedsunstar.com","games.pressdemocrat.com","games.sanluisobispo.com","games.star-telegram.com","gamingsearchjournal.com","giessener-allgemeine.de","greenocktelegraph.co.uk","hattiesburgamerican.com","heatherwholeinvolve.com","historyofroyalwomen.com","homeschoolgiveaways.com","ilgeniodellostreaming.*","india.mplandrecord.info","influencersgonewild.com","insidekstatesports.info","integral-calculator.com","investmentwatchblog.com","iptvdroid1.blogspot.com","jefferycontrolmodel.com","juegosdetiempolibre.org","julieseatsandtreats.com","keysbrasil.blogspot.com","keywestharborwebcam.com","knutsfordguardian.co.uk","kutubistan.blogspot.com","lancasterguardian.co.uk","lancewhosedifficult.com","lansingstatejournal.com","laurelberninteriors.com","legendaryrttextures.com","linklog.tiagorangel.com","lirik3satu.blogspot.com","loldewfwvwvwewefdw.cyou","matthewhotelscience.com","megaplayer.bokracdn.run","metamani.blog15.fc2.com","miltonfriedmancores.org","ministryofsolutions.com","mobile-tracker-free.com","mobileweb.bankmellat.ir","morrisvillemustangs.com","mountainbike-magazin.de","movielinkbdofficial.com","mrfreemium.blogspot.com","myhomebook-magazine.com","naumburger-tageblatt.de","newlifefuneralhomes.com","news-und-nachrichten.de","northdevongazette.co.uk","northwalespioneer.co.uk","northwichguardian.co.uk","nudeblackgirlfriend.com","nutraceuticalsworld.com","onlinesoccermanager.com","osteusfilmestuga.online","pamelachangemission.com","pandajogosgratis.com.br","paradehomeandgarden.com","patriotathleticfund.com","pcoptimizedsettings.com","pepperlivestream.online","peterboroughtoday.co.uk","phonenumber-lookup.info","player.bestrapeporn.com","player.smashystream.com","player.tormalayalamhd.*","player.xxxbestsites.com","portaldosreceptores.org","portcanaveralwebcam.com","portstmaartenwebcam.com","poughkeepsiejournal.com","pramejarab.blogspot.com","predominantlyorange.com","premierfantasytools.com","prepared-housewives.com","privateindianmovies.com","programmingeeksclub.com","publicopiniononline.com","puzzles.pressherald.com","rebeccacostthousand.com","rebeccapracticeloss.com","receive-sms-online.info","rppk13baru.blogspot.com","searchenginereports.net","seoul-station-druid.com","sexyteengirlfriends.net","sexywomeninlingerie.com","shannonpersonalcost.com","singlehoroskop-loewe.de","snowman-information.com","spacestation-online.com","sqlserveregitimleri.com","standard-freeholder.com","stevenspointjournal.com","stowmarketmercury.co.uk","streamtapeadblockuser.*","swindonadvertiser.co.uk","talentstareducation.com","teamupinternational.com","tech.pubghighdamage.com","the-voice-of-germany.de","thechroniclesofhome.com","thehappierhomemaker.com","theinternettaughtme.com","thescottishfarmer.co.uk","thisisoxfordshire.co.uk","tips97tech.blogspot.com","traderepublic.community","travelbook-magazine.com","tutorialesdecalidad.com","valuable.hatenablog.com","verteleseriesonline.com","watchseries.unblocked.*","wiesbadener-tagblatt.de","wiltsglosstandard.co.uk","wimbledonguardian.co.uk","windowsaplicaciones.com","xxxjapaneseporntube.com","yourlocalguardian.co.uk","youtube4kdownloader.com","zonamarela.blogspot.com","zone-telechargement.ing","zoomtventertainment.com","720pxmovies.blogspot.com","abendzeitung-muenchen.de","advertiserandtimes.co.uk","afilmyhouse.blogspot.com","altebwsneno.blogspot.com","anime4mega-descargas.net","aspirapolveremigliori.it","ate60vs7zcjhsjo5qgv8.com","atlantichockeyonline.com","aussenwirtschaftslupe.de","basingstokegazette.co.uk","bestialitysexanimals.com","boundlessnecromancer.com","broadbottomvillage.co.uk","businesssoftwarehere.com","canonprintersdrivers.com","cardboardtranslation.com","celebrityleakednudes.com","childrenslibrarylady.com","cimbusinessevents.com.au","cle0desktop.blogspot.com","cloudcomputingtopics.net","culture-informatique.net","cybertruckownersclub.com","democratandchronicle.com","dictionary.cambridge.org","dictionnaire-medical.net","dominican-republic.co.il","doncasterfreepress.co.uk","downloads.wegomovies.com","downloadtwittervideo.com","dsocker1234.blogspot.com","einrichtungsbeispiele.de","ellenpoliticalfollow.com","enfieldindependent.co.uk","fid-gesundheitswissen.de","freegrannypornmovies.com","freehdinterracialporn.in","ftlauderdalebeachcam.com","futbolenlatelevision.com","galaxytranslations10.com","gamershit.altervista.org","games.crosswordgiant.com","games.idahostatesman.com","games.thenewstribune.com","games.tri-cityherald.com","gcertificationcourse.com","gelnhaeuser-tageblatt.de","general-anzeiger-bonn.de","greenbaypressgazette.com","hampshirechronicle.co.uk","hentaianimedownloads.com","hilfen-de.translate.goog","hotmaturegirlfriends.com","inlovingmemoriesnews.com","inmatefindcalifornia.com","insurancebillpayment.net","intelligence-console.com","jacquieetmichelelite.com","jeanprofessorcentral.com","jennifereconomicgive.com","juegos.elnuevoherald.com","jumpmanclubbrasil.com.br","katherineschoolphone.com","lampertheimer-zeitung.de","largsandmillportnews.com","latribunadeautomocion.es","lauterbacher-anzeiger.de","lespassionsdechinouk.com","liveanimalporn.zooo.club","majorleaguepickleball.co","mansfieldnewsjournal.com","marshfieldnewsherald.com","mediapemersatubangsa.com","meine-anzeigenzeitung.de","mentalhealthcoaching.org","minecraft-serverlist.net","moalm-qudwa.blogspot.com","montgomeryadvertiser.com","multivideodownloader.com","my-code4you.blogspot.com","northantstelegraph.co.uk","northernirelandworld.com","northsomersettimes.co.uk","nutraingredients-usa.com","nyangames.altervista.org","oberhessische-zeitung.de","onlinetv.planetfools.com","personality-database.com","phenomenalityuniform.com","philly.arkadiumarena.com","photos-public-domain.com","play.mercadolivre.com.br","player.subespanolvip.com","polseksongs.blogspot.com","portevergladeswebcam.com","programasvirtualespc.net","puzzles.centralmaine.com","quelleestladifference.fr","reddit-soccerstreams.com","redditchadvertiser.co.uk","renierassociatigroup.com","riprendiamocicatania.com","roadrunnersathletics.com","robertordercharacter.com","sandiegouniontribune.com","senaleszdhd.blogspot.com","shoppinglys.blogspot.com","smotret-porno-onlain.com","softdroid4u.blogspot.com","southwalesguardian.co.uk","stream.googleapiscdn.com","teresapoliticallearn.com","the-crossword-solver.com","thebharatexpressnews.com","thedesigninspiration.com","therelaxedhomeschool.com","thescarboroughnews.co.uk","thunderousintentions.com","tirumalatirupatiyatra.in","tivysideadvertiser.co.uk","tricountyindependent.com","tubeinterracial-porn.com","unityassetcollection.com","upscaler.stockphotos.com","ustreasuryyieldcurve.com","verpeliculasporno.gratis","virginmediatelevision.ie","wandsworthguardian.co.uk","warringtonguardian.co.uk","watchdoctorwhoonline.com","watchtrailerparkboys.com","wharfedaleobserver.co.uk","workproductivityinfo.com","actionviewphotography.com","arabic-robot.blogspot.com","blog.receivefreesms.co.uk","braunschweiger-zeitung.de","bucyrustelegraphforum.com","burlingtoncountytimes.com","businessnamegenerator.com","caroloportunidades.com.br","christopheruntilpoint.com","constructionplacement.org","convert-case.softbaba.com","cooldns-de.translate.goog","ctrmarketingsolutions.com","depo-program.blogspot.com","derivative-calculator.net","devere-group-hongkong.com","devoloperxda.blogspot.com","dictionnaire.lerobert.com","everydayhomeandgarden.com","fantasyfootballgeek.co.uk","fifties-beat.blogspot.com","fitnesshealtharticles.com","footballleagueworld.co.uk","fotografareindigitale.com","freeserverhostingweb.club","freewatchserialonline.com","game-kentang.blogspot.com","games.daytondailynews.com","games.gameshownetwork.com","games.lancasteronline.com","games.ledger-enquirer.com","games.moviestvnetwork.com","games.theportugalnews.com","gloucestershirelive.co.uk","harrogateadvertiser.co.uk","koume-in-huistenbosch.net","krankheiten-simulieren.de","lancashiretelegraph.co.uk","lancastereaglegazette.com","latribunadelpaisvasco.com","mega-hentai2.blogspot.com","messengernewspapers.co.uk","monte-carlo-lab.pages.dev","northwaleschronicle.co.uk","nutraingredients-asia.com","oeffentlicher-dienst.info","oneessentialcommunity.com","onepiece-manga-online.net","passionatecarbloggers.com","percentagecalculator.guru","peterboroughmatters.co.uk","pickleballteamleagues.com","pickleballtournaments.com","portclintonnewsherald.com","printedelectronicsnow.com","programmiedovetrovarli.it","projetomotog.blogspot.com","puzzles.independent.co.uk","realcanadiansuperstore.ca","receitasoncaseiras.online","rotherhamadvertiser.co.uk","sataniabatch.blogspot.com","schooltravelorganiser.com","scripcheck.great-site.net","searchmovie.wp.xdomain.jp","sentinelandenterprise.com","seogroup.bookmarking.info","silverpetticoatreview.com","softwaresolutionshere.com","sofwaremania.blogspot.com","storage.googleapiscdn.com","telenovelas-turcas.com.es","thebeginningaftertheend.*","thesouthernreporter.co.uk","transparentcalifornia.com","truesteamachievements.com","tucsitupdate.blogspot.com","ultimateninjablazingx.com","usahealthandlifestyle.com","vercanalesdominicanos.com","vintage-erotica-forum.com","whatisareverseauction.com","xn--k9ja7fb0161b5jtgfm.jp","youtubemp3donusturucu.net","yusepjaelani.blogspot.com","a-b-f-dd-aa-bb-cctwd3a.fun","a-b-f-dd-aa-bb-ccyh5my.fun","arena.gamesforthebrain.com","audiobookexchangeplace.com","avengerinator.blogspot.com","barefeetonthedashboard.com","barryanddistrictnews.co.uk","basseqwevewcewcewecwcw.xyz","bezpolitickekorektnosti.cz","bibliotecahermetica.com.br","bromsgroveadvertiser.co.uk","change-ta-vie-coaching.com","chelmsfordweeklynews.co.uk","collegefootballplayoff.com","cornerstoneconfessions.com","cotannualconference.org.uk","cuatrolatastv.blogspot.com","dinheirocursosdownload.com","downloads.sayrodigital.net","eastlondonadvertiser.co.uk","elperiodicoextremadura.com","eppingforestguardian.co.uk","flashplayer.fullstacks.net","former-railroad-worker.com","frankfurter-wochenblatt.de","funnymadworld.blogspot.com","games.bellinghamherald.com","games.everythingzoomer.com","greatyarmouthmercury.co.uk","helmstedter-nachrichten.de","html5.gamedistribution.com","interestingengineering.com","investigationdiscovery.com","istanbulescortnetworks.com","jilliandescribecompany.com","johnwardflighttraining.com","kidderminstershuttle.co.uk","mailtool-de.translate.goog","motive213link.blogspot.com","musicbusinessworldwide.com","noticias.gospelmais.com.br","nutraingredients-latam.com","photoshopvideotutorial.com","puzzles.bestforpuzzles.com","recetas.arrozconleche.info","redditsoccerstreams.name>>","ripleyfieldworktracker.com","riverdesdelatribuna.com.ar","sagittarius-horoscopes.com","skillmineopportunities.com","stroudnewsandjournal.co.uk","stuttgarter-nachrichten.de","sulocale.sulopachinews.com","thelastgamestandingexp.com","thetelegraphandargus.co.uk","tiendaenlinea.claro.com.ni","todoseriales1.blogspot.com","tokoasrimotedanpayet.my.id","tralhasvarias.blogspot.com","video-to-mp3-converter.com","watchimpracticaljokers.com","whowantstuffs.blogspot.com","windowcleaningforums.co.uk","wisconsinrapidstribune.com","wolfenbuetteler-zeitung.de","wolfsburger-nachrichten.de","yorkshireeveningpost.co.uk","buckscountycouriertimes.com","celestialtributesonline.com","chardandilminsternews.co.uk","charlottepilgrimagetour.com","choose.kaiserpermanente.org","cloud-computing-central.com","cointiply.arkadiumarena.com","constructionmethodology.com","cool--web-de.translate.goog","denbighshirefreepress.co.uk","domainregistrationtips.info","download.kingtecnologia.com","dramakrsubindo.blogspot.com","elperiodicomediterraneo.com","embed.nextgencloudtools.com","evlenmekisteyenbayanlar.net","flash-firmware.blogspot.com","games.myrtlebeachonline.com","ge-map-overlays.appspot.com","happypenguin.altervista.org","helensburghadvertiser.co.uk","iphonechecker.herokuapp.com","kathyinformationwhether.com","leightonbuzzardonline.co.uk","littlepandatranslations.com","lurdchinexgist.blogspot.com","newssokuhou666.blog.fc2.com","northumberlandgazette.co.uk","parametric-architecture.com","pasatiemposparaimprimir.com","practicalpainmanagement.com","puzzles.crosswordsolver.org","redcarpet-fashionawards.com","redhillandreigatelife.co.uk","richardquestionbuilding.com","runcornandwidnesworld.co.uk","rupertisdivingintoocean.com","saffronwaldenreporter.co.uk","somersetcountygazette.co.uk","sztucznainteligencjablog.pl","thewestmorlandgazette.co.uk","timesofindia.indiatimes.com","watchfootballhighlights.com","watchmalcolminthemiddle.com","watchonlyfoolsandhorses.com","your-local-pest-control.com","zanesvilletimesrecorder.com","barkinganddagenhampost.co.uk","centrocommercialevulcano.com","conoscereilrischioclinico.it","correction-livre-scolaire.fr","economictimes.indiatimes.com","emperorscan.mundoalterno.org","games.springfieldnewssun.com","gps--cache-de.translate.goog","imagenesderopaparaperros.com","lizs-early-learning-spot.com","locurainformaticadigital.com","michiganrugcleaning.cleaning","mimaletamusical.blogspot.com","net--tools-de.translate.goog","net--tours-de.translate.goog","pekalongan-cits.blogspot.com","publicrecords.netronline.com","skibiditoilet.yourmom.eu.org","springfieldspringfield.co.uk","teachersguidetn.blogspot.com","tekken8combo.kagewebsite.com","theeminenceinshadowmanga.com","uptodatefinishconference.com","watchonlinemovies.vercel.app","wattonandswaffhamtimes.co.uk","www-daftarharga.blogspot.com","xn--90afacv0cu2a3cr.xn--p1ai","youkaiwatch2345.blog.fc2.com","bayaningfilipino.blogspot.com","beautypageants.indiatimes.com","becclesandbungayjournal.co.uk","braintreeandwithamtimes.co.uk","counterstrike-hack.leforum.eu","dev-dark-blog.pantheonsite.io","dumfriesandgallowaylife.co.uk","educationtips213.blogspot.com","fun--seiten-de.translate.goog","hortonanderfarom.blogspot.com","jeremyparticipantanything.com","panlasangpinoymeatrecipes.com","pharmaceutical-technology.com","play.virginmediatelevision.ie","pressurewasherpumpdiagram.com","thefreedommatrix.blogspot.com","thetfordandbrandontimes.co.uk","thetottenhamindependent.co.uk","walkthrough-indo.blogspot.com","web--spiele-de.translate.goog","wojtekczytawh40k.blogspot.com","bordercountiesadvertizer.co.uk","caq21harderv991gpluralplay.xyz","clactonandfrintongazette.co.uk","comousarzararadio.blogspot.com","coolsoftware-de.translate.goog","hipsteralcolico.altervista.org","kryptografie-de.translate.goog","maldonandburnhamstandard.co.uk","mp3songsdownloadf.blogspot.com","noicetranslations.blogspot.com","oxfordlearnersdictionaries.com","pengantartidurkuh.blogspot.com","photo--alben-de.translate.goog","readgraphicnovels.blogspot.com","rheinische-anzeigenblaetter.de","thelibrarydigital.blogspot.com","touhoudougamatome.blog.fc2.com","watchcalifornicationonline.com","wwwfotografgotlin.blogspot.com","bitcoinminingforex.blogspot.com","cool--domains-de.translate.goog","ibecamethewifeofthemalelead.com","pickcrackpasswords.blogspot.com","posturecorrectorshop-online.com","safeframe.googlesyndication.com","sozialversicherung-kompetent.de","utilidades.ecuadjsradiocorp.com","xn--90afacv0clj6ac0dxa.xn--p1ai","akihabarahitorigurasiseikatu.com","darlingtonandstocktontimes.co.uk","deletedspeedstreams.blogspot.com","freesoftpdfdownload.blogspot.com","games.games.newsgames.parade.com","insuranceloan.akbastiloantips.in","richmondandtwickenhamtimes.co.uk","situsberita2terbaru.blogspot.com","such--maschine-de.translate.goog","uptodatefinishconferenceroom.com","games.charlottegames.cnhinews.com","loadsamusicsarchives.blogspot.com","pythonmatplotlibtips.blogspot.com","ragnarokscanlation.opchapters.com","tw.xn--h9jepie9n6a5394exeq51z.com","hollywoodhinditracks2.blogspot.com","papagiovannipaoloii.altervista.org","softwareengineer-de.translate.goog","harwichandmanningtreestandard.co.uk","jyankuotakarakanteidan.blogspot.com","rojadirecta-tv-en-vivo.blogspot.com","thenightwithoutthedawn.blogspot.com","burnhamandhighbridgeweeklynews.co.uk","tenseishitaraslimedattaken-manga.com","wetter--vorhersage-de.translate.goog","wymondhamandattleboroughmercury.co.uk","marketing-business-revenus-internet.fr","hardware--entwicklung-de.translate.goog","xn--n8jwbyc5ezgnfpeyd3i0a3ow693bw65a.com","sharpen-free-design-generator.netlify.app","a-b-c-d-e-f9jeats0w5hf22jbbxcrpnq37qq6nbxjwypsy.fun","xn-----0b4asja7ccgu2b4b0gd0edbjm2jpa1b1e9zva7a0347s4da2797e8qri.xn--1ck2e1b"];
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
        const $scriptletArglistRefs$ = /* 13997 */ "1937;-1938;1858,1859;439;1041,1759;1757;148;1578;58;128;491,641;58,500;3038;391,500,516,806,1139,1140;170;1145,2197;1759;1317,2608,2609;58,516,840,3798;1760,2275;170;58,1510;170;170;170;2865;-59,-1938;3533,3534;60,422,527,535,2073;454,2809,2810;439,527;2029;1388;582,1761;170;3310;1067;2191;170,463,1875;148;552,1140,1207;959;170;170;170;-169,-2859,-2860,2865;170;-1938,3111,3112,3113,3114,3115,4018,4019,4020,4021;58;58,422,474,478,479,480,481,1759;500,1009,1010,1011,1012,1013,1014;170;3061;1041;422;1757;500,743;697;3325,3326;1759;1041;1961;58,422,500,1761;419;142,143;58,2473;1858;148;446;148,453;446,474,608,845;142,461;500,2014;2037,2038,2039,2040;232,762;1510;4026;1041;407;170;58;58,466,1041,1760,1907,1908;-1938;-1938;500,516,806,1233,1758;3705;58,527;1858;58,806,1234;58,410,422;652,743;170;419;986,1307;167,181,594,734,1858,1859;2842;-148,1383;170;58;60,1762;170,1858;439,446,500,551,806,1416;148;60,61,438;259,260;2568;3609;61;684,1782;60,684,3836,3837,3838;1578;1760,2275;1901,3659;1760,2275;1763,2964;446,472,473,1757;167;1181,3705;390,3955;170;706;453;391,527;58,1087;2327;3748;419;170;1958;142;142;170;1959;170;-148,1383;58,3868;170;58,500,1041,1590,1591;58,142,500,1577,1578,1579,1580;645;439,446,500;1760;422,439,679;58,474,1578;849;170;58;1962,1963;170;2967;500;170,1314,2681;170;58,59,60,61,1909;779;3968;170;1439;422,492,522;170;1306;1224;1578;1041;2191,2192;1761;2202;58,142,500,1577,1578,1579,1580;1318;2293;170;1167,1713;58,391,-392,422,803;58,108,1624;1041;170;2971;58,59,60,61;170,1091;594;58,840,856,2234,2751;170;180;1317;2307,2308,2309,2310;660;625;58,743,2621;58;58,466;3191;422,872;446;148;1510;948;3239;504;879;1145,1393;1869;1272;1761;58,439,500,596,640;1190,1228,1510,2734;493;2730,2731;645;447,1041,2828;58;829;1145,1474,1761,2349;58,3234;1637,2818;1832;1041;528;1860;1858;137;1858,1859;3638;1858;416,417,1858;466,467;-1938;645,675,1726;427;-1938;142,1838,1839,2529;2331,3153;170,387,1313;761,2533;446;3003,3004,3005,3006,3007,3008,4052,4055;461;160,2133;170;61,645;1858,1859;2207;1858;3293;2487;2498,2629,2699;1832;1418;58,466,1907,1908;58;-1938;433,647,865,866;1490;410;58,500,516,806,1233,1758;500,1231,1232,1759;3985;1543;428;1510;1759;3434;461,2558,2559;506,663;170,419;167,181,419,594,668;1289;446,549,1041,1578;170,1310;-148,1383;1719;58,1367,1758;1578;58,819,1758;645,1319,2463;1759;-148,1383;1379;-148,1383;609;1858,1859;422,439,550,679,894;1244;170;148;1839;1510;58,3202;1510;61,598,645;645;1879;1191;1191;1191;645;61;58,673,1296;618;468,1148;3319;1145,1686,2349;3325,3326,3681;326,327;501;422,501,527;3272,3273;2660;170;1578;170;2937;765,766;58,1510;500;3734;58,500;522,645,1227;900;645,1578,1726,1929;743;170;1510,1512,1513,1514;-1938,3642,3643;3864,3865;1578;1761;1041,1170,1171;170,1858;170;2151;142;1858,1859;58,879,1760,2233;1839;956,1758;170,1314,1708;736;2998,2999;58,840,2234;170;160,755,2191,2423,3015,3016,3017,3018;170;3532;1578;527;58,3868;58,1648;2655;209,210;172,173,2622;446,501,527,905;148;422,439,679;58;-455,-2810,-2811;58;58,456,527,629,679,761,801,816;3439;3631;1369;1832;58,941;170,832,1220;61;1510;565,1158;598;1832;1344;170;58;472;58,1041,1760,1772;527,1578,1760;170;2103,2104;527;1858,1859;58,468,1764,1926;1041;1578;209;131,1858;500,1758;1472,1473;1792;1858,1859;58,474,507,508,509;526;2975,2976;1758,1759,1760,1763;1858,2752;1858,2752;3183,3184;58,60,652,1167;58;832;108;58,1759;645;58,62,63,64,65,66,67,1041,1578;509;422,439,527,679;1760;58,552,1207;61,645,3627;552,1140;1079;146;1996,1997,1998,1999,2000,2001;1149,1150;1758;160,3318;1839;452;1959;1792;1760;856,2234;856,2234;72,73,170,1309,1316,1858,1859,2565;2373;441;427,1858,1859;663,1236;419,1832;542;3874,3875;58;58;170;148;1510;68,69;58,1041;2208;61;1578;1578;266,419;743,1760,1765,1916,3010;1510;1781;645,1740;1760;500,806;645,1633;1510;68,69;58,645;645,673,920;1858,1859,3531;3885;1578;1041;527,596,3207,3209;706;1792;491;1145;58,500;1100;415;3022;1170;1326;514,645;170;-1938;58;1393;170;170;684;61,167,645,2380,2381,2382,2383;1858,1859;1879;1228;1584,1599,1600;2581,2582;645;58,527,1761;1510;1510;170;419;75,-1938;58;645;419;170;1757;941,1123;58,645;549;1510;-1938;2889;61,645;1596,1646,1666,1689,1690,1691,1692,1693,1694,1695,1696,1697;1596,1646,1666,1689,1690,1691,1692,1693,1694,1695,1696,1697;1723;58;58,1792;500,1542,1543,1544,1545;2929;881;1760;1792;58,1792,1793;1761;2716;58,500,1145;1205;1839,3983;58,3830,3831,3832,3833,3834,3835,3874,3875;58,527,1758,1760;461,1821;1294;1828,3917,3918;1648,2896,2897,2898;1510;549;3277;170;3255;58,627;466;58,1578;58,62,63,65,66,67,1578;58;58,466,1041,1907,1908;522;1132;438,446,528;1294;3105;1858;1182,3705;1369;1510;127;60,1041;500;1757;58,1578,3230;684,1641,1642;58,456,652,743;527;2187;466,995;1759;170;500,743;3933;1041,1769;1757;387,429,1313,1703;3671,3672;887;461;711,1755;1760;58,1578,3230;1858;422,780;3933;1725;1578,3426;3085;446,2599;422;1041;1041;-148,1383;170,413,414,415,1306;1510;170;142;2250;58,1761;501,1758;415;522,598,1071;170;170;3333;3333;1510;1858;58;3078;1855;1802;982;427;908;3500,3501,3502,3503,3504,3505,3506,3507,3508,3509;474;58,468,1148,1788;516;645;481;-1953,1953,3982;58,439,601,624,625;485,624;485,624;58,627;1858,1859;390;2242,2243;645,2957;1757;1510;61;3976;645;58;-1938;1041;1760,2275;213;2408;58,1758;4051,4052;-1938;2674;2408;1858;2408;687;2408;2408;2408;644;58;1510;2408;68,69;68,69;1858,1859;1702;160,1992,4047;717,1858;170;148;446,500,806;58;-1938;450;767,768,769;650;1828;1543,2607;58,627;527;1792;4045;3859;58,2626;446,456,500,516,550;58,1920,1922;2813;1761;58,1970;2463;142,2529;2423,3015;-169,-2855,-2856,-2857,-2858,2865;58;474,1762;58;1758;68,69;500;1759;2808;142;684,3105;2236;58;2977;390,1453,1454;419;58;1759;446;3967;2818;1542;645;549;456,527,1062,1063,1064,1760,1761;-1938;1879;58,627;439,446,500,527,640,905;780;608,1804,1805;3079,3080;715,716,1760;58,1759;1027;170,1858;58,521;438,645;501;58;68,69;1516,1517;170;1761;422,439,1761;170;170;170;170;170;170;170;170;170;1809;641,684,1596,1646,1649,1654,1655,1656,1689,1690,1691,1692,1693,1694,1695,1696,1697;524;2818;2134;485;684,1596,1646,1650,1651,1652,1653,1689,1690,1691,1692,1693,1694,1695,1696,1697;645,1510,1720,1721;645;468;2498;652,743;652,743;652,673,743,2357;652,743;461;1771;453;1530;1123;1510;2767;484,1158,1159;1578;58,422,527,606,607,608,609,610,1757;549;148,1525,1526;1004;1832;3984;1858,1859;1022,1032,2508;1686,3855;170;1563;1858,1859;170;1100;170,419,1307;852,1479,1595,1596,1597;58,468,1764,1926;706;1369;500,806;1858,1859;61,466,565,598,645,2248,3540;1760;1759,1769;793;514;170;1244;1760,2275;527,983;58;58,500,527,806;1085;1444;1311,3258;1858,1859;3027;170;58;58;1759;61;1858,1859;-169;1789;1456;3427;81;1294;820,2714;58,500,806,1648;1128;1041;1578,1760;429;946;422;1759,1764;58,2234;1765;1758;58,1413,1795;453,2220,2221;1858,1859;58;474,1758;1762,1763;58,468,527,652,1041,1578,-1579,1758,1792,3151;1792;544,545;729,730,731,732;58;450,729,730,955,1578,1760;2520;2210;58,59,60,61,1909;167,181,1858,1859;410;2034;2034;58;160;58,1237,2528,2534;1142;1716;1758;1578;603,1218;213;527;58,565,598,1792,1939,2783;2049;1705;1855;733;170;1563,3158,3160,3161,3162;3682,3683;1510;500;1256;3943;2481;422,872;2767;58;68,69;989,990;645;645;645;58,743,1578,2621;98;-209,-1938;3774,3775,3776;1266;451,474,663;645;1758;2468;142,872;468,1578,1792;68,69;501,909;1510;179,3303;422,1045;500;500;58,1578,3230;264,265,2329,2330,2331,2332;1539;58;148,494,495,496,497,498,499,500;468;-1938;58,3321,3707;2339;450,479,549,1041;1578;68,69,1578;1762;68,69;1041;945,2244;167,936,942,943;528,662,663;3532;58,522;58,1759;484,511;1510;1413,1414;68,69;743,1041;68,69;598;58;58,1041,1578,2073,2134;1510;1041;1362;58;58,1759;700;3208;461;1801;136,3879;453,768,3194,3195,3196,3197;500,550,806,1761;-1938;58;58,439,500,1758;500,806;941,1548;2724;3723;446,534;1855;3996;419;1879;1858,1859;1578;1759;422;2278;625,976,1334,1578;684;61;2052;58,2616;684;58;684;1510;-1938;1758;3372;1578;2043;1459;3749;433;-1938;1768;450,1061,1759;3680;1760;148,1525,1527;2248;645;415,1383,1510;-1938;676;148;989,990;484,638;58,1578;1759;457,459;58,1200,1578;1757;1774;446,500;170;2056;1510;1510;551,1758;170;446,1026;1356;3174,3175;4048;170;2882,2883;68,69;791,915;461;3440;1079,1080,1081,1082;390,1801;58,2906;711,1001,3487;3445,3446;131,1858;-1938;1761;527;58,61,1578;1420;941,1548;645;1222;-1938;639,661;170,1091;679,1142,1757;500,743;941;-1938;58,142,500,1577,1578,1579,1580;1578,1760;1760;3532;170;738;806,954;500,806;1648,2896,2897;840;58,466,1041,1907,1908;58,466,1041,1907,1908;468;1510;946;3147;439;1758;170;58;1510;68,69;645;58,466,1041,1907,1908;58,466,1578,1907,1908;-2855;2941;1041;58;58,466,1578,1907,1908;1578;1858;1057,1328;58;409;58;1510;645;2528;60,1823,1824;391,644;684;1839;1808;446,641,784;148;1041;1770;170,429;58,1041,2648,3228,3229;1742;1041;1041;1578;452;3174;514;638,2614,2615;645;1758;142,3547;419;500,1517,1542,1543,1544,1545;1954;452;58,1578,2695,3230;645;2399;502;645;1041,1760;58;-1938;1139;605;429;645;1578;873,874,1578;58,1596,1638,1689,1690,1691,1692,1693,1694,1695,1696,1697;1759;755;58,1041,2648,3228,3229;1578;1758;1792;1510;1759;1762;2207;58,59,743,1760,3165;500;2569;275,276;2303;513,1832;2474;1578,1720;533,645;2162,2163;485,601,625,645;1510;438,446,528;58;1510;1510;663;565,598,645;565,598,1935;1858,1859;3998;1761;3085;451,454,820,1740,3709;1578;-1938;1789,1791;1510;1760;3544;1291;1510;1759,1760;3623;3623,3756,3757;58;484,645;58;1765;1294;1578,3454,3455,3456,3457;500,1483;-169,-2855;1510;970,971;68,69;1510;3511,3512;934;1510;142;58,485,645;1578,1761;731;58,743,1041,1578;2919,2920;1758;941;58,1041,2648,3228,3229;645;1760;1510;1578;635;61,391,446,1724;68,69;1578;1578;170;1510;1432;1759;1244;1145;645;58,1760;1030;2333;861;58;1510;1319;859;482;1759;2374;501;58,439,601,625,626;58,439,520,528,624,626,857;58,439,601,624,625,626,627;2269,2270,3989;58,439,601,624,625;1804;170;829;1291;433;3072,3073;2350,2351,3076;452;58;1758;170;645;598,645,1510;645,1289,1388;2639;61,598;61,627;645;61,598;3676;61,1802;645;3871;598;527;645;58,1758;-171;-171;452;1792;1510;1228;58,995,1097,1648,3178;58,1758;650;1760,2275;1760,2275;170,236,387,1704;3961,3962;58,652,1041;645,1726;61,645,1760,2248;1041;645,1510,1970,3241;1970,3719;68,69;58;68,69;170;1031;711;1858;410;500;501;514,645;58,527;1510;767,768,769;3553,3554;446;1868;-1938;1758;1832;1256;2479;139,140,142,143;1110;58,1578;422,742,743,856;102,103,104,105,3807;1858;1259;422,3205;645;1078;1578,1720;1287;58,60,456,652,743,1167;2676,2677;415;1510;58,994,1761;170,463;170;58;627,2441,2442,2443,2444;1578;81;58,598,673,916,1943;500,806;1179;58,1921,1922;422,1759;1759;1041,1578,3388;419;829;257,258;1510;645;433;439;674;1758;58;58,525;645;3060;1510;2694;1855,2127;170,1109;1148,3610;652;61,606,3224;1760;1510;170;645;1041;3560;1759;1510;4031;142;1578;2248,2528;1959;58,3707;58;2910;1510;2049;1832;1761;1944,1950;1510;419,1858;549;58,422,1208,1759;1510;1294;451,514,645;58;1510;2410;3825,3826;500,1041,1563;1855;645;2097;1828;170,670,986;58,1142,1763;1510;170;1291;58;1855,1858;645;1578;1974,-3538,3538,3539;1858,1859;58,1758,1759,1760;1510;61;645;645;58;514,645;509,792,1176,1177,1178;446;58;625;645;58;290;170;-1938;439;1858,1859;1282;58;1510;2416;2881;645;500;1258;852;170;3645;58,2015;1762;3084;652,1532,3651,3655,3656;58,509,792;1719;58,501;598;562;2259;1609,1610,1611;374;3453;3329,3330;390;3550,3551,3552;2041;58,1539;500,806;170;1760;1761;1726;2328;1858;3122,3123;1041;652,743;652,743;849;415,645,899;159;3633;3166,3167,3168,3169,3170;1759;500,743;645;645;58,3676,3677,3678,3679;1510;1759;1858;1510;2818;58,527,806,1234,1757;684,2522,2804,2805;1133;500,806,1588;446,595;1510;596;1578;702,703,704;1765;528,553,1225;832;1766;1578;170,388;58,142,500,1577,1578,1579,1580;875;461;2872;852,1479,1595,1596,1597;281,1616,1617;58;58,1578,3563;58,1578;58,468,1764,1926,1927,1928;4036;391;3851;1020;61;1098,2067;170;1758,1759,1760;422,596;1007;598;1484;989,990;1503;500,1683;1294;2237;1406;1190;553,554,2312;2033;58,3009;-148,1383;1829;58,1041;61,645,2173;58,148,608,1759;645;422,450;516;1515,1516,1517;68,69;254,255;1749;645;684,3359,3360;1319;1038;170;1388;466,625,645;-1938;81;989,990;58;1510;1233;511,1050,1051;1427;645;170;1765;684,1919,3880;1761;1880;1397;466,645;1244,1714,1715;1758,1765;2335;447;618,1757;-203;1510;446,592;58,608;58;68,69;1761;2668;975;429,432;58;58,61,98,1578,3819;58,61,98,1578,3819;1758;684,755,1686;58,61,466,1578,1907,1908;58,60,456,652,743,819,1167;1720,1792;2203,2204,2205;3931,3932;3494;1578;170;-1938;446,500,806,807,808;58,1578,2656;500;58,882;1510;453;481,730,1148;500,872;1792;58;1339;-1414,-1415;1292;2979;4017;1801;58;1041,1146;1510;1308;1758;58;850,1517,1519,1520,1523;3492,3493;142;452,2273;1510;1510;-2861,-2862,-2863;61,1719;466,625;3464;2767;3893;514,528,1260;485;68,69;859;446;645;684,1735;663,1236;3166,3167,3168,3169,3170;1761;968;58,451;2307,2308,2309,2310;1510;625;645;645;58;-1938;58;1758;1867;1496,1510,1594;1761;3495;58,840,2234;509;1760;58;941;1758;1041;1295;1839;2386;2885,3980;3979;1578;652;1916;500,1596,1647,1648,1689,1690,1691,1692,1693,1694,1695,1696,1697;584;652;1760;60;58,819,1321;1041;287,288,1644,1968;58,1699,1801;556;2492;2145;1758,1760;1761;58;743,1761,2411;58,1041;1510;1510;596,1760;1823,1824;1510;1040;1041;1578,1607;170;391;1001;645;584;58,3707;829,2164;1759;1041,1578;451,485,601;645;58;3737;58,1578;509;1578;461;1041,1759;170;58;522,1759,2134;58,3428;1180;453,768,3194,3195,3196,3197;58,2725,2726;461,500,598,645,1041,1578,2070,3192,3193;1361;3773;743;1758;58,466,1578,1907,1908;58;3867;361,362;1510;820;61;1510;58,1759;2612;651,1578;422;1759;1758;58,598,1578;1578,3454,3455,3456,3457;1041;2468;1510;790,791;1578;598;170;60,484,501,514,608,858;415,2401;461,1465,2592;1759,1760;474,1771;4048;4048;4048;4048;4048;4048;645,1789;170;2596;989,990;755;598,645;1761;1041;456,1064,1760;450;3047,3048;1578;3676;1510;645;1510;1724,3823,3824;501;2347;1759;61,58;3261;2664;1018;500;645;3940;1510;525;522,1762,2134;1510;58;978,979;58,1413,1795;645;1294;1556;1228,1510;645;1959;3799;2548;58,485,645;61;1510,1823,1824;1808;1510;453,1858;549;1760;474;142,461,2694,3384;1858;509;1832;1510;663,916,1001,1082,1236,1747;553;663,916,918,1001,1082,1236,1747;501;131,1858;986;1858,1859;1510;170;1869;1148,3610;581,582,583,1761;1007;645;1823,1824;1858;3532;-1938;58,679;142,2938,3103,3104,3105,3106,3107,3108;755,1686;3887;723;1162;2700;-1938;1001,2417;829;308;1510;2826;461,1821;170;1369,1510;-1938;1510;1256;1760,2459;3730;1758;439;645;1179;2478;645;58;501,782,783,1761;500,1542,1543,1544,1545;500,1542,1543,1544,1545;431;58,466,1041,1907,1908;58;2799,2800,2801,2802;1510;447,859;58;645;170,1311;582,583,1761;1431;142;2818;755,3105;-59,-1579,-1778,-1779,-1780,-1938;142;1609,1610,1611;705;1858;391,802;806,1761;598;645;974;419;1760,1792;668;142;1142,1271;1686;2986;1765,2476;131,1858;1256;246,247,373;1759;3011;1087;1863;806;806,1356,1761;500;357;553,2285;644;645;3024;1760;1287;60;58,1413,1795;2700;3214,3215;1477;1759;446,527;514;2631;484;1359;1801;1510;500,1542,1543,1544,1545;500,1542,1543,1544,1545;170;450;1758,1759,1760,1761;527;390,684;2207;1761;1373;500;170;200,201,1858,1859,3795;58;549;60,61;645;82,1510,2788;-59,-60,-61,-62,-1910;1030;1759;1758,1759,1760,1761;582,583,1761;58,1277;1510;1269;1397;2835,2836;58;58,645,1030,1578,1760,2645,2646,2648,3230;58,60,645;684;61;-169,-2855;645;1041;1592;58,59,60,61,1909;1758;3120,-3122;1578;1041;1759;1763;58;170;1510;1858;-1938,2048;1719;3710;1041;1041;1578,3463;170;645;1761;170;3600;1294;3969;58;148,500,618;1106;1758;1758;3166,3167,3168,3169,3170;58,1235;1510;645;547,674,728;1145,1761,2197;603,2244;1484,1510;1510;170;1858;701;722;731;1817;58;58;1674;1759;1858;581,582,583,1761;3532;1145,2358;1686;1080;-1938;-1938;2606;1510;1510;3570;76,77,78,79,80,81;1858,1875;735;2216,2219;1041;820;2485;1294;1510;1832;1759;684;719;1758;1294;58,597,743,1041,1792;-59,-1149,-1579,-1938,-3726;1294;597;1294;1294;1294;1762;1510;422,785;3279,-3281;976;170;2818;170;58,2876,2877;3950;1934;1319;170;2710;645;1244;946;446,1041;503,504;60,1792;1041;1758;1858;1510;60,645;433;3092,3093;58,61;58;58;645;3251;1278;899;1578;1858;1761;1759,1760;509;645;1145;613,1490,1491;556;3866;3866;3866;1510;687;58,687,1698;3755;1762;1369;645;1510;1823,1824;731,3064;1719,1758;936;2241;608,1804,1805;61;608,1804,1805;2294;608,1804,1805;608,1804,1805;608,1804,1805;134;3564;58;684;1510;1510;2541,2542;2827;1945;1757;1817;2016;1855;1510;1510;1855;427;98;1166;1761;61;61,1802;652;645;645;645;1823,1824;645;3676;58;61,1802;645;58,60,61,3404,3405,3406;645,1510;3676;2343,2426,2427;645;61;689;652;645,1801;645,1389;645;645;61;565;501;645;645;61,598,779;3385;1827;1510;500;1759;1510;170;645;1510;1801;598;170;58;58;1759;2408;58;2408;2408;1256;645;58,645,1041,2648;1510;941,2098;1686;1760,2275;1760,2275;1760,2275;98,3920;447;1841;1034;1035;422;2408;1760,2275;2408;1607;170;888;1510;138;645;645;2408;1497,1498,-1500,1500;1510;230,231;1858;1832;598;1510,3463,3667,3668,3669;148;1758,1759;58;2211;1510;1954,3982;2701;501;1510;2643,2644;500,806,2300,2301;58;1761;1759;2715;1760;1858;1278;1758;422;1760,2699;1539;1510;1612;1294;58,2783;466;1726,1929;144,224;170;2028;468,742;170,986;3660;3722;345,346;61;61,598,1041,1760,2248;1758;1456;1294;2282;683;142;684;58,1578,3230;2818;1041;645;58;500,806,1296;1761;3166,3167,3168,3169,3170;1148,3610;684;1858;1858;3243;58;58,998;-1938;461,582,1170,1726,1738;58;1578;3490,3491;684;466;58,979,1917;2745,2746;706;2978;-2855;439,551;537;598,1007;58,2238;58;562;1041,1759;58,1041,1510,1578,2254,2788;58,1758;58,551;58;1761;512;439;58;1832;1041;58,433,1298;1368;501;1400;3785;684,1596,1689,1690,1691,1692,1693,1694,1695,1696,1697,3785;1792;2816;2757;1000;1855,1880;514,608;3729;415,1510;1966;1760;1758;1113;1761;1228,1291;1259;889,890,1858;852,1479,1595,1596,1597;1858;-1938;1578;1762;58;1350;419;922;1875;3608;927;58,629,679,761,801,816;1323;385,1709,1879;58,1578;1578;907;1510;1758,1759;2597,2598;170;1148,3610;61;1758;1510;645,1510;58;58,1429;1510,2505;-59;2820;170;645,1235;1510;2369;879,1759,2070;1763;1815;1636;427,2237,3988;61;934;1510;940;514;1170;58;2074,2075,2076,4024;461,1404,1510,1821;829;58;645;1823,1824;481;439;170;1761;1758,3065,3179;1369;1358;684;941,1548;1510;2818;1850,1851,1852,1853,1902;538;527;1510;2412;170;456,527,1062,1063,1064,1760,1761;170;1543;466,625;1858;1858;1761;645;608,1804,1805;556,638,645,761;829;1510;-440,-447,-501,-528,-641,-906;1863;1758;598;170;684;1832;2817;1858,1859;142;170,427;1791;1041;854;1543;61,598,1510;1510,1578;58,62,63,64,65,66,67,1041,1578;3347;1510,3058;-148,1383;58,598,645;501;608,711,1260;58,527;645;58,438,528,561,562;645;625;514;645,920,2325;58,862;3353,3354;1724;451,527,598,645;527,645;529,530;58,439,456,3516,3517,3518,3519,3520;58,439,456,3516,3517,3518,3519,3520;58,439;58,439,456,3516,3517,3518,3519,3520;58,439,456,3516,3517,3518,3519,3520;1850,1851,1852,1853,1902;58;58,439,456,3516,3517,3518,3519,3520;58,439,456,3516,3517,3518,3519,3520;58,439,456,3516,3517,3518,3519,3520;58,439,456,3516,3517,3518,3519,3520;622,1478;1570;652;58,743,2201;780;1839,1848;170,1543;3935;2865;1195;1510;1724;1479,1480,1481,1482;806;1444;2385;1855,2800;1340;3998;407,832,1842,1843,2959,3789,3790,3791;58,565,598,1792,2783;1540;427;598;-1938;1100,1510;645;1510;1182,3705;452;58;1041;1510;755;3674;455;3379;791;2630;1982;58,3676;1832;2818;645;437;61;1724;2119;58;1789;1041;452;1832;1202;1510;941,1548;1510;652,743;3475,3476,3477,3478,3479,3480,3481,3482;1858,1859,3727,3728;1138;452;1578;1759;1761;1228,1291;438;2708;645;1001,1356;1418;598;645;645;645,2941;2305;58,148;58;1041,2080;2789;645;929;1850,1851,1852,1853,1902;446,456,500,806,1256,2188,2189;500,676;58,500,806,1068,1145;1510,1578,1672;422,446,500,516,613,806;500,806,1588;446,456,500;2282;485,1934;419;61,1727;1858;2315;500,806,1041,1598;822,823;461;3747;1578;1578,1758;1510;1801;438;1543;1510;1336;453;170;170;170;58;1762;2987,2988;415;3078;1578;1759;58,1167;977;461,1821;58,468,1041,1926,1927,1928;58,652,743,2356;58,468,1764,1926,1927,1928;1510;-1938;1532,1533,1534,1535;2291;1850,1851,1852,1853,1902;170;1297,2071;3306,3307;61;1832;910;-169,-2855;1484;926;58,433,869;1393;2165;501,645;1294;2321;1578;58,951,1763;422,679;1510;645;1758,1759,1760;731,3065;-1938;2702;1832;2673;684,3358,3360;1510;1156;631;422,450;474;446,451,528;584;2384;923;3689;391,802;514,675;711;1563;446;1644;-1938,2418;3180;61;450;1291;58,148;1510,2821;2818;427,1858,1859;2391,2392;170,386,1313;514,601;1783;1759;3616;514;164;216,217,218,219,220;391,645,674,1759;1041;623,709;1578;142;1792;500,1542,1545,1546,1547;645;1765;58,1069,1757;58,613,2454;514;2093;61,1542,1578,1775;645;874,1759;621,1760;148,472;58,1758;58,474,2393;1041,1578;156;1510;1578;3978;58,1041;1765;1041;1765;1578;1832;1041;1578;500,1492;1578;446,500,806,1758;1672;1112;1916;1765;684,755,1686;58,501,551,596,652,706,856;1758;1758;755,872,3762;3338,3339,3340;1145,1294,1417;58,3620,3621,3622,3623,3624;652;1761;58,391,1757;58,466,1578,1907,1908;58,1578;684,2670;500;468,730,955,1760,1789;1809;955;58;527,3494;755;58,515;2645;-1938;3676;58,466,1578,1907,1908;58;706;58,2005;1372;1578;446,1759;161;1578;142,2981;1758;170;1170,3077;755,2423,3015,3016;390,1634;2477;469;3311;58;1759;1789;58,481;3862,3863;170,1858;58,1578;3714,3715,3716,3717;565;556;438,625;148,756;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;2758;538;3746;989,990;58,597,665,1758;645;645;58,1510;3928;466;501;645;58;645;645;61,501;501;996,2180;645;472;2941;989,990;2839;645;2641;645;446,1760;58;2818;501,1578,1760;446,1760;410,758,759;1510;1761;1759;58,1578,3230;456,645,1761,2145;514;684;1759;450;1294;1578;1226;645;58,1041,2648,3228,3229;58,994,995;1543;134,280;1041;1792;708,820,1596,1689,1690,1691,1692,1693,1694,1695,1696,1697,1761;645;527,1041;1760;1157;2909;1758;1041,1578;527,819;446,1041;1294;645,1801;58,879;319;61;1041;1758;929;228,3413,3414;598;1510;58;645;1465;1503;1510;170;598,645;1070,1757;1510;676;58;58,645,689;1291;1041;1510;653;1760;1041;2198;645;1760,1803;160,321;58,3561;839;3700;61,565;1510;446,676;528,819;1510;549;415;706;1600;684,1596,1626,1646,1669,1689,1690,1691,1692,1693,1694,1695,1696,1697;1005;1510;706;1510;415,1383,2818;663,1236;1759;1858;886;674;58;652,743;58,59,60,61,1909;684;674;989,990;58;2026;1761;461;446,461,472,473,1758,2158;645;1578;1578,3454,3455,3456,3457,3459;3947;1760;148,1145;2318;652,1142;58,529,2767,2852;989,990;477;2125;1510;2052;1759;500,806;706;2316;706;629,679;1510;645;3873;1228;514;527;2818;1858,1859;1823,1824;1269;565;1761;1759;58,527,1578;61;685;1228;439,522,835;170;170,795,1858;-169,-2855,2865;142;170;2086;1510;1858,1859;1019;1291,1510;598;1510;1584,1599,1600;1455;2347,2348;1041;58;514;170;602;476;514;61;1510;645;645;1757;1759;1041;466,625,645;142;58;3532;1228;2359;58;461,719,1145,2495;461,1291,1510;58;598;58;645;1850,1851,1852,1853,1902;706;1761;899,1029,1228,1510,1520,1549,1550,1551,1552,1553;1858;1510;58;461,1228;645;3972,3973;1041;1802;1543;3265;755,1041,1596,1689,1690,1691,1692,1693,1694,1695,1696,1697,1772,2430,2431,2432,2433;645;598,3870;58;1765;170,1307;278,279;3854;706;850,1517,1518,1519,1521,1523,1524;142,461,2694;676;645,2514;170;170;1510;1759;468;142;1510;562,608,663,791,1225,2182;711;61,791;58,485,506,553,791,920,951,2182,3060,3788;945,1510;142,1839,2529;1758,1759,1760;1510;-1938,3843,3844,3845,3846,3847,3848,4043,4044;419,1705;848,849;968;1769;1640,3821;1987;1858,1859;142,4022;142;2185;2385;1761;1659,1685;684,1586,1684;3351;1510;1688;415;1066;1612,3571,3572,3573;446,645;2747;969;61,2936,2937,2938;596,1757;598;582,583,1761;2622;148,422,466,600;148,1527,1554,1555;3164;415;142,2682;1858;1041;1294;1294;1578;461,1319;58,500;446,500,806;500,1542,1543,1544,1545;58,500,527,600,806;1546;58,1578;58,422,527,745,2621;645,3698;61;3657;1510;1858;1510;3872;1592,1823,1824;-1938;439,753;2237;390;148;1139;1834;1475;2880;58;4006;142,500,2420;1520,1557,1558;667;516;1510;2742;1148;1510;72,73,1854;1510;3545;1510;705,794;439;491,618;1758;422;1761;2556;500,806;58,466,1041,1907,1908;3247;3857,3858;58,61,645;1792;1578;58,439,500;-3227;559;446;1520,3091;1047;148,458,460;868;598;-148,1383;170;1510;1863;415;1858,1859;746;2406,2407;1578;1578;58,645,2648;1041;1578,1993;58,588,589,590;2121;446,500;516;691,692;645;58;485,514;1397;645;410;895;58,433,527,528;3135,3136;1724,1736;410;500;1510;645;1510;68;-2855;2913,2914,2915;2450;645;2636;1578;433,2459;3078;1148;1578;1510;1858;1913,1914;1510,2129;1758;514;968,1596,1647,1649,1689,1690,1691,1692,1693,1694,1695,1696,1697;1663;1578,3454,3455,3456,3457;1776;58;1767,3473,3474;652;1041;1760,2642,2781;684;951;58;58;1007,1781,1782,2271;60,652;1041;58;58;58;58,979,1917;2056;81;3630;676;407;422;58,1543,3192;1578;1510;142;1578;1543;1832;793,1758;58;422;2775,2776;1510;446,1760;1723;461,1821,1822;989,990;1041;58;2051,2813;58,689;1041;755,1761,1789,2343;879;1510;641,879,1291,1596,1689,1690,1691,1692,1693,1694,1695,1696,1697,1782,2893,2894,2895;1578,3463;1904,1905;1825;170;170;1125;1858,1879;170;1858,2152;1393;556,916;645;221;1346;60;170;2865;98,3892;58,514,625;516,1758;3041,3042;170;1858;645;58;514;81;148,1525,1526;138;1858;3809;684,1585,1586,1587;58,1596,1646,1689,1690,1691,1692,1693,1694,1695,1696,1697;1762;1294;1294;1041;1294;1257;832;1294;1760;1294;1510;58,59,596,597,598,1760;1294;1294;1510;913,1496,1510,1594;1294;1578;58;645;1760;1510;598;1976;446,827;1510;484,524,645;3308;1510;2552;1294;527,1761;1881;3621,3827,3828;58;142,698,699,700;706;323,324;454,3709;170;648;1510;687,743;778;433,527,528;707;1758;645;484,510;1578;484,1158;2656;645;645;645;556;3034;1041,1578;1759;1792;1510;1510,1772;3020,3022,3023;1757;645;793;1510;645;1148,3610;598;58,61,645,3105;2585;485,951;142,2529;2785;645;645;645;58;58,2264;645;2942;1832;1578;3866;-59,-688;1294;58;1066;58,1760;1294;598;705;2903;1510;1294;1686,3669,3694,3695,3696,3697;1758;58,652;1510,3286;119;1465;148;58;608,1804,1805;528;608,1804,1805;608,1804,1805;608,1804,1805;58,439,624,625;484,485,486,487,488,489;608,1804,1805;645,1630;2087;2567,2773,2774;439,466,527,629,679,781;1858;1858;1804;1215;452;1858,1859;1758;446,1760;1067;1858;419;676;1758,1759,1760;3532;516;989,990;989,990;989,990;1041,2879;645;390,565,645;438,451;61,565;565,645,1510;645;645;599,1724;645;452,645;61,1724;652;61;61;645;645;645;645;61,1510;58;1510;415,2684;1142,1759;2266,2267,2268;138;1792;876;852,1479,1595,1596,1597;1510;2165;1300;645;1510;1510;1578;2203;1637;625;301,337;1510;645;1760,2275;1510,2126;1759;743;58,461,1758,1762;743,761;58;598,627;1758;826;170;598;2056;1510;1123,1338;446,447,1764;625;839;2408;1294;598;732;1170;1510;1879;427,1337;298;2184;415;2519;2621;1327;645;2064;131,1858;1510;2928;1757;-1938;170;1759;1041,1510;170;500;148,676;1578;446,500,546;447;446,1759;1758;1758;500,806,2206;1510;170;1145;516,743,1758,3760;1758;58,438;2813;466;1170;58,60,1296,1578,1726,1929;58,1578,1726,1792,1929;58;3227;2352;58;58;1138;1462;2850;61;703;1510;1858,1859;1899;1760,2940;61,1760,2248;645,1758;861;598;565;451,645;142;645;1764;652;1578;1758;2060;684,1578;2539;170;1334;987;58;170;1759;2831;4010;550,1759;1578;1100,1510;1294;1041,3243;1510;58;500,806;527,528,902;684,1596,1662,1689,1690,1691,1692,1693,1694,1695,1696,1697,3463;1758,1759,1760,1761;1510;58;645;98;1758;58;501;58,1041,2648,3228,3229;58;1259;1624;1041;3710;1578;58;1041;58;58,1760;58,527,1760;1761;58,1041,2788;1041;1760;1762;58,743,1041,1578;58;1761;1761;446,1760;1759;58,1041,1578;446,1761;-1938;1759;58,2448;1759;58;934;2229;1858;2346;170;991;645;3785;419;2334;58,454,2871;1041;645;58;1080,2461;1510;2207;596;645;991;1148,3610;1758,1759,1760,1761;1761;832;879;2968,2969;58;61;58;1874;61;-1938,3468,3469,4046;645,1823,1824;684;652;170,1865;839,2612,2924,2925,2926,2927;1430;3308;1757;1758,1759,1760,1761;58,3513,3514,3515;1758,1759,1760,1761;3033;1493;536;1510;1510;2323;527;527,645;-148,1383;1761;1116;61,1510;-1938;645;1294;58;61,1802;1399;1041;58;1041;58;594;1294;81,142;93,94,95,96,1578;422;148,1763;684,1919,3880;1510;2912;1447;285,286;2815;1348;58;467,1123;61;58,627;142,1531;3270;461,1821;1763;1930;3532;2237,3988;142;1510;706;170;1858;2146;1510;491,500,550,853;1994;419;3808;446,1760;58,456,527,629,679,680,1774;1291;2186;58,1041;500,806,1762,1763;645;3344;645;608,1804,1805;608,1804,1805;608,1804,1805;608,1804,1805;1979;645;2488,2489;527,780;1413,1414;1510;608,1804,1805;1804,1805,1806;1760;1041;2549;2549;2549,2550;3948;845;1758;58;1312,3853;1566;941;450,1760,2070;1823,1824;142,1839,2529;-148,1383;58,4016;58,645,689;645;645;645;645;1052;574,575;446,484,812,813;645;673;645;645;509;2772;645;58,451;645,1724;514,645;645;3599;501,645,911;600,711;645,959;645,941;528,3535;514,645;645;61,645;645;58,536,625,1189,1190;58,450,1759,1760;58;58;58;1858;58,684,3806;598,684,1758,3806;330;170;657,658,659;645;1510;3559;455,456,551,1041,1578,1757;645;1682;60;142,2510;522,2409;1858;1041;1858,1859;3532;1210;-1938;598;1759,1793,2363;61,1792;598;1510;170;1269;1858;1832;3401,3402;3118;438;58,3707;1719;1719;556,645;500;614;1763;58;1763;645;1418;2341;1510;170;959;1578;170;839,3066;1510;170;500;452;1758,1761;446,1760;1510;645;446;879;61,633,3451;61,633,1578,3451;170;645;148;-1938;1860;1985;942,1286;1510;170;631;461;468;1510;170;726,1510;58,433,1782;58;446;652,743;652,743;3024;142;1510;1858,1859;1097;1832;2528;313;415;645;446,1293;1095;61,3797;1510;594;2558,3138;58;1761;706;466;466,598;506,2652;501;1740;645;645;501;550,2258;645;1041;1495;1041;1123,3309;58,468,1041,1761,1928;61;446,500,527,1762;1510;1762;58,1016,1758;446,1760;446,1760;755;4014;58,514;2750;447;148;1510;3690;1406;3901;1510;549,820;439;2977,3000,3001,-3003;3341;58,3496,3497,3498,3999,4000;58,451;1324;832;170;2207;1760;491;1041;-1938;58,439,514,645;2567;3933;1041,1758;58,1759;2126;1041;422,603;1596,1689,1690,1691,1692,1693,1694,1695,1696,1697;58,439,456,536,608,1167,4027;58,1167,3793;58,468,1148,3610;1369;61,633,3451;1578;446,527;1578;1760;446,905;58,645,1041,2248;58;422,527;598,1578,3617,3618,3619;450,472,714;1930;645;1139;1724;1467;1510;1510;2385;452;1832;170,1706;645;1104;1942,2118;472;3248;613;2121;1085;3744;2653;1510;1858;1510;1273;1510;148;170;584;1016,1501,1502;1016,1501,1502;170;1404;1510;2237;1328;3532;138;1850,1851,1852,1853,1902;3035,3036,3037;1858;2520;506;645;645;3981;3981;1880,3116;1858;2491;-1952;3269;556,591;58;953;142;645,1760;1792;309;58;1510;755,2423,3015,3016;1510;743,2455;645;645;1510;2812;1100;1510;2818;500;1477;719;556;1934;1244;2265;1930,1931;1858;1198,1434;2373;1578;170;684,3242;1578;2197;2081;445;-59,-60,-61,-62,-1579,-1910,-1938,3111,3112,3113,3114,3115;1294;58;1758,1759,1760,1761;58;3312;2966;1294;450;1510;1543,3156;500,1542,1545,1546,1547;791,2519;58,390,1041,2057;1041,1587,1596,1689,1690,1691,1692,1693,1694,1695,1696,1697,1759;61;1002,2122,2201;1510;2396;60,446;1369;422,439,1161;1758,1759,1760;1294;811;1510;1832;58;58;58,1413,1795;1858;1164,1858,1859;389,4002;142;1761;1041;58,466;149;61,598;1762;1762;1759;407,1172,1173;58,98,3819;1758;1041,1761;3576,4007;58;58,907,1289,2415;466,625,645;61;142;3603,3604;481,684,1148,3408,3409,3410;527;3623,3624;1765;1757;1041;1792;1203;1041,1578;3462;3532;684;1821;2025;450,1578,1789;527,705;500;1759;58;1510;390,1369;322;1869;1041,1578,1792;527;148;58,596,679;1244;827,2054,2055;1230;2066;58,840;1127;1855;625,2364;1763;645;4037,4038;58,453,3536;500,2070,2744;1839;1510;170;684;1858;390;645;1145;516;2061;-169,-2855;1761;1880;170;1578;58;645;2627;1759;58,1510,3470;3483,3484,3485,3611;1858,1859;61;2019;645;1809;514,645;58;645;645,3216;2943;598,1934;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;920,1001,2983,3060;1757;645,3334,3335,3336,3337;2465;565;645;500,1331;474,599,608,1761;2560;58,3154;645;989,990;989,990;645,1510;58,1578;1759;3647;1510;58,422,527,1758,1760;1755,1756;1510;2428;743;1760;1510;391;446;20,-59,-1579,-1938;1578;58,3039;1759;2466,2467;1510;58;2767,2848;1596,1689,1690,1691,1692,1693,1694,1695,1696,1697;924;160;1879;438,627,1719;1758,1772;708;1792;1510;597,743,1762;58,71;992;58,1578;1510;1503;1510;1758;1761;1792;743,1758;732,993;596,2201;2408;1046;1760;1740;422,577,578;1760;1760;1740;58,71;58,71;1760;58,1578,3230;645;879;3408;645;58,1578;58;170;58,71;3665;474,1041;1041;58,479,1759;1578,1759;438;58,71;645;1510;529;1760,1911,1912,1913,1914;1393,1686;468;941,1548;946;-59,-60,-61,-62,-1910,-1938;1510;58;2207;58,71;58;1858;1792;170;1871,1872;684,1596,1626,1646,1669,1689,1690,1691,1692,1693,1694,1695,1696,1697;833;743,1148,3610;674;679,761,801,1142,1320,1719,1757;1510;390;3248;514,546,608,645;1578;438,446,485,502;1108;1832;553,2285,2605;1832;1510;1510;706;879;1858;3792;1578;61,1722;60;1759;58,3878;1759;1578;1510;1041;684;598;676;1510;419;61;58,468,1926,1928;1515,1516,1517;645;989,990;2678;2827;2591;3146;468;598;3094;684;1520,1557,1558;461,2505;396;1880;148,1906;500,872;2108;1858,1859;3666;61;1758;1858;500,1221;1510;1992,2136,2137,2138,2139,2140,2141;1510;1828;1850,1851,1852,1853,1902;1510;58,527,3378;1839;170;170;2818;1510;61;556,601;415;142,2529;2700;1510;1867;1510;2529;1758;1102;1444;2963;501;706;1294;1758;645;500,806;2865;645;58;1858;3082;422,-1947,1947;1466;852,1479,1595,1596,1597;58,500,645,1758;461,3543;850;2290;3565;2784;1879;415;407,1172,1173;645;687,1578,1648,3563;1761;1858,1875;598;2177;1291;3441;602;2209;1578;684;3637;1510;1786;1858,1859;1510;1294;1578;743,1758;1510;879;452;2958;829;58;58,1578,3230;58,1578,3230;58,1578,3230;1510;1858;1294;391,802;1858,1859;3486;920;915,916;711;506,553,920,3788;1148,3610;879,1397;1327;1542;1170;1510;58,1148,3610;1578;1858,1875;2161;645;2456;684;922;501;427;3185,3186;3532;-59,-1149,-1579,-1938,-3611;452;1858,1859;1858,1875;3142;99,100;1757;1724;584;1832;1030;2129;684;645;584;1510;1173;485,514;466,625;-1938;1510;1331,1541;516,818;1510;142,1228;142,1839,2529;2065;1622;1041;390;1041,1042;3997;2107,2108;58,500,806,1145,1761;1148,3610;2232;58;500,806;1510;61;58;1294;1510;645;170;1041;1393;1339;61,514;4013;446,527,968;631;1295;1041;941,1548;968,1657,1658,1659;61;514;422;1858,1859;138;1879;3062;618,619;565;1510;170;527,550,679;1034;501,514,645;686,687,2134;514;501;2984;645;1510;58,1760,2446;501,645;466,625,645;1832;1759;1041;667;142;58,1762;1578;58;2314;1022;645;58,466,1907,1908;941;644,645,1382;415,2555;2932;705,879,1174,1175,3356;1510;527;3247;1637;1148,3610;58,1612;645;1510;58,466,1041,1907,1908;340;1510;4035;500,879,1043;1510,2456;1041;1761;3086,3087;668;1573;1510;1762;645;1510;391,802;2256;684,1933;2002;1182,3705;3976;1510;1041;205,206,207;645;58,2612,2613;645;603;645;1041;456;160;1510;419,1256;429;429;429;429;1858,1859;58;500;468;422,446,645,806;2811;1858;500,1542,1543,1544,1545;1584,1599,1600;1510;941;422;-59,-60,-61,-62,-1910,-1938;174;1291;1534,1536,1537,1538;1858,1875;58;446,514;61;1759;2207;1792;652,2871;2675;565;170;446,711;1510;1645;1759;58,1578;454;58;2567;446,500,806;1700,1942,1943;1758;58,1563,1940,1941;148,3095,3096,3097,3098,3099;1761;58;1761;1760;1510;645;1762;170,1313;142;2618,3432,3433;1723;1760;1569,2366,2367,2368;160;1510;481;58;3235;1041;1041;524,1041;1496,1510,1594;829;142;452;879,2196;1041;58;899,2638;2712;142;170;514;976;1719;645;684,1523;1758;148;391,1457;1578;598;415;452;755;446,1760;717,1086;423;142,1838,1839,2529;1510,1542,2788;1904,1905;1352,1353;1759;1007;829;1591;452;1510;645,1236;645,1935;527,645;3998;1294;1817;61,645;594;1858;1451;2050;684,3238;645;834;1510;1510;2077,2078;1007;2720;1510;142;1578,3454,3455,3456,3457;1294;1760;1041;58,433,1761;1294;1294;598;466,625,645;1294;514,1242;514;1294;1170,3100;1510;684;645;2201;1294;160,3670;461;603;142;461,2908;1510;598;1055,1056;1054;556;645;1510;1510;594,1858,1859;-1938;289;1698;1041;1041;1760;1760,1765;1758;2173;2337;58;2767;2493;61,556,1719,3510;645;61;485,642;645;2587;2200;645;1759;1534,1536,1537,1538;58,71;627,645,1113;645;1481,1494;1672;1510;375;2670;1860;142,1256;989,990;645;-59,-688;1866,1873,2540;1792;2825;1510;3693;451;645;446,500,949,950;1719;1295;1510;649;2459;1148;1338;1444;2402,3148;68,69;484,485,486,487,488,489;485;608,1804,1805;608,1804,1805;608,1804,1805;391,439;483,484,485,486,487,488,489;645;608,1804,1805;608,1804,1805;608,1804,1805;608,1804,1805;608,1804,1805;608,1804,1805;518,519;608,1804,1805;520;1759;608,1804,1805;438,474,514;608,1804,1805;608,1804,1805;516;1955,1956;645;1832;1510;2196;449;58;644;461,1510,3125;599,2762,2763;1709;415;516;2459;3450;1041;1855;1510;3052;1192;1510;138;466,2399;645;1724;58,59,60,61,1909;61,598;58;652;61,598;3676;645;645;652;58;58;645;58;645;61,472,501,598,627,1477,1719;58;1832;514;926;58,71;160,755,3448;1100,1510;446,1041,1759,2900;2017;2818;3684,3685;1832;1221;645;170;2865;58;3676;645;926;2519;1760,2275;1510,1816;148,522,684,1369;531,761,1007,2070;2408;1760,2275;1510;466,625,645;686;422,1758;1264;1041,1760;1510;1832;1510;516;1093;1596,1689,1690,1691,1692,1693,1694,1695,1696,1697,2433;2680;1724;170;422,439,1757;645;1170;1782;1041;527;701,2252,2253,2254;1029;170;644;61,645;1510;1510;676,1555;598;407,1172,1173;446,556,1753;501,553,2285;645,1726,3488,3489;1510;755,2423,3015,3016;1858;1041;645;3909,3910,3911;2102;-1938;500;1393;446,500,1762;1510;1510;433,596;341,342;1160;170;148,522,684,1369,1587,1619,1620;58,485,645;3761;3761;1858;1593;2520,3418,3419;1041,1578;2126;1578;61,1578,1792;58;61;58,608,645,1409,1410,1724;741;563,564,565;1719;755;446,1760;1539;645;645,1758;684,3874,3875;565,1792;2623;61;854;1105,1762;58,61;2395;61,1760,2248;1758;58,451;549,1001;1607;1759;598,1760;1510,1826;645;1451;645,1369;501;1520,1557,1558,1559,1560,1561,1562;427;61;1758;1068;419;2584;410;514;527;1943;415;1789,1817;517;1041;58,899,1923;645;142,167,1675;2918;1510;645;708,744,1758;446,1758;2818;856;621,1041;1510;1858,1859;419;1369;452;645;439;1510;1925;598;645;185,186,3605,4004;160,1369,1724;1855;1510;527,644;58,71;1041,1792;466;598;598;1431;148;58,1760;170;422;1759;1510;668;1943,2338;61;645;645;1510;1037;1759;-148,1383;527;684,3429;61;1759;1041;1578;58;58;1578;645;1792;1578,1792;1758;60;527,652,1759;1780;58,1041;390,1761;466,625,645;142,1839,2529;466,625;676,780,847;1759;645;875;461;514,645;1510;1294;684;3015;1578;1097;1510;58;1485;466,645;676;3993,3994;466;1291;1503;58,1792;273,274;58;1858,1875;1949;390,3946;529;391;2484;3283,3284,3285;491,1074;1578,1759;1148;466;1510;170;1879;618;1510;2806;1294;1784;1832;1294;58,501;3922;644;1510;1510;527;527,645;1041;1041;1041;914;58,1578;645;652;461;645;645;61;2248,2721;1294;1858,1875;1294;170;2985;770;58,71;466;58,71;2074,2075,2076,4024;1393;1809;2425;4032;446,500,954;3898;633;466,625,645;879,2373,3356;645,856,2234,2639;1510;170;1802;-2855;645;1099;1758,1759,1760;1858;2054,3133,3134;981,1253;645;415;58;1089;1510;922;1758;1723;760;1832;4039;58,451;3532;1822;2865;1282;461,1821,2937;679;58;3532;58;1510;1858;474;3915;446,1124;598;598;1578;1142;522,680,1375,1376,1377;678,1774;419,1154;2059;645;1860;1130;2878;2593,2594;391,446,474,485,1724;608,1804,1805;608,1804,1805;2736;170;989,990;1724;598;433;1444;1294;608,1804,1805;608,1804,1805;1510;608,1804,1805;608,1804,1805;608,1804,1805;170;148;3886;2703;3171,3172;446,1760;1916;1758;2818;170;58,466,1907,1908;1190,1228,2734;446,1124;1510;1510;1761;625;-169,-2855;1138;151;2865;3232;1510;1755;514,645;645;645;645;1510;1269;446,1124;58,689;1724;989,990;438,446,645;1716;602,604;446,514;1170,2937;446;645,3732,3733;509;645;514,711;391,802;598;446,556,1753,2337;645;446,556,1753,2337;484;2450;645;1356;645;58,451;645;514;645;1041;461,500,1068,1510,1539;81;3521,3522,3523,3524;1510;1855;1510;3829;1280;419,1858,1859;170;1193;645;363;2651;1397;3275;446;439,1758;58;1758,1759;-1938;2865;1762;2089;1448;390;68,69;2581;3323;1510;684;1858,1859;1858,1859;1510;2528;1936;1510;527;1201;1875;1510;1448,2840,2841,2949;1510;170;433,446,645;652,902,3648,3649,3650,3651,3652,3653,3654;598;58,1578;1763;3056;500;3255;1510;856;452;438;1228;1294;1444;1898;1759;1041;988;1880;1139;170;1858;1145;170;879;645;543;3015;645;1578;3289;2518;1228,1510;941,2886,2887,2888;2114,2115;1510,1637;58;935;933;58,71;1858;3532;3377;1183;520;645;1355;527;1244;160,755,3579,3580,3581,3582,3583,3584;3144;1761;645;2460;645;1269;58,645;645;1294;2539;1510;58;603;598;1858,1859;501;500,1425;852,1479,1595,1596,1597;1510;451,485,601;1515,1516,1517;446,1760;446,1760;645;668;1510;58,3518;514,1269;2248;3403;4042;1294;879,1404,2759,2819;1007;58;1858,1875;58,527,1757;2456,2682,3127,3128,3129,3130;553,2285;549,820;58,1759;603;1510;3081;170;1510;1510;1858,1859;58;501;739;142,461,2788,2789,3547;142,167,415,461,1055,2786,2787,3547;1760,2459;684;2452;1760,3856;668;58,979,1917;3532;407,1172,1173;1510;58,3794;61,1792;1757;1759;422,468,1144,1145,1146,1147,1578;58;58,468,1041,1578,1764,1926,1927,1928;632,633,652;1578;1858;1724;1458;451,601,1719;446,1760;461,1592,1823,2475,2507;527;1858,1859;2543,2544,2545,2546;58;415;160;652;1440,1441;876;1041,1578;1256;419;1510;1228;598,645,743;3975;1858,1859;1520,1671,2768;1761;1759;1758;849;1055,1056,1057;1397;58,468,1578,1764,1926,1928;1758,1759,1760;1510;1489;1510;2062;1290;852,1479,1595,1596,1597;1510;170;1510;1299;1100,1510;58;2818;645;989,990;514;446,514;756;1179;1960;1832;58;461;1016,1501,1502;684,3343;1016,1501,1502;598;1510;1510;631;598;1863;1510;58,1578;58,610,1094;142,1838,1839,2529;98,3949;1077;1760,2275;1758;500,806,1588;138,237,238;58;3771;1510;452;2237;2408;1839;1431;1017;860;1612;2478;3802,3803;2961;-1938;645;248,249;989,990;1041;254,255,256;1930,1931;58,433,474,527,528;1510;1760,2275;142,2529;422,450,1299;645;645;61;3991,3992;1815;369;415;645;446,451;645;645;484,883;2767;625;674;446,466,528;58,979,1917;527;2096;58,439,549,1760,1772;2818;1809;1964;170;3817;1041;97,98;3970;446;68,69;1407;70;452;468;3925;3246;645,2282;1510;645;829;1858;142;58,1041,1578,1596,1689,1690,1691,1692,1693,1694,1695,1696,1697;61;987;1759;1759;3916;500,1488;1041,1578;1757;419,1832,1833;645;1510;170;1294;1510;3421;1294;1510;474,1759;1431;1510;1759,2292;652;2450;645;3430,3431;58,3620,3621,3622,3623,3624;1761;1792,3625;2648;1041;1534,1536,1537,1538;501,556;1510;645;1510;1510;1965;613,1490,1491;60;468,730,1041,1578;2042;-515;58,3923;2424;2004;1858;1759;391,446,506,617;2818;1041;466,625;598,1755;450;1578;1363;645;630;58;1858;903;1496,1510,1594;-1938;3578;957;1431;1858,1859;170;170,1855,1858,1878,3213;142;633;829;170;58;685;514,645,785;839,1007,2779,2780;1686;3966;1858,1859;1719,3399;645,1719;645;645;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;4053,4054;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;2871;562,645;451;58,645;58,3154;1269;527;501;466,625,645;61;58,485,645;58,451,663;58,451;1447;645;439;2527;1510;1740;509;438,556;1760;2629;562;1510;1510;1637;485;3038;438,1740,1751;58;422,446;1940;774,775;1761;1510;1041;58;1761;527,551,1196,1757;598;264,265,2329,2330,2331;1041;2574,2575;2575,2588;3408;1761;1759;1761;743,2261;1758;501,1759;1041;1607;1760;1760;1041;627,2144,2145,2445;1041;391,802;1840;598;1510;108,687;461;645;148,946;1510;1758;1510;684;58,1041;1858,1859;645;58;1041;1148,3610;58,148,516,1170;58;58,1041;167,1675;58;1607;1510;-169,2865;170;170;1294;802;58,1041,1926,1928;461,1821;58,468,1578,1926,1928;3881,3882,3883;1369;1510;3231;1576;1510;1510;796;422;989,990;1740;1291;2153;2425;706;2628;556,601,1252;1041;452,645;461;58;461;852;684,1578;446,1760;1578,3454,3455,3456,3457;645;1792;61;1758;1578,3454,3455,3456,3457;1578,3454,3455,3456,3457;58;3459;1578;58,59,60,61,1909;1510;645;1510;1578;1712;4048;61;-1938;2377,2683;598;170;1170;415;1592;58,1758;142,148;514;1855;2552;2117;1510;452;1219,2585;3632;1041;485;451,645;61,167,645,755,2380,2381,2382,2383;3612;391,802;1510;170;470;1021;1510;1445;719;1975;427;1543,3906;170;1858;1860;3139;2760,2761;170;1858,1859;1484;2632;1832;1758;1510;485;501;501;2222;1510;514,645;58;542;2226,2227;1510;419;170;1858,1859;1214;2036,3586,3587;1858,1859;1510;1041;142,500,879,2843;1510;1510;1510;-1938;415;645;1139;1041;946;1510;514,711,1747;1170;1041;1758;485;645,1228;452;645,1510;2769;2767;2086;3288;1404;2148,2149;1731;1731;1510;1789;1041,1789;1858;1858;645;452;645;1370;1719,2112;1492;917,918;915,916;58,485,791,951,2182;915,917;2023,2024;1832;1041;1148,3610;170;1348;1563;1291,1510;1855;1759;61,645;132,133;2966;407;1025;1510;4033;2429;1510;1818,3380;2320;1228;622;622,941;622,1145,1543;1510;1832;1510;1510;142,1007;1858,1870;1759;2295,2296;684,3822;1877;1041;3365;142;3244;3735,3736;1510;138;58,743,1028,1772;3676;684;1369;391,562,1251,1755,2011,2012,2013;438,514,1740;2511;2600;1510;701;1510;1510;422,606,1773;446,500,806,1030,1261;1736;1041;2539;2818;410;461;1161;467;1760;1269;2921;1858,1859;1510;1758,2360;446,1760;645;713;1269;1510;645,3699;3701;2767;1170;839,1517,1519,1522,1523,1604;993,1510;3290,3291;1858,1859;639;500,1542,1543,1544,1545;1823,1824;3934;1858,1859;58,1578;450,1041,1146,2699;785;849;1858;1369;422;3259;1596,1638,1639,1640,1689,1690,1691,1692,1693,1694,1695,1696,1697;1858;1294;1397;61,598;1760;645;170;645;163;1850,1851,1852,1853,1902;419;61,645,2571,2572;1510;829;1832;1148;61;645;514,1724;1510;1112;1879;1858,1859;58;1510;688,791;1510;1762;474,819;3711;549;1148;142;879,1810,2562,2563,2564;58,616;1341;2850;58,466,1578,1907,1908;2179;1578;645;1584,1599,1600;1510;58,1041;58,1398,1399;3252,3253;1510;58,879,1369,1578;1148;1510;1055,1056;598;1578;60,829,1578;461,1821;1299;1510;58,905;818;170;1858,1875;58;456;446,1760;461,1335;1510;1858;1048;1578;1760;58;1041;58;684,1930;652;1510;1294;1618;500,743;391,802;1510;1510;2580;515;170;645;1510;391,1743;485;1510;429,432;1858,1859;500,1542,1543,1544,1545;1287;170;1858,1859;527,673;170;1304,1305;684;58;516;1182,3705;1510;1148,3610;1760;58,652;645;466;58,439,618,1665;2818;603;58,2647,2648,3228,3229;1765;1880;1760;58;645;1578;-2855;1510;1510;98,1578;461,2271,2561;2502,2503;-169;516;1510;1269;468,1543;1170;58;1041;2022;1510;1510;1400;1444;281,284;1858;2803;-169,-2855,2865;1510;2558,2559;3068,3069;1724;1510;1510;446,1760;3702;1431,2404;472,645,1145;553,2285,2605;645;645,3346;2464;514;645;485;468,1148;142,1719;1041;1578;989,990;989,990;1596,1613,1614,1615,1689,1690,1691,1692,1693,1694,1695,1696,1697;598;58;58,484,536,1237,1238;170;516;170;2198;1578,2198;1832;1274,1275;418,1198;809;2845;1904,1905;1904,1905;1858,1859;446,1760;1496,1594,1671;875;1041;976;645;514,645;58;1510;1008;170;1255;603;1145;58,514;142,1821;598;170;645;1510;880;557;946;142;1631;1294;58,527,599;1759;1759;1294;58;427,1858,1859;1393;1792;1510;1832;1294;527;433,439,466,522,748,749,1719;701;645;645;244;676;2287;3877;1289,1858;1122;-169,-2855;1294;698,699,700;1294;514;1863;3383;500;1080;1041,1760;170;1858,1859;645;1760,2498;1758;1762;1765;645;419;1269;446;1510;2767;645;3876;3765;58,2830;3201;61,2974;989,990;565,598;645;1863;1745;1510;439,1760;3422;170;1041,1913,1914;1914;193,331,368;461,1366;1832;1759;1510;1510;1687;446,1760;466,565,1469;1041;58;1510;3952,3953,3954;645;1760;645;645;58,1581,1582;1510;645;674;142,1838,1839,2529;391,802;645;391,802;695;797;1041,1792;1832;1140,1913,1914;2159;656;1417;250,251,252;452;831;791;1041;391,802;786,787,788;3499;1761;1510;170;1444;58,1279;1279;608,1804,1805;608,1804,1805;625;608,1804,1805;608,1804,1805;608,1804,1805;608,1804,1805;483,484,485,486,487,488,489;608,1804,1805;3740;989,990;2967;427,1858,1859;1512;58,1761;461,3132;740;-1938,2679;1041,1578;1123,1198,1465;941,3800,3801;335;1629,2753;98,3770,3771,3772;2585;447,879;1510;1510;1041,1510;676;706;1145;500,806;989,990;645;684;58,1413,1795;645;645,2169;652;645;61,3938;645,2277;645,1801;645;60;652;1724;453,1145;3038;681;485;485;-1938;1481;415;556;1510;1100,1510;3894;2126;1497,1498,-1500,1500;1869;1759;522;1904,1905;485;1808;407;2818;3804,3805;1510;2240;1510;1510;1369;2027;148,453;687;58,610;1170,2497;1827;1858,1875;1510;501,598;1017;706;1510;58;1832;514;645;1510;2408;-169,1295,-2855;1858,1859;856;1510;1510;1002,1230;-2855;1294;-2855;1758;1510;1858;598;1510;1510;2274;1269;1510;829;1020;1510;3315;2483;1444;1444;598;170;474,484;1342;645;3967;1771;1578;1760;1041;500;500;500;1510;922,966;3588;2181;1118;1413,1414,1794,1795;1369;142,1607;2439;684;984;58,1581,1582;1578;58,485;456;3760;1612;1858;500;676;1001;58;1259;1294;1294;1462;3260;1510;1759;1001,2610;645;514;514;1239;20,378,379,380,381,382,383,384;2064;1442;439;1228;1761;1145;485,601;58;645;142,1839,2529;645;170;451,645,2298;58,61;2689;1823,1824;645;58,710;647,1210;598;1289;598;3741;446,1760;58,514,531,532;1510;1510;598,684;598;1520,1522;1972;-1938;3816,3860;1510,1821;170;142;1510;645;170;3416;58,1924;58;58;1068;434,435,436;755;4011;922;1165;744;1267;142;679;829;1703;170;3067;170;170;1858,1859;461;1861;58,142;452,1758;1578,3454,3455,3456,3457;1055,1056,1057;1510,1578;1041;1041;-1938;1925;58;2009,2010;2223;2073;58,2626;58,2626;148,58;58;58;58;3143;481,1041;2524;447;1759;1103;645;989,990;1425;1295;856;1444;1076;160;485;645;684;170;1510;1759;1510;170,1879;170;170;1612;1759;427;446;170,842;684,1732,3442,3443;167,170,444;1510;1758,2302,2665;1759;446,1760;1041,1759;989,990;1758;1041,1759;2449;433;456,468,1041;645;1510;941;3748;1041;446,1760;170;1858,1859;1858,1859;644;1858;1758,1759,1760;1041;1170;1858;1510;1858;1477;1165;613,1490,1491;58,61,1578;3083;1510;645;1761;3890,3891;514;1450;514;2378;58,61;859;312;2539;879,1758;3692;1797,1798,1799,1800;2818;58;1858;415,1383;3105;1041;2198;190;170;225;2601;1520;1832;1832;390;453,2143;1170;684,1970;3059;450,1041,1789;1510;3752;58,565,598,1792,2783;58,2783;1510;1808;61,565,598,1510;58,468,1041,1772,1926,1928;1510;1760;941;170;832;2126;1858;1758;61;1759;1578;645;1269;509;391,514;1294;61;1510;58,59,60,61,1909;3929;1510;1863;1294;1832;1510;598;154,155;1578;2084;804;528,819,2069;1832;1384,1385;1855;3578;1757;170;58;98,3902,3903,3904,3905;-1938;1758;1510;645;1858;131,1858;1294;1294;941;1444;433,2205;2134;58,2205;1759;61,565,598;598,879,1728,2796,2797;1510;1510;1444;135;598;446,1760;58;1829;170;2400;2707;501;679,817;60;679;1758;1763;58,456;1763;1758;4001;501;1400;58;706;439;608,1804,1805;484;3750;1607;-1938;58,951,1763;422,439,780,854,855;453;608,1804,1805;608,1804,1805;608,1804,1805;608,1804,1805;415;2003;3924;3021;2397;58;58;1186,1187;516;142,2529;1510;2064;944;1760;61,711,1755;645;645,697;1719;1724;645;645;446;485;556,645;446,556,1753;1719;645;645;645;446,556,1753;1269;562;446;514;2337;446,556,1753;391,802;484,1745,1746;501,528,556,615;466,625,645;391,802;514;58,433;58,433;1269;61,684;485;466,625,645;1510;703;645;58,461,810;1855;1761;1578;1578;170;58,2007;1930,1931;2770;3799;584;1510;438;1510;1153;3051;1049;501,645;58;980;83,84,85,86,87,88;645;1515,1516,1517;1145;2111;514;-1938;1510;1510;3529,3530;1761;438;3015;-1938;170;1832;565;989,990;1578,2286,3447;1763;2126;3589;745;706;1858,1875;438;1510;3038;58,628,629,1761;2630;827;527;1510;58,732,1041;1140,1913,1914;645;1858,1875;1510;148;3118;501,2512;58,514;61,1578,3451,3615;645;2710,3314;879;160;461;3101;645;196;446,1760;500,1571;645;645;514;61;58;645;1763;514;3249;514;652;148;451,601,1167;281,282,283,284;516;1128;1758;1510;598;500;461,1821;1758;500;1761;1510,2521,2522;3325,3326;3031;1510;500;2353,2354,2355;461,3105;645;58;446,1760;1510;1765;461;3673;142;598;1510;941;1510;527;1760;1291;1858;297;58;58;645;754;3766;2539;1276;3254;1760;501;501;-148,1383;684;450;468;1855;941,1548;58;407,1172,1173;58,1760;2207;1761;1510;422;1832;1510;3888,3889;1510;645;58,3794;645;676;481,1578,3590,3591;58,107,108,3899;1041;755,852,1578;1041;2030,2031;61;466,625,645;58,474,1759;1578;481;58,61,3895;58,60,1022,1041,2892;-148,1383;-1938;485;188;450;391,422,528,748,800,801;851;1041;989,990;527;1761;461,810,846;645;2754,2755;879;1510;1510;514;645;1359;3467;61,598;2096;3912;1759;1760;1510;58,468,1041,1926,1928;1510;631,735,1100,1123,1583,1584;1146;1510;1300;142;419;1761;142,461;1295;1510;453;1510;3012;2670;964;2884;3386;1444;2121;1967;1294;1832;58;1456,1858;1832;721,722,1759,1760;1390;1858;1858;1850,1851,1852,1853,1902;390;142,2529;142,2529;1643;419;1880;2685;500;645;1858;170;291;849;1578;58;1412;438,645,1163;1484;645;3294,3295,3296,3297,3298,3299,3300,3301,3302;684,3357,3360;474;170;466,819,820;98,1014,1537,1596,1676,1677,1678,1679,1680,1681,1689,1690,1691,1692,1693,1694,1695,1696,1697;684;631;391,802;1170;1415;58,979,1917;735,1584,1599,1600;3596;598;1717;1858;1465;1294;1294;879;1858;1858;1510;391,802;58;1097,3056;1023;1759;1792;1510;1730;674;1465;1041;645;-1938;-169;1578;1244;58;2490;1510;1444;1294;1294;645;447;3166,3167,3168,3169,3170;170;170;1542,1775;500,1542,1545,1546,1547;58;1759;645;1294;1294;1404;61,1510;2379;645;2398;684,1296;485;58,1041,1413,1795;245;1041;1578,1792;1760;1769;703;1294;989,990;58,485;61;1148,3610;644;142;772;645;1510;1510;1763;1020;2870;1510;1510;415;415;645,1759;446,1760;2317;553,920,1001,3060;684,1718;1041;58,422,468,551,552,1578,1724,1792;446,1760;2907;1578;1880;1861;58;784;58;645;2068;3124;1863;514;-1938;1282;1510;2244;2748;1294;170;453;1758;1789;1858;3157,3159;474,879,1759;58;1148;329,1839;1510;390;170;1294;3525,3526,3527,3528;2790;712;1894;61,1719;645;645,1145;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;3166,3167,3168,3169,3170;666;989,990;1041;58,422,439,780;1041;645;472;391,446,467,1026,1228,1229;58;645;61;989,990;58,451;989,990;438;1578,2729;170;120,121,122,123;58;1288;1510,1823,1824;1413,1414;1041;58;58,1761;1216;989,990;1510;438,556,645,1740;58,645;1761;1759;3661,3662;1510;1041;1858,1859;447;824,825;3465;1642;485;1578;1760;2574,2575;2575,2588;684,2470;1758;1792;1760;58;1759;743;732,1041,1769;1510;58;501,1740;58,1041,1596,1689,1690,1691,1692,1693,1694,1695,1696,1697,2433,2437,2438;1294;1761;1403;1761;1510;1510;2440;1758;514;514;514;1348;1510;58,500,806;1578;391,802;391,802;879;645;1148,3610;1003;1740;1510;645;1758;1759;879;1858;466;2371,2372;1339;484,673,2767;941;645;603,645,1001;1724;527,780;1444;1282;960;1510;2056,2124;1578,3454,3455,3456,3457;142;1761;474;390,1686,3564;1760;1757;3544;466;1510;684,1585,1586,1587;1758,1759,1760;946;2373;645;2567;1823,1824;649;452;1510;461,1517,1565,1566,1567,1568;760;501;989,990;1759;142,391,461,2499,2500;1510;645;1858;1294;2865;1273;98;644;1510;1858,1875;142;1758;453,975;645;1510;1510;438,600,645;1510;1510;989,990;645;81,3278;3937;451;1510;410;1295;717;1510;170;461,2506;447;1190,1456,1510,1513,1520,2711;941,1548;1510;645,2263;645;1686;1741;1273;170;645;645;453;422;485;1082,1747,3562;531,1112;1510;1510;1148,3610;2767;989,990;1510;1510;2523;142,461,2694;3532;1858;1858;645;451,485;58,1578,3230;58,1578,3230;58,1578,3230;58,1578,3230;58,1578,3230;58,1578,3230;2539;169;1008;131,1858;791;899,1755;502;484;142,143;415;1100;1444;688;1510;645,1001;2916,2917;1444;1596,1689,1690,1691,1692,1693,1694,1695,1696,1697,2014;1510;1510;1510;1510;1784;60,622,1510,3155;1444;-1938;1832;456,645,680,2297;3365;58,527;1510,2456;1761;839,2853;58,1036;1760;522;-59,-60,-61,-62,-1579,-1910,-1931,-1932,-1938,-2008;1510;58,1029,1772;438;453;1510;1510;1832;3555,3556;645;1882;549;3532;941;170;58;874,2658;3250;1151;58;743;1879;3382;732,1148,3610;3332;788;1510;1578;1148,3610;1858,1859;446,2531,2532;2899;1758;1419;2910;1145;1510;148;58,920,921;2675;645;-746;2285;1588;1832;1832;849;1832;763;1130;3266;2539;58;650,2777,2778;109,110,111,2191,3105,3368,3369,3370,3371,3372,3373,3374,3375,3376;3308;849;2728;2728;1578;1578;1711;474,1135;2050;618;4029;1479,1517,1596,1689,1690,1691,1692,1693,1694,1695,1696,1697;652;706;170;461;1041;645;2822,2823;1510;1858,1875;735,3595;1858;1252;832;391,802;391,802;452;2539;793,1758;1510;58,631;452;1823,1824;1002;1758;1510;1858;452;1294;170;1761;2167;1520;755,1068;3705;879;446;456;549;1858;900;2286;732,1041,1772,2286;1014,1537,2950,2951,2952,2953,2954,2955,2956;58,979,1917;1294;1510;58,1581,1582;832;453;3977;2196;598;529;419;3313;829;456;456,732;1510;3726;1832;1228;452;3071;989,990;58,2621;1364,1365,1758;645;1041;1510;148;1858;1759;1760;407,1172,1173;2150;879;466,625,645;1041;3711;645;1299;1294;514,645;170;1510;1510;58,1596,1689,1690,1691,1692,1693,1694,1695,1696,1697;3449;1168;1608;684;1758;58,59,60,61,1909;645,1760;58;1100,1510,1569;1068,1823,1824,1825;2247;170;645,2263;645;1510;453,1217;1497,1498,-1500,1500;1510;468;58,500,645,829,1331,1623;1041;1510;1510;1496,1594,1671;170;485;722,1041,1145;3799;645;391,802;1170;879,3356;1510,3028;2603;446,1760;2595;1510;830;3074;3024;514;68,69;645;531,989,990;688,2983;706;390;1510;514,1744;1904,1905;1904,1905;1904,1905;1904,1905;1904,1905;864;864;832;684;556,645;645,735,3125,3629;645;832;2326;527,1354,1578;1858,1859;89,3424,3425;1444;1510;142,2662,2663;2818;58,468,1760,1926,1928;1510;461,1517,1565,1566,1567,1568;2824;1294;684,3463;1294;453;1294;819;1762;1880;3641;58,743;1291;2408;61;1294;1294;446,1760;1294;501;1294;501;1294;941;514;439,466,748;522;3102;852,1479,1595,1596,1597;445;925;1609,1610,1611;1510;485;170;1481,1494;1758;941;598;2818;514;1510;170;898;1510;1758;1760;2749;58;391,802;936;1484;645;645;2974;598,645;645;645;645;645;556;485,645,1934,2257;645;645;556,645,2611;1832;407,1172,1173;516,1477;1759;1578,1760,3454,3455,3456,3457;645,1757,1760,1769;58,2557;391,802;645;1041;927;1512;-169;3074;2336;645;3472;1832;1510;472;-1938;1510;687,1632;1758;461,1465,1637,2625;461;148;452;645;973,1279;608,1804,1805;608,1804,1805;608,1804,1805;608,1804,1805;1863;142;1832;621,622;1855,1864;58;1510;1510;801;3705;2451;832;1269;684,2766;58,1578;598;2402;1123;719,1041,1510,1720;1510;1294;1832;1300;2134;1510;1510;447;553,789,1079,2173,2174;58,979,1917;1291;645;58;645;598;556,645;645;58,2959,2960;1758,1759,1760;785,996,1026;527;468,1578;461,598,1041,1578,1600,1787,1810,2662,3189,3190,3191;522;1465;645;514;58;565;514;598;1148;58;625;452;485;1510;1510;1041,3256;1760,2275;500,1393,1520;170;447;598;1465,2271;1510;829;58;61;1380;2190;1355;1510,1736;1858;1510;706;1182,3705;584;142;1444;58,59,60,61;1170;1832;131,1858;645;142;1510;501;407,1172,1173;1832;645;170;474,484;474,484;474,484;474,484;474,484;474,484;1348;138;124,125,1301,1302;58,433,447,474,551,867;452;1485;148;61;701,1228;485;343,344;684;1758;2187;58,1296,1726,1792,1929;2535;1858,1859;170;170;900,1204;484;2529;1510;81,1884,1885,1886,1887,1888,1889,1890,1891,1892,1893,3187,3188;170;1808;1758;598;1759;598;598;1041;598;58,598;1760;684;1789,1790;645;1832;1460;597;170;1510;58;1100,1517,1671;1169;468;708;446,1760;708;170;422,1719;170;1858;170;1510;58,1925;1444;2373;446,556,1753,2337;1936;142,2063;1510;2844;407,1172,1173;708;645;1510;1762;879;1444;1543;407;466;989,990;1832;2818;1792;411,412;1758,1759,1760,1761;1860;3974;2760,2761;1855,1858;3676;446,1760;58,1578;58,142,1035,2981;1041;1699;1793;684,1578,2155;625,819;1510;1044;409;1510;1858,1875;1510;422;645;1879;1510;1858,1859;3022;142;645,1236,2403;485;2245;485,2283;500;1510;1758;598;2829;1832;-148,1383;1294;59,1140,1760,1910;1757;1674;1510;2922;2212;1040;1832;170;1510;1832;1832;2661;645;1510;3423;1858,1875;1198;1510;1510;58;454,585;1294;1510;58;58;3710;1444;1510;58,598,1995;175;527;-148,1383;451,601;391;1278;764;415;981,1465;461,1821;514;849;3967;2813;1759;1784;3223;1578;645;1510;852,3542;419;452;514;484,611,612,613;849;1294;2054,3133,3134;1510;1808;645;1858,1859;706;1510;58,451;58,438,514,531,549;1510;598,3703;1850,1851,1852,1853,1902;1510;684,3131;3012;601;1832;1759;3738;58,1376;1759;61;391,511,529,645;391,511,529;645;3742;1850,1851,1852,1853,1902;1510;2526;922;1510,2070;608,1804,1805;1858,1876;608,1804,1805;58,484;157,2157;3271;1858;1759;1294;1294;1294;1510;1185;586,587;516;1007;1701;58,1767;59,1140,1760,1910,1913,1914;1315;58;1913,1914;58;59,1140,1910,1911,1912,1913,1914;549;1981;-148,1383;3054,3055;711;928;645;1269;989,990;484,511,513,514;706,1825;2460;3639;485;1228,1510;645,920;598,879,2796;446,556,1753;484;446,556,1753;446,556,1753;484,1745,1746;645;645;446,484,645;446,556,1753;645;446,556,1753,2337;58,645;645;560;645;466;514;2258;989,990;1510;1510;1578;1148;-1938;1510;142,2537;1510;832;1510;58,1930;3529;3919;1510;317,318;3261;243;566,567,568,569,570,571,572;566,567,568,569,570,571,572;527;1759;1759;1608,3942;645;1758;1291,1510;451,485,601;1858,1859;419;3038;1041,1510;1858,1875;1393;879;461,1465;1792;514;438,484,528,546,547,548,549;3397,3398;989,990;1858;849;645;1148;652,902,3654;1510;645;645;549;1444;1858;3117;672;170;1578;1761;1510;1444;2207;58;2688;1294;2764;1858,1859;645;1294;2385;1510;2345;3262;58,61;61,633,3451;1758,1759,1760,1761;832;2919;645;2982;60,598,684,1578,3658;1431;1858;829;832;849;142,1821;1880;1040,1757;58,527;1510;58;1510;2933;142,1839,2529;1510;461;836;1858,1875;719;58;1510;645;832;1041;1041;1041;415,2818;645;1758,1759,1760;645,1763;58;1934;920,1001;2245;466;391,802;645;645;58,645,1724,2901,2902;645;601,1252;485,601;527;849;3435,4040;1823,1824;1578;805;553,1130;1510;1832;2285;2722;461;58,2281;1357;148,877;58,466,500,550,1456,1759;446;1729;1294;684,2032;832;1858;645,701;1294;1808;1879;684;1858,2833,2834;1510;598;58;1294;439;2737,2738,2739,2740,2741;1369;1400,3718;2299;2813;418;170;549;61;213;879;450,2650;468,1041;229;645;1510;1510;314,315,316;2535,2747;3119;60,1809;60;1510;3810,3811;645;58;58,3794;646,647,1761;684;1578;61,633,1578,3451;1792;1858,1875;1822;2279;391,422,528,748,800,801;485;1578,3454,3455,3456,3457;1510;58;58;1041;1510;2486;2085;701;1510;1578;1041,1578;1578;1759;1170;3691;170;1397;1369;1845,1846,1847;2911;1510;1510;522,1759;540;2501;1759;1055,1056,1057;2086;1510;879;61;989,990;391,802;989,990;3140;-148,1383;-169,-2855;2832;1041;1832;850;2423;1209;2313;1880;1832;1832;427,1863;407,1172,1173;645;1578,1792;1832;1578;1858,1859;522,637;1761;626,780,996;553,554;142,2529;1510;138;2312;2923;1759;1510;58,61,598;501,645,2798;1823,1824;2113;1041;167,415,425,879,1055,2786,2787;645;1444;456;131,1858;1041;415,1772,2713;524,1041,1578;852,1479,1595,1596,1597;468,1578;1510;1858;645;98,755;1858;1592;645;1551;1269;1850,1851,1852,1853,1902;1858;1510;849;1444;892;1520;170;-1938;645;2772;391,802;1510;58,979,1917;1759;3628;11,20,378,379,380,381,383;170,1313;849;1758;1294;1510;1294;148;1510;3183,3184;1002,2122,2201,2288;446,1026;1294;1294;1294;1294;1510,1760;2053;1481,3400;686;2090;1161;446,501;1858,1859;1294;1294;684,1034,1596,1689,1690,1691,1692,1693,1694,1695,1696,1697,3363;1294;1139;58;453;1041,2765;1759;1578;433;565,598,829;608,1804,1805;1578;733,2153;1829;167,1520;773,779;58;1510;58,1413;3355;652;622;1041;4041;645;1041,1759;58;-1938;1510;1510;1510;1017;3281;645;-1938;514;1145;645;1759;58,422,551,552;673,1296,1792;1041,1759;58,514,531,1113;645,1041;743;-169,-2855;936;603;603,936;1760;170;142,1506,2095;645;170,407;1097;269,270,1849;1510;1759;1858,1875;3575;1294;1758;1858;1858;1510;422;1294;1294;645;1759;516;58,598,879,1543;645;645;-148,1383;1294;58;3525,3526,3527,3528;3995;3963,3964;3331;3030;58,61,1719;501;2249;1388,1637;1724;3166,3167,3168,3169,3170;1001;3166,3167,3168,3169,3170;1325;598,645,663;451;58,485,645;58;391,802;451;556;391,802;774,777;1719;645;663,2248;989,990;598;1510;2818;735,3595;461;645;509;58;644,706;1510;514;1510;485,690;453;2624;142;2337;475,3263,3264;774,777;58,-1778,-1779,-1780;1578;527,1041;58,1041,1759;551;1740;514;645;1740;1041;1041;645;1068;684;645,1724;1915,1916;3778,3779,4023;941,1548;1510;452;1485;941,1510,1573;1462;1041;2617;1948;1510;1510;1041;645;58;1578;879;645;1145,2193;1858,1875;645;1510;407;446,1760;446,1760;2818;1759;1510,2254;461;1295;989,990;1041;989,990;732,1041;645;726;879,1007;2945,2946;1823,1824;391,1347,1812;142,466,645;2814;939;1832;453;3286;598;1759;1510;1510;1510;1510;160,2691,2692,2693;407;170;1510;1510;1510;1510;701;679;3532;527;451,485,514,601;446,485,514,645;407;2980;1294;1269;1106;514;1761;1369;407;598,1510,1607;1758,1759,1760;1510;4005;1145,2175;645;1510;446;645;501;1986;1294;452;1294;645;553,2285;98;407,1172,1173;706;217,218,219;755;644;562,645;645;1228;2421;391,802;1510;410;1858,1875;446,501;446,501;446,501;61,684;551,1768;645;438;1510;1792;1578,1789;1510;1130,1401,1402;1510;1444;170;349,350;468;422,1266;461;2566;1726;491,641;1863;968,1551,1596,1646,1666,1667,1668,1689,1690,1691,1692,1693,1694,1695,1696,1697;1858,1859;58,485,916,918;58,915,916,917;920,2172;1510;3222;407;1444;468;1863;1517,1519,1520;3663,3664;645;946;1510;1510;1830,1831;1252;2966;2207;461,1465,2369,2370;3365;215;1088;1510,1589;1637;461,1821;1510;1578,1792;1510;1510;1510;427,430;755;645;1510;1058,1059;170,1858;827;1858;2577;1269;2178;1332;1510;1510;1510;1211,1212;1510;3049;1510;1858,1875;438;645;500,1331;129,130,419;549;684,829,879,1736,1880,1986,1990,1991;419;514;849;1837;848,849;427,1863;1858,1875;785;-1938,3724;185,186;1832;185,186,4004;189;1858,1875;3141;1294;1294;1393;1256;1832;750,751,752;1757;1510;625;1510;1832;2339;1863;1510;852,1479,1595,1596,1597;706;1765;645;2214,2215,2217;1510;645;1510;3965;2539;58;843;170;461,1517,1565,1566,1567,1568;1145;1170;1510;1294;3593;1578;2126;885;58;2567;2966;58;2659;768;58;1863;1510;131,1858;390;706;1291;429,1832;3705;3813;1760;1578;58,3861;468,1789;468;1510,1813;1014,1537,2950,2951,2952,2953,2954;468,1578;1607;1510;1510;1510;1190,1517,1603,1604,1605,1606;1510;1936,2847;1041;645,2282;468;456;2116;1510;705;1858;1041;98;1228;1832;1510,3211,3212;1832;1395;645;645;832;2126;1858;1664;1596,1647,1689,1690,1691,1692,1693,1694,1695,1696,1697;1634;3818;58,1578;58;1761;58,856,2152,2234;58;1578;1510;58,1539;58,1612;1484;1510;1858;1510;3976;170;1170;1510;1858;1858;1041;1510;1578,3454,3455,3456,3457;294;1858,1875;1858;645;1858;1146;1510;500,1039;516,818;2298;422;1822;2818;1808;1510;58,451;645;2070,2456;1489;58,2842;1068,2168;1578;2539;391,802;501;2197;58,61;1510;-169,-2855,2865;1832;3900;967;320,1904,1905;170;1904,1905;1904,1905;170;433;1451;1431;170;645;1465;645;452,484,905;58;1855;259,263;170;461,1821;1294;2818;170;3268;170;1550;391,802;1724;142,2529;645;677;500;1294;1294;391,802;390,1719;481;1294;1510;989,990;683;1294;1294;1294;1832;391,802;989,990;3676;391,802;391,802;203,204;1510;1510;2119;1510;1510;852,1479,1595,1596,1597;170;1369;1858,1875;1269;676;645;170;989,990;1671;391,802;556;645;1759;1510;506,3987;170;1228,1607;1001,1755;645;58,60,61,645,1719,1792;514,645;2722;3025;527,1648,2171,2172;390;501,2155,2156;2245;645;645;2732;58,1361,2877,3198,3199,3200,3201;1750;645,2213;529;645;645;447;391,802;58,59,60,61,1909;1294;1578;2128;1510;461;856;970;1016,1501,1502;556,838,839,840,841;645;451,485,601;989,990;391,802;2271;1863;170;1024;2176;645;142,1510;1510;3411;1020;3411;2756;1041,1140,1913,1914;608,1804,1805;598;2840;1510;170;167,1675;509;58;1880;142;1863;514;461,1821;514;1760;565,598;989,990;391,802;2865;645;3676;3676;645;645;645;514;2228;1858,1875;832;1510;1510;3386;1758,1759,1760;3088,3089,3090;832;1759;1510;2385;989,990;1863;668;1223,1510;3767,3768;3257;1517,3145;2126;598;652;981;1510,1814;58,1969;-169,-2855,2865;58,98,1542,1626,1627,1628;170;2408;1758,1759,1760;170;1228;1758,1760;1757;415;461;583;1858;3907;1510;3646;1510;536,1510;645;1182,3705;1804;1510;170;2659;500;500,806;1393,2166;500;58,1578;603,676,1504,1505,1506,1507,1508,1509;1510;3731;1858;450,468,1761;1041;1758,1759,1760;142;419;1444;1858,1875;1858;1758;2522;1578;514,645,989;61,1510;1510;1510;58,59,60,61;58,1296,1726,1929;1510;1510;1971;849;306,307,1114,1115;839;3322;2654;2586;1759;58,61;645;598;645;645;1563;645;172;1510;875;1510;644;2199;1510;142;142;81;645;58,1456,2376;58,645;1055,1056,1057;1228,1510,1578;1228,1510;461;1041;1228;58,1767;1041;58,1578;422,1719;422,1719;422,1719;522;1850,1851,1852,1853,1902;1850,1851,1852,1853,1902;1858,1875,2092;1294;849;1444;170;58,1925;407,1172,1173;2142;706;2818;142;598;452;2818;3936;391,802;1413,1796;3317;645;645;120,121,122,123;553,554,663,1236;58,1792,1914;433,3607;58;1040;1792;433,474,1758;1760;608,2239;1761;1041;1759;972,973,974;1228,1510;1686;1510;1294;60,61;1762;1228,1510;170;4009;446,514;645;1129;485,601;422,645,1578;645;466;1041;2335;485,601,1252;645;1148,3610;58;645;1371;2388;1145;438,645;1578;1858;1858;1880;1276;419,1832;1510;3532;1858,1875;391,802;1858,1859;1041;645;142;2637;1832;58,951;170,1137,1858;1510;1510;58;58,500,1758,2709;1510;454,556,3709;61;1510;1686;565,598,1510;391,451,645;1510;415;2337;645;1758;390;1578,3712,3713;1145;1563,3688;170;1438;2385;1142;2538;645;1510;1510;148,565,598,645,1761;1393,1520,3849;1228;3057;1294;668;497,1858;1444;2659;58,598;2659;410;1446,1686;468;1542,1785,1819;1510;112,113,114,115,116,117,118;58,840,2751;422,718;68;1759;1477;631;1733;1858;645;1369;1444;138;1510;1832;645;3367;485;608,1804,1805;3305;409;407,1172,1173;598;556,645;608,1804,1805;608,1804,1805;422;1269;2703,2704,2705,2706,4052,4055;58;1068;142,2529;3930;1432,1433,1757;1858;598,879,2796;446,556,1753;391,802;1074;2245;514,645;481,1148,3466;645,1510;645;645;446,556,1753;556,1752,2337;446,556,1753;645;645;1145,1592;1479,1480,1481,1482;565;1465,2389,2682;60,474,1041,1758;1510;966;556,645;951;645;391,802;1148,3610;1759;1880;1510;2244;1858;2255;2255;2255;1510;1612;645;461,1348;1444;1510;1510;1823,1824;527;1053;170;461,1821;1435;1855;3233;989,990;1858,1875;1510;1335;629,1761;170;1510;1358;2585;3308;61;553;170;1673;1510;1879;1444;1145,2164;1823,1824,1825,3586;461;1510;1832;1438;1942;645;643;1170,1758;645;1759;2698;1792;1858;1510;2522;391,802;645,2941;989,990;645;2417;390;989,990;645;645;1388,2791,2792;1389;1510;1759;2201;598;645,1823,1824;2948;1510;684;3086,3087;1510;1759,1760;1762;696;60;644;522;446,1760;1510;1858,1875;1858,1859;645;501,553,554,555;308;422;959;72,73,74;1294;1294;58,422,1002;2109;1228;1269;1444;735,1578,3125;522,1858,2515;2541,2542;1510;3342;1760;1510;732;481;863;1855;2735;1758;461;1832;1832;390;1510;1832;334;2548;58,468,1041,1926,1928;-148,1383;810,1510,2475;1578;170,419,420,421;3851;1510;1510;1510;1182,3705;58;2082;1760;98;2984;1145;938;989,990;170,785;1832;1510;1510;58,468,1041,1926,1928;58,468,1041,1926,1928;1858,1859;706,1510;1703;1510;142,1510,1600,2827,3043,3044,3045,3046;2170;1462;1510;1510;1510;1510;1510;500,879;1510;451;989,990;645;514;645;144,145;148,1578;1510;1510;743,1758;481,1041,1789;450,1758,1759,1760,1761,1789;3577;1294;3415;191,192;1510;407;2672;598,645;1510;81;1510;131,1858;1858,1875;1510;684;1832;131,1858;849;1832;422,1144,1145,1146,1148;1863;2207;1832;142;660;645,2262;148,1858;1758;58;170;1445,2319;3396;1625;494;199;829;1832;338;1510;415;1510;1930,1931;645,2248;645;461;701,1510;452;3974;452;844;3013;1510;58,743,2621;1477;98;160;170,442,443;1858;1510;1444;1444;2939;645;2273;645;645;2990;1510,1823,1824;58,979,1917;1510;-2855;684;160;1578;58;61,3820;645,2282;58,1578;1294;1858;1760;828;148,1443;1294;390;2567;2570;1858,1859;1858;292,293;755,879;58;58;1444;3365;1858;879;1444;1510;1761;58;1510;645;58,468;61,684,1148,1596,1659,1662,1689,1690,1691,1692,1693,1694,1695,1696,1697;3163;979;645;3959,3960;1218;58,840;485,514;989,990;505;3236;1578;58,451;61,645;1758;58,645;58,451;1578;1758;422;58,451;1534,1536,1537,1538;1900;1755;461;645;461,1821;170;999;1510,2930,2931,2932;1510;514;170;1510;1510;500,1331;131,1858;131,1858;415,941;170;1858;1820,3884;1510;415;1148,3610;514;989,990;931;1817;1510;58;1,2,3,4,5,6,7,8,9,10,12,13,14,15,16,17,18,19,20,21,378,379,380,381,383;391,802;81;618;1393;645;1726;142;989,990;645;1858,1859;625;58,451;989,990;391,802;391,802;802;1758;-1938;1858,1875;1510;1762;706;613,1490,1491;1759;427,1863;556,645;1510;438;2131;472,553,554;20,378,379,380,381,382,383;852,1479,1595,1596,1597;1759;1510;2207;645;58,1761;3687;2385;1041;514;1740;645,3567;61;58;1369;438;1474;1510;1761;328;1832;170;364,365,366,367;438,1740;1026,1040;879;58,468,1764,1926;58,468,1764,1926;1123;645;645;1510;391,802;1510;170;1758,1759,1760;1957;1957;1510,2782,3149,3150;625,1206;2462;2324;1510;1510;390;58;989,990;1451,1462,1510,2890,2891;1510;516;706;700,905,1757;989,990;1510;58;1041;-1938;1294;142;1587,1619,1620;2033;1510;879,1469;1444;1510;1863;1269;689;160;2018;1850,1851,1852,1853,1902;1510;1294;1065;997;1858;2573;1444;176;170;1041;142,2529;514;1863;1228;1858,1859;1294;1510;706;1510;989,990;645;58,500;446;645;58;645,920;645;3852;1879;1563,3688;261,262;1858,1875;930;58;1858,1875;829;391,802;1835;1510;446,1283,1284;273,274;1832;1348;1858;170;1758;645;370,371,372;1510;645;98,3914;565;848,849;598,920;3974;438;663,1236;2094;438;1858;3532;1858,1875;1510;1294;879;58,1578,3230;58,1578,3230;1080;1863;915,916,917,918;193,331;1256;789;1858,1875;1832;58,505;1510;1759;415;645;468;446,500,1544,1758;2733;3117;1510;3532;1510;415;645;1510;1671;170;1760;1041,1578;1759;527,608;1294;1278,1510;514;1510;2457;1510;1510;645;501;645;941,1510;58;422;1832;1148,3610;1148;1148,3610;2970;3126;879;1123;415;1858,1859;1575,1576;1291;1760;142;468,1148;1510;58,454;1858,1859;556,645;415;170;3972,3973;1578,3454,3455,3456,3457;1510;1145;1294;58;446;1269;1578,1792;1858;1858;58,1578;598;3532;-1938;1182,3705;514;941;1777,1778,1779;1855;1259;2865,2866,2867;684,1510,1637;427,1863;1760;1510;446,1760;1339,1449;1510;668;142,1839,2529;1863;961;61,1510,2456;2712;407,1172,1173;849;391,802;1578;246,247;2583;170;1510;1351;1759;1228;61,1296,1932;481;1014,1537,2950,2951,2952,2953,2954;446,1760;1510;407;3594;645;2669,2670,2671;419;1858,1859;832;556,645;645;1578;1228,1510;58,600,645;142,837;500,1606,2602;601;598;1858,1859;1421;501;1510;1624;2818;2360,2361;1041;1618;1510;1510;989,990;747;1100,1510;1510;1855;1832;1858,1859;1510;1578;1510;500;732,1148;415;720;1510;501;645;1761;1858;391,802;446,1760;2251;1510;1510;598;58,451;1510;170;1510;1832;58,1596,1689,1690,1691,1692,1693,1694,1695,1696,1697;415;1510;1904,1905;1904,1905;1904,1905;1904,1905;1904,1905;1904,1905;1904,1905;2064;2567;1068;1510;556;170;452;-148,1383;1858,1875;1041;1510;1510;170;120,121,122,123;1759;407,1172,1173;2130;1596,1689,1690,1691,1692,1693,1694,1695,1696,1697;1510;415;645;1510;1578;1858,1875;1858;1858;1510;2215,2216;148,522,684,1369,1587,1619,1620;58,1635;1294;461,1517,1565,1566,1567,1568;1294;1510;1294;1294;989,990;1294;391,802;1510;407,1172,1173;1879;461,1821;815;2099;1282;2337;1510;440;1858;391,802;645;1858,1859;1369,1370;879;514;58,1581,1582;1858;170;1858;1858;58,2272;879,1672;2105,2106;2106;1860;737;974;989,990;391,802;903;645;1858,1875;336;1100;1510;1758;1486,1487;1279;2771;1510;1858;1510;1858;3986;447;1858;1572,1573;1578,3454,3455,3456,3457;700;1832;1758;645;438;645;645;645;1295;1858,1875;856;1148,3610;407,1172,1173;684,1686;1465;433;1759;1578;1510;415;58;4028;1510;1510;645;2667;1355;1294;1294;3014;1041;1858,1875;1510;946,1145,2129;1510;549,879;645,1142,2494;2191,2504;1510;1863;1792;1661;1032,1033;1294;645;422;1858;565;148;407;1574;391,802;1792;-3177;170;1510;170;613,1490,1491;1578;1510;1863;-3761;3744;1510;1858,1859;452;170;598;1858;1510;407;981;755;645;676;645;1761;1784;58;879;1049;1510;645;419,1858;3974;68,69;645;1758;391,802;422,1719;1510;167;1858;142;1170;989,990;645;58;645;1510;2271;1510;1294;1041;58;58;1578;1578;1510;58;1041;500,806,1588;2700;1294;1510;170;1510;272;1789;1041;271;2276;481,1041;427;453;461,1821;3137;391,802;528;1607;131,1858;468;1294;1510;391,802;391,802;58,451;1041;989,990;1470;1858;1452;452;1510;2126;2732;2539;1858;419;170;1510;61;1863;170;706;676;514,645;645;415;1832;829;504;514;1510;1832;466,645;645;645;601,645;625;4056,4057,4058,4059;527;1041;1197;1510;1294;1578,3454,3455,3456,3457;3941;1578;427,1863;3921;58;1510;952;1510;2905;1510;1510;706;1123,1130;1510;1832;1858,1875;1510;461;3897;645;3019;58;856;3054,3055;61,1296,1932;2230;451,485,601;514;645;1832;1510;81;58;514;1244,1250;391,802;600,1748;645;645;446;491;391,802;645;645;514;446,872;484,514,645;391,802;1719;981;1858;1201;1832;2271;1148,3610;706;1822,2554;1510;1123;-1938;461,1821;419,1858,1859;2818;170;1294;2183;1904,1905;126;3606;59;1858;2818;832,2049;989,990;1510;811,1832;1858,1875;142;1041,1596,1689,1690,1691,1692,1693,1694,1695,1696,1697,3463;1510;1832;1510;461,2273;832;1578;1858,1859;1510;1510;1858,1859;3568;446;1510;1510;706;3381;514,645;482;1510;58;407,1172,1173;81;1510,1818;2434,2435,2436;1858,1859;3971;539;1254;1431;514;170;58,59,60,61,1909;1184;645;989,990;1269;2246;391,802;989,990;391,802;989,990;1269;645;620;601;989,990;60;3461;645;645;58,1123;58;1510;1041;645;1041;1759;500,806;1510;1879;2207;142,2529;419;1938;446,1760;3292;422;668;1510;170;468;1624;2789;3849;446,1760;58;1294;549,820;2977,3001,-3003;514,556;1510;415;138;1444;1895,1896;1578;1578;1426;1578;3951;946;58;1294;58,1041,2904;1982;451;514,645;1858,1875;2385;1759;1757;1148,3610;1760;1578;1148,3610;466,625,645;58,1148;439,527,596,1761;1757;-148,1383;58,468,1761,1764,1926,1927,1928;303,304,305;1863;1145;267,268;645;1863;58,1596,1649,1689,1690,1691,1692,1693,1694,1695,1696,1697,2894,3392,3393;981;706;415;58,468,1041,1926,1928;523;1123;2244;58,500,1041,1371;1481,1494;1510;879;484;1698;684,1585,1586,1587;1855;1808;668;1431,2469;61;1670;854;138;1268;1858,1875;1759;668;645;1863;1903;755;1510;58,1041,3009;452;439,625;1371;142,832,2529;1510;1832;1294;1100,1510;1858,1875;669;910;408,2394;1858;1858;338,339;676;3532;1510;1510;1055,1056,1057;148,700,2962;446;829,1170,1291;1801;1759;2818;193;1294;3452;3245;166;1041;1510;98;451;58;922;645;58,979,1917;58,1918,1919;390;2633;1510;939;1294;1123;281,283;3840,3841,3842;410;178;500,1542,1545,1546,1547;1858,1860;1860;527,1075;2818;1294;1294;131,1858;3325,3326,3327;58;58,2640;1858;461,1517,1565,1566,1567,1568;58;625;684,1542,1660,1661;1510;142;58;506,645,1747;1510;1578;1759;58,598;1020;645;58;1832;645;58,2723;645;438,484,549,556,1111,1112,1113;58,1041;446,1760;1100;1578;1863;19,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,397,398,399,400,401,402,403,404,405,406;1190;579,580;58;452;598,879,2796;142;170;1809;391,802;-169,1980,-2855;501,645;58;160;1510;1145;1858;1858;1510;1855,1879,1883;1858,1859;1829;941;160,295,296,427,1839;1294;3525,3526,3527,3528;3525,3526,3527,3528;19,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,397,398,399,400,401,402,403,404,405,406;1858,1859;989,990;3166,3167,3168,3169,3170;645;58;989,990;989,990;645;989,990;989,990;438;1285,2120;598;645;645;1761;684;61;829;2280;1510;1148,3610;1510;1510;1510;447;1765;485;1858,1875;446;446,536;645;1369;645;438;1858;1060;1436,1437;58,468,1760,1926,1928;1148;1858;1294;2818;2846;1510;514;645;1041;2289;3276;1343;142,1838,1839,2529;1510;1510;1510;645;2511;1041;989,990;1578,3454,3455,3456,3457;989,990;719;1510;3676;1904,1905;461,1517,1565,1566,1567,1568;989,990;989,990;1510;3751;419;1863;706;981;1858,1875;170;299,300;407,1172,1173;1832;1858,1875;61,3597,3598;706;391,802;598,645;514;645;1858,1875;3105;391,802;58,391,573;645;1369,3050;584;422;806;2782;1170;3040;1510;433,1268;706;1294;645;1444;1510;468;1510;58,59,60,61;1858;1863;131,1858;1165;1294;989,990;1510;1510;2837;1510;2344;2991,2992,2993,2994,2995;1759;1832;1145;2457;1510;1510;458;1832;1761;447;1041;1832;836;277;1823,1824;934;701;3458;1510;446,1760;1858;170;674;1294;485;1855;1862;148,165,1862,3780,3781,3782,3783,3784;1858;1863;1863;1578;415;1515,1516,1517;1760;1510;1510;1863;1510,1578;684,1736,1819,1987,1988,1989;1832;849;849;799;541;839,1170;3532;347,348,407;142;1858,1875;415,755;407;170;446,556,1753;1510;755,3532;706;1510;2447;2528;332,333;1510;1182,3705;3705;1510;1858;625;1863;1762;1596,1689,1690,1691,1692,1693,1694,1695,1696,1697;645;1760;1510;2070,2555;1760;391;2207;-148,1383;170;1863;1510;1510;58,61,598,1296,1932,1933;645;1510;1510;446,556,1753;2014;592;2014;1863;1014,1537,2950,2951,2952,2953,2954;2224,2225;500,1041,1278,1319;1510;1808;514;391,802;1510;2974;407;1578;1294;1041,3304;676;549;446;3471;1016,1501,1502;989,990;2619,2620;944;645;1422;1294;1294;1022;60,4015;852,1479,1595,1596,1597;131,1858;500;391,802;391,802;58;1823,1824;2058;1294;706;1860;466;645;920,1001,3060;461;160;4003;941,3274;1510;514;461,1465;1151;735,879,1291,2070,2231;1510;634;514,524;466,625;438;2260;989,990;3217,3218,3219,3220;1237,3103,3106,3107,3108,3109,3110;514,645;1041;1393;584;771;1444;1808;170;1041,1140,1913,1914;446;3541;1510;1904,1905;1904,1905;485;2258;1832;645;645,1510;170;3850;674;556,1751;645;1041;391,802;1294;58;1510;1510;584;902;902;1294;684,3956;391,802;645;2271;461,1821;1510;1578;170;1510;142,2529;1810;1863;407,1172,1173;2020,2021;989,990;1510;706;1510;1252;241,242;645;645,2213;2200;1832;1863;1256;1759;1858,2579;705;142;989,990;1510;1858;3532;142;461,1823,3557;390;58;4050;550,598,1084,1131,1758;1145;160;549;706;684,3627;3436,3437,3438;3436,3437,3438;3436,3437,3438;170;1303;58;1510;1858,1859;1863;2164;1510;452;1134;1832;58,59,60,61;58,59,60,61;1100,1510;61;989,990;989,990;2079;3926;3386;1904,1905;1294;1294;1294;1510;3796;1510;1510;1760,2275;645;58;2425;1510;1607;516;1510;1510;170;-148,1383;170;490;1386,1387,1388;650;1510;1510;1792;407;390,500;1510;1510;1758,1759,1760;1858;1228,1510;706;500,684,1331;500;676;1858;1041;1243;407;1832;2248;1510;1578;1294;1858,1859;989,990;2135;58,61;1510;1858;556,645;391,802;58;2516;989,990;1858;2207;461,1821;3532;903;391,802;1510;829;1857;58;1510;1822;391,802;142;645;391,802;1759;1858;170,453;3549;58,3442,3443;1760;1761;1510;1510;20,378,379,380,381,382,383;904;1218,1256;166;407;446;645,1789;2539;3463;1858;1510;3689;1759;391,802;1858;1863;1863;1858;419;3325,3326;645;2539;981;1510;501;1066;446;422;1510;152,153;1510;1294;1644,3786,3787;1041,1148;558;645;391,802;131,1858;936;3613;706;2509;1703;131,1858;1510;170;2248;1760;1832;500;2241;514;2331,3153;3365;1832;1393;61,1792;1510;1510;706;1858,1875;1510;2657;1913,1914;463,464;3887;1578;652;1266;1782;2797;2049;891,1858;1578,1792;645;989,990;645;1510;2337;645;1510;1510;58;1510;1103;1832;1832;849;989,990;1761;832;1041;1760;1510;58,500,1528;58;2126;1510;1510;2496;2091;485;1148,3610;514;2255;2255;645;1858,1859;645;3546;514;1510;1371,1792,3181,3182;645;514;1860;1832;1596,1689,1690,1691,1692,1693,1694,1695,1696,1697;3558;1510;989,990;849;1863;461,1821;1068;474;1759;1510;645;1294;832;1510;452;1510,-1512;187;2207;1510;1510;1510;2390;58;514;645;645;1766;1041;645;61,598;1510;1621;446,4025;1294;1583;1510;645;1858;407;879;1758;1592;170;58,501;962,963;1148,3610;1297;453;1510;1381;1510;1510;2686,2687;1855;1578;1858;1041;1578;1148,3610;58,468,1926,1928;1596,1689,1690,1691,1692,1693,1694,1695,1696,1697;1148,3610;601;415;141;2070;58,450,468,1041,1926;1757;1578;1578;1041;1510;1148;461;148;1145,1510;2004;1882;1863;1858;2097;407,1172,1173;2373;645;2419;2207;170;1510;1510;1510;3417;2471;514;438;1470;1369;645;1510;1863;1832;516;668;1609,1610,1611;177;2547;1879;1510;3739;1761;1761;1510;1282;1423,1424;1863;1510;1858;1510;527;170;1515,1516,1517;1832;910,2394;1832;1832;1858;1510;142;645;2207;1510;645;58,1792,2201,3177;645;645;58,3070;1372;391,802;391,802;1971;1262,1510;514;3644;1858,1875;170;879,1496;2425;148;1294;3189;1260,1291;941;172,173;170;58;2990;1759;170;468,1148;142;3601;989,990;391,802;391,802;1863;562,645;603;1170;565,1760;1510;1686;1510;419,1863;1977,1978;1278;745,1397;1759;1510;415;645;2337;446,556,1753,1754;466,625;989,990;391,802;148;645;391,802;390;1510;407;1510;3602;142,3387;1759;1761;446,536,537;1510;1291;58,468,1765,1926,1928;2088;556;58,468,1578,1926,1928;1145;1510;1510;645;1228;645;584;1578,3454,3455,3456,3457;1510;468;1904,1905;1213;1452;183;514;391,802;645;1510;645;3532;454,684;1510;981;1758;1510;755;2536;514;3675;1510;1858;515;645;170;1510;391,802;773;1510;831;1510;1541;461,1821;1294;391,802;668;1858;1510;1858,1875;829;645;391,802;1510;446,501;668;1170;1858,1875;1863;1858;170;1858,1859;915,916,919;3777;58,1804;1145;1858,1859;645;1823,1824;193,194;1863;879;2478;2478;645;598;829;1758;3038;645;4049;645;2365;1510;2015;645;2089;1858;-1938;934;1863;1863;461;1148,3610;1863;1268;3700;684,1585,1586,1587;1510;1510;1510;903;684,1585,1586,1587;1858,1875;1709;1832;1294;1510;1863;1170;989,990;2694;684;58,59,60,61;1096,1097;222,223;391,802;645;390;2807;1510;1145;1510;879;446,1760;1760;60,439,684;1510;58,1578,3230;142;170;3990;1510;58;1014,1537,2950,2951,2952,2953,2954;1510;1510;1832;58,59,60,61;1863;58,59,60,61;1510;427;1832;1170;1858;-148,1383;1041;427,668;1930,1931;1294;2795;1734;684;875;514,1251;3458;407,1172,1173;706;881,941;1510;645;58;466,625,645;1510;415,879;1510;58,415,461;514;2271;1041;989,990;556,645;1289;602,603;3585;2302;1510;142;1578;1294;2199;391,802;645;3839;832;1904,1905;1904,1905;1904,1905;1904,1905;2553;452;-148,1383;1510;1863;598,1041,1578;170;142,1592;832;1863;1098;757;3420;859;1294;989,990;1510;58;3913;391,802;170;1476;2670;2670;3957;1294;514;613,1490,1491;1758,1759,1760;1484;467;1463,1464;989,990;427,1863;1863;1863;391,802;941;1608,2235;142,461,1370,1529,1530;61,501,598,2417;989,990;601;989,990;391,802;427;1291;150;2147;447;2666;2273;2818;142;391,802;407,1172,1173;391,802;625;645;58;879;1510;1510;461,2154;685;1510;1510;-1565;170;1294;466;1170;645,3032;184;391,802;989,990;1858,1859;1029;1904,1905;58,59,60,61;598,645,1578;2482;645;58,59,60,61;2387;2248;645;1510;1863;58,59,60,61;410;1760,2275;1863;391,802;407,1172,1173;1510;645;1879;1808;1294;1294;1182,3705;81;170,1858;1817;1863;1808;882;565;1510;829;1832;500;58,500,1601,1602;1041;170;1322;1510;3390,3391;1858;2207;1294;1510;1294;1104;1123;410;1858,1859;3569;1592,1823,1824;1856;1813;1182,3705;170;1858;645;3366;1294;98,3814,3815,3816;553,2285,2605;645;1832;2818;1510;1041;989,990;645,1141;170;1858;1510;2937;645;1285;1858;1510;1874;1510;148;2197;1510;1792;849;419;1759;58;452;98,3753;2495;922;438,645;1439;1041;601;485;2818;2818;1396;170;1294;1832;1858;989,990;1510;419;989,990;2207;527;1859;598;2282;645;391,654,655;644;981;1762;1294;1281;1858;1858;645;407;1858;875;1393;598,1757;514;652;106;625;1858,1859;1510;1510;1510;170;2934;647,744;1863;1425;2056;645;989,990;142;58;3378;58,1578;727;1510;3704;58,1581,1582;1543;446,556,1753;391,802;598;446,556,1753;870,871;471;1378;3063;668;649;446,1760;1832;1758;1510;2990;1510;391,802;2581;1808;1858;2255;2255;1134;1510;1510;3261;1832;645;1510;1294;1465;1832;849;1858;1510;2419;1858,1875;645;2284;1863;58,59;142;1510;1510;58,59;462,645;1858,1875;1294;170,419,1307;2216;514;1832;452;142;58,59;58,501;989,990;645;484,485,897;391,802;1041;1832;645;1858;1510;1510;1858;407,1172,1173;1858,1875;1510;1040;58,1002,2122,2123;1510;1879,3361,3362;1041;1510;1832;516;1858;2977,3000,3001,-3003;466;81,1295;1148;1765;1832;1863;1863;1148,3610;281,1616,1617;1760;58,468,1926;1832;1858;1510;598;1294;1510;58,468,1041,1926,1928;1832;1759;1510;1278;1710;446,500,806;1832;1858,1875;668;1858;1832;1860;514,645;645;1858,1875;996;706;131,1858;1758;1832;1510;407,1172,1173;170;1515,1516,1517;1863;849;1863;1510;1858;645;1020,1143;1510;1760;422,1792,2201;524;719;645;1510;1759;1760;3991,3992;1294;1510;415;1431;645;645;1294;598,645;1832;2549;446,1760;1855;1294;1294;550;645;407,1172,1173;58;1256;584;1510;474,645,688;1858;1822;576;1470;645;598,1510;391,802;391,802;233,234,235;1199,1200;2035;3348,3349,3350;58,468,1578,1926,1928;1495;1578;1858;422,1759,1760;58,1759;142;170;407,1172,1173;989,990;944;1858,1875;1349;162;1596,1689,1690,1691,1692,1693,1694,1695,1696,1697;1041,2699;170;4002;3525,3526,3527,3528;58,829;142,1839,2529;1510;1510;451;989,990;989,990;2989;989,990;2919;142;1759;1637;170;946;684;706;58,468,1764,1926;936,1228;3574;1444;2990;514,645;1394;1863;645;447;1758,1759,1760;451,1269;1510;645;465;1145;989,990;1760;1510;645;1762;946;58;3094;1510;516;1863;1294;1761;1858,1875;1269;58;989,990;514;415;58;461,1821;3532;934,1194;1510;170;514;391,802;1294;1828;4002;446,501;427,1863;1863;1863;158;1510;2818;1858;645;645;1510;1510;1510;1294;2478;1510;645;457,458,459;499;501,1029,1237;514;3532;1863;438;1294;1832;645;246,247;2207;1758;1269;936;3601;1510;549;1832;1858,1859;446,1760;932;645;1858;1759;142;989,990;1832;852,1479,1595,1596,1597;1461;1294;170;645,1510;1782,2578;58,527,551;1510;1858,1875;-3977;1072;1182,3705;1510;142;2873,2874,2875;170;1510;516;1510;660;407;1041;879,1448,2840,2841;2996,2997;1808;3463;-148,1383;-148,1383;-148,1383;131,1858;58,3225;745;742,2405;58,59,60,61,1909;3394;1971;1934;1863;1510;2720;1863;1858;3275;645;879;1510;1106;58,1094;58;1762;989,990;142,2529;1578;1855;2193;142;2818;645;879;676;906;1384;625;59,1140,1760,1910;1510;391,802;1510;391,802;170;391,802;514;193,214;946;391,802;1294;1904,1905;-786,1904,1905;1904,1905;1904,1905;1904,1905;-148,1383;1863;1863;644;1510;829;90,91,92;-148,1383;1294;1294;1294;407,1172,1173;1858,1875;1863;1041;1269;2340;1858,1875;3325,3326;170;1510;1294;829;1510;2046;1510;598,1739,1801,2173;989,990;1832;81,1629;1510;1510;58;1761;101,3444;1218;415;1832;514,556;1858,1875;668;989,990;391,802;58,59,60,61;1510;1218;1863;1832;501;1510;645;2304;1858,1875;1510;1510;1510;1291;422;1020,1360;989,990;645;58,59,60,61;2818;1832;2387;645;1294;1294;1294;1858,1875;1858,1875;391,802;170;1858;1294;1510;1510;1510;1032,1033;629,679,1032,1033;832,885;3287;1510;1858,1859;3324;58,59,60,61;1686,3869;754,1832;1145;3745;142;1510;1510;391,802;645;407;2517;4030;989,990;1817;981;2255;1863;645;58,59,60,61;2164;439;682;167,1256;1295;170;2245;131,1858;1510;419;1760;1982;1832;3754;668;451;1832;1055,1056,1057;1858;1510;391,645;2106;2070;1510;3927;514;466,625,645;645;433;516;170;433;1103;1228;1858;1858;391,611;645;644;903;461,1517,1565,1566,1567,1568;1858,1876;645;1629;211,212;1904,1905;3320;3021;61;3054,3055;856,2234,2717;981;989,990;1858;989,990;645;645;598,1510;514,645;981;981;1100,1510;501,562;1510;1510;1496,1510,1594;645;1858;1858;2255;447;1863;549;645;1759;1295,1970;1879;58,59;1294;468;58,59;1578;58;1510;1269;170;1510;631;1510;1145;1291;1510;1510;676;3412;755;2811;1510;1760,1765;1510;989,990;989,990;1510;1510;1832;671;424,425,426,1510;2793;1041;3763;1148,3610;2935;1863;645;1858,1859;645;1832;1817;1462;-169,-2864,-2865;1148,3610;598;1510;2187;832;1858,1875;1578;1294;3566;1758;58,468,1764,1926,1928;1930;1148,3610;58,468,1764;645;1761;1858;142,461,2694;391,802;58,743,1760;1759;58,468,1041,1926,1928;1510;390;1760;352,353;706;1858;1510;1863;1188;1832;985;3255;1832;849;1832;1809;724,725;1858,1875;1858;1759;1510;910,2394;1832;58,59,60,61;1411;1934;1510;989,990;989,990;645;1080,2813;1858;1244,1245,1246,1247,1248,1249,1250;391,802;1510;407,1172,1173;1510;1145;1758;3183,3184;3237;1858;170;1294;1858,1875;1758,2362;58,59,60,61;901;58;1510;3261;1510;148;1792;58;446;58;1578;1863;1510;1578;170;170;1265;1863;1294;1863;1839;1462;1510;446,556,1753;1228,1510;645;2245;989,990;989,990;989,990;1737;668;1863;1863;1858;1117;645;58;1170;58;2788;922;1510;485;821;2245;58,451;645;1510;1510;989,990;1629;1724;1724;1510;1510;2944;1145;1510;989,990;1510;58,142,516;1858,1875;447;1832;1293;1863;981,2110;3240;598;2604;645;391,802;1863;1515,1516,1517;407;446,1510;1369;1510;706,893;1510;706;1858,1859;903;1863;645;2240;720;-1938;2818;645;645;1863;58,59,60,61;58;1510;1858,1875;1758;1832;1858;1862;1578;1041;1510;941;1863;2207;1858,1875;1510;485;1041;2865;1510;1863;1510;148;58,2695;1510;-3977;645;1863;941;1863;2700;1278;598;1510;142;58;1510;645;645;170,429;1041;1863;1863;1240,1241;706;1863;645;3769;58;556;170;645;1858;58,71;1858;1041;407,1172,1173;58,2271;3720,3721;2311;1080;142;516;899,1041;410;391,802;2101;879;1510;415;1823,1824;1759;58,1578;1570;645;596;1510;829;1904,1905;1904,1905;1904,1905;1904,1905;1904,1905;1904,1905;1006,1007;1858;618;58,71;1510;896;1758;452,516;1108;645;1832;1294;1121;1863;1858;1863;1858;1858;1759;427;1510;1510;1863;407;1863;645;1510;407,1172,1173;170;514,1269;1860;407,1172,1173;2818;1510;989,990;989,990;427;1510;1863;170;1612;934;1759;407;1510;1817;1029;58,59,60,61;1858,1859;58,59,60,61;1294;170;1510;755;3705;1863;1182,3705;1182,3705;1182,3705;2530;1510;461,1517,1565,1566,1567,1568;452;407;2425;1269;3626;407,1172,1173;1484;1760;516,884;1939;1844;706;1495;1863;1510;3896;58,59,60,61;645;391,802;1294;1823,1824;170;1832;1863;1041;989,990;981;1856,1858,1859;1858,1875;170;1757;1406;1698;446,773;407;941,1510;1510;2710;501,516,645;2100;58,485,814;1510;1863;3532;1391,1392;1083;1863;1858;1858;170,1136,1858;170,1858;989,990;684,1930,1931;3053;1510;453;1858,1875;391,802;391,802;1858;989,990;390;849;1094;1863;1858;415;1858;706;961;1329;-3112,-3113,-3114,-3115,-3116;3812;302;58,1578,3152;415;664;1510;484,1745,1746;981;676;1510;58;668;645;2255;1510;2818;1686;410,1126;390;1858,1875;170;755,1510;58,59;429,432;170;468;1759;878;1479,1480,1481,1482;58,59;1510;407,1172,1173;485;170;195;1510;58;1863;1863;58,645;253;645;1832;989,990;1148,3610;1515,1516,1517;1832;1596,1689,1690,1691,1692,1693,1694,1695,1696,1697;58,59,60,61;683;466,684,976,1760,2634,2635;58,468,1041;1863;3758,3759;1510;1510;1858,1859;1510,3267;668;1510,1813;58;645;1832;1832;61;1408;356,1117;2181;1832;1863;1832;2237;1860;829;407,1172,1173;645;1858;1148;514;58,59,60,61;98;2056;3075;3328;1510;407,1172,1173;1294;1719;645,1719;446,776;438,556,645;1836;1808;832;170,1707;1282;453,1041,3536;527,1123;58;1759;3893,3939;832;170;989,990;879;1863;514;1863;1510;1761;-1938;1510;1740;645;802;20,-59,378,379,380,381,382,383,-1938;407,1172,1173;1858,1859;422,872;1510;965;1107;447;1758;2585;170;516;1474;706;1858;645;706;1510;1563,3688;645;645;516;1510;427,1863;1228;1405;1294;989,990;645;160,584,3614;941,2458;1808;1832;61;58,59,60,61;1863;1858;461,1465;-1938;1858;1862;1863;1832;1474;58,1578;1417,2195;1858;1961,2965;1858;58;1832;1510;1510;1182;1510;527;407;3640;1823,1824;2468;645;1510;1863;1493;1510;1510;1832;1510;2794;422;897;1863;1863;-148,1383;2649;2649;645;407;2525;1863;1510;549;452;645;989,990;3026;1863;391,802;1510;170;452;1904,1905;1904,1905;-786,1904,1905;1904,1905;1904,1905;1904,1905;1904,1905;1904,1905;1904,1905;1904,1905;1474;1808;466,625,645;1510;668;514;170;645;391,802;170;1510;1294;1832;1858;427,1863;839;1863;1832;170;1858;1863;170;1510;1858,1859;989,990;645;1510;2590;1510;1228;3206;1863;2402;1510;461,1821;1510;1020,3203,3204;1029;58,59,60,61;160,167,3990;1496,1510,1594;1294;1510;1510;1294;1294;1294;934;1510;1510;674;1863;391,802;1858;989,990;58,527;1294;516;2194;1729;1858,1859;1758;58,1982,2008;1510;1294;636;1510;2761;645;148,756;594,1092;1510;1858;3686;603;2422;1510;645;1510;1760;1294;981;3958;1973;1145;170;1148,3610;1858;706;1335;1858,1876;1808;2306;981;2207;2934;246,354;1832;1294;3634,3635;2255;2255;849;1578;1269;2551;1510;1863;170;849;3744;1863;1481,1494;1468;1897;556,645;645;148,700;1294;1278;1808;2096;1148,3610;970;1184,1330;645;645;1858,1875;1863;1863;1510;706;1510;1510;58;1863;1356;1578;1578;2164;527;391,802;1510;58,468,1041,1926,1928;468;628,629;1808;1510;1481,1494;1858;958;1818;1510;1811;3217,3218,3219;1510;1832;1863;1510;1860;1858,1860;142;1863;1863;849;3179;1858;1510;1269;452;1858;447;849;2347;1484;1523;142;1832;391,802;58,59,60,61;1858;58;2215,2216;3536;645;1084;58,1041;645;1758;1863;1832;170;170;527;849;170;1510;1863;1858;1510;377;3725;524;1808;674;58,425,1237;1759;467;3634,3635;466;509;829;645,1041,1510;1148,3610;3119;1858;618;58,1578,3230;1856,1858,1859;2207;1757;773;1863;1858;645;1858;1863;1269;1858;912;1510;645;58,59,60,61;531;1832;516;684;1761;358,359,360;3316;676;1263;2589;1572,1573;556,645;1578;1858;645;2472;1578;1484;598;1863;1510;1510;410;170;706;452;378,379,381,3029;1855;989,990;485;376;3345;1858,1859;989,990;1041;1510;2794;2794;981;1904,1905;1904,1905;1904,1905;1904,1905;1904,1905;58,59,60,61;1863;1446;2818;170;645;500;1863;645;644;2849;1510;1510;989,990;1858,1875;1858;2966;645;645;989,990;1294;1294;1294;1858;829;1863;3204;1858,1859;148,522;981;1294;1294;1294;1510;58,59,60,61;2083;1345;1510;1863;2190;2006,2007;1294;1863;1863;500;58,59,60,61;1510;325;1510;2972,2973;58,59,60,61;1510;1832;829;1393;1294;98,1596,1676,1678,1679,1680,1681,1689,1690,1691,1692,1693,1694,1695,1696,1697;1510;1832;58,59,60,61;1285;1858;1863;461;1858;1510;58,1758;1510;1510;989,990;1618;1471;1832;3532;1101;1294;961;2218,4052,4055;1832;981;144,224;674;1294;1904,1905;1904,1905;2255;1863;849;2015;407,1172,1173;1510;645;427,1863;170;1808;645;516;1479,1517,1609,1610,1611;410;1863;1858;2164;1090;170;410;407,1172,1173;301;2047;1510;1858,1875;407;645;3173;1863;1858;1858;1148,3610;415;1393;1366;1145;142;1858;1858;829,1686;259,263;1863;1863;2337;645,1510;120,121,122,123;958;1510;516;170;58,1772,1928;829;58;58,59,60,61;438;1863;1808;1904,1905;453;645;170;2818;1832;58,59,60,61,1909;1904,1905;407,1172,1173;1510;2818;1863;170;1832;3634,3635;2700;958;1832;839;1268;3743;1510;829;1863;684,1578;3705;-1540;407,1172,1173;645;310,311;516,531;1832;514;1895,1896;1759;1510;1855;1858,1859;1510;1510;645,956;1510;2389;1904,1905;1904,1905;1904,1905;1904,1905;1510;170;1863;1832;58,59,60,61;2965;668;58,527,1759;1510;645,2342;1294;2513;1115,1303;1757;58,59,60,61;755;407;674;981;1863;1474;1858;58,59,60,61;1832;347,4008;1510;4012;644;58;58,59,60,61;2072;829;706;1393;2480;2945,2946,2947;1294;170;1578;1510;1858;170;1510;584;1858;429,1863;1863;645;934;3395;1510;58,59,60,61;947;1850,1851,1852,1853,1902;1294;1809;468;1858;1073;58;58,3152;856;856;1510;981;981;1832;829;1858,1875;3706;407,1172,1173;514;142,2851;1832;1904,1905;58,59,60,61;58,59,60,61;448;1474;961;645;645;451;58,59;1808;1510;1510;1465;1858;1832;1863;58,468,1926,1928;1863;1510;1510;1481,1494;170,1270;407,1172,1173;668;1510;1863;1863;1339;2576;1858;1510;829;516,1145;422;170;1863;1863;1510;989,990;1863;1760;1808;3389;910;58,1119,1120;170;2453;58,1761;706;1510;1510;1578,3407;1294;170;1863;446;1510;1510;2842;1759;1578;645;461,1821;1510;562,674;2696;407,1510;1858,1859;419,1832;1858,1859;674;1510;1858;1510;58;2413,2414;2743;58,59,60,61;1863;170;645;501;981;1510;1510;1123;1904,1905;1904,1905;1904,1905;1904,1905;879,1369;170;170;1832;1863;531;3634,3635;645;1510;461,1821;1759;1510;705;58,59,60,61;58,59,60,61;1904,1905;946;58,59,60,61;170;1863;452;170;1758,1759,1760;989,990;1858,1876;1832;1832;829;170;1510;170;1768;1832;2818;2044,2045;1858;1858;1863;3053;1510;170;593;355;58;1904,1905;499;3944,3945;856;3764;981;679;1904,1905;447;1041;1863;1510;2818;1294;58,59;1421;676;1145;645;1474;1863;2036;58,59,60,61;1858;1291;1711;407;1858;1858,1875;1510;1863;1832;391,802;2322;3364;2838;645;226,227;1863;1863;1759;1757;1863;461,1517,1565,1566,1567,1568;645,2282;1339;415;170;1832;1832;2727;1578,3454,3455,3456,3457,3458;58,59,60,61;1510;1371;3634,3635;461,1821;1393;2513;645;447;1858;1510;2333;1295;1510;142,2529;1282;1055,1056,1057;2132;148;1904,1905;1904,1905;1904,1905;1904,1905;1904,1905;1904,1905;182;1858;1510;2160;427,1863;1832;391,706;516;1863;1971;1863;3053;170,3221;668;645;1510;1221;1863;1858,1876;1858,1876;1832;934;1466;644;1904,1905;3352;1761;1858;453;81;1510;1510;849;1510;407;58,2842;522;2036;58,856;645;1858;617;98;1393;407,1172,1173;1510;1823,1824;58,693,694;2282;829;2375;1333;58,71;58,71;1904,1905;1510;676;407,1172,1173;1863;58;1152;1510;1863;1510;1863;1294;407;549;1123,1374,1760,1765;1510;1510;1863;3705;1863;958;1510;170;829;1904,1905;1904,1905;1863;170;171;3908;2216,2219;549;58,59,60,61;1758,1759,1760;1863;3634,3635;1758;3708;540;3053;1228;1904,1905;1761;1148,3610;3282;452;1808;2818;1863;170;1228;1510;427,1863;197,198;1145;1510;2868,2869;2697;1759;1393;415;1832;170;170;1858;1832;1510;1863;1510;351;2718,2719;1904,1905;1510;3634,3635;1863;1510;1983,1984;446;3705;1792;1510;613;1904,1905;461,900;410;1863;755;58,59,60,61;1858;1510;644;829;1858;3592;1510;832;1904,1905;407,1172,1173;1863;58,59,60,61;1863;58,1578,3230;1863;1863;1510;419,1863;392,393,409,410,4034;1148;58;58;1510;1832;1863;2207;1510;1510;394,395;1510;1904,1905;3634,3635;472,500,806,1761;407,1172,1173;1510;1510;422,644;3634,3635;3634,3635;676;3548;142;798;1474;142;645;59;1578;1863;58,1237,1278,1807;652;829;1474;1155;1863;1863;3231;1510;1863;1760;3634,3635;2690;58,59,60,61;407;1429;2998,3210;1510;644,1123;1863;1863;1393;3634,3635;1428;1863;1578;1863;516;3634,3635;1510;3634,3635;1863;1761;2522;1858,1859;1393;3634,3635;1123;170;829;829;58;2101;58,453;3634,3635;645;1015;1510;3636;170;1510;652;1510;1863;81;466,644;1904,1905;167,1675;1863;937;3634,3635;59;1904,1905;527;946;3460;1510;596;452;3634,3635;1863;1971;968;839;1863;645;3634,3635;1863;1510;3634,3635;1510;239,240;58,71;652";
        const arglistRefs = $scriptletArglistRefs$.split(';');
        for ( const i of todoIndices ) {
            for ( const ref of JSON.parse(`[${arglistRefs[i]}]`) ) {
                todo.add(ref);
            }
        }
    }
}

if ( $hasRegexes$ ) {
    const $scriptletFromRegexes$ = /* 8 */ ["-embed.c","^moon(?:-[a-z0-9]+)?-embed\\.com$","68,69","moonfile","^moonfile-[a-z0-9-]+\\.com$","68,69",".","^[0-9a-z]{5,8}\\.(art|cfd|fun|icu|info|live|pro|sbs|world)$","68,69","-mkay.co","^moo-[a-z0-9]+(-[a-z0-9]+)*-mkay\\.com$","68,69","file-","^file-[a-z0-9]+(-[a-z0-9]+)*-(moon|embed)\\.com$","68,69","-moo.com","^fle-[a-z0-9]+(-[a-z0-9]+)*-moo\\.com$","68,69","filemoon","^filemoon-[a-z0-9]+(?:-[a-z0-9]+)*\\.(?:com|xyz)$","68,69","tamilpri","(\\d{0,1})?tamilprint(\\d{1,2})?\\.[a-z]{3,7}","142,1578,2555"];
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
    const $scriptletFunctions$ = /* 57 */
[trustedEditInboundObject,adjustSetTimeout,jsonPruneFetchResponse,jsonPruneXhrResponse,trustedReplaceXhrResponse,trustedReplaceFetchResponse,trustedPreventDomBypass,jsonPrune,jsonEdit,jsonlEditXhrResponse,noWindowOpenIf,setConstant,abortCurrentScript,preventXhr,preventSetTimeout,preventFetch,trustedReplaceArgument,removeAttr,trustedOverrideElementMethod,abortOnPropertyRead,trustedReplaceOutboundText,trustedSuppressNativeMethod,preventAddEventListener,abortOnStackTrace,preventSetInterval,preventInnerHTML,adjustSetInterval,zeta_mb58kw52,trustedSetConstant,jsonEditFetchResponse,zeta_movh4xh5,abortOnPropertyWrite,noWebrtc,zeta_8echnktd,zeta_2brklsgs,zeta_djbdt5ns,preventRequestAnimationFrame,noEvalIf,preventBab,trustedPreventFetch,disableNewtabLinks,trustedJsonEditFetchResponse,editObjectOnSetter,trustedJsonEdit,trustedJsonEditXhrResponse,preventClipboardWrite,jsonEditXhrResponse,xmlPrune,m3uPrune,trustedPreventXhr,spoofCSS,zeta_j7s0f4ys,alertBuster,preventCanvas,mpegdashPrune,jsonEditFetchRequest,proxyApplyConfig];
    const $scriptletArgs$ = /* 3461 */ ["JSON.stringify","0","[?.attestationRequest][?.context.client.userAgent*=\"channel\"].context.client[?.clientName==\"WEB\"]+={\"clientScreen\":\"CHANNEL\"}","[?.attestationRequest][?.context.client.userAgent*=\"lactmilli\"]+={\"params\":\"8AUB\"}","[?.attestationRequest][?.context.client.userAgent*=\"yahi\"]+={\"params\":\"YAHI\"}","[?.attestationRequest][?.context.client.userAgent*=\"instream\"].playbackContext[?.contentPlaybackContext]+={\"adPlaybackContext\":{\"adType\":\"AD_TYPE_INSTREAM\"}}","[?.attestationRequest][?.context.client.userAgent=/channel|lactmilli|instream/].playbackContext.contentPlaybackContext.lactMilliseconds=\"${now}\"","[?.attestationRequest][?.context.client.userAgent=/adunit|channel|lactmilli|instream|inline|yahi|eafg/].playbackContext.contentPlaybackContext.referer=repl({\"regex\":\"(?:#reloadxhr)?$\",\"replacement\":\"#reloadxhr\"})","[native code]","17000","0.001","adPlacements adSlots playerResponse.adPlacements playerResponse.adSlots [].playerResponse.adPlacements [].playerResponse.adSlots","","propsToMatch","/\\/player(\\?|$)/","adPlacements adSlots playerResponse.adPlacements playerResponse.adSlots","/playlist?","/\\/player(?:\\?.+)?$/","\"adPlacements\"","\"no_ads\"","/playlist\\?list=|\\/player(?:\\?.+)?$|watch\\?[tv]=/","/\"adPlacements.*?([A-Z]\"\\}|\"\\}{2,4})\\}\\],/","/\"adPlacements.*?(\"adSlots\"|\"adBreakHeartbeatParams\")/gms","$1","player?","\"adSlots\"","/^\\W+$/","Node.prototype.appendChild","fetch","Request","JSON.parse","entries.[-].command.reelWatchEndpoint.adClientParams.isAd","/get_watch?","require.0.3.0.__bbox.require.[].3.1.__bbox.result.data.viewer.sideFeedUnit.nodes.[].new_adverts.nodes.[-].sponsored_data","data.viewer.sideFeedUnit.nodes.[].new_adverts.nodes.[-].sponsored_data","/graphql","..data.viewer..nodes.*[?.__typename==\"AdsSideFeedUnit\"]","require.0.3.0.__bbox.require.[].3.1.__bbox.result.data.serpResponse.results.edges.[-].rendering_strategy.view_model.story.sponsored_data.ad_id","..node[?.*.__typename==\"SponsoredData\"]","..nodes.*[?.sponsored_data]",".data[?.category==\"SPONSORED\"].node",".data.viewer.news_feed.edges.*[?.category==\"SPONSORED\"].node","Function.prototype.toString","Node.prototype.insertBefore","Element.prototype.insertAdjacentElement","Element.prototype.append","Element.prototype.prepend","Element.prototype.before","Element.prototype.after","Object.getOwnPropertyDescriptor","XMLHttpRequest.prototype","console.clear","undefined","globalThis","break;case","WebAssembly","atob","/vast.php?","/click\\.com|preroll|native_render\\.js|acscdn/","length:10001","]();}","500","162.252.214.4","true","c.adsco.re","adsco.re:2087","/^ [-\\d]/","Math.random","parseInt(localStorage['\\x","adBlockDetected","Math","localStorage['\\x","-load.com/script/","length:101",")](this,...","3000-6000","(new Error(","/fd/ls/lsp.aspx","document.getElementById","json:\"body\"","condition","ad-detection-bait","document.querySelector","-id-","scriptBlocked","false","blocked","testUrls","[]","adblock",".offsetHeight>0","/^https:\\/\\/pagead2\\.googlesyndication\\.com\\/pagead\\/js\\/adsbygoogle\\.js\\?client=ca-pub-3497863494706299$/","data-instype","ins.adsbygoogle:has(> div#aswift_0_host)","stay","url:https://googleads.g.doubleclick.net/pagead/ads?client=ca-pub-3497863494706299 method:HEAD mode:no-cors","throttle","121","String.prototype.indexOf","json:\"/\"","/premium","HTMLIFrameElement.prototype.remove","iframe[src^=\"https://googleads.g.doubleclick.net/pagead/ads?client=ca-pub-3497863494706299\"]","Worker.prototype.postMessage","4000-","g.doubleclick.net","length:100000","String.prototype.includes","/Copyright|doubleclick$/","favicon","length:252","Headers.prototype.get","/.+/","image/png.","/^text\\/plain;charset=UTF-8$/","json:\"content-type\"","cache-control","Headers.prototype.has","summerday","length:10","{\"type\":\"cors\"}","/offsetHeight|loaded/","HTMLScriptElement.prototype.onerror","pagead2.googlesyndication.com/pagead/js/adsbygoogle.js method:HEAD","emptyStr","Node.prototype.contains","{\"className\":\"adsbygoogle\"}","abort","load","showFallbackModal","Object.prototype.hasRightPartnership","falseFunc","Object.prototype.hasLeftPartnership","Object.prototype.hasTopPartnership","Object.prototype.hasBottomPartnership","document.querySelectorAll","security.js","Element.prototype.attachShadow","noopFunc","HTMLAnchorElement.prototype.click","a[target=\"_blank\"]","OffscreenCanvas.prototype.getContext","=== false","Element.prototype.removeChild","/blocked|tick/","/click|load/","/document\\.location|pop\\.|exo|cookie|\\.php/","/ok_|pemsrv\\.com|window\\.location\\.href/","parseInt","json:\"1800000000000\"","/^(179\\d{10}|null)$/","parseFloat","Number","/^179\\d{10}$/","/^https:\\/\\/s\\.pemsrv\\.com.+/","window.location.href","doAdRedirect","%22vt%22","html","DOMParser.prototype.parseFromString","\"/<[Aa]/\"","method:POST","/^wall-backdrop$/","/unknown|BLOCKED/i","Keen","stream.insertion","/video/auth/media","akamaiDisableServerIpLookup","MONETIZER101.init","/outboundLink/","Object.prototype.adService.initialize","v.fwmrm.net/ad/g/","war:noop-vmap1.xml","DD_RUM.addAction","nads.createAd","trueFunc","t++","dvtag.getTargeting","ga","class|style","div[id^=\"los40_gpt\"]","huecosPBS.nstdX","null","config.globalInteractions.[].bsData","googlesyndication","DTM.trackAsyncPV","_satellite","{}","_satellite.getVisitorId","mobileanalytics","pp_adblock_is_off","newPageViewSpeedtest","pubg.unload","generateGalleryAd","mediator","Object.prototype.subscribe","gbTracker","gbTracker.sendAutoSearchEvent","Object.prototype.vjsPlayer.ads","marmalade","setInterval","url:ipapi.co","doubleclick","isPeriodic","*","data-woman-ex","a[href][data-woman-ex]","data-trm-action|data-trm-category|data-trm-label",".trm_event","KeenTracking","network_user_id","cloudflare.com/cdn-cgi/trace","WP.prebid","onLoad","History","/(^(?!.*(Function|HTMLDocument).*))/",".call(null)","10","api","google.ima.OmidVerificationVendor","Object.prototype.omidAccessModeRules","googletag.cmd","skipAdSeconds","0.02","/recommendations.","_aps","/api/analytics","Object.prototype.setDisableFlashAds","DD_RUM.addTiming","chameleonVideo.adDisabledRequested","AdmostClient","analytics","native code","15000","(null)","5000","datalayer","Object.prototype.isInitialLoadDisabled","lr-ingest.io","listingGoogleEETracking","dcsMultiTrack","urlStrArray","pa","Object.prototype.setConfigurations","/gtm.js","JadIds","Object.prototype.bk_addPageCtx","Object.prototype.bk_doJSTag","passFingerPrint","optimizely","optimizely.initialized","document.createElement","break;case $.","google_optimize","google_optimize.get","_gsq","_gsq.push","_gsDevice","Object.prototype.renderDirect):matches-path(/\\/(?:weather\\/|pogoda\\/|hava\\/)/","iom","iom.c","_conv_q","_conv_q.push","google.ima.settings.setDisableFlashAds","pa.privacy","populateClientData4RBA","YT.ImaManager","UOLPD","UOLPD.dataLayer","__configuredDFPTags","URL_VAST_YOUTUBE","Adman","dplus","dplus.track","_satellite.track","/EzoIvent|TDELAY/","google.ima.dai","/froloa.js","adv","gfkS2sExtension","gfkS2sExtension.HTML5VODExtension","click","/event_callback=function\\(\\){window\\.location=t\\.getAttribute\\(\"href\"\\)/","AnalyticsEventTrackingJS","AnalyticsEventTrackingJS.addToBasket","AnalyticsEventTrackingJS.trackErrorMessage","initializeslideshow","b()","3000","ads","fathom","fathom.trackGoal","Origami","Origami.fastclick","{\"value\": \".ad-placement-interstitial\"}",".easyAdsBox","jad","hasAdblocker","Sentry","Sentry.init","TRC","TRC._taboolaClone","fp","fp.t","fp.s","initializeNewRelic","turnerAnalyticsObj","turnerAnalyticsObj.setVideoObject4AnalyticsProperty","turnerAnalyticsObj.getVideoObject4AnalyticsProperty","optimizelyDatafile","optimizelyDatafile.featureFlags","fingerprint","fingerprint.getCookie","gform.utils","gform.utils.trigger","get_fingerprint","moatPrebidApi","moatPrebidApi.getMoatTargetingForPage","readyPromise","cpd_configdata","cpd_configdata.url","yieldlove_cmd","yieldlove_cmd.push","dataLayer.push","1.1.1.1/cdn-cgi/trace","_etmc","_etmc.push","freshpaint","freshpaint.track","ShowRewards","stLight","stLight.options","DD_RUM.addError","sensorsDataAnalytic201505","sensorsDataAnalytic201505.init","sensorsDataAnalytic201505.quick","sensorsDataAnalytic201505.track","s","s.tl","taboola timeout","clearInterval(run)","smartech","/TDELAY|EzoIvent/","sensors","sensors.init","/piwik-","2200","2300","sensors.track","googleFC","adn","adn.clearDivs","_vwo_code","live.streamtheworld.com/partnerIds","gtag","_taboola","_taboola.push","clicky","clicky.goal","WURFL","_sp_.config.events.onSPPMObjectReady","gtm","gtm.trackEvent","mParticle.Identity.getCurrentUser","_omapp.scripts.geolocation","{\"value\": {\"status\":\"loaded\",\"object\":null,\"data\":{\"country\":{\"shortName\":\"\",\"longName\":\"\"},\"administrative_area_level_1\":{\"shortName\":\"\",\"longName\":\"\"},\"administrative_area_level_2\":{\"shortName\":\"\",\"longName\":\"\"},\"locality\":{\"shortName\":\"\",\"longName\":\"\"},\"original\":{\"ip\":\"\",\"ip_decimal\":null,\"country\":\"\",\"country_eu\":false,\"country_iso\":\"\",\"city\":\"\",\"latitude\":null,\"longitude\":null,\"user_agent\":{\"product\":\"\",\"version\":\"\",\"comment\":\"\",\"raw_value\":\"\"},\"zip_code\":\"\",\"time_zone\":\"\"}},\"error\":\"\"}}","JSGlobals.prebidEnabled","i||(e(),i=!0)","2500","elasticApm","elasticApm.init","ga.sendGaEvent","adConfig","ads.viralize.tv","adobe","MT","MT.track","ClickOmniPartner","adex","adex.getAdexUser","Adkit","Object.prototype.shouldExpectGoogleCMP","apntag.refresh","pa.sendEvent","Munchkin","Munchkin.init","ttd_dom_ready","ramp","appInfo.snowplow.trackSelfDescribingEvent","_vwo_code.init","adobePageView","adobeSearchBox","elements",".dropdown-menu a[href]","dapTracker","dapTracker.track","newrelic","newrelic.setCustomAttribute","adobeDataLayer","adobeDataLayer.push","Object.prototype._adsDisabled","Object.defineProperty","1","json:\"_adsEnabled\"","_adsDisabled","utag","utag.link","_satellite.kpCustomEvent","Object.prototype.disablecommercials","Object.prototype._autoPlayOnlyWithPrerollAd","Sentry.addBreadcrumb","freestar.newAdSlots","String.prototype.allReplace","executaGoogleAnalytics3","initJWPlayerMux","initJWPlayerMux.utils","initJWPlayerMux.utils.now","ambossAnalytics","ambossAnalytics.getUserAttribution","dataset.ready","script[src^=\"https://www.googletagmanager.com/gtag/js?id=\"]","Osano","Osano.cm","Osano.cm.addEventListener","Osano.cm.removeEventListener","pa.getVisitorId","googletag.setConfig","RISKX","RISKX.go","RISKX.setSid","Sentry.configureScope","baMet.register","Object.prototype.componentInScreen","HSBC","json:{\"SITE\":{},\"DCS\":{},\"PAGE\":{}}","smetrics.bankofamerica.com","ytInitialPlayerResponse.playerAds","ytInitialPlayerResponse.adPlacements","ytInitialPlayerResponse.adSlots","playerResponse.adPlacements","playerResponse.adPlacements playerResponse.playerAds playerResponse.adSlots adPlacements playerAds adSlots important","reelWatchSequenceResponse.entries.[-].command.reelWatchEndpoint.adClientParams.isAd entries.[-].command.reelWatchEndpoint.adClientParams.isAd","url:/reel_watch_sequence?","..itemSectionRenderer.contents.*[?.adSlotRenderer]","/get_watch","Object","fireEvent","enabled","force_disabled","hard_block","header_menu_abvs","10000","adsbygoogle","nsShowMaxCount","toiads","objVc.interstitial_web","adb","navigator.userAgent","require.0.3.0.__bbox.require.[].3.1.__bbox.result.data.serpResponse.results.edges.[-].relay_rendering_strategy.view_model.story.sponsored_data.ad_id","/\\{\"node\":\\{\"role\":\"SEARCH_ADS\"[^\\n]+?cursor\":[^}]+\\}/g","/api/graphql","/\\{\"node\":\\{\"__typename\":\"MarketplaceFeedAdStory\"[^\\n]+?\"cursor\":(?:null|\"\\{[^\\n]+?\\}\"|[^\\n]+?MarketplaceSearchFeedStoriesEdge\")\\}/g","/\\{\"node\":\\{\"__typename\":\"VideoHomeFeedUnitSectionComponent\"[^\\n]+?\"sponsored_data\":\\{\"ad_id\"[^\\n]+?\"cursor\":null\\}/","require.0.3.0.__bbox.require.[].3.1.__bbox.result.data.node","require.0.3.0.__bbox.require.[].3.1.__bbox.result.data.node.story.sponsored_data.ad_id","require.0.3.0.__bbox.require.[].3.1.__bbox.result.data.marketplace_search.feed_units.edges.[-].node.story.sponsored_data.ad_id","require.0.3.0.__bbox.require.[].3.1.__bbox.result.data.viewer.marketplace_feed_stories.edges.[-].node.story.sponsored_data.ad_id","data.viewer.instream_video_ads data.scrubber","..node[?.__typename==\"MarketplaceFeedAdStory\"]","__eiPb","detector","_ml_ads_ns","jQuery","cookie","showAds","adBlockerDetected","show","SmartAdServerASMI","repl:/\"adBlockWallEnabled\":true/\"adBlockWallEnabled\":false/","adBlockWallEnabled","_sp_._networkListenerData","SZAdBlockDetection","_sp_.config","AntiAd.check","open","/^/","showNotice","_sp_","$","_sp_.mms.startMsg","retrievalService","admrlWpJsonP","yafaIt","LieDetector","ClickHandler","IsAdblockRequest","InfMediafireMobileFunc","1000","newcontent","ExoLoader.serve","Fingerprint2","request=adb","AdController","popupBlocked","/\\}\\s*\\(.*?\\b(self|this|window)\\b.*?\\)/","_0x","stop","onload","ga.length","adblock_added","setTimeout","admc","exoNoExternalUI38djdkjDDJsio96","String.prototype.charCodeAt","ai_","window.open","adcashMacros","SBMGlobal.run.pcCallback","SBMGlobal.run.gramCallback","(!o)","(!i)","Object.prototype.hideAds","Object.prototype._getSalesHouseConfigurations","player-feedback","samInitDetection","decodeURI","decodeURIComponent","Date.prototype.toUTCString","Adcash","lobster","openLity","ad_abblock_ad","String.fromCharCode","shift","PopAds","AdBlocker","Adblock","addEventListener","displayMessage","runAdblock","TestAdBlock","ExoLoader","loadTool","cticodes","imgadbpops","document.write","redirect","4000","inlineScript","onclick","RunAds","/^(?:click|mousedown)$/","bypassEventsInProxies","jQuery.adblock","test-block","adi","ads_block","blockAdBlock","blurred","exoOpts","doOpen","prPuShown","flashvars.adv_pre_src","showPopunder","IS_ADBLOCK","page_params.holiday_promo","__NA","ads_priv","ab_detected","adsEnabled","document.dispatchEvent","t4PP","href|target","a[href=\"https://imgprime.com/view.php\"][target=\"_blank\"]","complete","String.prototype.charAt","sc_adv_out","mz","ad_blocker","AaDetector","_abb","puShown","/doOpen|popundr/","pURL","readyState","serve","stop()","btoa","Math.floor","AdBlockDetectorWorkaround","apstagLOADED","jQuery.hello","/Adb|moneyDetect/","isShowingAd","VikiPlayer.prototype.pingAbFactor","player.options.disableAds","__htapop","exopop","/^(?:load|click)$/","popMagic","script","atOptions","XMLHttpRequest","flashvars.adv_pre_vast","flashvars.adv_pre_vast_alt","x_width","getexoloader","disableDeveloper","oms.ads_detect","Blocco","2000","_site_ads_ns","hasAdBlock","pop","ltvModal","luxuretv.config","popns","pushiserve","creativeLoaded-","exoframe","/^load[A-Za-z]{12,}/","rollexzone","tick","registerLazyExo","ALoader","Object.prototype.AdOverlay","tkn_popunder","detect","dlw","40000","ctt()","can_run_ads","test","adsBlockerDetector","NREUM","pop3","__ads","ready","popzone","FlixPop.isPopGloballyEnabled","/exo","ads.pop_url","checkAdblockUser","checkPub","6000","tabUnder","check_adblock","l.parentNode.insertBefore(s","_blank","ExoLoader.addZone","encodeURIComponent","isAdBlockActive","raConf","__ADX_URL_U","tabunder","RegExp","POSTBACK_PIXEL","mousedown","preventDefault","'0x","Aloader","advobj","replace","popTimes","addElementToBody","phantomPopunders","$.magnificPopup.open","adsenseadBlock","stagedPopUnder","seconds","clearInterval","CustomEvent","exoJsPop101","popjs.init","-0x","closeMyAd","smrtSP","adblockSuspected","nextFunction","250","xRds","cRAds","myTimer","1500","advertising","countdown","tiPopAction","rmVideoPlay","r3H4","disasterpingu","AdservingModule","ab1","ab2","hidekeep","pp12","__Y","App.views.adsView.adblock","document.createEvent","ShowAdbblock","style","clientHeight","flashvars.adv_pause_html","/^(?:click|mousedown|mousemove|touchstart|touchend|touchmove)$/","system.popunder","BOOTLOADER_LOADED","PerformanceLongTaskTiming","proxyLocation","Int32Array","$.fx.off","popMagic.init","/DOMContentLoaded|load/","y.readyState","document.getElementsByTagName","smrtSB","href","#opfk","byepopup","awm","location","adBlockEnabled","getCookie","history.go","dataPopUnder","/error|canplay/","(t)","EPeventFire","additional_src","300","____POP","openx","is_noadblock","window.location","()","hblocked","AdBlockUtil","css_class.show","/adbl/i","error","[src]","CANG","DOMContentLoaded","adlinkfly","updato-overlay","innerText","/amazon-adsystem|example\\.com/","document.cookie","|","attr","scriptSrc","SmartWallSDK","segs_pop","cxStartDetectionProcess","Abd_Detector","counter","paywallWrapper","isAdBlocked","/enthusiastgaming|googleoptimize|googletagmanager/","css_class","ez","path","*.adserverDomain","$getWin","/doubleclick|googlesyndication/","__NEXT_DATA__.props.clientConfigSettings.videoAds","blockAds","_ctrl_vt.blocked.ad_script","registerSlideshowAd","50","debugger","mm","shortener","require","/^(?!.*(einthusan\\.io|yahoo|rtnotif|ajax|quantcast|bugsnag))/","caca","getUrlParameter","trigger","Ok","given","getScriptFromCss","method:HEAD","safelink.adblock","goafricaSplashScreenAd","try","/adnxs.com|onetag-sys.com|teads.tv|google-analytics.com|rubiconproject.com|casalemedia.com/","openPopunder","0x","xhr.prototype.realSend","initializeCourier","userAgent","_0xbeb9","1800","popAdsClickCount","redirectPage","adblocker","ad_","azar","popunderSetup","https","popunder","preventExit","hilltop","jsPopunder","aadblock","S9tt","popUpUrl","Notification","srcdoc","iframe","readCookieDelit","trafficjunky","checked","input#chkIsAdd","adSSetup","adblockerModal","750","capapubli","Aloader.serve","mouseup","sp_ad","app_vars.force_disable_adblock","adsHeight","onmousemove","button","yuidea-","adsBlocked","_sp_.msg.displayMessage","pop_under","location.href","_0x32d5","url","blur","CaptchmeState.adb","glxopen","adverts-top-container","disable","200","/googlesyndication|outbrain/","CekAab","timeLeft","testadblock","document.addEventListener","google_ad_client","UhasAB","adbackDebug","googletag","performance","rbm_block_active","SubmitDownload1","show()","user=null","getIfc","adblockcheck","!bergblock","overlayBtn","adBlockRunning","Date","htaUrl","_pop","n.trigger","CnnXt.Event.fire","_ti_update_user","&nbsp","document.body.appendChild","BetterJsPop","/.?/","setExoCookie","adblockDetected","frg","abDetected","target","I833","urls","urls.0","Object.assign","KeepOpeningPops","bindall","ad_block","time","KillAdBlock","read_cookie","ReviveBannerInterstitial","eval","GNCA_Ad_Support","checkAdBlocker","midRoll","adBlocked","Date.now","AdBlock","iframeTestTimeMS","runInIframe","deployads","='\\x","Debugger","stackDepth:3","warning","100","_checkBait","[href*=\"ccbill\"]","close_screen","onerror","dismissAdBlock","VMG.Components.Adblock","adblock_popup","FuckAdBlock","isAdEnabled","promo","_0x311a","mockingbird","adblockDetector","crakPopInParams","console.log","hasPoped","Math.round","flashvars.protect_block","flashvars.video_click_url","h1mm.w3","banner","google_jobrunner","blocker_div","onscroll","keep-ads","#rbm_block_active","checkAdblock","checkAds","#DontBloxMyAdZ","#pageWrapper","adpbtest","initDetection","alert","check","isBlanketFound","showModal","myaabpfun","sec","_wm","adFilled","//","NativeAd","gadb","damoh.ani-stream.com","showPopup","mouseout","clientWidth","adrecover","checkadBlock","gandalfads","Tool","cmnnrunads","downloadJSAtOnload","run","ReactAds","phtData","adBlocker","StileApp.somecontrols.adBlockDetected","killAdBlock","innerHTML","google_tag_data","readyplayer","noAdBlock","autoRecov","adblockblock","popit","popstate","noPop","Ha","rid","[onclick^=\"window.open\"]","spot","adsOk","adBlockChecker","_$","12345","flashvars.popunder_url","urlForPopup","isal","/innerHTML|AdBlock/","checkStopBlock","overlay","popad","!za.gl","document.hidden","adblockEnabled","ppu","adspot_top","is_adblocked","/offsetHeight|google|Global/","an_message","Adblocker","pogo.intermission.staticAdIntermissionPeriod","localStorage","timeoutChecker","t","my_pop","nombre_dominio",".height","!?safelink_redirect=","document.documentElement","time.html","block_detected","/^(?:mousedown|mouseup)$/","ckaduMobilePop","tieneAdblock","popundr","obj","ujsmediatags method:HEAD","adsAreBlocked","spr","document.oncontextmenu","document.onmousedown","document.onkeydown","compupaste","redirectURL","bait","!atomtt","TID","!/download\\/|link/","Math.pow","adsanity_ad_block_vars","pace","ai_adb","openInNewTab",".append","!!{});","runAdBlocker","setOCookie","document.getElementsByClassName","td_ad_background_click_link","initBCPopunder","flashvars.logo_url","flashvars.logo_text","nlf.custom.userCapabilities","displayCookieWallBanner","adblockinfo","JSON","pum-open","svonm","/\\/VisitorAPI\\.js|\\/AppMeasurement\\.js/","popjs","/adblock/i","count","LoadThisScript","showPremLite","closeBlockerModal","5","keydown","Popunder","ag_adBlockerDetected","document.head.appendChild","bait.css","Date.prototype.toGMTString","initPu","jsUnda","ABD","adBlockDetector.isEnabled","adtoniq","__esModule","break","myFunction_ads","areAdsDisplayed","gkAdsWerbung","pop_target","onLoadEvent","is_banner","$easyadvtblock","mfbDetect","Pub2a","/adsbygoogle|initDetection/","block","console","send","ab_cl","V4ss","#clickfakeplayer","popunders","visibility","sadbl","aclib","show_dfp_preroll","show_youtube_preroll","brave_load_popup","pageParams.dispAds","PrivateMode","scroll","document.bridCanRunAds","doads","pu","MessageChannel","advads_passive_ads","tmohentai","pmc_admanager.show_interrupt_ads","ai_adb_overlay","AlobaidiDetectAdBlock","jwplayer.utils.Timer","showMsgAb","Advertisement","type","input[value^=\"http\"]","wutimeBotPattern","adsbytrafficjunkycontext","abp1","$REACTBASE_STATE.serverModules.push","popup_ads","ipod","pr_okvalida","scriptwz_url","enlace","Popup","$.ajax","appendChild","Exoloader","offsetWidth","zomap.de","/$|adBlock/","adblockerpopup","adblockCheck","checkVPN","cancelAdBlocker","Promise","setNptTechAdblockerCookie","for-variations","!api?call=","cnbc.canShowAds","ExoSupport","/^(?:click|mousedown|mouseup)$/","di()","getElementById","loadRunative","value.media.ad_breaks","onAdVideoStart","zonefile","pwparams","fuckAdBlock","firefaucet","mark","stop-scrolling","detectAdBlock","Adv","blockUI","adsafeprotected","'\\'","oncontextmenu","Base64","disableItToContinue","google","parcelRequire","mdpDeBlocker","flashvars.adv_start_html","mobilePop","/_0x|debug/","my_inter_listen","EviPopunder","adver","tcpusher","preadvercb","document.readyState","prerollMain","/^(click|mousedown|mousemove|touchstart|touchend|touchmove)/","popping","adsrefresh","/ai_adb|_0x/","canRunAds","mdp_deblocker","adBlock","bi()","#divDownload","modal","dclm_ajax_var.disclaimer_redirect_url","$ADP","load_pop_power","MG2Loader","/SplashScreen|BannerAd/","Connext","break;","checkTarget","i--","Time_Start","blocker","adUnits","afs_ads","b2a","data.[].vast_url","deleted","MutationObserver","LIDetector","ezstandalone.enabled","damoh","foundation.adPlayer.bitmovin","homad-global-configs","weltConfig.switches.videoAdBlockBlocker","XMLHttpRequest.prototype.open","svonm.com","/\"enabled\":\\s*true/","\"enabled\":false","adReinsertion","window.__gv_org_tfa","Object.prototype.adReinsertion.homad.enabled","getHomadConfig","aud.springserve.com","<VAST version=\"3.0\"></VAST>","timeupdate","testhide","getComputedStyle","doOnce","popi","googlefc","angular","detected","{r()","450","ab","go_popup","Debug","offsetHeight","length","noBlocker","/youboranqs01|spotx|springserve/","js-btn-skip","r()","adblockActivated","penci_adlbock","Number.isNaN","fabActive","gWkbAdVert","noblock","!gdrivedownload","document.onclick","daCheckManager","prompt","data-popunder-url","saveLastEvent","friendlyduck",".post.movies","purple_box","detectAdblock","adblockDetect","adsLoadable","allclick_Public","a#clickfakeplayer",".fake_player > [href][target]",".link","'\\x","initAdserver","splashpage.init","window[_0x","checkSiteNormalLoad","/blob|injectedScript/","ASSetCookieAds","___tp","STREAM_CONFIGS",".clickbutton","Detected","XF","hide","mdp",".test","backgroundBanner","interstitial","letShowAds","antiblock","ulp_noadb",".show","url:!luscious.net","Object.prototype.adblock_detected","afterOpen","AffiliateAdBlock",".appendChild","adsbygoogle.loaded","ads_unblocked","xxSetting.adBlockerDetection","ppload","RegAdBlocking","a.adm","checkABlockP","Drupal.behaviors.adBlockerPopup","ADBLOCK","fake_ad","samOverlay","!refine?search","native","koddostu_com_adblock_yok","player.ads.cuePoints","adthrive","!t.me","bADBlock","secondsLeft","better_ads_adblock","tie","Adv_ab","ignore_adblock","$.prototype.offset","ea.add","ad_pods.0.ads.0.segments.0.media ad_pods.1.ads.1.segments.1.media ad_pods.2.ads.2.segments.2.media ad_pods.3.ads.3.segments.3.media ad_pods.4.ads.4.segments.4.media ad_pods.5.ads.5.segments.5.media ad_pods.6.ads.6.segments.6.media ad_pods.7.ads.7.segments.7.media ad_pods.8.ads.8.segments.8.media","mouseleave","NativeDisplayAdID","t()","zendplace","mouseover","event.triggered","_cpp","sgpbCanRunAds","pareAdblock","ppcnt","data-ppcnt_ads","main[onclick]","Blocker","AdBDetected","navigator.brave","document.activeElement","{ \"value\": {\"tagName\": \"IFRAME\" }}","runAt","2","clickCount","body","hasFocus","{\"value\": \"Mozilla/5.0 (iPhone14,3; U; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/19A346 Safari/602.1\"}","timeSec","getlink","/wpsafe|wait/","timer","/getElementById|gotoo/","/visibilitychange|blur/","stopCountdown","tid","ppuQnty","web_share_ads_adsterra_config wap_short_link_middle_page_ad wap_short_link_middle_page_show_time data.ads_cpm_info","value","Object.prototype.isAllAdClose","DOMNodeRemoved","data.meta.require_addon data.meta.require_captcha data.meta.require_notifications data.meta.require_og_ads data.meta.require_video data.meta.require_web data.meta.require_related_topics data.meta.require_custom_ad_step data.meta.og_ads_offers data.meta.addon_url data.displayAds data.linkCustomAdOffers","data.getDetailPageContent.linkCustomAdOffers.[-].title","data.getTaboolaAds.*","/chp_?ad/","tp-time","/adblock|isRequestPresent/","bmcdn6","window.onload","devtools","documentElement.innerHTML","{\"type\": \"opaque\"}","document.hasFocus","/adoto|\\/ads\\/js/","htmls","?key=","isRequestPresent","xmlhttp","data-ppcnt_ads|onclick","#main","#main[onclick*=\"mainClick\"]","disabled",".btn-primary","focusOut","googletagmanager","suaads","/window\\.location\\.href|n/","8000","json:\"drall_Suaads_annersads_JS__randomAds\"","/randomAds|div-gpt-ad|divAdsInit/","json:\"ADs-1\"","json:\"click\"","visibilitychange","window.addEventListener","/visibilitychange|blur|pageshow|keydown|beforeunload|pagehide/","/\\$\\('|ai-close/","app_vars.please_disable_adblock","/scorecardresearch\\.com|outbrain\\.com|taboola\\.com|criteo\\.net|rubiconproject\\.com|adform\\.net|casalemedia\\.com|adservice\\.google\\.com/","shouldOpenPopUp","/blur|focus/","bypass",".MyAd > a[target=\"_blank\"]","antiAdBlockerHandler","onScriptError","php","div_form","private","navigator.webkitTemporaryStorage.queryUsageAndQuota","contextmenu","remainingSeconds","mode:no-cors","0.1","Math.random() <= 0.15","checkBrowser","bypass_url","1600","showadas","submit","validateForm","throwFunc","/pagead2\\.googlesyndication\\.com|inklinkor\\.com/","EventTarget.prototype.addEventListener","delete window","/countdown--|getElementById/","SMart1","/outbrain\\.com|adligature\\.com|quantserve\\.com|srvtrck\\.com|googlesyndication/","{\"type\": \"cors\"}","doTest","checkAdsBlocked",".btn","http","Element.prototype.closest","rel","chp_ad","document.documentElement.lang.toLowerCase","maxclick","#get-link-button","Swal.fire","surfe.pro","czilladx","adsbygoogle.js","!devuploads.com","war:googlesyndication_adsbygoogle.js","window.adLink","localStorage._d","blank","google_srt","json:0.61234","vizier","checkAdBlock","xnjThB","googlesyn","displayAdBlockerMessage","pastepc","checkMockObjects","detectedAdblock","pagead2.googlesyndication.com/pagead/js/adsbygoogle.js","googletagservices","isTabActive","[href*=\"survey\"]","adForm","clicked","charCodeAt","decodeURIComponent(escape","clicksCount",".data.isAdsEnabled=false","/api/files","document.createTreeWalker","json:{\"acceptNode\": \"function() { return NodeFilter.FILTER_REJECT; }\"}","if","prevent","..directLink","..props[?.children*=\"clicksCount\"].children","adskeeper",".downloadbtn","zigi_tag_id","self.Math","setCookie","advertisement3","start","AdLink","!buzzheavier.com","removeChild",".href","notifyExec","fairAdblock","data.value data.redirectUrl data.bannerUrl","/admin/settings","!gcloud","/seconds--|timeLeft--/","json:\"main\"","/div-gpt-ad-dgking|\\.GoogleActiveViewElement/","/div-gpt-ad-|\\.adsbygoogle/","json:\"container\"","adblock_detected","/pub\\.clickadu|bing\\.com/","a","\"/chp_?ad/\"","/blocked|null/","remaining--","json:\"header\"","/ad-chk|aads-frame/","!/document|window|const|var|let/","RegExp.prototype.exec.constructor","\"+\"","Function.prototype.constructor","anonymous@https","Document.prototype.addEventListener.call","HTMLElement.prototype.click.call","HTMLElement.prototype.click.apply","/document.createElement|window.open/",".cfd","script[data-domain=","document.body.appendChild(s)","document.head||","push","ov.advertising.tisoomi.loadScript","abp","userHasAdblocker","embedAddefend","/injectedScript.*inlineScript/","/(?=.*onerror)(?=^(?!.*(https)))/","/injectedScript|blob/","hommy.mutation.mutation","hommy","hommy.waitUntil","ACtMan","video.channel","/(www\\.[a-z]{8,16}\\.com|cloudfront\\.net)\\/.+\\.(css|js)$/","/popundersPerIP[\\s\\S]*?Date[\\s\\S]*?getElementsByTagName[\\s\\S]*?insertBefore/","clearTimeout","/www|cloudfront/","shouldShow","matchMedia","target.appendChild(s","l.appendChild(s)","document.body.appendChild(s","no-referrer-when-downgrade","Object.prototype.loadHillTopBanner","/^data:/","Document.prototype.createElement","\"script\"","litespeed/js","appendTo:","myEl","ExoDetector","!embedy","Pub2","/loadMomoVip|loadExo|includeSpecial/","loadNeverBlock","flashvars.mlogo","adver.abFucker.serve","displayCache","vpPrerollVideo","SpecialUp","flashvars","v2:$./^adv_/","zfgloaded","/btoa|break/","/\\st\\.[a-zA-Z]*\\s/","navigator","/(?=^(?!.*(https)))/","key in document","zfgformats","zfgstorage","zfgloadedpopup","/\\st\\.[a-zA-Z]*\\sinlineScript/","zfgcodeloaded","outbrain",".ads_mode=\"0\"","/embed/settings",".ads_mode_dl=\"0\"","$+={\"ads_suppressed\":true}","/inlineScript|stackDepth:1/","_app/immutable/chunks/","Date.prototype.toISOString","wpadmngr.com","adserverDomain","AtcshAltNm",".js?_=","FingerprintJS","/https|stackDepth:3/","HTMLAllCollection","shown_at","!/d/","PlayerConfig.config.CustomAdSetting","affiliate","_createCatchAllDiv","/click|mouse/","document","PlayerConfig.trusted","PlayerConfig.config.AffiliateAdViewLevel","3","univresalP","puTSstrpcht","!/prcf.fiyar|themes|pixsense|.jpg/","hold_click","focus","js_func_decode_base_64","decodeURIComponent(atob","/(?=^(?!.*(https|injectedScript)))/","jQuery.popunder","AdDetect","ai_front","abDetectorPro","/googlesyndication|doubleclick/","src=atob","Document.prototype.querySelector","\"/[0-9a-f]+-modal/\"","/\\/[0-9a-f]+\\.js\\?ver=/","tie.ad_blocker_detector","admiral",".EnableAdmiral=false",".ShowAds=false","gnt.x.uam","interactive","gnt.u.z","..admiralScriptCode",".props[?.id==\"admiral-bootstrap\"].dangerouslySetInnerHTML","decodeURI(decodeURI","dc.adfree","__INITIAL_DATA__.siteData.admiralScript",".cmd.unshift","/admiral/","runtimeConfig.AM_PATH","CACHE",".indexOf","/runtime-config","__disableAds","..props.children.*[?.key==\"admiral-script\"]","..props.config.ad.enabled=false","..Admiral.isEnabled=false","..admiral=false","/ad\\.doubleclick\\.net|static\\.dable\\.io/","error-report.com","loader.min.js","content-loader.com","Element.prototype.setAttribute","/error-report|new Promise|;await new|:\\[?window|&&window,|void 0\\]|location\\.href|void 0\\|\\|window|,window,|void 0,window|,window\\]|\\)\\.join\\(String\\.fromCharCode|adShieldError/","script[id][onerror]","asap","quitAfter","loadShield","Range.prototype.createContextualFragment","json:\"<script></script>\"","html-load.com",".scriptLoader.*[?.id==\"ad_stack_split_provider\"]","adLight","objAd.loadAdShield","window.myAd.runAd","RT-1562-AdShield-script-on-Huffpost","{\"value\": \"(function(){let link=document.createElement('link');link.rel='stylesheet';link.href='//image.ygosu.com/style/main.css';document.head.appendChild(link)})()\"}","error-report","{\"value\": \"(function(){let link=document.createElement('link');link.rel='stylesheet';link.href='https://loawa.com/assets/css/loawa.min.css';document.head.appendChild(link)})()\"}","/content-loader\\.com|css-load\\.com|html-load\\.com/","json:\"setTimeout((()=>{if(!location.pathname.startsWith('/game'))return;const t=document.getElementById('question-label');t&&(window.animation=lottie.loadAnimation({container:t,renderer:'svg',loop:!0,autoplay:!1,path:'/assets/animationsLottielab/gameDots.json'}))}),1e3);\"","__cfRLUnblockHandlers","disableAdShield","page-kit.io","json:\"freestar-bootstrap\"","/^[A-Z][a-z]+_$/","\"data-sdk\"","abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=","features.ad02 features.adshield","HTMLScriptElement.prototype.setAttribute","AHE.is_member","AppBootstrapData.config.adshieldAdblockRecovery","AppBootstrapData.config.adshieldNativeAdRecovery","AppBootstrapData.__initializeFeatures__.adshieldAdblockRecovery.enabled","AppState.reduxState.features.adshieldAdblockRecovery","..adshieldAdblockRecovery=false","/fetchappbootstrapdata","..adshieldAdblockRecovery.enabled=false","/error-report|nowprocket/","/loadRecoveryScripts|nowprocket/","autoRecovery","Object.prototype._adShieldLoaded",".featureFlags.*[?.featureName==\"AdShield\"]","/configs","Object.prototype.htmlLoadScriptService.loadScript","Object.prototype.removeAdScripts","HTMLScriptElement.prototype.onload","..AdShield.isEnabled=false","String.prototype.match","__adblocker","__INITIAL_STATE__.config.theme.ads.isAdBlockerEnabled","generalTimeLeft","__INITIAL_STATE__.gameLists.gamesNoPrerollIds.indexOf","__aaZoneid","DoodPop",".check=false","#over","document.ontouchend","Array.prototype.shift","/^.+$/s","HTMLElement.prototype.click","premium","'1'","playID","openNewTab","download-wrapper","MDCore.adblock","Please wait","#downloadvideo","unescape","ads playerAds","..allowAdblock=true","displayLayer","adId","pop_init","adsbyjuicy","np.detect","/^ms(hta|iexec)(\\.exe)? |^(bash <<<|curl -kfsSL) \\$\\(echo .+? base64 -d\\b|^cmd \\/c .*?\\bcurl .+?(\\.exe|\\.bat)\\b|^cmd .*?\\bfor \\/f .*?\\bdelims .*?\\bpow |(^|\\\\)powershell(\\.exe)? .*?-w(indowStyle)? h(idden)?\\b|(^|\\\\)powershell(\\.exe)? .*?-w[a-z]* m[a-z]* |(^|\\\\)powershell(\\.exe)? .*?-NoP\\b|(^|\\\\)powershell(\\.exe)? .*?-e(xecution)?p(olicy)? b(ypass)?\\b|(^|\\\\)powershell(\\.exe)? .*?-e(xecution)?p(olicy)? u(nrestricted)?\\b|(^|\\\\)powershell(\\.exe)? .*?\\biex\\(|(^|\\\\)powershell(\\.exe)? .*?Invoke-Expression|(^|\\\\)powershell.+?Invoke-WebRequest|(^|\\\\)powershell.+?-UseBasicParsing|^cmd .*?\\/c .+? -nop .+? iex\\b|^(cmd|powershell)\\b.+?recaptcha|^(cmd|powershell)\\b.+?#(Verification|     )|^(cmd|powershell)\\b.+?     #|^osascript .+?\\bcurl http|^curl -s\\b.+?\\| (bash|sh|zsh)\\b|^\\/bin\\/(bash|sh|zsh) -c\\b.+?\\bcurl|^bash -c\\b.+?\\$\\(curl|^python3? -c\\b.+?\\b(exec|urllib|subprocess)\\b|^echo .+?base64 .+?\\b(bash|osascript|z?sh)\\b|openssl base64 -d|^curl\\b .+?chmod \\+x.+?&&|^(bash|sh|osascript)\\b.+?recaptcha|^(bash|sh|osascript)\\b.+?#(Verification|     )|^(bash|sh|osascript)\\b.+?     #|^wget .+?\\| (bash|sh)\\b|^curl\\b.+?-o\\b.+?\\/tmp\\/.+?&&|^nc .+?-e \\/bin\\/(bash|sh)\\b|^\\/tmp\\/.+?chmod \\+x.+?&&|^wget -q.+?\\.(sh|py|bin|elf)\\b|^cmd .+?\\bcertutil .+?\\b(\\.exe|\\.bat)\\b|(^|\\\\)powershell(\\.exe)? .+?\\birm .+?\\.[a-z]+\\/.+?powershell|\\bpcalua(\\.exe)? .*?\\b(curl|powershell|saps|cmd)\\b|^cmd .+?\\bcmdkey .+?\\bschtasks|^Invoke-Command .+?Base64String|^c(onhost|md) .*?--headless |^iex\\(i(rm|wr) |^\\(?irm .+?\\biex\\b|^%COMSPEC% .*?\\bstart .*?\\/min\\b|^cmd .*?\\/c .*?%TEMP%.*?\\.bat\\b|\\bconvert\\b.*?\\$env:ComSpec\\b|^<#Verification|^Invoke-WebRequest .+?\\bwscript(\\.exe)?\\b|^\\$url.+?\\n\\$filename.+?\\.exe/msi","domAlert","Beware, uBlock Origin blocked a potential ClickFix attack: ${text}","excludeMatches","/Maintainer|Contributor|^\\{|^http|^(git|import|require|use) /i","Beware. uBlock Origin blocked a potential ClickFix attack: ${text}","dataset.zone","length:40000-60000","prerolls midrolls postrolls comm_ad house_ad pause_ad block_ad end_ad exit_ad pin_ad content_pool vertical_ad elements","/detail","adClosedTimestamp","data.item.[-].business_info.ad_desc","/feed/rcmd","killads","NMAFMediaPlayerController.vastManager.vastShown","api/v1/detail","xmxalr","HTMLIFrameElement.prototype.contentWindow","reklama-flash-body","/scoreUrl|pingUrl/","appPageData.appAds","appPageData.appAdsHandles","fakeAd","adUrl",".azurewebsites.net","assets.preroll assets.prerollDebug","/stream-link","/doubleclick|ad-delivery|googlesyndication/","__NEXT_DATA__.runtimeConfig._qub_sdk.qubConfig.video.adBlockerDetectorEnabled","__NEXT_DATA__.runtimeConfig._qub_sdk.qubConfig.ad.adBlockerDetectorEnabled","..adBlockerDetectorEnabled=false","history.replaceState","data.[].relationships.advert data.[].relationships.vast","offers","/#EXT-X-DISCONTINUITY\\n(?:#EXTINF:.*,\\n.+?adType=preroll[\\s\\S]+?)(?=#EXT-X-DISCONTINUITY)/gm","/.*\\.m3u8/","tampilkanUrl","__ninjaAdMaxAbdLoaded",".layers.*[?.metadata.name==\"POI_Ads\"]","/PCWeb_Real.json",".*[?.adId]","/gaid=","war:noop-vast2.xml","consent","arePiratesOnBoard","__INIT_CONFIG__.randvar","instanceof Event","prebidConfig.steering.disableVideoAutoBid","xml","await _0x","json:\"Blog1\"","ad-top","adblock.js","adbl",".getComputedStyle","STORAGE2","app_advert","googletag._loaded_","closeBanner","NoTenia","breaks interstitials info","interstitials","xpath(//*[name()=\"Period\"][.//*[name()=\"BaseURL\" and contains(text(),\".mp.lura.live/prod/\")]] | //*[name()=\"MPD\"]/@mediaPresentationDuration)",".mpd","ads.policy.skipMode","/play","ad_slots","plugins.dfp","lura.live/prod/","/prog.m3u8","!embedtv.best","pop_","Array.isArray","POP_URL","repl:/\"popactive\":true/\"popactive\":false/","[style*=\"z-index\"]","remove()","(!1)","backRedirect","adv_pre_duration","adv_post_duration",".offsetHeight","!asyaanimeleri.",".*[?.linkurl^=\"http\"]","initPop","app._data.ads","message","adsense","reklamlar","json:[{\"sure\":\"0\"}]","/api/video","Object.prototype.showInterstitialAd","skipAdblockCheck","data.header_script data.footer_script data.direct_link_ads data.direct_link_ads_vip_1 data.direct_link_ads_vip_2 data.direct_link_ads_play_vip_2 data.direct_link_ads_zoom_vip_2","/config","createAgeModal","Object[_0x","adsPlayer","this","json:\"mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/145.0.0.0 safari/537.36\"","mozilla/5.0","popup=","()}",".art-control-fullscreen","a[target=\"_blank\"][rel*=\"sponsored\"]","shopeeLinks","pubAdsService","offsetLeft","config.pauseInspect","appContext.adManager.context.current.adFriendly","HTMLIFrameElement",".style","dsanity_ad_block_vars","show_download_links","downloadbtn","height","blockAdBlock._options.baitClass","/AdBlock/i","charAt","fadeIn","checkAD","latest!==","detectAdBlocker",".ready","/'shift'|break;/","xpv","xpv.v",".clientHeight===0","document.blocked_var","____ads_js_blocked","wIsAdBlocked","WebSite.plsDisableAdBlock","css","videootv","ads_blocked","samDetected","Drupal.behaviors.agBlockAdBlock","NoAdBlock","mMCheckAgainBlock","countClicks","settings.adBlockerDetection","eabdModal","ab_root.show","gaData","wrapfabtest","fuckAdBlock._options.baitClass","$ado","/ado/i","app.js","popUnderStage","samAdBlockAction","googlebot","advert","bscheck.adblocker","qpcheck.ads","tmnramp","!sf-converter.com","clickAds.banner.urls","json:[{\"url\":{\"limit\":0,\"url\":\"\"}}]","ad","show_ads","ignielAdBlock","isContentBlocked","GetWindowHeight","/pop|wm|forceClick/","CloudflareApps.installs.Ik7rmQ4t95Qk.options.measureDomain","detectAB1",".init","ActiveXObject","uBlockOriginDetected","/_0x|localStorage\\.getItem/","google_ad_status","googletag._vars_","googletag._loadStarted_","google_unique_id","google.javascript","google.javascript.ads","google_global_correlator","ads.servers.[].apiAddress","paywallGateway.truncateContent","Constant","u_cfg","adBlockDisabled","__NEXT_DATA__.props.pageProps.adVideo","blockedElement","/ad","onpopstate","popState","adthrive.config","__C","ad-block-popup","exitTimer","innerHTML.replace","ajax","abu","countDown","HTMLElement.prototype.insertAdjacentHTML","_ads","clientSide.adbDetect","eabpDialog","TotemToolsObject","puHref","flashvars.adv_postpause_vast","/Adblock|_ad_/","advads_passive_groups","GLX_GLOBAL_UUID_RESULT","Pop","f.parentNode.removeChild(f)","swal","keepChecking","t.pt","clickAnywhere urls","a[href*=\"/ads.php\"][target=\"_blank\"]","nitroAds","class.scroll","/showModal|isBlanketFound/","disableDeveloperTools","[onclick*=\"window.open\"]","openWindow","Check","checkCookieClick","readyToVote","12000","!vidmoly","anchor.href","target|href","a[href^=\"//\"]","wpsite_clickable_data","insertBefore","offsetParent","meta.advertise","next","vidorev_jav_plugin_video_ads_object.vid_ads_m_video_ads","data.attributes.config.freewheel data.attributes.config.featureFlags.dPlayer","data.attributes.ssaiInfo.forecastTimeline data.attributes.ssaiInfo.vendorAttributes.nonLinearAds data.attributes.ssaiInfo.vendorAttributes.videoView data.attributes.ssaiInfo.vendorAttributes.breaks.[].ads.[].adMetadata data.attributes.ssaiInfo.vendorAttributes.breaks.[].ads.[].adParameters data.attributes.ssaiInfo.vendorAttributes.breaks.[].timeOffset","xpath(//*[name()=\"MPD\"][.//*[name()=\"BaseURL\" and contains(text(),'dash_clear_fmp4') and contains(text(),'/a/')]]/@mediaPresentationDuration | //*[name()=\"Period\"][./*[name()=\"BaseURL\" and contains(text(),'dash_clear_fmp4') and contains(text(),'/a/')]])","xpath(//*[name()=\"MPD\"][.//*[name()=\"BaseURL\" and contains(text(),\"emea-free\")]]/@mediaPresentationDuration | //*[name()=\"MPD\"][.//*[name()=\"BaseURL\" and contains(text(),\"emea-free\")]]//*[name()=\"Period\"]/@start | //*[name()=\"Period\"][./*[name()=\"BaseURL\" and contains(text(),\"emea-free\")]])","ssaiInfo","data.attributes.ssaiInfo","/videoPlaybackInfo","adsProvider.init","SDKLoaded","css_class.scroll","mnpwclone","0.3","7000","[href*=\"nihonjav\"]","/null|Error/","bannersRequest","/atob|overlay/","vads","doSecondPop","a[href][onclick^=\"getFullStory\"]","!newdmn","parentNode.removeChild","popUp","devtoolschange","rccbase_styles","POPUNDER_ENABLED","plugins.preroll","DHAntiAdBlocker","/out.php","ishop_codes","#advVid","location.replace","showada","showax","adp","__tnt","compatibility","popundrCheck","rexxx.swp","constructor","p18","clickHandler","onbeforeunload","prebid","asc","json:{\"cmd\": [null], \"que\": [null], \"wrapperVersion\": \"6.19.0\", \"refreshQue\": {\"waitDelay\": 3000, \"que\": []}, \"isLoaded\": true, \"bidderSettings\": {}, \"libLoaded\": true, \"version\": \"v9.20.0\", \"installedModules\": [], \"adUnits\": [], \"aliasRegistry\": {}, \"medianetGlobals\": {}}","google_tag_manager","json:{ \"G-Z8CH48V654\": { \"_spx\": false, \"bootstrap\": 1704067200000, \"dataLayer\": { \"name\": \"dataLayer\" } }, \"SANDBOXED_JS_SEMAPHORE\": 0, \"dataLayer\": { \"gtmDom\": true, \"gtmLoad\": true, \"subscribers\": 1 }, \"sequence\": 1 }","ADBLOCKED","Object.prototype.adsEnabled","ai_run_scripts","clearInterval(i)","ospen","pu_count","mypop","adblock_use","Object.prototype.adblockFound","download","1100","createCanvas","bizpanda","__spotSettings","/pop|_blank/","movie.advertising.ad_server playlist.movie.advertising.ad_server","unblocker","playerAdSettings.adLink","playerAdSettings.waitTime","computed","manager","window.location.href=link","moonicorn.network","/dyn\\.ads|loadAdsDelayed/","xv.sda.pp.init","xv.conf.dyn.ads","xv.conf.dyn.excld","onreadystatechange","skmedix.com","skmedix.pl","MediaContainer.Metadata.[].Ad","doubleclick.com","opaque","_init","href|target|data-ipshover-target|data-ipshover|data-autolink|rel","a[href^=\"https://thumpertalk.com/link/click/\"][target=\"_blank\"]","/touchstart|mousedown|click/","latest","secs","event.simulate","isAdsLoaded","adblockerAlert","/^https?:\\/\\/redirector\\.googlevideo\\.com.*/","/.*m3u8/","cuepoints","cuepoints.[].start cuepoints.[].end cuepoints.[].start_float cuepoints.[].end_float","Period[id*=\"-roll-\"][id*=\"-ad-\"]","pubads.g.doubleclick.net/ondemand","/ads/banner","reachGoal","Adb","randStr","SPHMoverlay","ai","timer.remove","popupBlocker","afScript","Object.prototype.parseXML","Object.prototype.blackscreenDuration","Object.prototype.adPlayerId","/ads",":visible","mMcreateCookie","downloadButton","SmartPopunder.make","readystatechange","document.removeEventListener",".button[href^=\"javascript\"]","animation","status","adsblock","pub.network","timePassed","timeleft","input[id=\"button1\"][class=\"btn btn-primary\"][disabled]","t(a)",".fadeIn()","result","evolokParams.adblock","[src*=\"SPOT\"]","asap stay",".pageProps.__APOLLO_STATE__.*[?.__typename==\"AotSidebar\"]","/_next/data","pageProps.__TEMPLATE_QUERY_DATA__.aotFooterWidgets","props.pageProps.data.aotHomepageTopBar props.pageProps.data.aotHomepageTopBar props.pageProps.data.aotHeaderAdScripts props.pageProps.data.aotFooterWidgets","counter--","daadb","l-1","_htas","magnificPopup","skipOptions","method:HEAD url:doubleclick.net","xpath(//*[name()=\"Period\"][.//*[name()=\"BaseURL\" and contains(text(),\"https:\")]])","style.display","tvid.in/log","1150","0.5","testadtags ad","document.referrer","quadsOptions","history.pushState","loadjscssfile","load_ads","/debugger|offsetParent/","/ads|imasdk/","6","__NEXT_DATA__.props.pageProps.adsConfig","make_rand_div","new_config.timedown","catch","google_ad","response.timeline.elements.[-].advertiserId","url:/api/v2/tabs/for_you","timercounter","document.location","innerHeight","cainPopUp","#timer","!bowfile.com","cloudfront.net/?","href|target|data-onclick","a[id=\"dl\"][data-onclick^=\"window.open\"]","a.getAttribute(\"data-ad-client\")||\"\"","truex","truex.client","answers","!display","/nerveheels/","No","foreverJQ","/document.createElement|stackDepth:2/","container.innerHTML","top-right","hiddenProxyDetected","SteadyWidgetSettings.adblockActive","temp","inhumanity_pop_var_name","url:googlesyndication","enforceAdStatus","starPop","Element.prototype.matches","litespeed","__PoSettings","HTMLSelectElement","youtube","aTagChange","Object.prototype.ads","display","a[onclick^=\"setTimeout\"]","detectBlockAds","eb","/analytics|livestats/","/nextFunction|2000/","resource_response.data.[-].pin_promotion_id resource_response.data.results.[-].pin_promotion_id","initialReduxState.pins.{-}.pin_promotion_id initialReduxState.resources.UserHomefeedResource.*.data.[-].pin_promotion_id","player","mahimeta","__htas","chp_adblock_browser","/adb/i","tdBlock",".t-out-span [href*=\"utm_source\"]","src",".t-out-span [src*=\".gif\"]","notifier","penciBlocksArray",".panel-body > .text-center > button","modal-window","isScrexed","fallbackAds","popurl","SF.adblock","() => n(t)","() => t()","startfrom","Math.imul","checkAdsStatus","wtg-ads","/ad-","void 0","/__ez|window.location.href/","D4zz","Object.prototype.ads.nopreroll_",").show()","function","/open.*_blank/","advanced_ads_ready","loadAdBlocker","HP_Scout.adBlocked","SD_IS_BLOCKING","isBlocking","adFreePopup","Object.prototype.isPremium","__BACKPLANE_API__.renderOptions.showAdBlock",".quiver-cam-player--ad-not-running.quiver-cam-player--free video","debug","Object.prototype.isNoAds","tv3Cmp.ConsentGiven","distance","site-access","chAdblock","/,ad\\n.+?(?=#UPLYNK-SEGMENT)/gm","/uplynk\\.com\\/.*?\\.m3u8/","remaining","/ads|doubleclick/","/Ads|adbl|offsetHeight/",".innerHTML","onmousedown",".ob-dynamic-rec-link","setupSkin","/app.js","dqst.pl","PvVideoSlider","_chjeuHenj","[].data.searchResults.listings.[-].targetingSegments","noConflict","preroll_helper.advs","/show|innerHTML/","create_ad","contador","Object.prototype.enableInterstitial","addAds","/show|document\\.createElement/","loadXMLDoc","register","MobileInGameGames","__osw","uniconsent.com","/coinzillatag|czilladx/","divWidth","Script_Manager","Script_Manager_Time","bullads","Msg","!download","/click|mousedown/","adjsData","AdService.info.abd","UABP","adBlockDetectionResult","popped","/xlirdr|hotplay\\-games|hyenadata/","document.body.insertAdjacentHTML","exo","tic","download_loading","detector_launch","pu_url","Click","afStorage","puShown1","onAdblockerDetected","htmlAds","second","lycos_ad","150","passthetest","checkBlock","/thaudray\\.com|putchumt\\.com/","popName","vlitag","asgPopScript","/(?=^(?!.*(jquery|turnstile|challenge-platform)))/","Object.prototype.loadCosplay","Object.prototype.loadImages","FMPoopS","/window\\['(?:\\\\x[0-9a-f]{2}){2}/","urls.length","importantFunc","console.warn","sam","current()","confirm","pandaAdviewValidate","showAdBlock","aaaaa-modal","/(?=^(?!.*(http)))/","()=>","$onet","adsRedirectPopups","canGetAds","method:/head/i","Storage.prototype.setItem","bannerDismissed","length:11000","goToURL","ad_blocker_active","init_welcome_ad","setinteracted",".MediaStep","data.xdt_injected_story_units.ad_media_items","dataLayer","document.body.contains","nothingCanStopMeShowThisMessage","window.focus",".freewheel.prerolls=false","/player",".freewheel.midrolls=false","imasdk","TextEncoder.prototype.encode","!/^\\//","fakeElement","adEnable","adtech-brightline adtech-google-pal adtech-iab-om","/playbackInfo","fallback.ssaiInfo manifest.url","fallback.ssaiInfo","xpath(//*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"]/@start | //*[name()=\"Period\"][not(.//*[name()=\"SegmentTimeline\"])][not(.//*[name()=\"ContentProtection\"])] | //*[name()=\"Period\"][./*[name()=\"BaseURL\"]][not(.//*[name()=\"ContentProtection\"])][not(.//*[name()=\"AdaptationSet\"][@contentType=\"text\"])])","/dash.mpd","xpath(//*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"]/@start | //*[name()=\"Period\"][not(.//*[name()=\"SegmentTimeline\"])][not(.//*[name()=\"ContentProtection\"])] | //*[name()=\"Period\"][./*[name()=\"BaseURL\"]][not(.//*[name()=\"ContentProtection\"])])","/-vod-.+\\.mpd/","htmlSectionsEncoded","event.dispatch","adx","popupurls","displayAds","cls_report?","arrvast","-0x1","childNodes","wbar","[href=\"/bestporn.html\"]","_adshrink.skiptime","gclid","event","!yt1d.com","button#getlink","button#gotolink","AbleToRunAds","PreRollAd.timeCounter","result.ads","tpc.googlesyndication.com","id","#div-gpt-ad-footer","#div-gpt-ad-pagebottom","#div-gpt-ad-relatedbottom-1","#div-gpt-ad-sidebottom","goog","document.body","abpblocked","p$00a","openAdsModal","paAddUnit","gloacmug.net","items.[-].potentialActions.0.object.impressionToken items.[-].hasPart.0.potentialActions.0.object.impressionToken","context.adsIncluded","refresh","adt","Array.prototype.indexOf","interactionCount","/cloudfront|thaudray\\.com/","test_adblock","vastEnabled","/adskeeper|cloudflare/","#gotolink","detectadsbocker","c325","two_worker_data_js.js","adobeModalTestABenabled","FEATURE_DISABLE_ADOBE_POPUP_BY_COUNTRY","questpassGuard","isAdBlockerEnabled","shortConfig","akadb","eazy_ad_unblocker","json:\"\"","unlock","adswizz.com","document.onkeypress","adsSrc","sssp","emptyObj","[style*=\"background-image: url\"]","[href*=\"click?\"]","/freychang|passback|popunder|tag|banquetunarmedgrater/","google-analytics","myTestAd","/<VAST version.+VAST>/","<VAST version=\\\"4.0\\\"></VAST>","deezer.getAudiobreak","Ads","smartLoaded","..ads_audio=false","ShowAdBLockerNotice","ad_listener","!shrdsk","notify","AdB","push-allow-modal",".hide","(!0)","Delay","ima","Cookiebot","\"adsBlocked\"","stream.insertion.adSession stream.insertion.points stream.insertion stream.sources.*.insertion pods.0.ads","ads.metadata ads.document ads.dxc ads.live ads.vod","site-access-popup","*.tanya_video_ads","deblocker","data?","script.src","/#EXT-X-DISCONTINUITY.{1,100}#EXT-X-DISCONTINUITY/gm","mixed.m3u8","feature_flags.interstitial_ads_flag","feature_flags.interstitials_every_four_slides","?","downloadToken","waldoSlotIds","Uint8Array","redirectpage","13500","adblockstatus","adScriptLoaded","/adoto|googlesyndication/","props.sponsoredAlternative","ad-delivery","document.documentElement.lang","adSettings","banner_is_blocked","Object.prototype.rekids","Object.prototype.gafSlot","Object.prototype.advViewability","WP.inline","/getComputedStyle[\\s\\S]*?style\\.display=\"none\"[\\s\\S]*?styleBlocked[\\s\\S]*?detected/","__headpayload","WP","r https","WP.gaf.loadBunch","Object.prototype.loadBunch","Object.prototype.bodyCode","consoleLoaded?clearInterval","Object.keys","[?.context.bidRequestId].*","RegExp.prototype.test","json:\"wirtualnemedia\"","/^dobreprogramy$/","decodeURL","updateProgress","/salesPopup|mira-snackbar/","Object.prototype.adBlocked","DOMAssistant","rotator","adblock popup vast","detectImgLoad","killAdKiller","current-=1",".access=true","/no_ads/config","/zefoy\\.com\\S+:3:1/","/getComputedStyle|bait/","AController_3","json:\"div\"","ins",".clientHeight","googleAd","/showModal|chooseAction|doAction|callbackAdsBlocked/","_shouldProcessLink","cpmecs","/adlink/i","[onclick]","noreferrer","[onload^=\"window.open\"]","dontask","aoAdBlockDetected","button[onclick^=\"window.open\"]","function(e)","touchstart","Brid.A9.prototype.backfillAdUnits","adlinkfly_url","siteAccessFlag","/adblocker|alert/","doubleclick.net/instream/ad_status.js","war:doubleclick_instream_ad_status.js","redURL","/children\\('ins'\\)|Adblock|adsbygoogle/","dct","slideShow.displayInterstitial","openPopup","Object.getPrototypeOf","plugins","ai_wait_for_jquery","pbjs","tOS2","ips","Error","/stackDepth:1\\s/","tryShowVideoAdAsync","chkADB","onDetected","detectAdblocker","document.ready","a[href*=\"torrentico.top/sim/go.php\"]","success.page.spaces.player.widget_wrappers.[].widget.data.intervention_data","VAST",".props.pageProps.page.blocks.*[?..resource^=\"nc-ad\"]","{\"value\": \"Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1\"}","navigator.standalone","navigator.platform","{\"value\": \"iPhone\"}","searchCount","empire.pop","empire.direct","empire.directHideAds","pagead2.googlesyndication.com","empire.mediaData.advisorMovie","empire.mediaData.advisorSerie","fuckadb","[type=\"submit\"]","setTimer","auto_safelink","!abyss.to","daadb_get_data_fetch","penci_adlbock.ad_blocker_detector","siteAccessPopup","/adsbygoogle|adblock|innerHTML|setTimeout/","/innerHTML|_0x/","Object.prototype.adblockDetector","biteDisplay","blext","/[a-z]\\(!0\\)/","800","vidorev_jav_plugin_video_ads_object","vidorev_jav_plugin_video_ads_object_post","dai_iframe","popactive","/detectAdBlocker|window.open/","S_Popup","eazy_ad_unblocker_dialog_opener","rabLimit","-1","popUnder","/GoToURL|delay/","nudgeAdBlock","/googlesyndication|ads/","/Content/_AdBlock/AdBlockDetected.html","adBlckActive","AB.html","feedBack.showAffilaePromo","ShowAdvertising","a img:not([src=\"images/main_logo_inverted.png\"])","visible","a[href][target=\"_blank\"],[src^=\"//ad.a-ads.com/\"]","avails","amazonaws.com","ima3_dai","topaz.","FAVE.settings.ads.ssai.prod.clips.enabled","FAVE.settings.ads.ssai.prod.liveAuth.enabled","FAVE.settings.ads.ssai.prod.liveUnauth.enabled","ssaiInfo fallback.ssaiInfo","xpath(//*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"]/@start | //*[name()=\"Period\"][.//*[name()=\"BaseURL\" and contains(text(),\".prd.media.\")]])","/sandbox/i","analytics.initialized","autoptimize","UserCustomPop","method:GET","data.reg","time-events","/#EXTINF:[^\\n]+\\nhttps:\\/\\/redirector\\.googlevideo\\.com[^\\n]+/gms","/\\/ondemand\\/.+\\.m3u8/","/redirector\\.googlevideo\\.com\\/videoplayback[\\s\\S]*?dclk_video_ads/",".m3u8","phxSiteConfig.gallery.ads.interstitialFrequency","loadpagecheck","popupAt","modal_blocker","art3m1sItemNames.affiliate-wrapper","\"\"","isOpened","playerResponse.adPlacements playerResponse.playerAds adPlacements playerAds","GeneratorAds","isAdBlockerActive","pop.doEvent","'shift'","bFired","scrollIncrement","di.app.WebplayerApp.Ads.Adblocks.app.AdBlockDetectApp.startWithParent","a#downloadbtn[onclick^=\"window.open\"]","alink","/ads|googletagmanager/","sharedController.adblockDetector",".redirect","sliding","a[onclick]","infoey","settings.adBlockDetectionEnabled","displayInterstitialAdConfig","response.ads","/api","checkAdBlockeraz","blockingAds","setC","/data?|hideLayer/","popup","/atob|innerHTML/","/adScriptPath|MMDConfig/","xpath(//*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"]/@start | //*[name()=\"Period\"][.//*[name()=\"BaseURL\" and contains(text(),'adease')]])","[media^=\"A_D/\"]","adease adeaseBlob vmap","adease","aab","ips.controller.register","plugins.adService","QiyiPlayerProphetData.a.data","wait","/adsbygoogle|doubleclick/","adBreaks.[].startingOffset adBreaks.[].adBreakDuration adBreaks.[].ads adBreaks.[].startTime adBreak adBreakLocations","/session.json","xpath(//*[name()=\"Period\"][.//*[name()=\"BaseURL\" and contains(text(),\"_ad\") and contains(text(),\"creative\")]] | //*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"]/@start)","/\\/episode\\/.+?\\.mpd\\?/","session.showAds","toggleAdBlockInfo","cachebuster","config","OpenInNewTab_Over","/native|\\{n\\(\\)/","[style^=\"background\"]","[target^=\"_\"]","bodyElement.removeChild","aipAPItag.prerollSkipped","aipAPItag.setPreRollStatus","\"ads_disabled\":false","\"ads_disabled\":true","payments","reklam_1_saniye","reklam_1_gecsaniye","reklamsayisi","reklam_1","psresimler","data","runad","url:doubleclick.net","war:googletagservices_gpt.js","criteo","HTMLImageElement.prototype.onerror","++","\"flashtalking\"","war:32x32.png","triggered","data.home.home_timeline_urt.instructions.[].entries.[-].content.itemContent.promotedMetadata","url:/Home","data.search_by_raw_query.search_timeline.timeline.instructions.[].entries.[-].content.itemContent.promotedMetadata","url:/SearchTimeline","data.threaded_conversation_with_injections_v2.instructions.[].entries.[-].content.items.[].item.itemContent.promotedMetadata","url:/TweetDetail","data.user.result.timeline_v2.timeline.instructions.[].entries.[-].content.itemContent.promotedMetadata","url:/UserTweets","data.immersiveMedia.timeline.instructions.[].entries.[-].content.itemContent.promotedMetadata","url:/ImmersiveMedia","powerAPITag","rodo.checkIsDidomiConsent","newAdblockBoardDisplayed","protection","xtime","smartpop","EzoIvent","/doubleclick|googlesyndication|vlitag/","overlays","googleAdUrl","/googlesyndication|nitropay/","uBlockActive","/api/v1/events","Scribd.Blob.AdBlockerModal","AddAdsV2I.addBlock","xpath(//*[name()=\"Period\"][.//*[name()=\"BaseURL\" and contains(text(),'/ad/')]])","/Detect|adblock|style\\.display|\\.call\\(null\\)/","/google_ad_client/","total","popCookie","/0x|sandCheck/","hasAdBlocker","ShouldShow","offset","startDownload","cloudfront","[href*=\"jump\"]","!direct","a0b","/outbrain|criteo|thisiswaldo|media\\.net|ohbayersbur|adligature|quantserve|srvtrck|\\.css|\\.js/","2000-5000","contrformpub","data.device.adsParams data.device.adSponsorshipTemplate","url:/appconfig","innerWidth",".main-wrap","window.ts","initials",".*[?.advertiser]","$./^(bannerUnderComments|bannerBottom)$/","$.xplayerPluginSettings./^(ads|banner|bannerBottom)$/","/googlesyndication|googima\\.js|imasdk/","__brn_private_mode","download_click","Object.prototype.skipPreroll","/adskeeper|bidgear|googlesyndication|mgid/","fwmrm.net","/\\/ad\\/g\\/1/","adverts.breaks","result.responses.[].response.result.cards.[-].data.offers","ADB","downloadTimer","/ads|google/","/googlesyndication|googletagservices/","DisableDevtool","eClicked","number","sync","PlayerLogic.prototype.detectADB","ads-twitter.com","all","havenclick","VAST > Ad","/tserver","Object.prototype.prerollAds","secure.adnxs.com/ptv","war:noop-vast4.xml","notifyMe","alertmsg","/streams","adsClasses","gsecs","adtagparameter","dvsize","52","removeDLElements","/\\.append|\\.innerHTML|undefined|\\.css|blocker|flex|\\$\\('|obfuscatedMsg/","warn","adc","majorse","completed","testerli","showTrkURL","/popunder/i","readyWait","document.body.style.backgroundPosition","invoke","ssai_manifest ad_manifest playback_info.ad_info qvt.playback_info.ad_info","Object.prototype.setNeedShowAdblockWarning","load_banner","initializeChecks","HTMLDocument","video-popup","splashPage","adList","adsense-container","detect-modal","Node.prototype.removeChild","/^\\[object HTMLImageElement\\]$/","/emojis8\\.js:/","/attachonce == false/","ifmax","adRequest","nads","nitroAds.abp","adinplay.com","onloadUI","war:google-ima.js","/^data:text\\/javascript/","randomNumber","current.children","tmDetectAdBlocker","probeScript","PageLoader.DetectAb","!koyso.","adStatus","popUrl","one_time","PlaybackDetails.[].DaiVod","consentGiven","ad-block","data.searchClassifiedFeed.searchResultView.0.searchResultItemsV2.edges.[-].node.item.content.creative.clickThroughEvent.adsTrackingMetadata.metadata.adRequestId","data.me.personalizedFeed.feedItems.[-].promo.creative.clickThroughUrl.adsTrackingMetadata.metadata.adRequestId","data.me.rhrFeed.feedItems.[-].promo.creative.clickThroughUrl.adsTrackingMetadata.metadata.sponsor","mdpDeblocker","doubleclick.net","BN_CAMPAIGNS","media_place_list","...","/\\{[a-z]\\(!0\\)\\}/","canRedirect","/\\{[a-z]\\(e\\)\\}/","[].data.displayAdsV3.data.[-].__typename","[].data.TopAdsProducts.data.[-].__typename","[].data.topads.data.[-].__typename","/\\{\"id\":\\d{9,11}(?:(?!\"ads\":\\{\"id\":\"\").)+?\"ads\":\\{\"id\":\"\\d+\".+?\"__typename\":\"ProductCarouselV2\"\\},?/g","/graphql/InspirationCarousel","/\\{\"category_id\"(?:(?!\"ads\":\\{\"id\":\"\").)+?\"ads\":\\{\"id\":\"\\d+\".+?\"__typename\":\"ProductCarouselV2\"\\},?/g","/graphql/InspirationalCarousel","/\\{\"id\":\\d{9,11}(?:(?!\"isTopads\":false).)+?\"isTopads\":true.+?\"__typename\":\"recommendationItem\"\\},/g","/\\/graphql\\/productRecommendation/i","/,\\{\"id\":\\d{9,11}(?:(?!\"isTopads\":false).)+?\"isTopads\":true(?:(?!\"__typename\":\"recommendationItem\").)+?\"__typename\":\"recommendationItem\"\\}(?=\\])/","/\\{\"(?:productS|s)lashedPrice\"(?:(?!\"isTopads\":false).)+?\"isTopads\":true.+?\"__typename\":\"recommendationItem\"\\},?/g","/graphql/RecomWidget","/\\{\"appUrl\"(?:(?!\"isTopads\":false).)+?\"isTopads\":true.+?\"__typename\":\"recommendationItem\"\\},?/g","/graphql/ProductRecommendationQuery","adDetails","/secure?","data.search.products.[-].sponsored_ad.ad_source","url:/plp_search_v2?","data_source_modules.*.module_data.search_response.products.[-].sponsored_ad.ad_source","/pages/slp","GEMG.GPT.Interstitial","amiblock","String.prototype.concat","adBlockerDismissed","adBlockerDismissed_","karte3","18","callbackAdsBlocked","sandDetect",".ad-zone","showcfkModal","amodule.data","emptyArr","inner-ad","_ET","jssdks.mparticle.com","session.sessionAds session.sessionAdsRequired","/session","/#EXTINF:[^\\n]+\\n[^\\n]+?\\/preroll\\/[^\\n]+/gms","getComputedStyle(el)","/(?=^(?!.*(orchestrate|cloudflare)))/","Object.prototype.ADBLOCK_DETECTION",".features.*[?.slug==\"adblock-detection\"].enabled=false","/ad/","/count|verify|isCompleted/","postroll","itemList.[-].ad_info.ad_id","url:api/recommend/item_list/","/adinplay|googlesyndication/","!hidan.sh","ask","interceptClickEvent","isAdBlockDetected","pData.adblockOverlayEnabled","ad_block_detector","attached","div[class=\"share-embed-container\"]","/^\\w{11}[1-9]\\d+\\.ts/","cabdSettings","/outbrain|adligature|quantserve|adligature|srvtrck/","adsConfiguration","/vod",".streams.*.adUnits=[]","/manifest/video","/#EXTINF[^\\n]+\\n[^\\n]+?segment[^\\n]+/gms","layout.sections.mainContentCollection.components.[].data.productTiles.[-].sponsoredCreative.adGroupId","/search","fp-screen","puURL","!vidhidepre.com","[onclick*=\"_blank\"]","[onclick=\"goToURL();\"]","a[href][onclick^=\"window.open\"]","leaderboardAd","#leaderboardAd","placements.processingFile","dtGonza.playeradstime","\"-1\"","EV.Dab","ablk","/ethicalads\\.io|nitropay\\.com/","HTMLImageElement.prototype.onload","img","Image.prototype.complete","2d","Element.prototype.getBoundingClientRect",".length","HTMLImageElement.prototype.naturalWidth","240","#artifactFileContent","shutterstock.com","Object.prototype.adUrl","sorts.[].recommendationList.[-].contentMetadata.EncryptedAdTrackingData","/ads|chp_?ad/","ads.[-].ad_id","wp-ad","/clarity|googlesyndication/","playerEnhancedConfig.run","/aff|jump/","!/mlbbox\\.me|_self/","aclib.runPop","ADS.isBannersEnabled","ADS.STATUS_ERROR","json:\"COMPLETE\"","button[onclick*=\"open\"]","getComputedStyle(testAd)","openPopupForChapter","Object.prototype.popupOpened","src_pop","gifs.[-].cta.link","boosted_gifs","adsbygoogle_ama_fc_has_run","doThePop","thanksgivingdelights","yes.onclick","!vidsrc.","popundersPerIP","createInvisibleTrigger","jwDefaults.advertising","elimina_profilazione","elimina_pubblicita","snigelweb.com","abd","pum_popups","checkerimg","uzivo","openDirectLinkAd","!nikaplayer.com",".adsbygoogle:not(.adsbygoogle-noablate)","json:\"img\"","playlist.movie.advertising.ad_server","PopUnder","data.[].affiliate_url","cdnpk.net/v2/images/search?","cdnpk.net/Rest/Media/","war:noop.json","data.[-].inner.ctaCopy","?page=","/gampad/ads?",".adv-",".length === 0",".length === 31","window.matchMedia('(display-mode: standalone)').matches","Object.prototype.DetectByGoogleAd","a[target=\"_blank\"][style]","/adsActive|POPUNDER/i","/Executed|modal/","[breakId*=\"Roll\"]","/content.vmap","/#EXT-X-KEY:METHOD=NONE\\n#EXT(?:INF:[^\\n]+|-X-DISCONTINUITY)\\n.+?(?=#EXT-X-KEY)/gms","/media.m3u8","window.navigator.brave","sentry","showTav","document['\\x","showADBOverlay","springserve.com","document.documentElement.clientWidth","outbrain.com","s4.cdnpc.net/front/css/style.min.css","slider--features","s4.cdnpc.net/vite-bundle/main.css","data-v-d23a26c8","cdn.taboola.com/libtrc/san1go-network/loader.js","feOffset","hasAdblock","taboola","adbEnableForPage","/adblock|isblock/i","/\\b[a-z] inlineScript:/","result.adverts","data.pinotPausedPlaybackPage","fundingchoicesmessages","isAdblock","button[id][onclick*=\".html\"]","dclk_video_ads","ads breaks cuepoints times","streamProviders.[].adPlaylist streamProviders.[].ads","playback.","odabd","pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?ord=","b.google_reactive_tag_first","sbs.demdex.net/dest5.html?d_nsid=0&ord=","Demdex.canSetThirdPartyCookies","securepubads.g.doubleclick.net/pagead/ima_ppub_config?ippd=https%3A%2F%2Fwww.sbs.com.au%2Fondemand%2F&ord=","[\"4117\"]","configs.*.properties.componentConfigs.slideshowConfigs.*.interstitialNativeAds","url:/config","list.[].link.kicker","/content/v1/cms/api/amp/Document","properties.tiles.[-].isAd","/mestripewc/default/config","openPop","circle_animation","CountBack","990","displayAdBlockedVideo","/undefined|displayAdBlockedVideo/","cns.library","json:\"#app-root\"","google_ads_iframe","data-id|data-p","[data-id],[data-p]","BJSShowUnder","BJSShowUnder.bindTo","BJSShowUnder.add","Object.prototype._parseVAST","Object.prototype.createAdBlocker","Object.prototype.isAdPeriod","breaks custom_breaks_data pause_ads video_metadata.end_credits_time","pause_ads","/playlist","breaks","breaks custom_breaks_data pause_ads","xpath(//*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"][.//*[name()=\"BaseURL\" and contains(text(),\"/ads-\")]] | //*[name()=\"Period\"][starts-with(@id,\"ad\")] | //*[name()=\"Period\"][starts-with(@id,\"Ad\")] | //*[name()=\"Period\"]/@start)","MPD Period[id^=\"Ad\"i]","/inter","ABLK","_n_app.popunder","_n_app.options.ads.show_popunders","N_BetterJsPop.object","jwplayer.vast","Fingerprent2","grecaptcha.ready","test.remove","isAdb","/click|mouse|touch/","puOverlay","opopnso","c0ZZ","cuepointPlaylist vodPlaybackUrls.result.playbackUrls.cuepoints vodPlaylistedPlaybackUrls.result.playbackUrls.pauseBehavior vodPlaylistedPlaybackUrls.result.playbackUrls.pauseAdsResolution vodPlaylistedPlaybackUrls.result.playbackUrls.intraTitlePlaylist.[-].shouldShowOnScrubBar ads","xpath(//*[name()=\"Period\"][.//*[@value=\"Ad\"]] | /*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"]/@start)","[value=\"Ad\"]","xpath(//*[name()=\"Period\"][.//*[@value=\"Draper\"]] | /*[name()=\"MPD\"]/@mediaPresentationDuration | //*[name()=\"Period\"]/@start)","[value=\"Draper\"]","xpath(//*[name()=\"Period\"][.//*[name()=\"BaseURL\" and contains(text(),\"/interstitial/\")]] | /*[name()=\"MPD\"][.//*[name()=\"BaseURL\" and contains(text(),\"/interstitial/\")]]/@mediaPresentationDuration | /*[name()=\"MPD\"][.//*[name()=\"BaseURL\" and contains(text(),\"/interstitial/\")]]/*[name()=\"Period\"]/@start)","ue_adb_chk","moa_id","ad.doubleclick.net bid.g.doubleclick.net ggpht.com google.co.uk google.com googleads.g.doubleclick.net googleads4.g.doubleclick.net googleadservices.com googlesyndication.com googleusercontent.com gstatic.com gvt1.com prod.google.com pubads.g.doubleclick.net s0.2mdn.net static.doubleclick.net surveys.g.doubleclick.net youtube.com ytimg.com","lifeOnwer","__videoPlayerData.popunder","jsc.mgid.com","movie.advertising.ad_server","movie.advertising",".mandatoryAdvertising=false","/player/configuration","vast_urls","cloudflareinsights","show_adverts","runCheck","adsSlotRenderEndSeen","DOMTokenList.prototype.add","\"-\"","removedNodes.forEach","__NEXT_DATA__.props.pageProps.broadcastData.remainingWatchDuration","json:9999999999","/\"remainingWatchDuration\":\\d+/","\"remainingWatchDuration\":9999999999","/stream","/\"midTierRemainingAdWatchCount\":\\d+,\"showAds\":(false|true)/","\"midTierRemainingAdWatchCount\":0,\"showAds\":false","a[href][onclick^=\"openit\"]","cdgPops","json:\"1\"","pubfuture","/doubleclick|google-analytics/","flashvars.mlogo_link","'script'","/ip-acl-all.php","URLlist","adBlockNotice","aaw","aaw.processAdsOnPage","CAD.pageblockerWarning","underpop","adBlockerModal","10000-15000","/adex|loadAds|adCollapsedCount|ad-?block/i","location.reload","/function\\([a-z]\\){[a-z]\\([a-z]\\)}/","OneTrust","FOXIZ_MAIN_SCRIPT.siteAccessDetector","120000","openAdBlockPopup","drama-online","zoneid","\"data-cfasync\"","Object.init","advanced_ads_check_adblocker","div[class=\"nav tabTop\"] + div > div:first-child > div:first-child > a:has(> img[src*=\"/\"][src*=\"_\"][alt]), #head + div[id] > div:last-child > div > a:has(> img[src*=\"/\"][src*=\"_\"][alt])","/(?=^(?!.*(_next)))/","[].props.slides.[-].adIndex","#ad_blocker_detector","Array.prototype.includes","adblockTrigger","20","insertAd","!/^\\/|_self|alexsports|nativesurge/","method:HEAD mode:no-cors","attestHasAdBlockerActivated","extInstalled","blockThisUrl","SaveFiles.add","detectSandbox","bait.remove","rot_url","pop_type","/rekaa","pop_tag","/HTMLDocument|blob/","=","/wp-content\\/uploads\\/[a-z]+\\/[a-z]+\\.js/","google-ca-pub-4459622307906677","wbDeadHinweis","()=>{var c=Kb","0.2","__venatusLoaderInit","fired","popupInterval","/go/out","adbon","*.aurl","/cs?id=","repl:/\\.mp4$/.mp3/",".mp4","-banner","PopURL","LCI.adBlockDetectorEnabled","!y2meta","ConsoleBan","disableDevtool","ondevtoolopen","onkeydown","window.history.back","close","lastPopupTime","button#download","mode:\"no-cors\"","!magnetdl.","googlesyndication.com","repl:/blank/self/","stoCazzo","fetchAdsScript","_insertDirectAdLink","/doubleclick|atob|return new Promise|aHR0c|String\\.fromCharCode/","Visibility","importFAB","uas","ast","json:1","a[href][target=\"_blank\"]","custom_ads","/settings","url:ad/banner.gif","window.__CONFIGURATION__.adInsertion.enabled","window.__CONFIGURATION__.features.enableAdBlockerDetection","_carbonads","_bsa","redirectOnClick","widgets.outbrain.com","/googletagmanager|ip-api/","&&",".ads={\"movie\":false,\"series\":false,\"episode\":false,\"comments\":false,\"preroll\":false}",".preroll.ad",".preroll.countdownSec=0","()=>j(e=>e-1)","timeleftlink","handlePopup","bannerad sidebar ti_sidebar","moneyDetect","play","EFFECTIVE_APPS_GCB_BLOCKED_MESSAGE","sub","checkForAdBlocker","/createElement|addEventListener|clientHeight/","uberad_mode",".php","!notunmovie","handleRedirect","testAd","imasdk.googleapis.com","/topaz/api","data.availableProductCount","results.[-].advertisement","/partners/home","__aab_init","show_videoad_limited","__NATIVEADS_CANARY__","[breakId]","_VMAP_","DMP_ENABLE_ADS","ad_slot_recs","/doc-page/recommenders",".smartAdsForAccessNoAds=true","/doc-page/afa","Object.prototype.adOnAdBlockPreventPlayback","pre_roll_url","post_roll_url",".result.PlayAds=false","/api/get-urls","/adsbygoogle|dispatchEvent/","OfferwallSessionTracker","player.preroll",".redirected","promos","TNCMS.DMP",".rules.*[?.name==\"Ad Blocker\"]","/access/rules","/pop?","=>",".metadata.hideAds=true","a2d.tv/play/","link.click","document.body.style.overflow","fallback","!addons.mozilla.org","/await|clientHeight/","Function","Yii2App.playbackTimeout","..adTimeout=0","/api/v","!/\\/download|\\/play|cdn\\.videy\\.co/","!_self","#fab","www/delivery","/\\/js/","/\\/4\\//","prads","/googlesyndication|doubleclick|adsterra/",".adsbygoogle","/googlesyndication\\.com|offsetHeight/","String.prototype.split","null,http","..searchResults.*[?.isAd==true]","..mainContentComponentsListProps.*[?.isAd==true]","/search/snippet?","googletag.enums","json:{\"OutOfPageFormat\":{\"REWARDED\":true}}","/Werbeblocker|refresh\\\\/","cwAdblockDisabled","cmgpbjs","displayAdblockOverlay","start_full_screen_without_ad","drupalSettings.coolmath.hide_preroll_ads",".submit","pbjs.libLoaded",".features.pv=false","/playerConfig","flashvars.adv_pre_url","()&&","Object.prototype.adBlockerPop","BACK","wgAffiliateEnabled","!/^https:\\/\\/sendvid\\.com\\/[0-9a-z]+$/","vglnk","adNotificationDetected","String.prototype.startsWith","/ad-free-subscription","clkUnder","adsArr","data.getFinalClickoutUrl data.sendSraBid","data.getAd","onClick","..data.expectingAds=false","/profile","[href^=\"https://whulsaux.com\"]","adRendered","steamBanner clickAds clickAdsUa clickAdsRu pushNotification","!storiesig","openUp",".result.timeline.*[?.type==\"ad\"]","/livestitch","protectsubrev.com","dispatchEvent(window.catchdo)","En(e-1)","!adShown","/blocker|detected/","3200-","imageProbe","Promise.all","AdProvider","AdProvider.push","ads_","adClickThrough","..showAds=false","ad_blocker_detector","._$",".result.items.*[?.content*=\"'+'\"]","/comments","img[onerror]","KAA.state.revspot","enforceVideoShield","/initPops|popLite|popunder/","__US_CONFIG__.ads.adblock_measure_enabled","__US_CONFIG__.ads.adblock_wall_enabled","__US_CONFIG__.ads.urls","[?.type==\"ads\"].visibility.status=\"hidden\"","..suppress_ads=true","messages.*.ads messages.*.renderedAdsHtml","TextDecoder.prototype.decode","/<template data-assistant-ads-html=\"\"><aside aria-label.+?<\\/aside><\\/template>/","/<template for=\"conversation-partial-control\" data-web-mobile-dpu-apply=\"append\"><span( hidden)? data-conversation-control=\"assistant-ads\".+?<\\/(aside|div)><\\/template><\\/span><\\/template>/","\"type\":\"ads\",\"visibility\":{\"status\":\"allowed\"","\"type\":\"ads\",\"visibility\":{\"status\":\"hidden\"","shouldRun","ad-ipd","smartclip","window.getComputedStyle","maddenwiped","/redirect.php?","*.*","/api/banners","checkBanners","__SSR_CONFIG__.monkey","__revCatchInitialized","json:\"none\"","ab.dt","/^[a-zA-Z]{15}$/","data.initPlaybackSession.adScenarios data.initPlaybackSession.adExperience.adExperienceTypes",".data.initPlaybackSession.adExperience.adsEnabled=false","ConFig.config.ads","json:{\"pause\":{\"state\":{}}}","Object.prototype.adblockPlugin","initializeNtvxSheet","fireAd","juicy_tags","!youtu","injectAd",".isAdFree=true","resumeGame","/admaven|adspyglass/","__tcfapi","ezRewardedAds.requestAndShow","timeout","/eeea5e31|new\\s+Function/","timeLeft--","source.ads",".props.pageProps.globalData.publisherFeatureFlags.enableAdBlockDetection=false",".props.pageProps.globalData.publisherFeatureFlags.enableHardAdBlockDetection=false",".adsEnabled=false","/access","adsterraSmartLink adsterraSmartLink2","/^[a-zA-Z]{12}$/","/popup/i","length:1000-1010","/_0x|window\\.open/","Advert","popup-dialog-id","utilAds","/^a$/","/ADBLOCK|ADSENSE/","pubads.g.doubleclick.net","sponsor ad_provider","api.openlua.cloud","script-error","Element.prototype.remove","probe","HTMLElement.prototype.remove","/adsbygoogle|google-analytics|ads-twitter|doubleclick/","String.prototype.replace","decideForPlacement","=void 0","/\\{[a-z]+\\(\\)\\}/",".value||",".value&&","gsmAccessGate","bf-ad.net","protect","poseidonAdBootstrap.freestarReady","cue_points","/playback","..ads_enabled=\"0\"","data.promotions","__kbAdBait","OzB.adb","/offsetHeight|getComputedStyle/","Object.prototype.special","foxizParams.adDetectorMethod","/^\\/contact-us\\/$/","()=>e()","sponsored_ads","tag.min.js","..playGateQueue","playerHeadScriptSnippets","/api/config","shaman",".stories.*[?.storyType==\"ad\"]","cykloStories","innerHTML.length:0","isBlocked","/adblock|Error|getComputedStyle/","/click|pointerup/","handleUserAction",".bannerConfig..advertise.*","/\"features\":\\[/","\"features\":[\"ads-shutdown-nativeAds\",\"ads-shutdown-displayAds\",","/\\/owa\\/startupdata\\.ashx/","client=ca-pub-",".pub-slot-wrapper","top","0px","$..durationInSeconds=0","-ssai-vod-","Period:has(> EventStream[schemeIdUri=\"urn:sva:advertising-wg:ad-id-signaling\"])","/dash",".showModal","triggerPopunder","/getComputedStyle|offsetHeight/","ads-prebid",".data.*[?.hasAd==true]","/card/fill","just-detect-adblock","thistextshouldbethere","enforce","highperformanceformat","/^function\\([a-z]\\)\\{[a-z]\\([a-z]\\)\\}$|!1/","/bait|AdBlock/i","adb_failed","VVADS","FVPOA",".vast=0",".prerolls=0","data.*.elements.edges.[].node.outboundLink","data.children.[].data.outbound_link","method:POST url:/logImpressions","rwt",".js","_oEa","ADMITAD","body:browser","_hjSettings","/07c225f3\\.online|content-loader\\.com|css-load\\.com|html-load\\.com/","bmak.js_post","utreon.com/pl/api/event method:POST","log-sdk.ksapisrv.com/rest/wd/common/log/collect method:POST","firebase.analytics","require.0.3.0.__bbox.define.[].2.is_linkshim_supported","/(ping|score)Url","Object.prototype.updateModifiedCommerceUrl","HTMLAnchorElement.prototype.getAttribute","json:\"class\"","data-direct-ad","fingerprintjs-pro-react","flashvars.event_reporting","dataLayer.trackingId user.trackingId","Object.prototype.has_opted_out_tracking","cX_atfr","process","process.env","/VisitorAPI|AppMeasurement/","Visitor","''","?orgRef","analytics/bulk-pixel","eventing","/#rcmrclid=[a-zA-Z0-9]+/g","rcm.rambler.ru","send_gravity_event","send_recommendation_event","window.screen.height","method:POST body:zaraz","onclick|oncontextmenu|onmouseover","a[href][onclick*=\"this.href\"]","cmp.inmobi.com/geoip","method:POST url:pfanalytics.bentasker.co.uk","discord.com/api/v9/science","a[onclick=\"fire_download_click_tracking();\"]","adthrive._components.start","method:POST body:/content_view|impression|page_view/",".*[?.operationName==\"TrackEvent\"]","/v1/api","ftr__startScriptLoad","url:/undefined method:POST","linkfire.tracking","method:POST body:/pageview|engagement/","body:pageview method:POST","svc.webex.com/metrics","/i/api/1.1/flow/viewer.json","/i/api/1.1/flow/timeline.json","{\"skipToString\":true}","/i/api/1.1/graphql/viewer_context.json","faro.civitai.com","method:POST body:/\"track\"|adblock/","method:POST body:tracker","miner","CoinNebula","blogherads","Math.sqrt","update","/(trace|beacon)\\.qq\\.com/","splunkcloud.com/services/collector","event-router.olympics.com","hostingcloud.racing","tvid.in/log/","excess.duolingo.com/batch","/eventLog.ajax","t.wayfair.com/b.php?","navigator.sendBeacon","segment.io","mparticle.com","ceros.com/a?data","pluto.smallpdf.com","method:/post/i url:/\\/\\/chatgpt\\.com\\/ces\\/v1\\/[a-z]$/","method:/post/i url:ab.chatgpt.com/v1/rgstr","/eventhub\\.\\w+\\.miro\\.com\\/api\\/stream/","logs.netflix.com","s73cloud.com/metrics/","igniteseurope.com/stats/","_startBeaconSending","litix.io","/hpyjmp|marzaent/","brightline.tv",".cdnurl=[\"data:video/mp4;base64,AAAAHGZ0eXBNNFYgAAACAGlzb21pc28yYXZjMQAAAAhmcmVlAAAGF21kYXTeBAAAbGliZmFhYyAxLjI4AABCAJMgBDIARwAAArEGBf//rdxF6b3m2Ui3lizYINkj7u94MjY0IC0gY29yZSAxNDIgcjIgOTU2YzhkOCAtIEguMjY0L01QRUctNCBBVkMgY29kZWMgLSBDb3B5bGVmdCAyMDAzLTIwMTQgLSBodHRwOi8vd3d3LnZpZGVvbGFuLm9yZy94MjY0Lmh0bWwgLSBvcHRpb25zOiBjYWJhYz0wIHJlZj0zIGRlYmxvY2s9MTowOjAgYW5hbHlzZT0weDE6MHgxMTEgbWU9aGV4IHN1Ym1lPTcgcHN5PTEgcHN5X3JkPTEuMDA6MC4wMCBtaXhlZF9yZWY9MSBtZV9yYW5nZT0xNiBjaHJvbWFfbWU9MSB0cmVsbGlzPTEgOHg4ZGN0PTAgY3FtPTAgZGVhZHpvbmU9MjEsMTEgZmFzdF9wc2tpcD0xIGNocm9tYV9xcF9vZmZzZXQ9LTIgdGhyZWFkcz02IGxvb2thaGVhZF90aHJlYWRzPTEgc2xpY2VkX3RocmVhZHM9MCBucj0wIGRlY2ltYXRlPTEgaW50ZXJsYWNlZD0wIGJsdXJheV9jb21wYXQ9MCBjb25zdHJhaW5lZF9pbnRyYT0wIGJmcmFtZXM9MCB3ZWlnaHRwPTAga2V5aW50PTI1MCBrZXlpbnRfbWluPTI1IHNjZW5lY3V0PTQwIGludHJhX3JlZnJlc2g9MCByY19sb29rYWhlYWQ9NDAgcmM9Y3JmIG1idHJlZT0xIGNyZj0yMy4wIHFjb21wPTAuNjAgcXBtaW49MCBxcG1heD02OSBxcHN0ZXA9NCB2YnZfbWF4cmF0ZT03NjggdmJ2X2J1ZnNpemU9MzAwMCBjcmZfbWF4PTAuMCBuYWxfaHJkPW5vbmUgZmlsbGVyPTAgaXBfcmF0aW89MS40MCBhcT0xOjEuMDAAgAAAAFZliIQL8mKAAKvMnJycnJycnJycnXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXiEASZACGQAjgCEASZACGQAjgAAAAAdBmjgX4GSAIQBJkAIZACOAAAAAB0GaVAX4GSAhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZpgL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGagC/AySEASZACGQAjgAAAAAZBmqAvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZrAL8DJIQBJkAIZACOAAAAABkGa4C/AySEASZACGQAjgCEASZACGQAjgAAAAAZBmwAvwMkhAEmQAhkAI4AAAAAGQZsgL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGbQC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBm2AvwMkhAEmQAhkAI4AAAAAGQZuAL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGboC/AySEASZACGQAjgAAAAAZBm8AvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZvgL8DJIQBJkAIZACOAAAAABkGaAC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBmiAvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZpAL8DJIQBJkAIZACOAAAAABkGaYC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBmoAvwMkhAEmQAhkAI4AAAAAGQZqgL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGawC/AySEASZACGQAjgAAAAAZBmuAvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZsAL8DJIQBJkAIZACOAAAAABkGbIC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBm0AvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZtgL8DJIQBJkAIZACOAAAAABkGbgCvAySEASZACGQAjgCEASZACGQAjgAAAAAZBm6AnwMkhAEmQAhkAI4AhAEmQAhkAI4AhAEmQAhkAI4AhAEmQAhkAI4AAAAhubW9vdgAAAGxtdmhkAAAAAAAAAAAAAAAAAAAD6AAABDcAAQAAAQAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAzB0cmFrAAAAXHRraGQAAAADAAAAAAAAAAAAAAABAAAAAAAAA+kAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAALAAAACQAAAAAAAkZWR0cwAAABxlbHN0AAAAAAAAAAEAAAPpAAAAAAABAAAAAAKobWRpYQAAACBtZGhkAAAAAAAAAAAAAAAAAAB1MAAAdU5VxAAAAAAALWhkbHIAAAAAAAAAAHZpZGUAAAAAAAAAAAAAAABWaWRlb0hhbmRsZXIAAAACU21pbmYAAAAUdm1oZAAAAAEAAAAAAAAAAAAAACRkaW5mAAAAHGRyZWYAAAAAAAAAAQAAAAx1cmwgAAAAAQAAAhNzdGJsAAAAr3N0c2QAAAAAAAAAAQAAAJ9hdmMxAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAALAAkABIAAAASAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGP//AAAALWF2Y0MBQsAN/+EAFWdCwA3ZAsTsBEAAAPpAADqYA8UKkgEABWjLg8sgAAAAHHV1aWRraEDyXyRPxbo5pRvPAyPzAAAAAAAAABhzdHRzAAAAAAAAAAEAAAAeAAAD6QAAABRzdHNzAAAAAAAAAAEAAAABAAAAHHN0c2MAAAAAAAAAAQAAAAEAAAABAAAAAQAAAIxzdHN6AAAAAAAAAAAAAAAeAAADDwAAAAsAAAALAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAAiHN0Y28AAAAAAAAAHgAAAEYAAANnAAADewAAA5gAAAO0AAADxwAAA+MAAAP2AAAEEgAABCUAAARBAAAEXQAABHAAAASMAAAEnwAABLsAAATOAAAE6gAABQYAAAUZAAAFNQAABUgAAAVkAAAFdwAABZMAAAWmAAAFwgAABd4AAAXxAAAGDQAABGh0cmFrAAAAXHRraGQAAAADAAAAAAAAAAAAAAACAAAAAAAABDcAAAAAAAAAAAAAAAEBAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAkZWR0cwAAABxlbHN0AAAAAAAAAAEAAAQkAAADcAABAAAAAAPgbWRpYQAAACBtZGhkAAAAAAAAAAAAAAAAAAC7gAAAykBVxAAAAAAALWhkbHIAAAAAAAAAAHNvdW4AAAAAAAAAAAAAAABTb3VuZEhhbmRsZXIAAAADi21pbmYAAAAQc21oZAAAAAAAAAAAAAAAJGRpbmYAAAAcZHJlZgAAAAAAAAABAAAADHVybCAAAAABAAADT3N0YmwAAABnc3RzZAAAAAAAAAABAAAAV21wNGEAAAAAAAAAAQAAAAAAAAAAAAIAEAAAAAC7gAAAAAAAM2VzZHMAAAAAA4CAgCIAAgAEgICAFEAVBbjYAAu4AAAADcoFgICAAhGQBoCAgAECAAAAIHN0dHMAAAAAAAAAAgAAADIAAAQAAAAAAQAAAkAAAAFUc3RzYwAAAAAAAAAbAAAAAQAAAAEAAAABAAAAAgAAAAIAAAABAAAAAwAAAAEAAAABAAAABAAAAAIAAAABAAAABgAAAAEAAAABAAAABwAAAAIAAAABAAAACAAAAAEAAAABAAAACQAAAAIAAAABAAAACgAAAAEAAAABAAAACwAAAAIAAAABAAAADQAAAAEAAAABAAAADgAAAAIAAAABAAAADwAAAAEAAAABAAAAEAAAAAIAAAABAAAAEQAAAAEAAAABAAAAEgAAAAIAAAABAAAAFAAAAAEAAAABAAAAFQAAAAIAAAABAAAAFgAAAAEAAAABAAAAFwAAAAIAAAABAAAAGAAAAAEAAAABAAAAGQAAAAIAAAABAAAAGgAAAAEAAAABAAAAGwAAAAIAAAABAAAAHQAAAAEAAAABAAAAHgAAAAIAAAABAAAAHwAAAAQAAAABAAAA4HN0c3oAAAAAAAAAAAAAADMAAAAaAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAACMc3RjbwAAAAAAAAAfAAAALAAAA1UAAANyAAADhgAAA6IAAAO+AAAD0QAAA+0AAAQAAAAEHAAABC8AAARLAAAEZwAABHoAAASWAAAEqQAABMUAAATYAAAE9AAABRAAAAUjAAAFPwAABVIAAAVuAAAFgQAABZ0AAAWwAAAFzAAABegAAAX7AAAGFwAAAGJ1ZHRhAAAAWm1ldGEAAAAAAAAAIWhkbHIAAAAAAAAAAG1kaXJhcHBsAAAAAAAAAAAAAAAALWlsc3QAAAAlqXRvbwAAAB1kYXRhAAAAAQAAAABMYXZmNTUuMzMuMTAw\"]","/storage-resolve/files/audio/interactive","json:\"https://\"","data:video/mp4",".state_machine.tracks.*[?.metadata.uri^=\"spotify:ad:\"].manifest.file_urls_mp3.*.file_id=1","/track-playback",".state_machine.tracks.*[?.metadata.uri^=\"spotify:ad:\"].manifest.file_urls_mp3.*.file_url=\"data:video/mp4;base64,AAAAHGZ0eXBNNFYgAAACAGlzb21pc28yYXZjMQAAAAhmcmVlAAAGF21kYXTeBAAAbGliZmFhYyAxLjI4AABCAJMgBDIARwAAArEGBf//rdxF6b3m2Ui3lizYINkj7u94MjY0IC0gY29yZSAxNDIgcjIgOTU2YzhkOCAtIEguMjY0L01QRUctNCBBVkMgY29kZWMgLSBDb3B5bGVmdCAyMDAzLTIwMTQgLSBodHRwOi8vd3d3LnZpZGVvbGFuLm9yZy94MjY0Lmh0bWwgLSBvcHRpb25zOiBjYWJhYz0wIHJlZj0zIGRlYmxvY2s9MTowOjAgYW5hbHlzZT0weDE6MHgxMTEgbWU9aGV4IHN1Ym1lPTcgcHN5PTEgcHN5X3JkPTEuMDA6MC4wMCBtaXhlZF9yZWY9MSBtZV9yYW5nZT0xNiBjaHJvbWFfbWU9MSB0cmVsbGlzPTEgOHg4ZGN0PTAgY3FtPTAgZGVhZHpvbmU9MjEsMTEgZmFzdF9wc2tpcD0xIGNocm9tYV9xcF9vZmZzZXQ9LTIgdGhyZWFkcz02IGxvb2thaGVhZF90aHJlYWRzPTEgc2xpY2VkX3RocmVhZHM9MCBucj0wIGRlY2ltYXRlPTEgaW50ZXJsYWNlZD0wIGJsdXJheV9jb21wYXQ9MCBjb25zdHJhaW5lZF9pbnRyYT0wIGJmcmFtZXM9MCB3ZWlnaHRwPTAga2V5aW50PTI1MCBrZXlpbnRfbWluPTI1IHNjZW5lY3V0PTQwIGludHJhX3JlZnJlc2g9MCByY19sb29rYWhlYWQ9NDAgcmM9Y3JmIG1idHJlZT0xIGNyZj0yMy4wIHFjb21wPTAuNjAgcXBtaW49MCBxcG1heD02OSBxcHN0ZXA9NCB2YnZfbWF4cmF0ZT03NjggdmJ2X2J1ZnNpemU9MzAwMCBjcmZfbWF4PTAuMCBuYWxfaHJkPW5vbmUgZmlsbGVyPTAgaXBfcmF0aW89MS40MCBhcT0xOjEuMDAAgAAAAFZliIQL8mKAAKvMnJycnJycnJycnXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXiEASZACGQAjgCEASZACGQAjgAAAAAdBmjgX4GSAIQBJkAIZACOAAAAAB0GaVAX4GSAhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZpgL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGagC/AySEASZACGQAjgAAAAAZBmqAvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZrAL8DJIQBJkAIZACOAAAAABkGa4C/AySEASZACGQAjgCEASZACGQAjgAAAAAZBmwAvwMkhAEmQAhkAI4AAAAAGQZsgL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGbQC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBm2AvwMkhAEmQAhkAI4AAAAAGQZuAL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGboC/AySEASZACGQAjgAAAAAZBm8AvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZvgL8DJIQBJkAIZACOAAAAABkGaAC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBmiAvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZpAL8DJIQBJkAIZACOAAAAABkGaYC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBmoAvwMkhAEmQAhkAI4AAAAAGQZqgL8DJIQBJkAIZACOAIQBJkAIZACOAAAAABkGawC/AySEASZACGQAjgAAAAAZBmuAvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZsAL8DJIQBJkAIZACOAAAAABkGbIC/AySEASZACGQAjgCEASZACGQAjgAAAAAZBm0AvwMkhAEmQAhkAI4AhAEmQAhkAI4AAAAAGQZtgL8DJIQBJkAIZACOAAAAABkGbgCvAySEASZACGQAjgCEASZACGQAjgAAAAAZBm6AnwMkhAEmQAhkAI4AhAEmQAhkAI4AhAEmQAhkAI4AhAEmQAhkAI4AAAAhubW9vdgAAAGxtdmhkAAAAAAAAAAAAAAAAAAAD6AAABDcAAQAAAQAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAzB0cmFrAAAAXHRraGQAAAADAAAAAAAAAAAAAAABAAAAAAAAA+kAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAALAAAACQAAAAAAAkZWR0cwAAABxlbHN0AAAAAAAAAAEAAAPpAAAAAAABAAAAAAKobWRpYQAAACBtZGhkAAAAAAAAAAAAAAAAAAB1MAAAdU5VxAAAAAAALWhkbHIAAAAAAAAAAHZpZGUAAAAAAAAAAAAAAABWaWRlb0hhbmRsZXIAAAACU21pbmYAAAAUdm1oZAAAAAEAAAAAAAAAAAAAACRkaW5mAAAAHGRyZWYAAAAAAAAAAQAAAAx1cmwgAAAAAQAAAhNzdGJsAAAAr3N0c2QAAAAAAAAAAQAAAJ9hdmMxAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAALAAkABIAAAASAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGP//AAAALWF2Y0MBQsAN/+EAFWdCwA3ZAsTsBEAAAPpAADqYA8UKkgEABWjLg8sgAAAAHHV1aWRraEDyXyRPxbo5pRvPAyPzAAAAAAAAABhzdHRzAAAAAAAAAAEAAAAeAAAD6QAAABRzdHNzAAAAAAAAAAEAAAABAAAAHHN0c2MAAAAAAAAAAQAAAAEAAAABAAAAAQAAAIxzdHN6AAAAAAAAAAAAAAAeAAADDwAAAAsAAAALAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAACgAAAAoAAAAKAAAAiHN0Y28AAAAAAAAAHgAAAEYAAANnAAADewAAA5gAAAO0AAADxwAAA+MAAAP2AAAEEgAABCUAAARBAAAEXQAABHAAAASMAAAEnwAABLsAAATOAAAE6gAABQYAAAUZAAAFNQAABUgAAAVkAAAFdwAABZMAAAWmAAAFwgAABd4AAAXxAAAGDQAABGh0cmFrAAAAXHRraGQAAAADAAAAAAAAAAAAAAACAAAAAAAABDcAAAAAAAAAAAAAAAEBAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAkZWR0cwAAABxlbHN0AAAAAAAAAAEAAAQkAAADcAABAAAAAAPgbWRpYQAAACBtZGhkAAAAAAAAAAAAAAAAAAC7gAAAykBVxAAAAAAALWhkbHIAAAAAAAAAAHNvdW4AAAAAAAAAAAAAAABTb3VuZEhhbmRsZXIAAAADi21pbmYAAAAQc21oZAAAAAAAAAAAAAAAJGRpbmYAAAAcZHJlZgAAAAAAAAABAAAADHVybCAAAAABAAADT3N0YmwAAABnc3RzZAAAAAAAAAABAAAAV21wNGEAAAAAAAAAAQAAAAAAAAAAAAIAEAAAAAC7gAAAAAAAM2VzZHMAAAAAA4CAgCIAAgAEgICAFEAVBbjYAAu4AAAADcoFgICAAhGQBoCAgAECAAAAIHN0dHMAAAAAAAAAAgAAADIAAAQAAAAAAQAAAkAAAAFUc3RzYwAAAAAAAAAbAAAAAQAAAAEAAAABAAAAAgAAAAIAAAABAAAAAwAAAAEAAAABAAAABAAAAAIAAAABAAAABgAAAAEAAAABAAAABwAAAAIAAAABAAAACAAAAAEAAAABAAAACQAAAAIAAAABAAAACgAAAAEAAAABAAAACwAAAAIAAAABAAAADQAAAAEAAAABAAAADgAAAAIAAAABAAAADwAAAAEAAAABAAAAEAAAAAIAAAABAAAAEQAAAAEAAAABAAAAEgAAAAIAAAABAAAAFAAAAAEAAAABAAAAFQAAAAIAAAABAAAAFgAAAAEAAAABAAAAFwAAAAIAAAABAAAAGAAAAAEAAAABAAAAGQAAAAIAAAABAAAAGgAAAAEAAAABAAAAGwAAAAIAAAABAAAAHQAAAAEAAAABAAAAHgAAAAIAAAABAAAAHwAAAAQAAAABAAAA4HN0c3oAAAAAAAAAAAAAADMAAAAaAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAAAJAAAACQAAAAkAAACMc3RjbwAAAAAAAAAfAAAALAAAA1UAAANyAAADhgAAA6IAAAO+AAAD0QAAA+0AAAQAAAAEHAAABC8AAARLAAAEZwAABHoAAASWAAAEqQAABMUAAATYAAAE9AAABRAAAAUjAAAFPwAABVIAAAVuAAAFgQAABZ0AAAWwAAAFzAAABegAAAX7AAAGFwAAAGJ1ZHRhAAAAWm1ldGEAAAAAAAAAIWhkbHIAAAAAAAAAAG1kaXJhcHBsAAAAAAAAAAAAAAAALWlsc3QAAAAlqXRvbwAAAB1kYXRhAAAAAQAAAABMYXZmNTUuMzMuMTAw\""];
    const $scriptletArglists$ = /* 4060 */ ";0,0,1,2;0,0,1,3;0,0,1,4;0,0,1,5;0,0,1,6;0,0,1,7;1,8,9,10;2,11,12,13,14;2,15,12,13,16;3,11,12,13,17;4,18,19,20;4,21,12,20;4,22,23,17;5,18,19,24;5,25,19,24;5,25,19,26;6,27,28;6,27,29;6,27,30;7,31;5,25,19,32;7,33;3,34,12,13,35;8,36;7,37;8,38;8,39;9,40,13,35;9,38,13,35;9,41,13,35;6,27,42;6,43,30;6,43,42;6,44,30;6,44,42;6,45,30;6,45,42;6,46,30;6,46,42;6,47,30;6,47,42;6,48,30;6,48,42;6,27,49;6,27,50;6,43,49;6,43,50;6,48,49;6,48,50;6,45,49;6,45,50;6,47,49;6,47,50;6,44,49;6,44,50;6,46,49;6,46,50;10;11,51,52;12,53,54;12,55,56;13,57;13,58,59;14,60,61;13,62,63;13,64;13,65;10,66;12,67,68;11,69,52;12,70,71;15,72,73;14,74,75;14,76,75;13,77;16,78,1,79,80,81;16,82,1,79,80,83;11,84,85;11,86,85;11,87,88;14,89;14,90;13,91;17,92,93,94;15,95,12,12,96,97;16,98,1,99,80,100;18,101,102;19,103;14,12,104;15,105,106;16,107,1,12,80,108;15,109,110;20,111,112,113,80,114;16,111,1,115,80,116;16,117,1,115,80,116;15,118,119,120;14,121;11,122,52;15,123,124;21,125,126,127;22,128,129;11,130,131;11,132,131;11,133,131;11,134,131;23,135,136;11,137,138;18,139,140;11,141,52;24,142;23,143,144;22,145,146;10,147;16,148,1,149,80,150;16,151,1,149,80,150;16,152,1,149,80,153;20,56,154,155;11,156,138;15,157;7,158;25;21,159,160;15,161;16,78,1,12,80,162;14,163;19,164;3,165,12,13,166;11,167,138;19,168;1,169;11,170,138;15,171,172;13,171,172;11,173,138;11,174,175;1,176,61;11,177,175;11,178,138;17,179,180;11,181,182;7,183;15,184;11,185,138;11,186,187;11,188,138;13,189;11,190,175;26;11,191,138;11,192,138;11,193,138;11,194,138;11,195,138;11,196,187;11,197,138;11,198,138;15,199;24,200;15,201;15,202;1,203,204;17,205,206;17,207,208,94;12,209;11,210,12;13,211;13,202;23,212,213;23,214,215;14,216,217;15,218;11,219,187;11,220,187;11,221,187;26,222,12,223;13,224;11,225,187;13,226;11,227,138;13,218;11,228,138;11,229,63;11,230,187;11,231,187;1,232,233,10;1,234,235,10;11,236,88;11,237,138;13,238;11,239,138;11,240,138;11,241,138;11,242,187;11,243,138;13,244;19,245;11,246,138;11,247,138;11,248,138;11,249,187;11,250,63;12,251,252;11,253,187;11,254,138;11,255,187;11,256,138;11,257,12;19,258;11,259,187;11,260,138;11,261,187;11,262,138;11,263,138;11,264,187;11,265,138;11,266,138;11,267,187;11,268,187;11,269,187;11,270,187;11,271,187;11,272,187;11,273,138;11,274,138;1,275,235;11,276,187;13,277;26,278,204;27;11,279,187;11,280,138;22,281,282;11,283,187;11,284,138;11,285,138;11,286,138;1,287,288;1,289,204;11,290,187;11,291,138;11,292,187;11,293,138;16,82,1,294,80,295;11,296,52;11,297,63;11,298,187;11,299,138;11,300,187;11,301,88;11,302,187;11,303,138;11,304,138;11,305,138;11,306,187;11,307,138;11,308,138;11,309,187;11,310,88;11,311,187;11,312,138;11,313,138;11,314,138;11,315,138;11,316,187;11,317,138;1,318,235,10;11,319,187;11,320,12;11,321,187;11,322,138;11,323,138;13,324;11,325,187;11,326,138;11,327,187;11,328,138;11,329,138;11,330,187;11,331,138;11,332,138;11,333,187;11,334,138;11,335,138;11,336,138;11,337,187;11,338,138;1,339,204,10;1,340,235,10;11,341,138;15,211;1,342,204,10;11,343,187;11,344,138;15,345;1,203,346,10;1,203,347,10;11,348,138;14,349;11,350,187;11,351,138;11,352,187;13,353;11,354,138;11,355,187;11,356,138;11,357,187;11,358,138;11,359,187;11,360,138;11,361,187;11,362,138;11,363,138;28,364,365;11,366,85;1,8,288,10;1,367,368,10;11,369,187;11,370,138;11,371,138;1,372,204,10;13,373;11,374,187;11,375,187;11,376,138;11,377,138;11,378,187;11,379,138;11,380,138;11,381,85;11,382,138;11,383,138;11,384,187;11,385,138;11,386,138;11,387,52;11,388,138;11,389,138;11,390,138;11,391,138;22,281,12,392,393;11,394,187;11,395,138;11,396,187;11,397,138;11,398,187;11,399,138;11,400,63;16,401,402,403,80,404;11,405,187;11,406,138;11,407,138;11,408,63;11,409,85;11,410,138;11,411,175;11,412,402;11,413,138;11,414,187;11,415,187;11,416,138;11,417,187;11,418,138;22,128,419,392,420;11,421,187;11,422,187;11,423,138;11,424,138;11,425,138;11,426,138;11,427,187;11,428,138;11,429,138;11,430,138;11,431,138;11,432,138;28,433,434;15,435;11,436,52;11,437,52;11,438,52;11,439,52;7,440;2,441,12,13,442;29,443,13,444;22,128,445;24,446,61;7,447,448;22,128,449;24,450,451;15,452;30;11,453,1;15,454;11,455,12;24,456;19,457;7,458;4,459,187,460;4,461,187,460;4,462,187,460;7,463,464;7,465;7,466;3,467,12,13,460;8,468;9,468,13,35;19,469;19,470;22,12,456;14,456;11,471,182;12,472,473;12,474;14,475;14,476;19,477;16,30,1,478,80,479;1,12,451;19,480;31,481;11,482,52;32;19,483;12,484;15,485;22,281,486;31,487;12,488,480;19,489;19,490;19,491;31,492;19,493;22,281,494;22,128,495;14,496,497;19,498;19,499;31,500;13,501;11,502,138;12,82,503;12,70,504;1,505,204;19,506;19,484;22,128,507;19,508;19,509;12,510,511;19,512;23,513,514;33;12,488,515;31,484;31,516;19,517;19,518;22,128,519;22,128,520;13,184;11,521,63;11,522,138;15,523;12,488,524;12,525,526;19,527;19,528;12,488,529;31,530;31,531;12,532,533;19,534;22,12,505;12,488,535;22,12,536;12,537,538;19,539;14,511;12,251,511;31,528;19,474;12,472,540;19,541;19,542;31,543;31,544;12,78,545;1,546,547;23,507,548;17,549;19,550;22,551,552;19,553;12,488,554;12,488,555;12,488,52;19,556;19,557;11,558,85;19,525;12,507,484;19,559;19,560;19,561;11,562,12;11,563,85;31,564;11,565,63;31,566;31,567;31,568;11,569,63;19,570;12,488,536;19,69;31,571;19,251;17,572,573,574;34;11,575,175;1;31,576;22,12,484;19,577;11,578,85;19,579;35;12,541;19,580;12,581,582;31,583;24,584;12,488,585;26,586;19,587;19,588;31,589;14,590;11,557,63;19,591;14,592;19,593;11,594,138;11,595,63;31,596;22,281,597;22,598,599;12,251,600;31,601;12,70,602;11,51,175;11,603,12;11,604,12;11,605,402;22,606;14,607;19,608;14,609,610;11,611,63;19,612;22,12,613;12,488,614;11,615,12;19,616;23,457,617;22,128,618;36,619;22,620;23,251,621;14,622,497;11,623,138;19,624;11,625,138;11,626,182;23,82,627;1,628,629;1,630,497,10;11,631,63;14,632,1;11,633,138;11,53,182;19,634;11,89,85;12,635,515;11,636,63;12,472,637;31,638;11,639,131;22,12,640;19,641;14,642,497;12,510,497;14,643,644;19,645;12,56,526;11,646,63;12,251,647;24,505;22,12,648;19,649;31,650;11,651,85;19,652;12,653;12,56,654;12,655,656;19,51;22,657,658;14,659;19,660;19,661;37,662;19,663;19,664;19,665;11,666,138;12,78,52;11,667,138;31,668;1,669;26,670;14,82,235;19,671;19,672;19,673;12,537,674;31,675;31,676;11,677,85;14,678,679;11,680,63;11,681,85;26,682,683;12,506,89;22,128,684;26,685,610;31,686;31,541;19,687;22,281,658;19,688;11,689,85;22,128,610;12,135,599;12,56;19,690;12,691,692;31,693;22,128,456;12,472,694;19,695;11,696,85;19,636;14,135,497;12,525,56;19,697;31,698;14,699;14,700;19,566;37,541;11,701,12;14,537,1;22,702,703;22,12,659;12,472,587;12,587,704;19,705;19,706;19,707;11,708,63;11,51,138;14,678,610;19,709;22,128,678;22,710,711;12,712,549;31,713;17,714,715;14,716,235;12,717,718;11,719,85;10,648;19,89;12,720;22,12,721;19,722;11,581,63;22,723,724;31,725;14,726,727;12,636;12,510,728;15,729;12,730,731;14,732,610;22,128,733;12,488,734;11,474,63;14,735;22,12,736;14,736;22,737,12,392,738;12,488,476;31,69;14,739,288;22,740,741;14,742,61;12,510,82;14,743,610;10,744;12,472,745;10,746;11,747,187;11,748,12;19,749;31,750;12,78,89;11,751,138;19,752;26,753,610;19,754;11,755,85;13,756;14,757;1,758,204,223;11,89,138;11,759,12;7,204,760;10,12,217;12,30,56;12,587;31,761;13,762;11,763,52;12,488,764;11,765,85;11,557,138;19,766;14,732,767;14,768;19,769;22,740,770;19,771;13,772;11,773,138;19,774;12,507,587;22,657,775;11,776,63;10,777;12,525,778;19,487;15,779;11,780,85;19,781;12,78,782;13,783;11,784,138;22,12,785;31,786;14,787,288;12,488,788;19,789;26,12,790;19,791;26,12,12,1;14,792;12,78,793;13,794;12,795,546;12,488,795;19,796;23,745,797;22,551,798;22,740,799;12,588,800;19,801;22,551,505;12,510,802;19,803;31,804;14,505,610;19,805;12,537,251;31,587;17,806,807;12,808;12,56,525;12,507;12,401,809;31,526;17,810,811;19,812;19,745;24,813,497;14,289,814;12,488,158;19,815;11,587,182;19,816;22,817,648;11,818,63;19,596;19,819;31,820;17,821,822;26,823,204;11,824,85;11,825,138;22,281,826;14,827,61;12,596;19,828;22,128,829;12,830;11,831,52;19,832;12,488,484;22,128,833;14,536,235;14,834,835;13,836;31,824;14,837,1;26,838;12,78,839;12,840,841;11,842,85;19,843;19,844;19,845;14,846,497;31,847;14,848;24,849,497;31,850;14,505;11,851,85;10,852,217;12,78,853;31,854;11,56,138;22,12,855;19,856;11,857,138;14,858,402;11,859,138;12,78,289;11,860,138;13,779;22,740,861;12,532,526;12,401,862;19,863;1,864,547;19,865;19,650;12,488,866;11,89,402;11,867,402;14,868;17,869;31,870;7,871,872;12,873,798;14,488;14,874,497;31,660;31,875;14,827;12,78,876;11,877,1;11,289,63;31,878;22,281,879;19,880;12,881,662;11,882,63;31,883;14,456,1;22,12,884;14,885;11,886,138;12,472,887;11,553,402;12,510,888;12,510,889;31,890;12,588,888;12,70,891;19,892;23,532,893;14,894,895;24,896;17,714,897;31,898;12,251,899;14,452;12,472,900;22,281,505;11,901,85;15,184,779;19,857;14,902,61;19,903;19,904;19,905;14,536;19,906;31,907;26,12,12,10;11,908,175;12,909;12,507,549;19,910;11,911,63;23,912,548;11,913,12;11,914,52;11,553,85;14,827,451;19,915;12,78,916;11,917,63;12,78,918;12,78,919;14,920,610;14,921,497;19,922;31,923;12,488,924;12,488,925;12,488,916;14,917;12,78,926;12,488,927;12,78,928;31,929;15,289;15,202,119,120;14,182,547;22,128,930;22,128,931;12,537,678;14,732,368;14,932,288;26,877;11,933,1;19,934;14,935,368;14,732,233;22,281,775;10,936;31,525;19,937;11,938,85;12,488,89;15,939;14,940;22,941,942;14,943;11,944,138;12,488,945;14,732,497;12,251,946;12,532,56;11,947,63;31,948;1,949;31,950;12,712,600;31,951;11,952,85;11,69,138;11,953,138;14,745,368;14,515;31,954;14,955;11,956,138;14,957,610;11,958,63;31,952;22,128,959;24,732,235;19,960;19,961;22,962,963;31,964;19,965;23,251,548;17,549,966;1,622;31,967;11,968,63;12,513,654;12,488,969;24,970,971;11,972,12;19,526;12,488,973;11,929,63;11,974,63;14,975;13,289;14,976;12,840,281;12,78,977;12,200,718;19,978;10,979,1;11,980,63;11,717,63;26,670,204;11,981,85;22,551,982;14,983,683;11,984,85;14,985;1,12,12,223;14,986,61;14,987,451;22,281,232;19,602;11,988,1;11,847,138;19,989;26,669;14,990;26,12,12,223;11,991,1;22,281,648;19,992;19,993;12,69;12,488,994;10,995;19,532;12,996,252;12,655,785;26,997,497;31,998;22,999,785;11,1000,138;12,67,916;11,1001,1;22,281,1002;10,89,402,1003;15,1004;22,281;11,1005,85;12,1006;12,1007;12,1008;12,1009;22,740,1010;19,1011;14,1012,402;10,1013;12,870;19,1014;10,1015;11,1016,138;19,1017;19,1018;14,1019;11,1020,138;24,1021,497;22,657,1022;11,1023,85;19,242;12,472,798;12,745,1024;31,1025;11,536,85;19,1026;12,840,1027;19,507;11,1028,12;11,1029,12;11,1030,85;23,56,548;19,923;14,1031;12,78,1032;12,56,650;12,1033,505;14,1034;13,1035;13,1036;14,977,610;23,70,548;19,1037;22,740,1038;14,1038;12,488,793;14,912,497;11,1039,1;11,1040,63;11,1041,63;11,1042,85;14,89,1043;22,1044;19,1045;14,1046;14,182;12,251,1047;12,510,1048;19,1049;19,1050;19,1051;12,655,659;31,1052;11,1053,131;19,1054;12,251,1055;12,70,1056;19,1057;11,1058,63;11,1059,63;38;11,1060,182;23,78,1061;11,1062,63;11,1063,85;1,622,497,10;31,1064;19,798;19,1065;22,12,1066;14,456,644;12,78,1067;12,251,1068;12,78,1069;31,1070;19,928;12,840,678;10,485,402;19,1071;17,714,1072;19,1073;22,485,785;24,1074,497;14,1075;12,401,54;19,1076;11,1077,85;11,1078,85;14,1079;19,576;19,1080;22,128,1081;22,1082,505;19,1083;11,1084,63;12,545,807;19,1085;19,1086;11,1051,138;19,1087;37,1088;19,1089;31,1090;11,1091,63;19,1092;31,1093;11,1094,402;37,289;17,1095,1096;12,855,891;12,1047,891;31,1097;11,69,85;14,1098;10,289;11,1099,402;19,1100;31,1101;14,1102;11,1103,63;12,587,714;19,1104;12,1105;12,840,1106;11,1107,175;12,712,1108;12,67,1109;14,1110;15,1111;12,472,52;14,1112;31,1113;31,1114;22,740,1115;31,1116;12,488,887;12,1117,977;12,251,977;19,1118;12,78,1119;10,1120,217,1003;31,89;11,1121,63;31,1122;22,1123,1124;12,488,1125;14,732;19,1126;7,1127;24,1128;12,67,1129;19,1130;12,251,613;19,1131;11,1132,63;14,887;23,445,1133;14,1134;19,1135;14,1136;14,1137,610;15,1138;11,972,52;12,575;22,12,1139;19,824;17,1140;19,1141;12,650,602;12,1142;15,1143;19,1144;14,1145;11,1146,12;22,962;11,278,63;31,1147;14,1148;24,1148;22,281,1149;19,1150;12,1151;12,251,1152;22,12,515;19,1153;24,574,767;24,1154;11,1155,52;22,1156,703;12,542,1157;22,128,1108;12,78,1158;14,1159;11,1160,63;31,1161;14,1162;14,12,402;22,12,1163;11,500,63;14,52;14,929,402;12,488,1164;31,931;12,488,1165;12,472,1131;14,824;11,1166,12;19,1167;11,1168,138;19,1169;12,472,89;26,1170;1,1170;19,1171;12,532,1172;14,678;22,12,1173;11,69,63;12,912,1129;12,472,1019;26,1174;11,1175,1;14,1176;13,202,119;19,1177;14,1178,610;24,785;24,793;19,1179;7,1180;26,12,204,1;11,557,175;14,1012;22,281,798;12,488,510;12,78,1181;12,488,289;12,472,793;12,488,1182;19,1183;12,70,659;12,488,67;11,1184,63;13,1185;11,1186,187;13,1187;11,1188,85;23,1189,1190;4,1191,1192,1190;7,1193;11,1194,52;11,1195,85;11,1196,138;39,1197,1198;22,1199;7,447,1200;14,1201,679;12,1202;12,510,1203;12,1204;22,1082,1125;19,1205;12,488,1206;14,1207,1;14,678,1208;22,128,52;11,1209,85;22,740,1104;11,1210,187;22,128,785;14,1211;22,740,587;12,488,1212;12,78,1213;11,1214,63;11,452,182;12,251,89;13,1215;26,1216,497;14,1217,1;19,948;24,1074;24,807;22,1218;19,1219;12,488,587;19,1220;11,1221,85;14,632,895;11,1222,63;11,1223,63;10,1224;12,1225,798;40;31,1226;12,881,887;12,488,1227;17,1228;37,768;22,281,1229;19,1084;12,488,1230;12,70,526;12,488,507;22,281,12,392,1231;14,1232;13,452;11,1233,138;19,908;19,1234;11,1235,63;12,857;12,1236;17,714,1237;17,714,1238;17,714,1239;12,70,1240;19,1241;19,1242;12,532,1243;22,12,476;22,864,599;14,1244;23,910,1245;11,1246,182;14,785;12,135,372;19,1247;19,1248;17,869,1249;12,537,841;14,1250,61;12,82,1251;12,488,1252;14,1253;22,12,289;19,1145;12,488,1254;31,1255;22,281,1256;11,1257,63;14,1165;22,128,1258;24,452;11,1259,63;14,1260,497;15,1261;11,1262,85;12,488,1176;12,472,1176;14,1263;7,1264;14,1260;22,128,1265;11,1266,63;11,1267,63;12,507,89;11,1268,85;19,1204;19,1269;19,1270;12,251,1271;11,484,52;19,1272;11,1273,182;12,537,1274;12,472,281;11,1275,63;12,526,514;14,830;22,12,587;14,1276;10,1277;14,1278;26,685,204,10;19,1161;11,1279,182;11,452,175;11,1280,52;19,1281;10,1282;14,1283;14,718;26,1284;11,69,182;22,740,887;11,1285,402;19,1286;19,545;11,1287,85;19,1288;19,1289;12,56,505;14,928;19,1290;11,1162,85;7,1291;22,1292,1293;14,1294,1;14,289;12,488,1295;22,1296,1297;22,740,824;23,650,548;1,12,451,1;19,516;19,1298;11,1299,63;19,1300;10,1301;17,1302,1303;12,537,1176;12,537,1304;12,537,535;12,840,824;24,955;11,980,85;31,1305;11,1306,52;28,1307,1308,1309,1310;19,1311;26,864,204,223;14,928,610;16,1201,1,1312,80,1201;11,1313,175;28,457,1314;26,753,204,223;11,1315,1;1,1316,204,10;26,1317,204,10;26,1318,204,223;1,1319,204,223;19,1305;26,864,204,10;22,1320;22,830,1321;26,1322,204,223;37,1323;7,1324;1,1325,204;11,1326,63;12,537,1327;12,570,671;12,507,452;7,1328;7,1329;7,1330;37,1331;26,1332,204,10;14,1333;15,1334;12,1335,1336;14,1337;15,202,12,1338;11,1339,175;12,1335,955;15,1340;22,128,1341;12,537,1336;12,537,289;10,1342;11,1343,63;19,1344;17,1345,1346;17,1345,1347,94;17,1348,1349;22,830,1350;15,1351;26,838,204,10;19,1007;23,82,1352;14,1353,1354;16,78,1,1355,80,1356;16,78,1,1357,80,1356;16,840,1,1358,80,1359;16,1360,1,1358,80,1361;26,1318,204,10;1,1362,204,10;26,753,204,10;22,740,721;14,1212;19,1363;15,1364,12,1338;22,281,1365;22,1366;22,128,1367;17,714,1368;22,740,1369;22,740,827;14,505,61;31,1370;17,1302,12,94;10,1371;11,805,52;1,1372;11,1373,85;11,1374,138;11,1009,138;22,1375,658;22,1359,1376;15,1377;1,12,204,1378;20,526,1379,85;31,1335;23,457,1380;19,1381;26,1318,497,10;26,1318,1382,10;12,251,1369;19,1008;26,1039,204,10;11,1383,63;22,1384,1385;11,928,1386;13,1387;12,1388,1389;22,740,642;14,922;26,1390,204,10;1,1125,204,10;37,456;19,1391;15,1392,1393;26,864,204;1,864,204;22,128,1394;19,1395;17,549,1396;37,982;23,78,824;10,12,1043;1,864,204,10;23,28,1397;11,1398,131;22,281,1399;1,1125,204;37,1400;22,740,1401;22,281,1402;22,281,12,392,1403;19,1341;19,1404;15,1405;13,1406;37,452;15,1407;10,1408;26,12,204,223;1,12,204,223;15,452,1409;11,1410,182;12,30,1411;22,281,1412;28,1413,1414;11,1415,187;14,1416;16,78,1,79,80,1417;15,1418;14,1419;12,135,1420;22,740,1421;22,281,251;11,1422,52;22,740,484;15,1423;15,1424;26,685;11,1425,63;17,714,1426,94;22,281,1427;26,685,497,10;22,830;1,12,644;12,510,989;23,712,824;11,1428,1310;12,56,1429;14,827,235;26,685,497;1,622,497;12,28,67;15,762;24,1342;12,510,1430;12,30,1047;22,281,484;22,281,1431;41,1432,13,1433;16,1434,1310,1435;22,281,1436;22,281,1437;8,1438;8,1439;15,1440;17,1348,1441;22,281,613;22,281,1108;10,1442;19,56;12,56,1443;12,720,1444;11,1445,63;19,1446;11,1447,12;10,1448;22,281,1449;22,281,1450;24,1451;12,251,824;23,78,1452;3,1453,12,13,1454;10,1455;13,1143,119;10,12,217,1003;26,1456,204;16,82,1,1457,80,1458;16,135,1,1457,80,1459;16,78,1,1460,80,1461;15,1462;14,1463,679;21,881,1464;14,1465;26,1466,204;14,1201;22,1359;16,78,1,1467,80,1468;25,600,1469;12,1470,1471;12,1472,1471;23,840,1473;23,1474,1473;11,1475,138;11,1476,138;22,281,1477;10,1478;22,740,1479;12,251,1479;22,128,1480;12,251,1481;14,1482,61;14,216;11,1483,138;14,234,217;11,1484,85;14,1485;19,1486;23,70,899;23,67,1487;23,67,1488;23,67,1489;12,510,1490;11,1491,187;11,1492,138;12,1493;7,1494;20,56,112,12,80,1495;22,281,599;12,56,1496;12,1497,1496;20,56,112,12,80,1498;31,857;22,12,599;12,488,599;12,55,1117;22,12,1499;12,510,647;12,1500,647;12,251,1501;12,251,1502;22,128,1503;12,251,1504;14,1504;11,1505,138;12,251,647,1506;21,1507,1508,1437,1509;12,251,1510;37,647;12,570,1511;19,1512;10,1513;19,1514;22,12,597;14,1515;23,251,1516;11,1517,12;19,1518;31,1519;12,671,541;24,485;11,1520,52;14,1108;31,1521;14,1110,610;42,1522,1523;12,70,1524;12,30,252;12,148,252;22,12,252;12,70,252;12,532,1525;23,67,1526;12,30,1117;12,1527,252;23,445,1528;12,1388,1529;19,1530;19,1531;12,1117,30;12,1117,252;12,1033,54;12,525,1532;23,67,1533;12,70,1534;13,1535;41,1536,13,1537;41,1538,13,1537;41,1539,13,1537;23,602,1540;12,55,56,1506;22,740,515;21,1507,1508,1437,1541;12,1542,1543;12,53,1544,1506;12,537,1076;11,1545,63;12,545,1546;12,1527,1547;23,587,1548;12,28,54;12,537,1549;22,657,1550;10,1551;11,1552,88;14,1553;23,712,1554;22,1555,8,392,1556;11,1557,63;11,1558,1559;11,1560,138;22,128,1561;22,281,1561;26,1318;10,1562;11,1563,85;22,12,1564;14,538,610;37,1565;12,251,1565;37,1566;22,128,955;23,135,1567;19,1568;21,881,1464,1437;14,1569;31,1570;12,1179,1019;12,1179,1019,1506;12,532,1019,1506;22,128,1571;14,514;15,1572,119,1393;13,1572,119;22,740,1573;21,1574,1575,127,1576;11,1577,85;12,251,1578;11,1578,138;43,1579;43,1580;11,1581,52,1309,1582;11,1583,63;8,1584;8,1585;12,251,1586,1506;11,1587,63;22,737,1176;12,1578;11,1588;25,600,1589;22,1590;11,1591,52;23,525,1592;22,737,1593;22,128,1593;14,1593;2,289,12,13,1594;11,1595,63;8,1596;43,1597;43,1598;43,1599;15,1600;14,1601;14,1602;14,1603;16,1604,402,12,80,1605;17,899,1606,1607,1608,217;11,1609,138;16,1610,1,1611,80,1612;8,1613;11,1614,63;11,1615,138;11,1616,138;7,1617;16,1604,402,1618,80,1619;16,1604,402,1620,80,1619;37,1621;25,600,1612;16,1604,402,1622,80,1605;11,1623,63;11,1624,63;37,1625;14,8,61;16,78,1,1626,80,1627;21,1604,1628,127;22,128,1601;12,251,1629;11,1135,138;7,1630;21,1631,1628,127,548;11,1632,402;11,1633,85;11,1633,85,1309,1582;11,1634,85;11,1634,85,1309,1582;11,1635,85;11,1635,85,1309,1582;11,1636,85;11,1636,85,1309,1582;44,1637,13,1638;44,1639,13,1638;25,600,1640;25,600,1641;7,1642;11,1643,63;29,1644,13,1645;11,1646,138;11,1647,63;11,1648,52;43,1649;12,1650,1651,1506;11,1652,85;26,1653,204,10;11,1654,175;19,1655;31,1656;43,1657;17,699,1658;11,1659,182;11,1225,182;20,1660,1661,12,80,797;23,1662,505;11,871,88;10,12,402;28,1663,1664;11,1665,402;23,251,1666;22,128,1667;11,1668,1;12,488,532;37,200;1,1669,204,10;12,537,1544;24,89;17,869,1670;1,753;12,545,1671;7,1672;43,1673;23,251,1674;22,281,1675;12,1676;19,1677;22,1678;45,1679,1680,1681,1682,1683;45,1679,1680,1684,1682,1683;12,251,1685;15,184,1686;15,1535;22,740,456;22,1375;2,1687,12,13,1688;22,740,1689;2,1690,12,1691;2,1690,12,13,1691;11,1692,63;11,1693,63;2,1687,12,13,1694;11,1695,12;12,1696;12,1225,1697;22,1555,1698;11,1699,187;11,1700,187;12,840,1701;2,1702,12,13,1703;2,1704,12,13,1705;15,1706;24,476;11,1707,85;11,1708,85;43,1709;12,1710,827;7,1711;7,1712;4,1713,12,1714;22,281,1715;12,840,515;11,1716,63;46,1717,13,1718;8,1719;15,1720,1721;14,1722;11,1723,85;11,1724,52;22,281,1725,392,1312;11,1726,63;14,12,895;13,1727;22,128,627;14,1728;16,78,1,1729,80,1730;15,1731;14,1732;22,281,784;14,784;22,128,1733;22,12,1734;22,740,1735;11,1736,63;14,1737;11,1738,85;22,740,1012;7,1739,1740;47,1741,12,1742;3,289,1743,13,1744;7,1745;7,1746;48,1747,1748;10,1749;12,510,89;22,12,1750;12,1751,1012;12,840,1752;16,881,1,1753;17,699,1754,94;14,1755;24,1756;14,1757;31,1758;31,1759;14,642;22,281,1750;12,251,1760;12,655,457;10,1761;8,1762;12,840,1763;11,1764,88;23,510,507;22,1765,1766;28,1767,1768;2,289,12,13,1769;11,1770,85;11,1204,52;11,1771,63;3,1772,12,13,1773;23,251,1774;10,648,402,1003;12,840,1775;14,1733;12,840,1045;11,1776,52;22,740,505;16,107,1777,1778,80,1779;10,1780;22,281,510;22,281,1781,392,1782;18,139,1783;22,281,1784;11,1785,175;14,1786;11,1787,85;12,472,445;12,537,887;11,1788,85;19,1789;12,78,1790;19,1791;26,1792;1,1793;14,1794;24,1794;11,1795,182;14,827,497;22,128,1796;14,1797;14,923;14,1798,1;12,78,452;12,526,1799;37,476;14,472;22,551,1800;12,712,793;12,488,1801;12,401,602;14,931;14,485;22,740,1802;12,532,1803;11,1804,187;11,1805,63;12,1388,1806;11,1807,402;11,1808,85;11,1809,85;12,251,533;11,1810,182;12,488,1811;19,1812;11,1813,85;11,1814,85;14,929;19,1801;19,1815;19,1816;19,1817;12,829,67;11,1818,1;11,1819,85;14,1820;14,1821;12,488,1260;37,887;14,1822;12,488,1823;23,488,1528;11,1824,182;12,588,545;23,1825,1826;23,251,1827;22,128,600;37,1828;12,488,1829;12,655,1830;12,488,1831;11,1832,138;11,1833,138;15,798;31,1834;10,1835;28,1836,1837;14,1838;12,507,456;12,78,1839;12,881,1840;11,1841,131;14,1227,497;19,1842;22,12,1843;11,1844,52;11,1845,138;26,753,204;14,1204;12,82,456;22,128,1067;19,1839;12,488,1846;12,602,1847;11,1848,85;22,12,1849;19,1850;11,1851,187;11,1852,63;11,1853,402;11,1854,187;11,1855,187;11,1856,402;7,1857;11,1858,138;12,510,1859;19,1860;22,740,89;37,736;11,1861,63;11,1862,52;14,1760,895;11,1863,138;24,768;11,961,85;13,1864;31,1865;14,1866;19,1867;31,1868;14,1869;14,1870;14,1871;12,507,1872;11,1873,131;26,1874;31,1875;11,685,1;12,488,1876;23,70,931;11,1877,138;14,1878;11,525,138;19,1879;12,507,1880;11,1881,12;19,958;14,1766;14,1882;19,1883;19,1884;19,1047;12,70,1281;22,12,1885;14,844;14,1886,895;14,1887,61;14,1888,497;19,1160;23,67,1889;7,1890;14,1760;22,737;17,714,1891;14,1892;14,1893,497;22,128,1894;14,1895;17,549,1896,94;11,1897,138;14,1898;19,1899;12,516;1,1900,1901;10,1902;11,139,138;22,740,1903;17,1904,1905;19,1906;14,1907;12,1025,1908;7,1909;22,281,1499;26,1910,497,10;11,1911,12;7,1912;7,1913;47,1914,12,1742;47,1915,12,1742;7,1916;3,1917,12,13,1918;11,1919,138;11,1920,63;14,1921;19,1922;26,12,12,1923;1,12,1924,1;24,1760;22,740,1212;17,714,1925,94;14,1926,451;12,1927;22,740,1928;12,78,1312;22,12,1929;19,1930;17,549,1931;10,1932,402;12,56,1933;19,1934;22,1935;19,1936;19,475;11,1937,85;11,1938,138;11,1939,63;14,1940;12,1941;12,488,1942;31,1655;37,515;22,817,526;14,1943,727;11,1944,63;11,1945,63;31,1735;19,1946;12,1947,1948;19,1949;19,1710;19,1950;12,532,1951;11,1952,52;12,401,1953;12,1954;31,581;14,155;13,1955;28,1956,1957;28,1958,1959;11,1960,85;11,1961,85;23,510,824;11,456,1;19,1962;24,1963,497;31,1964;22,281,1965;12,1966;11,1967,85;11,1968,85;12,472,289;12,712,350;1,1969,1970;11,1971,138;19,1972;31,1973;22,1765;22,12,1974;23,67,12;11,1083,63;12,507,28;24,78,451;23,472,1019;7,1975;12,251,1976;11,1977,12;11,1978,1;22,281,1236;14,28;23,30,1979;12,70,662;15,1980;12,78,824;22,128,909;12,472,1213;14,1981;15,1982;22,740,1983;11,1984,138;11,1985,52;11,1986,52;12,602,1987;23,989,548;19,651;12,488,1794;20,56,1988,1989;7,1990;15,1991,12,1992;23,857,1993;17,1994,1995;12,251,1840;22,1996,1997;26,1998;22,830,232;22,830,1999;12,526,785;11,2000,63;11,2001,138;12,472,916;48,2002,2003;7,2004,2005;47,2006,12,2007;15,2008;12,532,514;14,2009;23,588,12;19,137;14,2010;19,862;23,588,2011;19,2012;26,505;23,912,507;22,740,785;14,2013;26,2014;12,526,56;19,917;19,2015;31,2016;11,2017,138;11,2018,402;11,2019,12;13,2020;15,2020;14,12,288;19,1656;12,840,1212;12,745,2021;22,1082,52;12,2022;26,2023;19,2024;22,2025,2026;17,714,2027;1,2028;12,28,2029;12,78,2030;13,2031;12,840,452;26,2032;26,2033;17,1348,2034;12,488,632;22,1082,627;22,281,2035;1,2036,288;12,28,2037;19,2038;17,1095,2039,2040;13,184,119;29,2041,13,2042;2,2043,12,13,2042;7,2044;26,2045;24,2046;26,2047;12,251,2048;11,1234,138;14,2049;26,2050;15,2051;47,2052,12,1742;12,78,2053;15,2054;19,30;26,1874,2055,2056;7,2057;19,2058;12,588,541;12,2059;11,699,138;11,2060,138;12,251,2061;23,70,514;1,2062;14,2063;15,2064;11,1853,2065;11,2066,52;14,981;12,251,473;23,251,2067;12,513,662;11,2068,1;22,817,2069;14,2070;22,281,1311;2,2071,12,13,2072;26,2073;26,1039,204;14,2074;23,857;14,1143;22,128,922;22,1082,2075;19,2076;19,583;26,2077;12,488,452;10,2078;15,2079;17,2080,2081,94;49,184,2082;11,2083,187;11,2084,138;14,2085;24,2086;15,2087;12,78,2088;23,2089,2090;12,840,2091;14,2092,610;11,2093,85;1,505,233;1,827,1354;23,70,12;11,2094,85;23,67,1979;26,2095;23,488,548;19,2096;13,2097;14,2098;11,2033,1;23,70,797;23,510,289;23,67,548;11,2062,175;19,2016;11,2099,402;12,251,456;12,537,514;23,2100,2101;12,2102;23,2103,445;10,2104;1,2105,1901;23,513,797;1,155,204;11,2106,138;14,2107,235;23,28,548;17,549,2108;13,485;12,1179;10,485,1;15,1838;12,78,1033;12,78,506;11,2109,138;15,231;14,2110;12,488,28;12,78,627;13,2111;22,128,2112;19,581;7,2113;7,2114;31,1179;22,128,2115;13,2116;12,507,807;12,251,2117;19,2118;23,1068,507;19,29;23,251,899;14,2119;13,1838;12,712,2120;17,714,2121,94;17,2122,2123,94;13,2124;17,1348,822;26,753,12,223;11,2125,88;17,1348,2126;12,488,2127;1,2128,235;22,128,599;12,82,505;19,2129;22,281,2130;11,2131,63;1,2132,204;1,2133,204;11,2134,1;12,2135;12,545;23,28,797;19,2136;12,78,887;15,2137;13,2138;12,510,2139;1,2140,204;11,2141,138;11,2142,63;14,2143;39,184,2144,1393;22,740,1732;22,12,2145;12,655,768;22,1082;19,2146;12,2147;12,67,1012;12,472,2088;11,2148,85;11,2149,85;22,12,2150;1,2151,233,223;11,2152,63;11,2153,12;22,1199,12,392,2154;24,2155;23,70,505;11,2156,187;11,2157,63;26,2158;37,89;12,537,798;14,2159;1,685;12,2160;12,70,532;7,289;48,2161,2162;1,2163,497,10;15,184,119,120;15,2164;14,2165;22,128,2166;17,2167,2168,94;11,2169,138;26,753;23,507,2170;15,2171;1,476,547;19,2172;31,2173;7,2174;12,488,2175;19,2176;14,2177;23,251,2178;26,2179;11,2180,85;12,200,2181;12,488,824;14,2182;26,2107;11,289,52;11,1026,52;19,2183;12,855,533;12,472,2049;12,251,2184;14,2185;12,532,1019;11,69,131;11,2186,52;15,2187;13,2188;11,2189,402;19,2190;19,2191;31,2192;14,2193;11,958,138;12,881,526;22,740,56;10,2194;22,2195,2069;12,840,2196;11,2197,138;14,2198;11,2199,52;11,2200,63;10,2201;24,289;19,2202;12,488,2203;19,2204;1,2205,204;31,2206;19,2207;24,2208;17,549,12,94;31,2209;22,456;11,2210,63;19,2211;12,78,678;12,251,2212;26,2213;12,545,2214;14,732,2215;1,1384,235;12,532,662;11,2216,63;19,2217;13,2218;22,281,2219;13,1371;19,1266;15,2220;19,2221;19,445;14,714;23,513,2222;19,2223;19,2224;12,1527,798;19,2225;37,798;12,70,2226;12,588,2227;12,401,1056;12,78,955;23,251,1528;19,2228;19,2229;12,488,2230;12,251,484;26,2231;12,2232,718;11,2233,63;12,2234;14,2235;37,824;13,1572;12,488,1444;23,251,2236;14,2237;12,2238,89;19,2239;11,2240,63;15,2241;16,2242,402,12,80,2243;15,452,2244;12,2245;11,2246,85;11,2247,138;1,2248,610;17,714,2249,94;22,740,700;7,2250;12,2251,1135;14,182,217;26,1039;31,885;11,2252,175;12,2253;22,281,2254;11,798,52;12,251,887;14,12,61;14,613;1,8,235;41,2255,13,2256;41,2257,13,2256;15,2258;16,2259,1,138,80,613;11,2158,1;10,2260;19,2209;31,1860;12,78,2261;11,1225,12;11,2262,63;7,2263;2,1916,12,13,2264;2,2265,2266,13,2264;47,2267,12,2268;47,2269,12,2270;12,30,2271;22,281,2272;22,128,89;13,1334;13,2273;22,12,70;22,740,2274;11,2275,1;13,2276;19,2277;12,56,2278;14,674;24,2279;12,488,2280;12,251,1108;17,714,2281;14,2107;11,2282,1;26,685,204,223;14,2283;14,2284,288;10,2285;17,1348,2286;17,1348,2287;12,2190;11,2288,63;11,2289,1;7,2290;23,862;15,2291;17,2292,2293;17,2292,2294;17,2292,2295;17,2292,2296;22,128,602;22,128,535;22,12,931;24,2297;22,12,2297;22,12,2298;11,2299,52;31,2300;23,488,2301;11,2277,88;11,2302,138;15,2303;7,2304;7,2305;14,2306;11,2307,1;12,2308,798;22,12,1165;37,2309;16,82,1,138,80,89;14,827,288;15,2310;11,2311,138;11,908,138;24,1212;11,2312,85;12,928;15,2313;17,1348,2314;11,2315,85;31,2316;14,178;11,2317,88;22,281,2318;11,2319,63;11,2320,138;11,2321,85;1,2322,233;31,2323;22,830,910;19,2324;16,107,1,2325,80,2326;26,877,12,223;13,2327;14,1888;12,2328;19,1369;22,740,2329;11,2330,2331;17,699,2332,94;17,714,2333,94;15,2334;15,2335;12,472,1165;14,2336;14,281;12,588,67;5,2337,2338,2339;14,2340;11,2341,63;43,2342;14,2343;14,2344;10,2345;23,251,2346;22,12,2347;12,488,2348;24,2349;12,488,989;14,484;14,2350;14,2351;12,472,178;15,2352;11,838,1;11,2353,138;21,881,2354;23,840,2101;23,1789,548;23,148,824;7,2355;7,2356;12,570;14,2357;7,2358;37,2359;12,1860;14,2360;12,251,2361;48,2362,2363;12,1117,2010;11,2364,85;11,2365,85;10,2366;26,2367;37,532;11,2368,63;12,56,2369;1,2370,2371,10;14,1212,895;11,2372,85;11,2373,63;15,2374;11,981,138;7,2375;15,2376;31,863;22,740,2377;11,2378,88;22,740,184;11,2379,85;37,1176;14,1206,727;11,2380,52;11,2381,52;11,2382,52;19,2383;14,2384;19,2385;23,2386,2387;11,2388,138;11,2389,138;19,2390;26,2391;0,2392,1,2393;16,2394,1,2395,80,2396;1,2397,204;26,2398,204;14,2399;12,251,515;11,2400,85;22,128,798;31,2401;31,2402;7,2403;31,2190;12,488,557;14,2404;14,1212,835;19,2405;26,2406,204,10;44,2407,13,2408;14,470;23,56,2409;14,2410;11,2411,138;16,251,1,2412,80,2413;12,251,281;11,2118,138;22,740,2414;11,2415,63;23,82,2416;12,532,28;22,281,2417;10,2418;14,2419;17,549,2420,574;10,2421;17,507,2422;14,662;23,510,2423;19,2424;17,549,2425;22,1082,2426;14,2427;11,2428,88;22,740,2429;14,2430;14,1209;14,2431;22,128,1176;23,56,881;15,2432,2433;14,2434;14,2435;11,2436,1;11,2437,63;14,538;12,840,2438;23,2439,2440;19,2441;31,634;11,844,63;31,2442;11,2443,2215;26,505,204,10;12,2444,456;23,2445,2446;22,128,78;24,899;11,883,138;23,989,2447;14,2448;12,537,1182;19,1416;14,2449;19,1306;31,2450;31,2451;17,714,2452;7,2453;19,2454;8,2455;28,457,2456;11,2457,63;28,2458,2459;21,2242,2460;26,753,497,10;11,2461,52;11,2462,52;11,2463,52;1,1756,204;13,2464;11,2465,402;11,2466,402;14,2467;12,655,488;14,627;23,251,824;17,549,2468;11,2469,1;31,2470;10,2471,402;22,740,2472;11,2473,1;14,2474;14,2475;36,2476;14,2323;11,2477,138;14,2478;11,2479,63;14,2480,2481;11,2482,187;11,2483,187;15,2484;22,281,2485;14,2486;14,69;11,2487,217;19,2488;19,372;11,2489,2490;14,2491;14,2492;11,2493,138;13,2494;31,753;12,82,89;12,78,2495;31,2496;24,2497;11,2498,138;11,2499,187;50,2500,1074,2501;50,2502,1074,2501;7,2503;2,2503,12,13,2504;15,2505;2,2258,12,13,2506;51;11,2507,85;11,2508,85;11,2509,85;2,2510,12,13,2264;3,2510,12,13,2264;47,2511,12,2268;14,155,727;22,281,2512;24,2513;23,526,2514;23,513,488;37,2515;15,2516;22,740,1943;36,485;11,122,182;7,2517;13,2518;5,2519,2520;48,2521,2522;11,2523,2331;11,2524,138;12,472,2525;22,128,2526;11,2527,2528;22,281,2529;7,2530;19,2531;11,2532,138;22,657,2533;12,526,2534;12,840,887;23,251,627;1,2535,204;26,2536,204;11,2537,85;17,549,2538,94;22,281,2539;15,2540;11,2541,138;22,128,8;11,2136,138;14,2542;22,128,135;12,251,2543;17,549,2544;31,2545;37,535;31,2219;11,2546,85;11,2547,85;7,2548;2,2548,12,13,2549;22,1038;11,2550,138;14,1796;11,2551,85;11,914,12;26,476,497,10;12,1404;1,2552;14,2553;14,2554;14,2555;14,2556;47,2557,2558,1742;7,2559,2560;19,2561;12,2562;2,2563;7,2563;24,916;12,537,28;11,2564,187;26,2565;15,2566;2,2567,12,13,2568;47,2569,12,2570;7,2571;11,2572,131;12,545,2573;19,2574;12,488,798;12,745,1047;12,2575;14,2576;17,699,2577,94;17,714,2578,94;23,507,2579;11,2580,63;11,2581,175;4,2582,2583,2584;11,2585,1;11,2586,1;11,2587,402;11,2588,12;14,2589;23,510,2590;19,2591;22,128,2335;15,2592,2593;13,2594;11,2595,52;36,2596;12,251,53;21,28,2597;13,2291,2598;22,281,2599;3,2600,12,13,2601;3,2602,12,13,2603;3,2604,12,13,2605;3,2606,12,13,2607;3,2608,12,13,2609;11,2610,2331;14,793;11,2424,85;31,2136;11,2611,138;12,526,2612;31,2613;11,2614,1;12,537,2615;15,762,119,120;12,28,89;14,2616;15,2617,119,1393;22,740,2618;12,1395;12,488,2619;1,2490,204,10;13,2620;31,2621;15,2622;11,2623,138;11,2624,85;47,2625,12,1742;14,2626;31,122;12,840,2627;26,1969;14,1449;1,2628,497,10;31,1160;26,12,497,10;1,685,204,10;12,488,2629;22,128,289;13,762,119;24,2630;12,53,1550;11,2631,85;22,281,2632;14,2633;1,2634,1354;15,2635;17,714,2636,94;10,2637;24,2638;15,2639;14,12,2640;14,2641;2,2642,12,13,2643;12,545,2644;22,281,8,392,2645;12,251,2646;42,2647,2648;42,2647,2649;42,2647,2650;13,2651;15,2651;1,785,204;14,775,1;19,2652;14,991;12,30,54;11,2653,63;12,488,2554;11,2654,63;13,2655;22,657,989;13,2656;15,2656;13,2657;7,2658;7,2659;14,2660;26,2661;15,2662,119,1393;11,1422,138;15,2663;11,2664,138;11,1428,63;11,2665,63;11,2666,1;11,2667,63;11,2668,138;15,2669;7,204,2670;15,2671;47,2672,12,2673;11,563,138;11,2674,88;12,488,549;15,2675,2676;11,2677,138;22,281,827;12,488,2678;2,2548,12,13,2679;11,2680,52;11,2681,1;7,2682,447;11,2683,2684;23,472,2685;14,2686;14,2687;19,2688;11,2689,63;11,2690,402;11,2691,85;12,488,1038;52;22,12,1766;23,840,1176;12,148,89;12,881,505;12,30,2692;37,2693;14,2694;19,2695;13,452,119;26,2696,497;1,685,204;14,1201,610;7,2697;11,2698,138;26,1969,204,223;26,685,204;12,488,2699;12,545,899;12,1154,2700;23,28,2701;11,1816,138;14,2702;22,281,2703;19,1944;14,1233;11,2704,88;16,78,1,182,80,2705;22,128,2706;21,2707,2708,1437,2709;26,2710,2481,10;14,1801;12,472,1777;11,2711,63;37,533;7,2712;14,2713;23,401,797;11,2714,63;13,2715;11,2716,138;16,78,1,182,80,1165;15,184,2717;12,78,2359,2718;12,840,2719;14,2720;11,2721,131;31,2722;11,2723,1;10,2724;22,281,989;14,2725;19,2726;11,2727,402;7,2728;11,2729,63;15,184,12,120;15,2464;1,1969,497,10;12,472,2730;7,2731;7,2732;7,2733;12,1154,2734;15,2735;14,2736;14,2737;14,2738,727;14,2739;22,740,2740;22,737,2741;7,2742;7,2743;7,2744;5,2745,12,2746;5,2747,12,2748;5,2749,12,2750;5,2751,12,2750;5,2752,12,2753;5,2754,12,2755;2,2756,12,13,2757;12,251,54;1,1039;2,2758,12,13,2759;2,2760,12,13,2761;11,2762,138;11,2763,1;20,2764,112,2765,80,2766;11,2767,2768;12,1154,2769;11,2770,138;16,82,1,79,80,2771;22,128,2772;11,2773,2774;14,2775;14,2776;15,2777;2,2778,12,13,2779;14,2414;4,2780,12,2522;14,2781;23,78,2782;11,2783,12;43,2784;13,2785;26,2786,12,10;11,2787,52;11,1256,52;2,2788,12,13,2789;15,2790;10,2791;12,1954,2792;12,537,1943;12,1527,2793;14,1943;14,51;11,2794,85;11,2795,1;14,2796;12,354,89;22,281,2797,392,2798;48,2799,2522;11,2800,52;15,2801;31,1422;2,2802,12,13,2803;41,2804,13,2805;4,2806,12,2522;11,1026;2,2807,12,13,2808;22,281,2809;12,78,2810;10,2811;14,251;17,549,2812,574;17,549,2813,574;17,549,2814,574;22,281,977;22,740,2815;12,840,2816;19,2130;7,2817;28,2818,2819;19,2820;12,78,2821;15,2822;11,2823,52;22,128,2824;11,2825,85;53,2826;11,2827,52;14,2828;11,2829,2830;25,2831;10,2832;11,2833;7,2834;37,2835;7,2836;12,1025,2837;15,2838;11,2839,1386;24,613;10,2840;1,12,451,10;10,2841;12,510,2842;11,2843,85;28,2844,2845;17,549,2846;22,740,1213;14,2847;11,475,85;24,470;22,281,2848;19,2849;12,588,2850;10,1442,217,1003;7,2851;7,2852;11,2853,63;22,281,2854;15,2855;23,251,2856;10,2857;12,1497,2858;24,1076;23,251,2859;11,2860,187;23,78,548;11,2861,402;11,2862,402;15,2863;11,2864,187;19,2865;11,2866,138;12,510,78;22,740,557;10,2867;22,281,2868;10,2869;16,135,1,79,80,2870;16,135,1,2871,80,807;22,740,2060;7,2872;22,740,940;12,840,798;22,281,2873;12,840,827;2,2874,12,13,2875;15,2876,2877;2,2878,12,13,2879;15,2880;14,2881;20,56,2882,2883;20,56,2884,63;11,2885,138;12,507,989;11,937,138;18,139,2886;22,281,2887;14,2888;47,2889,12,2890;5,2891,12,2892;11,2893,52;14,2894;12,2895;14,2896;31,2897;13,2898;19,2899;49,2900,1535;49,2901,2902;49,2903,2904;49,2905,2906;14,2907;13,2908;31,2909;15,1572;14,2910;22,281,515;23,1497,2911;19,1735;19,2842;15,1351,119;7,2912;7,2913;12,78,515;15,2914;12,840,536;11,2915,85;17,549,2916;48,2917,2522;13,2521;7,2918;2,2919,12,13,2920;19,2921;49,2922,2923;49,2924,2925;49,2926,2927;2,2928,12,13,2929;2,204,2930,13,2931;2,2932,12,13,2933;14,1074,610;11,2934,138;26,2935;1,2936,2937;14,2938;12,488,2939;11,2940,63;16,135,1,2941,80,2942;17,2943,2944,94;1,12,12,1;11,2945,187;11,2946,138;11,2947,138;12,0;11,2948,138;11,2949,138;11,2950,131;2,2951,2952,13,2953;2,2951,2954,13,2953;2,2955,12,13,2953;7,2955;7,2951,2952;7,2951,2954;47,2956,2957,1742;12,67,541;22,281,2958;11,2959,85;11,2960,182;11,2961,85;11,2962,187;19,2963;31,2964;1,2965,204;14,2966,895;11,2967,85;22,2968,505;11,2969,138;31,2970;31,2971;7,2972;47,2973,2974,1742;47,2975,2976,1742;47,2977,12,1742;11,2978,402;11,1160,402;12,251,2979;39,2258,2980;31,2981;14,89,610;11,2982,52;12,251,2983;7,2984;3,2985,12,13,16;44,2986,2987;11,2988,187;12,78,456;13,2989;7,2990;11,1874,1;11,2991,138;11,2992,63;21,2993,2994;12,1182,2995;12,251,894;28,2996,2997;5,2998,2999,3000;5,3001,3002,3000;17,549,2425,94;17,549,3003,94;12,488,3004;28,2058,3005;13,3006,119;11,931,138;22,817,484;15,3007;12,28,456;11,3008,12;12,251,3009;10,648,402;11,755,138;15,3010;11,3011,88;12,840,989;22,740,3012;12,251,1131;11,3013,187;11,3014,138;11,3015,138;11,560,52;12,1154,824;12,488,3016;14,3017;12,82,2323;14,12,3018;14,3019;24,3019;36,3020;22,737,3021;11,3022,187;14,1213;37,2053;24,2119;37,2119;11,3023,138;12,1076;14,56,3024;11,3025,138;23,1154,3026;22,740,627;15,762,119,1393;1,2163,12,223;12,251,3027;21,1631,3028,127;23,251,3029;37,1732;11,3030,138;50,3031,2107,1067;23,251,507;23,602,3032;7,3033;14,3034;23,3035,3036;10,648,3037;12,545,3038;10,3039;15,184,3040;11,3041,63;11,3042,63;12,488,3043;11,3044,138;12,510,515;11,3045,138;22,740,1117;14,1482;14,1943,895;12,1388,484;14,3046;7,204,3047;7,204,3048;22,737,1038;15,3049;12,251,3050;14,535;23,56,3051;15,3052;11,178,175;21,2993,2994,1437,3053;39,184,3054;14,3055;14,12,451;26,3056,497,3057;11,3058,63;14,3059;22,281,3060;10,3061;11,3062,1;2,204,3063,13,3064;16,2394,1,3065,80,3066;22,740,3067;22,281,3068;11,3069,85;10,3070;19,3071;19,3072;19,3073;19,3074;19,155;19,3075;11,2664,52;19,1009;19,3076;12,840,3077;17,549,3078,574;14,3079;10,3080,402;15,3081;16,515,402,3082;11,3083,63;12,881,3084;22,740,883;23,588,3085;12,135,989;22,1082,1446;14,1446;22,740,3086;22,740,3087;14,3087;11,866,85;22,740,1045;11,3088,52;11,3089,88;14,3090;28,1663,3091;18,139,3092;2,3093,12,13,3094;13,3095;11,3096,85;11,3097,85;11,3098,187;11,3099,187;37,184;19,3100;15,3101;14,184;22,128,557;12,251,1038;13,3102;22,128,3103;41,3104,13,3094;41,3105,12,13,1744;41,3106,13,1744;1,3107,204;26,3108,497,10;22,281,3109;12,840,89;7,3110;14,3111;22,3112,784;24,3113;14,3114;31,3115;14,3116;11,3117;10,3118;10,3119;22,740,3120;37,1038;14,3121;15,3122;13,3122;2,2258,12,13,3123;3,2258,12,13,3123;7,2590,3124;22,740,200;7,3125;15,3126;11,3127,63;11,3128,138;11,3129,63;47,3130,12,3131;11,3132,85;3,3133,12,13,3134;44,3135,13,3136;22,281,718;12,844;11,3137,85;11,3138;11,3139;41,3140,13,3141;14,3142;22,740,3143;11,3144,138;22,281,714;12,1388,899;14,3145;12,840,3146;22,1765,505;22,962,155;14,3147;44,3148,13,3149;10,3150;14,3151;41,3152,13,3153;12,510,1201;22,281,3154;14,202;14,3155;12,537,3156;12,840,3156;14,2427,497;10,3157;37,955;22,128,3158;14,3159;11,3160,1;44,3161,13,3162;10,3163;10,3164;37,3165;15,3166;15,3167;10,3168;12,200,515;11,3169,88;15,3170;14,3171;14,3172;16,3173,1777,12,80,3174;8,3175;8,3176;29,3176,13,3177;28,3178,3179;14,3180;11,3181,63;11,3182,85;11,3183,85;11,1143,85;11,3184,85;11,3185,63;24,3186;19,3187;44,3188,13,3189;11,3190,12;22,1082,3191;11,3192,52;11,1578,52;19,2206;22,12,3193;19,2969;11,3194,85;11,289,182;10,3195;11,1075,85;12,488,3196;11,3197,85;16,3198,1,12,80,3199;22,281,3200;11,3201,187;7,3202;2,3203,12,13,35;23,588,3204;41,3205,13,3206;18,1662,3207;1,3208,204,10;7,3209;10,3210;11,3211,138;46,3212,13,3213;13,3214,119;22,737,3215;14,3216;11,1076,175;22,281,3217;12,251,3218;14,12,3219;23,1117,3220;23,3221,3220;11,3222,138;11,3223,138;15,3224;13,3224;22,281,3225;43,3226;14,3227;22,281,857;24,515;24,3228;14,3228;29,3229,13,3230;17,899,3231,94;12,1388,515;11,3232,52;24,3233;14,3234;11,3235,85;11,3236,85;11,3237;43,3238;43,3239;7,3240;20,3241,3242;20,3241,3243;20,3241,3244,3245;37,536;26,2045,204;12,886,3246;13,3247;13,3248;14,3249;10,3250;22,281,3251;2,3252,12,13,3253;22,740,3254;11,3255,52;11,3256,63;16,82,1,3257,80,289;11,3258,85;16,78,1,1467,80,3259;3,3260,12,13,35;44,3261,13,35;28,3262,3263;11,3264,52;11,3265,138;24,1201;22,281,3266;19,3267;10,3268;12,587,662;14,3228,610;24,3228,288;22,128,3269;15,2031;43,3270;1,3271,235,10;13,3272;31,3273;11,3274,138;1,3275,204,223;12,510,3276;1,3277,204;3,3278,12,13,2256;16,98,1,3257,80,2454;43,3279;43,3280;41,3281,13,3282;2,3283,12,13,3282;16,78,1,1467,80,3284;12,840,3285;13,184,3286;12,510,3287;14,3288;22,740,3289;14,3290;16,251,1,2412,80,3291;22,3292;15,3293;2,3294,12,13,3295;22,737,3296;23,3297,3298;23,3299,3298;15,3300;23,3301,3302;14,3303;14,3304;24,3305;22,1359,3306;14,2237,497;11,3307,138;15,3308;22,281,56,3309,402;11,3310,63;3,3311,12,13,3312;44,3313,13,3312;2,3314,12,13,35;11,3315,63;14,3316;14,1135;14,3317;11,3318,63;11,3319,12;16,3198,1,99,80,3320;36,3321;7,3322;15,3323;22,128,1274;8,3324;2,3325,12,13,3326;19,3327;29,3328,13,3329;14,3330;22,740,3331;14,3332;22,3333,3334;11,122,138;8,3335;5,3336,3337,3338;15,3339;50,3340,1074,2501,3341,3342;41,3343,13,3344;54,3345,3346;14,3347;22,12,3348;14,3349;15,3350;46,3351,13,3352;49,3353,3354;11,1648,138;22,12,3355;15,3356;22,737,3357;14,3358;11,3359,85;14,12,233;11,3360,52;11,3361,52;43,3362;43,3363;7,3364;7,3365;13,3366;11,3367,138;12,251,3368;19,3369;31,3370;23,587,1069;15,3371;11,3372,52;11,1958,52;37,3373;11,3374,85;13,161;19,2251;13,3375;13,3376;11,3377,138;7,3378;22,12,3379;11,3380,138;16,3381,1,3382,80,3383;22,12,546;13,3384;11,3385,12;7,3386;11,3387,175;36,3388;11,3389,187;11,3390,187;13,3391;11,3392,187;16,1710,1310,3393,80,3394;13,3395;15,3396;5,3397,12,3398;11,3399,138;11,3400,138;23,3401,510;15,3402;17,3403,3404,94;13,3405;13,3406;13,3407;17,549,3408,574;11,3409,138;15,3410;55,3411,13,3412;31,3413;11,2590,63;15,3414;11,3415,187;15,3416;13,3417;13,3418;13,3419;13,3420;56,3421;13,3422;15,3423;13,3424;15,3425;19,55;19,3426;31,3427;24,3428;23,3429,3430;13,3431;15,3432;15,3433;15,3434;15,3435;13,3436;13,3437;13,3438;11,3439,138;15,3440;15,3441;13,3442;15,3443;15,3444;15,3445;13,3446;15,3447;13,3448;24,28;24,3020;13,3449;14,3450;15,3451;13,3452;15,3452;13,3453;41,3454,13,3455;16,2394,1,3456,80,3457;41,3458,13,3459;41,3460,13,3459";
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
