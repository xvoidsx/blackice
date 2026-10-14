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

// brave-unbreak

// Important!
// Isolate from global scope
(function uBOL_cssGenericImport() {

const lowlyGeneric = new Map(/* 1 */[[64188,"#kanews-modal-adblock"]]);
const highlyGeneric = /* 1 */"div[style*=\"box-shadow: rgb(136, 136, 136) 0px 0px 12px; color: \"]";
const exceptions = /* 8 */[".ad-placement","[class^=\"ad-\"]",".adunit",".ads_box",".ad_warn\n.ad_warn\n#topAd\n#topAd",".adsbox","div[id^=\"headlessui-dialog-\"], div.sheet-overlay",".js-consent.consent"];
const hostnames = /* 8 */["dez.ro","queer.pl","dhd24.com","dumpert.nl","swagbucks.com","directwonen.nl","bizjournals.com","computerbase.de"];
const hasEntities = false;

self.genericSelectorMaps = self.genericSelectorMaps ?? [];
self.genericSelectorMaps.push(lowlyGeneric);
self.genericDetails = self.genericDetails ?? [];
self.genericDetails.push({ highlyGeneric, exceptions, hostnames, hasEntities });

})();

/******************************************************************************/
