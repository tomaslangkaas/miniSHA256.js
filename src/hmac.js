(function(SHA256) {
    SHA256['hmac'] = function(key, keybits) {
        var inner = [],
            outer = [],
            i,
            hi,
            ho;
        if (keybits > 512) key = SHA256().digest(key, keybits);
        for (i = 0; i < 16; i++) {
            inner[i] = key[i] ^ 0x36363636;
            outer[i] = key[i] ^ 0x5c5c5c5c;
        }
        hi = SHA256().update(inner, 1);
        ho = SHA256().update(outer, 1);
        return function(message, messagebits) {
            return ho.digest(hi.digest(message, messagebits), 256);
        }
    }
})(miniSHA256);

/* minifed 248 bytes
(function(b){b.hmac=function(c,d){var e=[],f=[],a,g,h;512<d&&(c=b().digest(c,d));for(a=0;16>a;a++)e[a]=c[a]^909522486,f[a]=c[a]^1549556828;g=b().update(e,1);h=b().update(f,1);return function(a,b){return h.digest(g.digest(a,b),256)}}})(miniSHA256);
*/
