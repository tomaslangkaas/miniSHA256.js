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
        /*ho = SHA256().update([
            key[0]  ^ mo, key[1]  ^ mo, key[2]  ^ mo, key[3]  ^ mo,
            key[4]  ^ mo, key[5]  ^ mo, key[6]  ^ mo, key[7]  ^ mo,
            key[8]  ^ mo, key[9]  ^ mo, key[10] ^ mo, key[11] ^ mo,
            key[12] ^ mo, key[13] ^ mo, key[14] ^ mo, key[15] ^ mo
          ], 1);
        hi = SHA256().update([
            key[0]  ^ mi, key[1]  ^ mi, key[2]  ^ mi, key[3]  ^ mi,
            key[4]  ^ mi, key[5]  ^ mi, key[6]  ^ mi, key[7]  ^ mi,
            key[8]  ^ mi, key[9]  ^ mi, key[10] ^ mi, key[11] ^ mi,
            key[12] ^ mi, key[13] ^ mi, key[14] ^ mi, key[15] ^ mi
          ], 1);*/
        return function(message, messagebits) {
            return ho.digest(hi.digest(message, messagebits), 256);
        }
    }
})(miniSHA256);

/* minifed 248 bytes
(function(b){b.hmac=function(c,d){var e=[],f=[],a,g,h;512<d&&(c=b().digest(c,d));for(a=0;16>a;a++)e[a]=c[a]^909522486,f[a]=c[a]^1549556828;g=b().update(e,1);h=b().update(f,1);return function(a,b){return h.digest(g.digest(a,b),256)}}})(miniSHA256);
*/
