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
