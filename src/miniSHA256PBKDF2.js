(
    function(sha256) {
        sha256['pbkdf2'] = function(key, keylength,
            salt, saltlength,
            iterations, dkbytelength) {
            var i,
                j,
                pmac,
                temp,
                hmac = sha256.hmac(key, keylength),
                blocklength = (dkbytelength + 1) >>> 2,
                block = [],
                c = 1,
                offset = saltlength & 31,
                last = saltlength >>> 5;
            for (i = 0; i < blocklength; i += 8, c++) {
                salt[last] = salt[last] & -1 << 31 - offset ^ c >>> offset;
                salt[last + 1] = c << 32 - offset;
                pmac = hmac(salt, saltlength + 32);
                block[i] = pmac[0];
                block[i + 1] = pmac[1];
                block[i + 2] = pmac[2];
                block[i + 3] = pmac[3];
                block[i + 4] = pmac[4];
                block[i + 5] = pmac[5];
                block[i + 6] = pmac[6];
                block[i + 7] = pmac[7];
                for (j = 1; j < iterations; j++) {
                    pmac = hmac(pmac, 256);
                    block[i] ^= pmac[0];
                    block[i + 1] ^= pmac[1];
                    block[i + 2] ^= pmac[2];
                    block[i + 3] ^= pmac[3];
                    block[i + 4] ^= pmac[4];
                    block[i + 5] ^= pmac[5];
                    block[i + 6] ^= pmac[6];
                    block[i + 7] ^= pmac[7];
                }
            }
            return block;
        }
    })(
    miniSHA256
);

/*
bico.toHex(miniSHA256PBKDF2([1348563827, 2003792484],64,[1314997100],32,80000,64),32);
"4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
*/
