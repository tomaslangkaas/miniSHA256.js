var miniSHA256 = (function(s, p) {
    var l = 0,
        i, j, c = 4294967296,
        m = Math.pow;
    for (i = 2; l < 64; i++) {
        for (j = 2; j < i; j++) i % j || (j = i);
        if (j == i) {
            p.K[l++] = m(i, 1 / 3) * c | 0;
            if (l < 9) p.H[l - 1] = m(i, .5) * c | 0;
        }
    }
    s.prototype = p;
    function f() {
        return new s;
    };
    f.compare = function(a, b) {
        if (a.length !== b.length) return false;
        for (var i = 0, r = 0; i < a.length; i++) {
            r |= a[i] ^ b[i];
        }
        return !(r ^ 0)
    }
    return f;
})(function() {
    this.w = []; //temp processing array
    this.h = this.H.slice(); //current hash
    this.l = 0; //current length in bits, 32 bit arr
}, {
    K: [],
    H: [],
    p: function(m, i, t, k, w) { //message of 32 bit words, start index, temp hash, key, w temp arr
        var j, x, a = t[0],
            b = t[1],
            c = t[2],
            d = t[3],
            e = t[4],
            f = t[5],
            g = t[6],
            h = t[7];
        for (j = 0; j < 64; j++) {
            w[j & 15] = j < 16 ?
                m[i + j] | 0 :
                w[j + 9 & 15] + w[j & 15] +
                ((x = w[j + 14 & 15]) >>> 17 ^ x << 15 ^ x >>> 19 ^ x << 13 ^ x >>> 10) +
                ((x = w[j + 1 & 15]) >>> 7 ^ x << 25 ^ x >>> 18 ^ x << 14 ^ x >>> 3) | 0;
            x = h + (e >>> 6 ^ e << 26 ^ e >>> 11 ^ e << 21 ^ e >>> 25 ^ e << 7) +
                (g ^ e & (f ^ g)) + k[j] + w[j & 15] | 0;
            h = g;
            g = f;
            f = e;
            e = d + x | 0;
            d = c;
            c = b;
            b = a;
            a = x + (b >>> 2 ^ b << 30 ^ b >>> 13 ^ b << 19 ^ b >>> 22 ^ b << 10) +
                (b & c | d & (b | c)) | 0;
        }
        t[0] = t[0] + a | 0;
        t[1] = t[1] + b | 0;
        t[2] = t[2] + c | 0;
        t[3] = t[3] + d | 0;
        t[4] = t[4] + e | 0;
        t[5] = t[5] + f | 0;
        t[6] = t[6] + g | 0;
        t[7] = t[7] + h | 0;
    },
    'update': function(m, blocks, i) { //little tested
        i = i || 0;
        blocks = blocks || (m.length >>> 4);
        var p = this.p,
            w = this.w,
            k = this.K,
            h = this.h,
            b = blocks; //(j - i) >>> 4;
        this.l += b << 9;
        for (b; b--; i += 16) p(m, i, h, k, w);
        return this;
    },
    'digest': function(m, l) {
        m = m || [];
        l = l || 0;
        var p = this.p,
            w = this.w,
            k = this.K,
            h = this.h.slice(),
            j = l >>> 5,
            i;
        m = m.slice();
        m[j] |= (1 << 31) >>> (l & 31);
        m[j] &= -1 << (31 - (l & 31));
        m[(j = ((l + 64 >>> 9) << 4) + 16) - 1] = l + this.l;
        for (i = 0; i < j; i += 16) p(m, i, h, k, w);
        return h;
    }
});
