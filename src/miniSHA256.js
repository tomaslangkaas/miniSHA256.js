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
    f['compare'] = function(a, b) {
        if (a.length !== b.length) return false;
        for (var i = 0, r = 0; i < a.length; i++) {
            r |= a[i] ^ b[i];
        }
        return !(r ^ 0);
    };
    var speed;
    f['speed'] = function(limit) {
        if (limit || !speed) {
            limit = limit || 1;
            var d = +new Date,
                i = 0,
                diff, m = [];
            while ((diff = (+new Date) - d) < limit) {
                f().digest(m, 256);
                i++;
            }
            speed = i / diff;
        }
        return speed;
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
        l = (l === void(0) ? m.length * 32 : l);
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

/* minified 1.25 kb
miniSHA256 = function(f,d){function a(){return new f}var h=0,e,b,c=Math.pow;for(e=2;64>h;e++){for(b=2;b<e;b++)e%b||(b=e);b==e&&(d.a[h++]=4294967296*c(e,1/3)|0,9>h&&(d.c[h-1]=4294967296*c(e,.5)|0))}f.prototype=d;a.compare=function(a,c){if(a.length!==c.length)return!1;for(var b=0,d=0;b<a.length;b++)d|=a[b]^c[b];return!(d^0)};return a}(function(){this.g=[];this.f=this.c.slice();this.b=0},{a:[],c:[],p:function(f,d,a,h,e){var b,c,l=a[0],g=a[1],m=a[2],p=a[3],k=a[4],q=a[5],n=a[6],r=a[7];for(b=0;64>b;b++)e[b&15]=16>b?f[d+b]|0:e[b+9&15]+e[b&15]+((c=e[b+14&15])>>>17^c<<15^c>>>19^c<<13^c>>>10)+((c=e[b+1&15])>>>7^c<<25^c>>>18^c<<14^c>>>3)|0,c=r+(k>>>6^k<<26^k>>>11^k<<21^k>>>25^k<<7)+(n^k&(q^n))+h[b]+e[b&15]|0,r=n,n=q,q=k,k=p+c|0,p=m,m=g,g=l,l=c+(g>>>2^g<<30^g>>>13^g<<19^g>>>22^g<<10)+(g&m|p&(g|m))|0;a[0]=a[0]+l|0;a[1]=a[1]+g|0;a[2]=a[2]+m|0;a[3]=a[3]+p|0;a[4]=a[4]+k|0;a[5]=a[5]+q|0;a[6]=a[6]+n|0;a[7]=a[7]+r|0},update:function(f,d,a){a=a||0;d=d||f.length>>>4;var h=this.p,e=this.g,b=this.a,c=this.f;this.b+=d<<9;for(d;d--;a+=16)h(f,a,c,b,e);return this},digest:function(f,d){f=f||[];d=d||0;var a=this.p,h=this.g,e=this.a,b=this.f.slice(),c=d>>>5,l;f=f.slice();f[c]|=-2147483648>>>(d&31);f[c]&=-1<<31-(d&31);f[(c=(d+64>>>9<<4)+16)-1]=d+this.b;for(l=0;l<c;l+=16)a(f,l,b,e,h);return b}})
*/
