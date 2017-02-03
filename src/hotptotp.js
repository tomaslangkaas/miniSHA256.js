(function(SHA256) {
    function truncate(otp, digits) {
        var offset = otp[otp.length - 1] & 0xf;
        var bitOffset = (offset * 8) & 31;
        offset >>= 2;
        var truncated = (otp[offset] << (bitOffset)) & 0x7fffffff;
        if (bitOffset)
            truncated ^= otp[offset + 1] >>> (32 - bitOffset);
        return (truncated >>> 0) % Math.pow(10, digits);
    }
    SHA256['hotp'] = function(key, keySize) {
        var hmac = SHA256['hmac'](key, keySize);
        return function(counterInt, digits) {
            var hash = hmac(
              [Math.floor(counterInt / 0x100000000), counterInt >>> 0]
            )
            return digits ? truncate(hash, digits): hash;
        }
    }
})(miniSHA256);

(function(SHA256) {
    SHA256['totp'] = function(key, keySize, stepSize) {
        var hotpInstance = SHA256['hotp'](key, keySize);
        stepSize = stepSize || 30;
        return function(unixTime, digits) {
            unixTime = Math.floor((unixTime || (+new Date) / 1e3) / stepSize);
            return hotpInstance(unixTime, digits);
        }
    }
})(miniSHA256);

/* minified: 254 + 149 = 403 bytes
(function(a){a.hotp=function(c,d){var e=a.hmac(c,d);return function(a,g){var b=e([Math.floor(a/4294967296),a>>>0]);if(g){var f=b[b.length-1]&15,c=8*f&31,f=f>>2,d=b[f]<<c&2147483647;c&&(d^=b[f+1]>>>32-c);b=(d>>>0)%Math.pow(10,g)}return b}}})(miniSHA256);
(function(a){a.totp=function(c,d,e){var h=a.hotp(c,d);e=e||30;return function(a,b){a=Math.floor((a||+new Date/1E3)/e);return h(a,b)}}})(miniSHA256);
*/

/*
https://tools.ietf.org/html/rfc6238
*/
function test1(){
  var testKey = [
    0 | 0x31323334, 0 | 0x35363738, 0 | 0x39303132, 0 | 0x33343536,
    0 | 0x37383930, 0 | 0x31323334, 0 | 0x35363738, 0 | 0x39303132
  ];

  var stepSize = 30;
  return miniSHA256.totp(testKey)(59, 8);
}
/* */
