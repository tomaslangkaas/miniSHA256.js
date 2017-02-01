(function(SHA256) {
    function truncate(otp, digits) {
        var offset = otp[otp.length - 1] & 0xf;
        var bitOffset = (offset * 8) & 31;
        offset >>= 2;
        var truncated = (otp[offset] << (bitOffset)) & 0x7fffffff;
        digits = digits > 8 ? 8 : digits;
        if (bitOffset)
            truncated ^= otp[offset + 1] >>> (32 - bitOffset);
        return ('0000000' + (truncated % Math.pow(10, digits))).slice(-digits);
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
    SHA256['totp'] = function(key, keySize, stepSize) {
        var hotpInstance = SHA256['hotp'](key, keySize);
        stepSize = stepSize || 30;
        return function(unixTime, digits) {
            unixTime = Math.floor((unixTime || (+new Date) / 1e3) / stepSize);
            return hotpInstance(unixTime, digits);
        }
    }
})(miniSHA256);

/* minified 405 bytes
(function(a){a.hotp=function(c,d){var e=a.hmac(c,d);return function(a,h){var b=e([Math.floor(a/4294967296),a>>>0]);if(h){var f=h,g=b[b.length-1]&15,c=8*g&31,g=g>>2,d=b[g]<<c&2147483647,f=8<f?8:f;c&&(d^=b[g+1]>>>32-c);b=("0000000"+d%Math.pow(10,f)).slice(-f)}return b}};a.totp=function(c,d,e){var k=a.hotp(c,d);e=e||30;return function(a,b){a=Math.floor((a||+new Date/1E3)/e);return k(a,b)}}})(miniSHA256);
*/

/*
https://tools.ietf.org/html/rfc6238

function test1(){
  var testKey = [
    0 | 0x31323334, 0 | 0x35363738, 0 | 0x39303132, 0 | 0x33343536,
    0 | 0x37383930, 0 | 0x31323334, 0 | 0x35363738, 0 | 0x39303132
  ];

  var stepSize = 30;
  return miniSHA256.totp(testKey)(59, 8);
}
*/
