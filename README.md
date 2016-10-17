# miniSHA256.js
Minimal JavaScript implementation of SHA-256
```javascript
var sha256 = miniSHA256(); // new instance
var hash   = sha256.digest(
               // message = 'abc'
               // message as array of 32-bit integers MSD/BE
               [0 | 0x61626300],
               // message length in bits
               8 * 3
             );
// check that hash is 
// BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
var isExpected = ('' + hash) === ('' + [
  0 | 0xba7816bf, 0 | 0x8f01cfea, 0 | 0x414140de, 0 | 0x5dae2223,
  0 | 0xb00361a3, 0 | 0x96177a9c, 0 | 0xb410ff61, 0 | 0xf20015ad]);
```
[Github pages](https://tomaslangkaas.github.io/miniSHA256.js/)
