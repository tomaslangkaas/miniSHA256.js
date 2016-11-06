miniSHA256 = (function(s, p) {
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
  return function() {
    return new s;
  };
})(function() {
  //function sha256class(){
  //combine all parameters in one array/heap? typed array of int32, 16+8+1=25 int32?
  this.w = []; //temp processing array
  this.h = this.H.slice(); //current hash
  this.l = 0; //current length in bits, 32 bit arr
}, {
  //generate K and H at startup?
  //use typed arrays for arrays K, H and w?
  /*
  K:[	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2],
  H:[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
  */
  K: [],
  H: [],
  //todo: add configurable output hash? not.
  p: function(m, i, t, k, w) { //message of 32 bit words, start index, temp hash, key, w temp arr
    //var j,x,a=t[0]|0,b=t[1]|0,c=t[2]|0,d=t[3]|0,e=t[4]|0,f=t[5]|0,g=t[6]|0,h=t[7]|0;
    var j, x, a = t[0],
      b = t[1],
      c = t[2],
      d = t[3],
      e = t[4],
      f = t[5],
      g = t[6],
      h = t[7];
    //while(++j<64){
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
  //clone() => returns new instance with same state(current hash and bitlength)
  //clone:function(){},
  //update(words,startindex,stopindex) => array of 32 bit words, start at index, amount multiple of 16 (512 bits)
  //processes words, updates current hash and bitlength
  update: function(m, blocks, i) { //little tested
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
  //digest(words,index,bitlength) => array of 32 bit words, start at index, process amount according to bitlength, return final hash
  //does not update current hash and bitlength (allows forking/cloning)
  digest: function(m, l) {
    //provide array for hash result?
    //read m without copy or alter?
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
