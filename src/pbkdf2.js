(function(sha256) {
  sha256['pbkdf2'] = function(key, keylength,
    salt, saltlength,
    iterations, dkbytelength,
    onComplete
  ) {
    var i,
      //j,
      pmac,
      temp,
      hmac = sha256.hmac(key, keylength),
      //blocklength = (dkbytelength + 1) >>> 2,
      block = [],
      c = 1,
      offset = saltlength & 31,
      last = saltlength >>> 5;
    var n = ((dkbytelength + 1) >>> 5) * iterations;
    var count = 0;
    i = -8;
    c = 0;

    function run() {
      for (; count < n; count++) {
        if (count % iterations) {
          pmac = hmac(pmac, 256);
        } else {
          i += 8;
          c++;
          salt[last] = salt[last] & -1 << 31 - offset ^ c >>> offset;
          salt[last + 1] = c << 32 - offset;
          pmac = hmac(salt, saltlength + 32);
        }
        block[i] ^= pmac[0];
        block[i + 1] ^= pmac[1];
        block[i + 2] ^= pmac[2];
        block[i + 3] ^= pmac[3];
        block[i + 4] ^= pmac[4];
        block[i + 5] ^= pmac[5];
        block[i + 6] ^= pmac[6];
        block[i + 7] ^= pmac[7];
      }
      if (count === n) {
        onComplete && onComplete(block);
      }
    }
    setTimeout(run);
    /*for (i = 0; i < blocklength; i += 8, c++) {
        salt[last] = salt[last] & -1 << 31 - offset ^ c >>> offset;
        salt[last + 1] = c << 32 - offset;
        pmac = hmac(salt, saltlength + 32);
        block[i]     = pmac[0];
        block[i + 1] = pmac[1];
        block[i + 2] = pmac[2];
        block[i + 3] = pmac[3];
        block[i + 4] = pmac[4];
        block[i + 5] = pmac[5];
        block[i + 6] = pmac[6];
        block[i + 7] = pmac[7];
        for (j = 1; j < iterations; j++) {
            pmac = hmac(pmac, 256);
            block[i]     ^= pmac[0];
            block[i + 1] ^= pmac[1];
            block[i + 2] ^= pmac[2];
            block[i + 3] ^= pmac[3];
            block[i + 4] ^= pmac[4];
            block[i + 5] ^= pmac[5];
            block[i + 6] ^= pmac[6];
            block[i + 7] ^= pmac[7];
        }
    }*/
    //console.log(bico.toHex(block.slice(),32));
    //onComplete && onComplete(block);
    //return block;
  }
})(miniSHA256);

/* minified 419 bytes
(function(m){m.pbkdf2=function(d,e,f,g,n,a){var c;d=m.a(d,e);var p=a+1>>>2,b=[],h=1,k=g&31,l=g>>>5;for(a=0;a<p;a+=8,h++)for(f[l]=f[l]&-1<<31-k^h>>>k,f[l+1]=h<<32-k,c=d(f,g+32),b[a]=c[0],b[a+1]=c[1],b[a+2]=c[2],b[a+3]=c[3],b[a+4]=c[4],b[a+5]=c[5],b[a+6]=c[6],b[a+7]=c[7],e=1;e<n;e++)c=d(c,256),b[a]^=c[0],b[a+1]^=c[1],b[a+2]^=c[2],b[a+3]^=c[3],b[a+4]^=c[4],b[a+5]^=c[5],b[a+6]^=c[6],b[a+7]^=c[7];return b}})(miniSHA256);
*/
miniSHA256.pbkdf2([1348563827, 2003792484], 64, [1314997100], 32, 80000, 64, function(block) {
  console.log('pbkdf2', bico.toHex(block, 32), ' ** ',
    "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
  );
});
/*
bico.toHex(miniSHA256.pbkdf2([1348563827, 2003792484],64,[1314997100],32,80000,64),32);
"4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
*/
