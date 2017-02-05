(function(SHA256, setTimeout) {
    //salsa20/8 quarterround
    //state array x, index a, index b, index c, index d, temp var
    function qr(x, a, b, c, d, t) {
        x[a] ^= (t = x[d] + x[c]) << 7 ^ t >>> 25;
        x[b] ^= (t = x[a] + x[d]) << 9 ^ t >>> 23;
        x[c] ^= (t = x[b] + x[a]) << 13 ^ t >>> 19;
        x[d] ^= (t = x[c] + x[b]) << 18 ^ t >>> 14;
    }
    //(readArr, startIndex, destArr, destIndex, param r, tempArr1, tempArr2)
    function blockMix(readArr, startIndex, destArr, destIndex, r, t1, t2) {
        var x = t1, //[],
            w = t2, //[],
            i,
            xx16, xx16r, t, xx, r2 = r * 2,
            j = (r2 - 1) * 16 + startIndex;
        //read first input
        for (i = 0; i < 16; i++) {
            x[i] = w[i] = readArr[startIndex + i] ^ readArr[j + i];
        }
        for (xx = j = 0; xx < r2; j++) {
            //two loops combined in one: outer loop for block index x from 0 to 2*r-1,
            //inner loop for 4 double rounds of salsa20/8
            qr(x, 4, 8, 12, 0);
            qr(x, 9, 13, 1, 5);
            qr(x, 14, 2, 6, 10);
            qr(x, 3, 7, 11, 15);
            qr(x, 1, 2, 3, 0);
            qr(x, 6, 7, 4, 5);
            qr(x, 11, 8, 9, 10);
            qr(x, 12, 13, 14, 15);
            if (j == 3) { //if 8 rounds of salsa20/8 is completed, write to output array, read next input
                xx16r = 16 * ((xx >> 1) + (xx & 1 ? r : 0)) + destIndex; //destArr startIndex
                xx++; //update block index
                xx16 = startIndex + 16 * xx; //next readArr startIndex
                for (i = 0; i < 16; i++) {
                    x[i] = w[i] = readArr[xx16 + i] ^ (destArr[xx16r + i] = (x[i] + w[i]) | 0);
                }
                j = -1; //reset salsa20/8 double round index, gets incremented to 0 after end of for loop
            }
        }
    }

    function ROMix(inputArr, readIndex, N, r, V,
        t, x, t1, t2,
        onComplete, onProgress
    ) {
      //console.log('rom N', N);
        var r32 = r * 32,
            i, j, z, f = blockMix;
        for (i = 0; i < r32; i++)
            V[i] = (z = inputArr[i + readIndex]) >>> 24 ^ z >>> 8 & 65280 ^ (z & 65280) << 8 ^ (z & 255) << 24;
        var ms = 50,
            iter = 200,
            N2 = N * 2,
            target;
        i = 1;
        function run(){
          //console.log('iter', iter, i + iter, Math.min(N, i + iter), N);
          var start = +new Date, elapsed;
          if(i < N){
            target = Math.min(N, i + iter);
            iter = target - i;
            //console.log('t', target, iter, N);
            for (; i < target; i++) {
                f(V, r32 * i - r32, V, r32 * i, r, t1, t2);
            }
            if(i === N){
              f(V, N * r32 - r32, x, 0, r, t1, t2);
            }
            setTimeout(run, 0);
          }else if(i < N2){
            target = Math.min(N2, i + iter);
            iter = target - i;
            for (; i < N2; i++) {
                j = (x[r32 - 16] & (N - 1)) * r32;
                for (z = 0; z < r32; z++) {
                    t[z] = x[z] ^ V[z + j];
                }
                f(t, 0, x, 0, r, t1, t2);
            }
            if(i === N2){
              for (j = 0; j < r32; j++)
                  inputArr[j + readIndex] = (z = x[j]) >>> 24 ^ z >>> 8 & 65280 ^ (z & 65280) << 8 ^ (z & 255) << 24;
              i++;
              onComplete();
            }else{
              setTimeout(run, 0);
            }
          }
          elapsed = (+new Date) - start;
          //console.log(elapsed, iter, (iter * ms) / (elapsed || 1));
          iter = (iter * ms) / (elapsed || 0.001);
        }
        //setTimeout(run, 0); //speed up
        setTimeout(run, 0); //speed up
        run();
        /*for (i = 1; i < N; i++) {
            f(V, r32 * i - r32, V, r32 * i, r, t1, t2);
        }
        f(V, N * r32 - r32, x, 0, r, t1, t2);
        for (i = 0; i < N; i++) {
            j = (x[r32 - 16] & (N - 1)) * r32;
            for (z = 0; z < r32; z++) {
                t[z] = x[z] ^ V[z + j];
            }
            f(t, 0, x, 0, r, t1, t2);
        }
        for (i = 0; i < r32; i++)
            inputArr[i + readIndex] = (z = x[i]) >>> 24 ^ z >>> 8 & 65280 ^ (z & 65280) << 8 ^ (z & 255) << 24;
        onComplete();*/
    }

    SHA256['scrypt'] = function(passphrase, passbits, salt, saltbits, N, r, p, dkBytes, onComplete, onProgress) {
        var blocks = SHA256['pbkdf2'](
            passphrase, passbits, salt, saltbits, 1, p * 128 * r
        );
        var V = [],
            t = [],
            x = [],
            t1 = [],
            t2 = [];
        V.length = 32 * r * N;
        t.length = x.length = 32 * r;
        t1.length = t2.length = 16;
        var total = N * p * 2,
            count = 0,
            i = -1;

        function progress(iter) {

        }

        function run() {
            if (i < (p - 1)) {
                //setTimeout(function() {
                    i++;
                    ROMix(blocks, i * 32 * r, N, r,
                        V, t, x, t1, t2, run, progress);
                //}, 0);
            } else {
                onComplete(SHA256['pbkdf2'](
                    passphrase, passbits, blocks, p * 128 * r * 8, 1, dkBytes
                ));
            }
        }
        run();
        //console.log(blocks.length, 32 * r * p);
        //        for (var i = 0; i < p; i++) {
        //            ROMix(blocks, i * 32 * r, N, r,
        //                V, t, x, t1, t2);
        //        }
        //        onComplete(SHA256['pbkdf2'](
        //            passphrase, passbits, blocks, p * 128 * r * 8, 1, dkBytes
        //        ));
    }
})(miniSHA256, setTimeout);

function scryptTest(indexes) {
    var d = +new Date,
        vector = scryptVectors[indexes.shift()];
    miniSHA256.scrypt(
        vector.P, vector.PLen,
        vector.S, vector.SLen,
        vector.N, vector.r, vector.p,
        vector.dkLen,
        function(hash) {
            console.log((+new Date) - d + ' ms', '' + hash === '' + vector.expected, hash);
            if (indexes.length) {
                scryptTest(indexes);
            }
        }
    );
}

var scryptVectors = [{
        P: [],
        PLen: 0, // P = ""
        S: [],
        SLen: 0, // S = ""
        N: 16,
        r: 1,
        p: 1,
        dkLen: 64,
        expected: [
            0 | 0x77d65762, 0 | 0x38657b20, 0 | 0x3b19ca42, 0 | 0xc18a0497,
            0 | 0xf16b4844, 0 | 0xe3074ae8, 0 | 0xdfdffa3f, 0 | 0xede21442,
            0 | 0xfcd0069d, 0 | 0xed0948f8, 0 | 0x326a753a, 0 | 0x0fc81f17,
            0 | 0xe8d3e0fb, 0 | 0x2e0d3628, 0 | 0xcf35e20c, 0 | 0x38d18906
        ]
    },
    {
        // P = "password"
        P: [0 | 0x70617373, 0 | 0x776f7264],
        PLen: 8 * 8,
        // S = "NaCl"
        S: [0 | 0x4e61436c],
        SLen: 4 * 8,
        N: 1024,
        r: 8,
        p: 16,
        dkLen: 64,
        expected: [
            0 | 0xfdbabe1c, 0 | 0x9d347200, 0 | 0x7856e719, 0 | 0x0d01e9fe,
            0 | 0x7c6ad7cb, 0 | 0xc8237830, 0 | 0xe7737663, 0 | 0x4b373162,
            0 | 0x2eaf30d9, 0 | 0x2e22a388, 0 | 0x6ff10927, 0 | 0x9d9830da,
            0 | 0xc727afb9, 0 | 0x4a83ee6d, 0 | 0x8360cbdf, 0 | 0xa2cc0640
        ]
    },
    {
        // P = "pleaseletmein"
        P: [0 | 0x706c6561, 0 | 0x73656c65, 0 | 0x746d6569, 0 | 0x6e000000],
        PLen: 13 * 8,
        // S = "SodiumChloride"
        S: [0 | 0x536f6469, 0 | 0x756d4368, 0 | 0x6c6f7269, 0 | 0x64650000],
        SLen: 14 * 8,
        N: 16384,
        r: 8,
        p: 1,
        dkLen: 64,
        expected: [
            0 | 0x7023bdcb, 0 | 0x3afd7348, 0 | 0x461c06cd, 0 | 0x81fd38eb,
            0 | 0xfda8fbba, 0 | 0x904f8e3e, 0 | 0xa9b543f6, 0 | 0x545da1f2,
            0 | 0xd5432955, 0 | 0x613f0fcf, 0 | 0x62d49705, 0 | 0x242a9af9,
            0 | 0xe61e85dc, 0 | 0x0d651e40, 0 | 0xdfcf017b, 0 | 0x45575887
        ]
    },
    {
        // P = "pleaseletmein"
        P: [0 | 0x706c6561, 0 | 0x73656c65, 0 | 0x746d6569, 0 | 0x6e000000],
        PLen: 13 * 8,
        // S = "SodiumChloride"
        S: [0 | 0x536f6469, 0 | 0x756d4368, 0 | 0x6c6f7269, 0 | 0x64650000],
        SLen: 14 * 8,
        N: 1048576,
        r: 8,
        p: 1,
        dkLen: 64,
        expected: [
            0 | 0x2101cb9b, 0 | 0x6a511aae, 0 | 0xaddbbe09, 0 | 0xcf70f881,
            0 | 0xec568d57, 0 | 0x4a2ffd4d, 0 | 0xabe5ee98, 0 | 0x20adaa47,
            0 | 0x8e56fd8f, 0 | 0x4ba5d09f, 0 | 0xfa1c6d92, 0 | 0x7c40f4c3,
            0 | 0x37304049, 0 | 0xe8a952fb, 0 | 0xcbf45c6f, 0 | 0xa77a41a4
        ]
    }
];


scryptTest([0, 1, 2]);
//scryptTest(2); only works in chrome
//scryptTest(3); out of memory (chrome)
/*
bico.toHex(miniSHA256.scrypt([], 0, [], 0, 16, 1, 1, 64), 32);
"77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
*/
