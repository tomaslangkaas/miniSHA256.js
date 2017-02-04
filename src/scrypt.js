(function(SHA256) {
    //salsa20/8 quarterround
    //state array x, index a, index b, index c, index d, temp var
    function qr(x, a, b, c, d, t) {
        x[a] ^= (t = x[d] + x[c]) << 7 ^ t >>> 25;
        x[b] ^= (t = x[a] + x[d]) << 9 ^ t >>> 23;
        x[c] ^= (t = x[b] + x[a]) << 13 ^ t >>> 19;
        x[d] ^= (t = x[c] + x[b]) << 18 ^ t >>> 14;
    }
    //(readArr, startIndex, destArr, destIndex, param r)
    function blockMix(readArr, startIndex, destArr, destIndex, r) {
        var x = [],
            w = [],
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
            qr(x, 4,  8,  12, 0);
            qr(x, 9,  13, 1,  5);
            qr(x, 14, 2,  6,  10);
            qr(x, 3,  7,  11, 15);
            qr(x, 1,  2,  3,  0);
            qr(x, 6,  7,  4,  5);
            qr(x, 11, 8,  9,  10);
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

    function ROMix(inputArr, readIndex, N, r) {
        var V = [],
            r32 = r * 32,
            t = [],
            x = [],
            i, j, z, f = blockMix;
        for (i = 0; i < r32; i++)
            V[i] = (z = inputArr[i + readIndex]) >>> 24 ^ z >>> 8 & 65280 ^ (z & 65280) << 8 ^ (z & 255) << 24;
        for (i = 1; i < N; i++) f(V, r32 * i - r32, V, r32 * i, r);
        f(V, N * r32 - r32, x, 0, r);
        for (i = 0; i < N; i++) {
            j = (x[r32 - 16] & (N - 1)) * r32;
            for (z = 0; z < r32; z++) {
                t[z] = x[z] ^ V[z + j];
            }
            f(t, 0, x, 0, r);
        }
        for (i = 0; i < r32; i++)
            inputArr[i + readIndex] = (z = x[i]) >>> 24 ^ z >>> 8 & 65280 ^ (z & 65280) << 8 ^ (z & 255) << 24;
    }

    SHA256['scrypt'] = function (passphrase, passbits, salt, saltbits, N, r, p, dkBytes){
      var blocks = SHA256['pbkdf2'](
        passphrase, passbits, salt, saltbits, 1, p * 128 * r
      );
      for(var i = 0; i < p; i++){
        ROMix(blocks, i * 32, N, r);
      }
      return SHA256['pbkdf2'](
        passphrase, passbits, blocks, p * 128 * r * 8, 1, dkBytes
      );
    }

    function test() {

        function parseHex(e, t) {
            var n, r, i, s;
            for (n = i = 0, r = e.length; n < r;) {
                s = e.charCodeAt(n++);
                if (s > 47 && s < 58 || s > 64 && s < 71 || s > 96 && s < 103) {
                    t[i >>> 5] ^= ((s > 64 ? s + 9 : s) & 15) << 28 - (i & 31);
                    i += 4;
                }
            }
            return i;
        }

        function dispHex(w) {
            var s = '',
                l = w.length,
                i;
            for (i = 0; i < l; i++) {
                s += (0xf00000000 + w[i]).toString(16).slice(-8) + ' ';
            }
            return s;
        }



        /*

        function intRMix(V,x,f,N,r,startIndex,endBeforeIndex)
          //check startIndex or set to 1
          //n1 = endBeforeIndex < N ? endBeforeIndex : N
          //n2 = endBeforeIndex > N ? Math.min(2*N, endBeforeIndex): 0

          //return lastIndex+1

        */

        /*

        scrypt steps

        init=>derive start blocks
        params: p, N, r
        state: b,v,x
        b.length=32r*p
        x.length=32r
        v.length=32r*N

        processing steps: preprocess+p*2N+postprocess

        progP==-1 ==> preprocess

        progP==p+1 ==> postprocess

        parallell processing:
        romMix(paramsAndData,progressReportingFrequency)

        asyncSimul processing:
        romMix(paramsAndData,idealChunkProcessingTime,onprogressFn,oncompleteFn)

        general internal romMix(paramsAndData,chunkSize)

        */

        function switchEndian(w) {
            var i = 0,
                l = w.length,
                t;
            for (i; i < l; i++) {
                t = w[i];
                w[i] = t >>> 24 ^ t >>> 8 & 65280 ^ (t & 65280) << 8 ^ (t & 255) << 24;
            }
        }

        // test vectors blockmix, https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-00

        var inputString = 'f7ce0b65 3d2d72a4 108cf5ab e912ffdd 777616db bb27a70e 8204f3ae 2d0f6fad 89f68f48 11d1e87b cc3bd740 0a9ffd29 094f0184 639574f3 9ae5a131 5217bcd7 89499144 7213bb22 6c25b54d a86370fb cd984380 374666bb 8ffcb5bf 40c254b0 67d27c51 ce4ad5fe d829c90b 505a571b 7f4d1cad 6a523cda 770e67bc eaaf7e89';

        var outputString = 'a41f859c 6608cc99 3b81cacb 020cef05 044b2181 a2fd337d fd7b1c63 96682f29 ' +
            'b4393168 e3c9e6bc fe6bc5b7 a06d96ba e424cc10 2c91745c 24ad673d c7618f81 ' +
            '20edc975 323881a8 0540f64c 162dcd3c 21077cfe 5f8d5fe2 b1a4168f 953678b7 ' +
            '7d3b3d80 3b60e4ab 920996e5 9b4d53b6 5d2a2258 77d5edf5 842cb9f1 4eefe425';

        var romIn = 'f7ce0b65 3d2d72a4 108cf5ab e912ffdd' +
            '777616db bb27a70e 8204f3ae 2d0f6fad' +
            '89f68f48 11d1e87b cc3bd740 0a9ffd29' +
            '094f0184 639574f3 9ae5a131 5217bcd7' +
            '89499144 7213bb22 6c25b54d a86370fb' +
            'cd984380 374666bb 8ffcb5bf 40c254b0' +
            '67d27c51 ce4ad5fe d829c90b 505a571b' +
            '7f4d1cad 6a523cda 770e67bc eaaf7e89';

        var romOut = '79ccc193 629debca 047f0b70 604bf6b6' +
            '2ce3dd4a 9626e355 fafc6198 e6ea2b46' +
            'd5841367 3b99b029 d665c357 601fb426' +
            'a0b2f4bb a200ee9f 0a43d19b 571a9c71' +
            'ef1142e6 5d5a266f ddca832c e59faa7c' +
            'ac0b9cf1 be2bffca 300d01ee 387619c4' +
            'ae12fd44 38f203a0 e4e1c47e c314861f' +
            '4e9087cb 33396a68 73e8f9d2 539a4b8e';


        var inputArr = [],
            expected = [];
        parseHex(inputString, inputArr);
        switchEndian(inputArr);
        var outputArr = [];
        blockMix(inputArr, 0, outputArr, 0, 1);
        switchEndian(outputArr);
        parseHex(outputString, expected);
        console.log('test blockMix',
            //dispHex(outputArr),
            '' + outputArr === '' + expected);

        inputArr = [], expected = [];;
        parseHex(romIn, inputArr);
        var s = dispHex(inputArr);
        ROMix(inputArr, 0, 16, 1);
        parseHex(romOut, expected);
        console.log('test ROMix',
            //dispHex(inputArr),
            '' + inputArr === '' + expected);
    }

    test();
})(miniSHA256);

var scryptVectors = [
  {
    P: [], PLen: 0, // P = ""
    S: [], SLen: 0, // S = ""
    N: 16, r: 1, p: 1,
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
    P: [0 | 0x70617373, 0 | 0x776f7264], PLen: 8 * 8,
    // S = "NaCl"
    S: [0 | 0x4e61436c], SLen: 4 * 8,
    N: 1024, r: 8, p: 16,
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
    N: 16384, r: 8, p: 1,
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
    N: 1048576, r: 8, p: 1,
    dkLen: 64,
    expected: [
      0 | 0x2101cb9b, 0 | 0x6a511aae, 0 | 0xaddbbe09, 0 | 0xcf70f881,
      0 | 0xec568d57, 0 | 0x4a2ffd4d, 0 | 0xabe5ee98, 0 | 0x20adaa47,
      0 | 0x8e56fd8f, 0 | 0x4ba5d09f, 0 | 0xfa1c6d92, 0 | 0x7c40f4c3,
      0 | 0x37304049, 0 | 0xe8a952fb, 0 | 0xcbf45c6f, 0 | 0xa77a41a4
    ]
  }
];

/*
bico.toHex(miniSHA256.scrypt([], 0, [], 0, 16, 1, 1, 64), 32);
"77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
*/
