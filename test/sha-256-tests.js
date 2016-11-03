var SHA256tests = {
    'shaTest1': {
        title: 'Test 1',
        setup: function() {
            return function(done) {
                var pass = 0,
                    date = +new Date,
                    i, result,
                    vectors = SHA256TestVectors['set 1'];

                for (i = 0; i < 8; i++) {
                    result = miniSHA256().digest(
                        vectors[i].message,
                        vectors[i].messageLength
                    );
                    if ('' + result === '' + vectors[i].hash) {
                        pass++;
                    }
                }
                done([pass, i, (+new Date) - date]);
            }
        }
    },

    'shaTest3': {
        title: 'Test 3',
        setup: function() {
            return function(done) {
                var pass = 0,
                    date = +new Date,
                    message = [],
                    i, result,
                    vectors = SHA256TestVectors['set 2'],
                    len = vectors.length / 8;
                for (i = 0; i < len; i++) {
                    result = miniSHA256().digest(message, i);
                    if ('' + result === '' + vectors.slice(i * 8, i * 8 + 8)) {
                        pass++;
                    }
                }
                done([pass, len, (+new Date) - date]);
            }
        }
    },

    'shaTest4': {
        title: 'Test 4',
        setup: function() {
            return function(done) {
                var pass = 0,
                    date = +new Date,
                    message = [],
                    i, result,
                    vectors = SHA256TestVectors['set 3'],
                    len = vectors.length / 8;
                for (i = 0; i < len; i++) {
                    //place 1 at bit position i in 512 bit array
                    message[i >>> 5] = 1 << (31 - (i & 31));
                    result = miniSHA256().digest(message, 512);
                    //reset bit position to 0
                    message[i >>> 5] = 0;
                    if ('' + result === '' + vectors.slice(i * 8, i * 8 + 8)) {
                        pass++;
                    }
                }
                done([pass, len, (+new Date) - date]);
            }
        }
    },

    'shaTest5': {
        title: 'Test 5',
        setup: function() {
            var message = [],
                date = +new Date,
                pass = 0,
                count = 1,
                iter = 5000,
                limit = 0,
            vectors = SHA256TestVectors['set 4'];
            message = miniSHA256().digest(
                message,
                256
            );
            if ('' + message === '' + vectors.hash) {
                pass++;
            }
            return function(onComplete, onProgress) {
                limit += iter;
                var startDate = +new Date;
                for (count; count < 1e5 && count < limit; count++) {
                    message = miniSHA256().digest(
                        message,
                        256
                    );
                }
                iter = iter * 60 / ((+new Date) - startDate);
                if (count == 1e5) {
                    onComplete([
                        pass + ('' + message === '' + vectors.hash1e5),
                        2,
                        (+new Date) - date
                    ]);
                } else {
                    onProgress(count / 1e5);
                }
            }
        }
    }
};
