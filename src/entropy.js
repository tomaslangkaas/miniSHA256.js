(function(miniSHA256) {
  var requestLimit = 128,
    maxSize = 3 * requestLimit,
    buffer = [],
    requests = [],
    callbacks = [],
    words = [],
    //uncompressed = [],
    returnValues,
    returnFormat;

  function sha256d(message) { // double sha256
    return miniSHA256().digest(miniSHA256().digest(message));
  }

  function collect(values) {
    var D = Date;

    function run() {
      for (var i = 0, d = +new D() + 1; + new D() < d; i++);
      buffer.push(i);
      while (requests.length && requests[0] <= buffer.length) {
        returnValues = buffer.splice(0, requests.shift());
        callbacks.shift()(
          (returnFormat = words.shift()) ?
          (sha256d(returnValues.slice(0, 64)).concat(
            sha256d(returnValues.slice(64))
          )).slice(0, returnFormat) : returnValues
        );
      }
    }
    while (--values) setTimeout(run);
    run();
  }
  collect(maxSize);
  miniSHA256['entropy'] = function(bits, callback, raw) {
    var values = (bits + 3) >> 2; // 4 bits per entropy value
    if (values > 0 && values <= requestLimit && typeof callback === 'function') {
      requests.push(values);
      callbacks.push(callback);
      words.push(raw ? 0 : (bits + 31) >>> 5);
      //uncompressed.push(raw);
      collect(values);
      return true;
    } else {
      return false;
    }
  };
})(miniSHA256);
