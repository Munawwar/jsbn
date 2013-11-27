// Depends on jsbn.js and rng.js

// Version 1.1: support utf-8 encoding in pkcs1pad2

/*jslint bitwise: true, white: true */

/*global require, module, define */

(function (root, factory) {
    if (typeof define === "function" && define.amd) {
        define(['jsbn2.js'], factory);
    } else if (typeof exports === 'object') { //For NodeJS
        module.exports = factory(require('jsbn2.js'));
    } else { //For browsers
        root.RSAKey = factory(root.BigInteger);
    }
}(this, function (BigInteger) {
    //Utility functions

    // convert a (hex) string to a bignum object
    function parseBigInt(str,r) {
        return new BigInteger(str,r);
    }

    function byte2Hex(b) {
        if(b < 0x10)
            return "0" + b.toString(16);
        else
            return b.toString(16);
    }

    // PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
    function pkcs1pad2(s,n) {
        if(n < s.length + 11) { // TODO: fix for utf-8
            throw "Message too long for RSA";
        }
        var ba = [];
        var i = s.length - 1;
        while(i >= 0 && n > 0) {
            var c = s.charCodeAt(i--);
            if(c < 128) { // encode using utf-8
                ba[--n] = c;
            }
            else if((c > 127) && (c < 2048)) {
                ba[--n] = (c & 63) | 128;
                ba[--n] = (c >> 6) | 192;
            }
            else {
                ba[--n] = (c & 63) | 128;
                ba[--n] = ((c >> 6) & 63) | 128;
                ba[--n] = (c >> 12) | 224;
            }
        }
        ba[--n] = 0;
        var rng = new SecureRandom();
        var x = [];
        while(n > 2) { // random non-zero pad
            x[0] = 0;
            while(x[0] == 0) rng.nextBytes(x);
            ba[--n] = x[0];
        }
        ba[--n] = 2;
        ba[--n] = 0;
        return new BigInteger(ba);
    }

    //Arcfour as a PRNG
    var PRNG = (function () {
        function Arcfour() {
          this.i = 0;
          this.j = 0;
          this.S = [];
        }

        // Initialize arcfour context from key, an array of ints, each from [0..255]
        function ARC4init(key) {
          var i, j, t;
          for(i = 0; i < 256; ++i)
            this.S[i] = i;
          j = 0;
          for(i = 0; i < 256; ++i) {
            j = (j + this.S[i] + key[i % key.length]) & 255;
            t = this.S[i];
            this.S[i] = this.S[j];
            this.S[j] = t;
          }
          this.i = 0;
          this.j = 0;
        }

        function ARC4next() {
          var t;
          this.i = (this.i + 1) & 255;
          this.j = (this.j + this.S[this.i]) & 255;
          t = this.S[this.i];
          this.S[this.i] = this.S[this.j];
          this.S[this.j] = t;
          return this.S[(t + this.S[this.i]) & 255];
        }

        Arcfour.prototype.init = ARC4init;
        Arcfour.prototype.next = ARC4next;

        return {
            // Plug in your RNG constructor here
            newstate: function () {
              return new Arcfour();
            },
            // Pool size must be a multiple of 4 and greater than 32.
            // An array of bytes the size of the pool will be passed to init()
            psize: 256
        };
    }());

    /**
     * Random number generator - uses PRNG backend.
     * @class RSAKey.utils.SecureRandom
     * @private
     */
    // For best results, put code like
    // <body onClick='RSAKey.seed();' onKeyPress='RSAKey.seed();'>
    // in your main HTML document.
    function SecureRandom() {}
    (function () {
        var rng_state;
        var rng_pool;
        var rng_pptr;
        var rng_psize = PRNG.psize;

        // Mix in a 32-bit integer into the pool
        function rng_seed_int(x) {
          rng_pool[rng_pptr++] ^= x & 255;
          rng_pool[rng_pptr++] ^= (x >> 8) & 255;
          rng_pool[rng_pptr++] ^= (x >> 16) & 255;
          rng_pool[rng_pptr++] ^= (x >> 24) & 255;
          if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
        }

        /**
         * Mix in the current time (w/milliseconds) into the pool
         * @method seedTime
         * @static
         */
        function rng_seed_time() {
            rng_seed_int(new Date().getTime());
        }

        function rng_get_byte() {
          if(rng_state == null) {
            rng_seed_time();
            rng_state = PRNG.newstate();
            rng_state.init(rng_pool);
            for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
              rng_pool[rng_pptr] = 0;
            rng_pptr = 0;
            //rng_pool = null;
          }
          // TODO: allow reseeding after first request
          return rng_state.next();
        }

        function rng_get_bytes(ba) {
          var i;
          for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
        }

        SecureRandom.prototype.nextBytes = rng_get_bytes;
        SecureRandom.seedTime = rng_seed_time;

        // Initialize the pool with junk if needed.
        if(rng_pool == null) {
          rng_pool = [];
          rng_pptr = 0;
          var t;
          if(window.crypto && window.crypto.getRandomValues) {
            // Use webcrypto if available
            var ua = new Uint8Array(32);
            window.crypto.getRandomValues(ua);
            for(t = 0; t < 32; ++t)
              rng_pool[rng_pptr++] = ua[t];
          }
          if(navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
            // Extract entropy (256 bits) from NS4 RNG if available
            var z = window.crypto.random(32);
            for(t = 0; t < z.length; ++t)
              rng_pool[rng_pptr++] = z.charCodeAt(t) & 255;
          }
          while(rng_pptr < rng_psize) {  // extract some randomness from Math.random()
            t = Math.floor(65536 * Math.random());
            rng_pool[rng_pptr++] = t >>> 8;
            rng_pool[rng_pptr++] = t & 255;
          }
          rng_pptr = 0;
          rng_seed_time();
          //rng_seed_int(window.screenX);
          //rng_seed_int(window.screenY);
        }
    }());

    /**
     * "empty" RSA key constructor
     * @class
     */
    function RSAKey() {
        this.n = null;
        this.e = 0;
        this.d = null;
        this.p = null;
        this.q = null;
        this.dmp1 = null;
        this.dmq1 = null;
        this.coeff = null;
    }
    RSAKey.prototype = {
        // protected
        /**
         * Perform raw public operation on "x": return x^e (mod n)
         * @protected
         */
        doPublic: function (x) {
          return x.modPowInt(this.e, this.n);
        },

        // public
        /**
         * Set the public key fields N and e from hex strings
         */
        setPublic: function (N,E) {
            if(N != null && E != null && N.length > 0 && E.length > 0) {
                this.n = parseBigInt(N,16);
                this.e = parseInt(E,16);
            }
            else
                throw "Invalid RSA public key";
        },
        /**
         * Return the PKCS#1 RSA encryption of "text" as an even-length hex string
         */
        encrypt: function (text) {
            var m = pkcs1pad2(text,(this.n.bitLength()+7)>>3);
            if(m == null) return null;
            var c = this.doPublic(m);
            if(c == null) return null;
            var h = c.toString(16);
            if((h.length & 1) == 0) return h; else return "0" + h;
        }
        // Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
        /*encrypt_b64: function (text) {
            var h = this.encrypt(text);
            if(h) return hex2b64(h); else return null;
        }*/
    };
    /**
     * Calls {@link RSAKey.utils.SecureRandom#seedTime}
     * @static
     * @method
     */
    RSAKey.seed = SecureRandom.seedTime;
    /**
     * Namespace for RSA related utility classes/functions.
     * @static
     */
    RSAKey.utils = {
        SecureRandom: SecureRandom
    };

    return RSAKey;
}));
