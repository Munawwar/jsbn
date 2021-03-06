// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

/*jslint bitwise: true, white: true, eqeq: true*/

/*global module, define */

(function (root, factory) {
    if (typeof define === "function" && define.amd) {
        define(factory);
    } else if (typeof exports === 'object') { //For NodeJS
        module.exports = factory();
    } else { //For browsers
        root.BigInteger = factory();
    }
}(this, function () {
    //Copy all properties from obj to target object.
    function apply(target, obj) {
        for (var key in obj) {
            if (obj.hasOwnProperty(key)) {
                target[key] = obj[key];
            }
        }
    }

    // Bits per digit
    var dbits;

    // JavaScript engine analysis
    var canary = 0xdeadbeefcafe;
    var j_lm = ((canary&0xffffff)==0xefcafe);

    /**
     * BigInteger Class
     */
    function BigInteger(a,b,c) {
      if(a != null)
        if("number" == typeof a) this.fromNumber(a,b,c);
        else if(b == null && "string" != typeof a) this.fromString(a,256);
        else this.fromString(a,b);
    }

    // Digit conversions
    var int2char = (function () {
            var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
            return function (n) { return BI_RM.charAt(n); };
        }()),
        intAt = (function () {
            var BI_RC = [];
            var rr,vv;
            rr = "0".charCodeAt(0);
            for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
            rr = "a".charCodeAt(0);
            for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
            rr = "A".charCodeAt(0);
            for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
            return function (s,i) {
                var c = BI_RC[s.charCodeAt(i)];
                return (c==null)?-1:c;
            };
        }());

    // return new, unset BigInteger
    function nbi() { return new BigInteger(null); }

    // return bigint initialized to value
    function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

    // returns bit length of the integer x
    function nbits(x) {
      var r = 1, t;
      if((t=x>>>16) != 0) { x = t; r += 16; }
      if((t=x>>8) != 0) { x = t; r += 8; }
      if((t=x>>4) != 0) { x = t; r += 4; }
      if((t=x>>2) != 0) { x = t; r += 2; }
      if((t=x>>1) != 0) { x = t; r += 1; }
      return r;
    }

    // am: Compute w_j += (x*this_i), propagate carries,
    // c is initial carry, returns final carry.
    // c < 3*dvalue, x < 2*dvalue, this_i < dvalue
    // We need to select the fastest one that works in this environment.

    // am1: use a single mult and divide to get the high bits,
    // max digit bits should be 26 because
    // max internal value = 2*dvalue^2-2*dvalue (< 2^53)
    function am1(i,x,w,j,c,n) {
      while(--n >= 0) {
        var v = x*this[i++]+w[j]+c;
        c = Math.floor(v/0x4000000);
        w[j++] = v&0x3ffffff;
      }
      return c;
    }
    // am2 avoids a big mult-and-extract completely.
    // Max digit bits should be <= 30 because we do bitwise ops
    // on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
    function am2(i,x,w,j,c,n) {
      var xl = x&0x7fff, xh = x>>15;
      while(--n >= 0) {
        var l = this[i]&0x7fff;
        var h = this[i++]>>15;
        var m = xh*l+h*xl;
        l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
        c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
        w[j++] = l&0x3fffffff;
      }
      return c;
    }
    // Alternately, set max digit bits to 28 since some
    // browsers slow down when dealing with 32-bit numbers.
    function am3(i,x,w,j,c,n) {
      var xl = x&0x3fff, xh = x>>14;
      while(--n >= 0) {
        var l = this[i]&0x3fff;
        var h = this[i++]>>14;
        var m = xh*l+h*xl;
        l = xl*l+((m&0x3fff)<<14)+w[j]+c;
        c = (l>>28)+(m>>14)+xh*h;
        w[j++] = l&0xfffffff;
      }
      return c;
    }
    if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
      BigInteger.prototype.am = am2;
      dbits = 30;
    }
    else if(j_lm && (navigator.appName != "Netscape")) {
      BigInteger.prototype.am = am1;
      dbits = 26;
    }
    else { // Mozilla/Netscape seems to prefer am3
      BigInteger.prototype.am = am3;
      dbits = 28;
    }

    var BI_FP = 52;
    /**
     * @class BigInteger
     */
    apply(BigInteger.prototype, {
        DB: dbits,
        DM: ((1<<dbits)-1),
        DV: (1<<dbits),
        FV: Math.pow(2,BI_FP),
        F1: BI_FP-dbits,
        F2: 2*dbits-BI_FP,

        /**
         * copy this to r
         * @protected
         */
        copyTo: function (r) {
            for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
            r.t = this.t;
            r.s = this.s;
        },
        /**
         * set from integer value x, -DV <= x < DV
         * @protected
         */
        fromInt: function (x) {
            this.t = 1;
            this.s = (x<0)?-1:0;
            if(x > 0) this[0] = x;
            else if(x < -1) this[0] = x+this.DV;
            else this.t = 0;
        },
        /**
         * set from string and radix
         * @protected
         */
        fromString: function (s,b) {
            var k;
            if(b == 16) k = 4;
            else if(b == 8) k = 3;
            else if(b == 256) k = 8; // byte array
            else if(b == 2) k = 1;
            else if(b == 32) k = 5;
            else if(b == 4) k = 2;
            else { this.fromRadix(s,b); return; }
            this.t = 0;
            this.s = 0;
            var i = s.length, mi = false, sh = 0;
            while(--i >= 0) {
                var x = (k==8)?s[i]&0xff:intAt(s,i);
                if(x < 0) {
                    if(s.charAt(i) == "-") mi = true;
                    continue;
                }
                mi = false;
                if(sh == 0)
                    this[this.t++] = x;
                else if(sh+k > this.DB) {
                    this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
                    this[this.t++] = (x>>(this.DB-sh));
                }
                else
                    this[this.t-1] |= x<<sh;
                sh += k;
                if(sh >= this.DB) sh -= this.DB;
            }
            if(k == 8 && (s[0]&0x80) != 0) {
                this.s = -1;
                if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
            }
            this.clamp();
            if(mi) BigInteger.ZERO.subTo(this,this);
        },
        /**
         * clamp off excess high words
         * @protected
         */
        clamp: function () {
          var c = this.s&this.DM;
          while(this.t > 0 && this[this.t-1] == c) --this.t;
        },
        /**
         * r = this << n*DB
         * @protected
         */
        dlShiftTo: function (n,r) {
            var i;
            for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
            for(i = n-1; i >= 0; --i) r[i] = 0;
            r.t = this.t+n;
            r.s = this.s;
        },
        /**
         * r = this >> n*DB
         * @protected
         */
        drShiftTo: function (n,r) {
            for(var i = n; i < this.t; ++i) r[i-n] = this[i];
            r.t = Math.max(this.t-n,0);
            r.s = this.s;
        },
        /**
         * r = this << n
         * @protected
         */
        lShiftTo: function (n,r) {
            var bs = n%this.DB;
            var cbs = this.DB-bs;
            var bm = (1<<cbs)-1;
            var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
            for(i = this.t-1; i >= 0; --i) {
            r[i+ds+1] = (this[i]>>cbs)|c;
            c = (this[i]&bm)<<bs;
            }
            for(i = ds-1; i >= 0; --i) r[i] = 0;
            r[ds] = c;
            r.t = this.t+ds+1;
            r.s = this.s;
            r.clamp();
        },
        /**
         * r = this >> n
         * @protected
         */
        rShiftTo: function (n,r) {
            r.s = this.s;
            var ds = Math.floor(n/this.DB);
            if(ds >= this.t) { r.t = 0; return; }
            var bs = n%this.DB;
            var cbs = this.DB-bs;
            var bm = (1<<bs)-1;
            r[0] = this[ds]>>bs;
            for(var i = ds+1; i < this.t; ++i) {
                r[i-ds-1] |= (this[i]&bm)<<cbs;
                r[i-ds] = this[i]>>bs;
            }
            if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
            r.t = this.t-ds;
            r.clamp();
        },
        /**
         * r = this - a
         * @protected
         */
        subTo: function (a,r) {
            var i = 0, c = 0, m = Math.min(a.t,this.t);
            while(i < m) {
                c += this[i]-a[i];
                r[i++] = c&this.DM;
                c >>= this.DB;
            }
            if(a.t < this.t) {
                c -= a.s;
                while(i < this.t) {
                    c += this[i];
                    r[i++] = c&this.DM;
                    c >>= this.DB;
                }
                c += this.s;
            }
            else {
                c += this.s;
                while(i < a.t) {
                    c -= a[i];
                    r[i++] = c&this.DM;
                    c >>= this.DB;
                }
                c -= a.s;
            }
            r.s = (c<0)?-1:0;
            if(c < -1) r[i++] = this.DV+c;
            else if(c > 0) r[i++] = c;
            r.t = i;
            r.clamp();
        },
        /**
         * r = this * a, r != this,a (HAC 14.12)
         * "this" should be the larger one if appropriate.
         * @protected
         */
        multiplyTo: function (a,r) {
            var x = this.abs(), y = a.abs();
            var i = x.t;
            r.t = i+y.t;
            while(--i >= 0) r[i] = 0;
            for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
            r.s = 0;
            r.clamp();
            if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
        },
        /**
         * r = this^2, r != this (HAC 14.16)
         * @protected
         */
        squareTo:  function (r) {
            var x = this.abs();
            var i = r.t = 2*x.t;
            while(--i >= 0) r[i] = 0;
            for(i = 0; i < x.t-1; ++i) {
                var c = x.am(i,x[i],r,2*i,0,1);
                if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
                    r[i+x.t] -= x.DV;
                    r[i+x.t+1] = 1;
                }
            }
            if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
            r.s = 0;
            r.clamp();
        },
        /**
         * divide this by m, quotient and remainder to q, r (HAC 14.20)
         * r != q, this != m.  q or r may be null.
         * @protected
         */
        divRemTo: function (m,q,r) {
            var pm = m.abs();
            if(pm.t <= 0) return;
            var pt = this.abs();
            if(pt.t < pm.t) {
                if(q != null) q.fromInt(0);
                if(r != null) this.copyTo(r);
                return;
            }
            if(r == null) r = nbi();
            var y = nbi(), ts = this.s, ms = m.s;
            var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
            if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
            else { pm.copyTo(y); pt.copyTo(r); }
            var ys = y.t;
            var y0 = y[ys-1];
            if(y0 == 0) return;
            var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
            var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
            var i = r.t, j = i-ys, t = (q==null)?nbi():q;
            y.dlShiftTo(j,t);
            if(r.compareTo(t) >= 0) {
                r[r.t++] = 1;
                r.subTo(t,r);
            }
            BigInteger.ONE.dlShiftTo(ys,t);
            t.subTo(y,y);	// "negative" y so we can replace sub with am later
            while(y.t < ys) y[y.t++] = 0;
            while(--j >= 0) {
                // Estimate quotient digit
                var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
                if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
                    y.dlShiftTo(j,t);
                    r.subTo(t,r);
                    while(r[i] < --qd) r.subTo(t,r);
                }
            }
            if(q != null) {
                r.drShiftTo(ys,q);
                if(ts != ms) BigInteger.ZERO.subTo(q,q);
            }
            r.t = ys;
            r.clamp();
            if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
            if(ts < 0) BigInteger.ZERO.subTo(r,r);
        },
        /**
         * return "-1/this % 2^DB"; useful for Mont. reduction
         * justification:
         *         xy == 1 (mod m)
         *         xy =  1+km
         *   xy(2-xy) = (1+km)(1-km)
         * x[y(2-xy)] = 1-k^2m^2
         * x[y(2-xy)] == 1 (mod m^2)
         * if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
         * should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
         * JS multiply "overflows" differently from C/C++, so care is needed here.
         * @protected
         */
        invDigit: function () {
            if(this.t < 1) return 0;
            var x = this[0];
            if((x&1) == 0) return 0;
            var y = x&3;		// y == 1/x mod 2^2
            y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
            y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
            y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
            // last step - calculate inverse mod DV directly;
            // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
            y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
            // we really want the negative inverse, and -DV < y < DV
            return (y>0)?this.DV-y:-y;
        },
        /**
          * true iff this is even
          * @protected
          */
        isEven: function () { return ((this.t>0)?(this[0]&1):this.s) == 0; },
        /**
         * @protected
         * this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
         */
        exp: function (e,z) {
            if(e > 0xffffffff || e < 1) return BigInteger.ONE;
            var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
            g.copyTo(r);
            while(--i >= 0) {
                z.sqrTo(r,r2);
                if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
                else { var t = r; r = r2; r2 = t; }
            }
            return z.revert(r);
        },

        /*public methods*/
        /**
         * return string representation in given radix
         */
        toString: function (b) {
            if(this.s < 0) return "-"+this.negate().toString(b);
            var k;
            if(b == 16) k = 4;
            else if(b == 8) k = 3;
            else if(b == 2) k = 1;
            else if(b == 32) k = 5;
            else if(b == 4) k = 2;
            else return this.toRadix(b);
            var km = (1<<k)-1, d, m = false, r = "", i = this.t;
            var p = this.DB-(i*this.DB)%k;
            if(i-- > 0) {
                if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
                while(i >= 0) {
                  if(p < k) {
                    d = (this[i]&((1<<p)-1))<<(k-p);
                    d |= this[--i]>>(p+=this.DB-k);
                  }
                  else {
                    d = (this[i]>>(p-=k))&km;
                    if(p <= 0) { p += this.DB; --i; }
                  }
                  if(d > 0) m = true;
                  if(m) r += int2char(d);
                }
            }
            return m?r:"0";
        },
        /**
         * -this
         */
        negate: function () { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; },
        /**
         * |this|
         */
        abs: function () { return (this.s<0)?this.negate():this; },
        /**
         * return + if this > a, - if this < a, 0 if equal
         */
        compareTo: function (a) {
            var r = this.s-a.s;
            if(r != 0) return r;
            var i = this.t;
            r = i-a.t;
            if(r != 0) return (this.s<0)?-r:r;
            while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
            return 0;
        },
        /**
         * return the number of bits in "this"
         */
        bitLength: function () {
            if(this.t <= 0) return 0;
            return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
        },
        /**
         * this mod a
         */
        mod: function (a) {
            var r = nbi();
            this.abs().divRemTo(a,null,r);
            if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
            return r;
        },
        /**
         * this^e % m, 0 <= e < 2^32
         */
        modPowInt: function (e,m) {
            var z;
            if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
            return this.exp(e,z);
        }
    });

    // "constants"
    BigInteger.ZERO = nbv(0);
    BigInteger.ONE = nbv(1);

    /**
     * Modular reduction using "classic" algorithm
     * @class BigInteger.utils.Classic
     * @private
     */
    function Classic(m) { this.m = m; }
    Classic.prototype = {
        convert: function (x) {
            if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
            else return x;
        },
        revert: function (x) { return x; },
        reduce: function (x) { x.divRemTo(this.m,null,x); },
        mulTo: function (x,y,r) { x.multiplyTo(y,r); this.reduce(r); },
        sqrTo: function (x,r) { x.squareTo(r); this.reduce(r); }
    };


    /**
     * Montgomery reduction
     * @class BigInteger.utils.Montgomery
     * @private
     */
    function Montgomery(m) {
      this.m = m;
      this.mp = m.invDigit();
      this.mpl = this.mp&0x7fff;
      this.mph = this.mp>>15;
      this.um = (1<<(m.DB-15))-1;
      this.mt2 = 2*m.t;
    }
    Montgomery.prototype = {
        /**
         * xR mod m
         */
        convert: function (x) {
            var r = nbi();
            x.abs().dlShiftTo(this.m.t,r);
            r.divRemTo(this.m,null,r);
            if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
            return r;
        },
        /**
         * x/R mod m
         */
        revert: function (x) {
            var r = nbi();
            x.copyTo(r);
            this.reduce(r);
            return r;
        },
        /**
         * x = x/R mod m (HAC 14.32)
         */
        reduce: function (x) {
            while(x.t <= this.mt2)	// pad x so am has enough room later
            x[x.t++] = 0;
            for(var i = 0; i < this.m.t; ++i) {
            // faster way of calculating u0 = x[i]*mp mod DV
            var j = x[i]&0x7fff;
            var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
            // use am to combine the multiply-shift-add into one call
            j = i+this.m.t;
            x[j] += this.m.am(0,u0,x,i,0,this.m.t);
            // propagate carry
            while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
            }
            x.clamp();
            x.drShiftTo(this.m.t,x);
            if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
        },
        /**
         * r = "xy/R mod m"; x,y != r
         */
        mulTo: function (x,y,r) { x.multiplyTo(y,r); this.reduce(r); },
        /**
         * r = "x^2/R mod m"; x != r
         */
        sqrTo: function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }
    };

    /**
     * Namespace for BigInteger utililty functions/classes.
     */
    BigInteger.utils = {
        apply: apply,
        int2char: int2char,
        intAt: intAt,
        nbi: nbi,
        nbv: nbv,
        nbits: nbits,

        Classic: Classic,
        Montgomery: Montgomery
    };

    return BigInteger;
}));
