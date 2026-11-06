/* ==========================================================================
   crypto.js — tiny authenticated encryption for the phone pairing (ES5)
   The SAME file is used by the TV app and by the phone page.

   Construction (encrypt-then-MAC, keys derived from a random 16-byte key K):
     encKey = HMAC-SHA256(K, "iptv-enc")      macKey = HMAC-SHA256(K, "iptv-mac")
     keystream block i = SHA256(encKey || nonce || uint32be(i))
     ciphertext = plaintext XOR keystream
     tag = first 16 bytes of HMAC-SHA256(macKey, "v1" || nonce || ciphertext)
   Wire format:  "v1." + b64url(nonce12) + "." + b64url(ciphertext) + "." + b64url(tag16)
   ========================================================================== */
var PairCrypto = (function () {

  /* ---------------- SHA-256 ---------------- */
  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function sha256(bytes) {
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var len = bytes.length, bitLen = len * 8;
    var padLen = ((len + 9 + 63) >> 6) << 6;
    var m = new Array(padLen), i;
    for (i = 0; i < len; i++) m[i] = bytes[i];
    m[len] = 0x80;
    for (i = len + 1; i < padLen; i++) m[i] = 0;
    /* bit length, big-endian (fits in 32 bits for our tiny messages) */
    m[padLen - 4] = (bitLen >>> 24) & 0xff; m[padLen - 3] = (bitLen >>> 16) & 0xff;
    m[padLen - 2] = (bitLen >>> 8) & 0xff;  m[padLen - 1] = bitLen & 0xff;

    var W = new Array(64);
    for (var off = 0; off < padLen; off += 64) {
      for (i = 0; i < 16; i++) {
        W[i] = (m[off + i * 4] << 24) | (m[off + i * 4 + 1] << 16) | (m[off + i * 4 + 2] << 8) | m[off + i * 4 + 3];
      }
      for (i = 16; i < 64; i++) {
        var x = W[i - 15], y = W[i - 2];
        var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (i = 0; i < 64; i++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[i] + W[i]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    var out = [];
    for (i = 0; i < 8; i++) out.push((H[i] >>> 24) & 0xff, (H[i] >>> 16) & 0xff, (H[i] >>> 8) & 0xff, H[i] & 0xff);
    return out;
  }

  function hmac(key, msg) {
    if (key.length > 64) key = sha256(key);
    var ipad = [], opad = [], i;
    for (i = 0; i < 64; i++) {
      var k = i < key.length ? key[i] : 0;
      ipad.push(k ^ 0x36); opad.push(k ^ 0x5c);
    }
    return sha256(opad.concat(sha256(ipad.concat(msg))));
  }

  /* ---------------- encodings ---------------- */
  function utf8Encode(str) {
    var s = unescape(encodeURIComponent(str)), out = [];
    for (var i = 0; i < s.length; i++) out.push(s.charCodeAt(i));
    return out;
  }
  function utf8Decode(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return decodeURIComponent(escape(s));
  }

  var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  function b64urlEncode(bytes) {
    var out = '', i;
    for (i = 0; i + 2 < bytes.length; i += 3) {
      var n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      out += B64.charAt(n >>> 18 & 63) + B64.charAt(n >>> 12 & 63) + B64.charAt(n >>> 6 & 63) + B64.charAt(n & 63);
    }
    var rest = bytes.length - i;
    if (rest === 1) {
      n = bytes[i] << 16;
      out += B64.charAt(n >>> 18 & 63) + B64.charAt(n >>> 12 & 63);
    } else if (rest === 2) {
      n = (bytes[i] << 16) | (bytes[i + 1] << 8);
      out += B64.charAt(n >>> 18 & 63) + B64.charAt(n >>> 12 & 63) + B64.charAt(n >>> 6 & 63);
    }
    return out;
  }
  function b64urlDecode(str) {
    str = String(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    var out = [], buf = 0, bits = 0;
    for (var i = 0; i < str.length; i++) {
      var v = B64.indexOf(str.charAt(i));
      if (v < 0) throw new Error('bad base64');
      buf = (buf << 6) | v; bits += 6;
      if (bits >= 8) { bits -= 8; out.push((buf >>> bits) & 0xff); }
    }
    return out;
  }

  /* ---------------- randomness ---------------- */
  function randomBytes(n) {
    var out = [], i;
    var c = (typeof window !== 'undefined') && (window.crypto || window.msCrypto);
    if (c && c.getRandomValues) {
      var arr = new Uint8Array(n);
      c.getRandomValues(arr);
      for (i = 0; i < n; i++) out.push(arr[i]);
      return out;
    }
    /* fallback for very old engines: mix Math.random with time through SHA-256 */
    var seed = [];
    for (i = 0; i < 64; i++) seed.push(Math.floor(Math.random() * 256));
    var t = String(new Date().getTime()) + String(Math.random());
    seed = seed.concat(utf8Encode(t));
    var pool = [];
    for (var ctr = 0; pool.length < n; ctr++) pool = pool.concat(sha256(seed.concat([ctr & 255, ctr >> 8 & 255])));
    return pool.slice(0, n);
  }

  /* ---------------- seal / open ---------------- */
  function keys(key) {
    return { enc: hmac(key, utf8Encode('iptv-enc')), mac: hmac(key, utf8Encode('iptv-mac')) };
  }
  function xorStream(encKey, nonce, data) {
    var out = [], block = [];
    for (var i = 0; i < data.length; i++) {
      if (i % 32 === 0) {
        var ctr = i / 32;
        block = sha256(encKey.concat(nonce, [(ctr >>> 24) & 255, (ctr >>> 16) & 255, (ctr >>> 8) & 255, ctr & 255]));
      }
      out.push(data[i] ^ block[i % 32]);
    }
    return out;
  }

  /* key: byte array (16 bytes). Returns the wire string. */
  function seal(key, text) {
    var k = keys(key);
    var nonce = randomBytes(12);
    var ct = xorStream(k.enc, nonce, utf8Encode(text));
    var tag = hmac(k.mac, utf8Encode('v1').concat(nonce, ct)).slice(0, 16);
    return 'v1.' + b64urlEncode(nonce) + '.' + b64urlEncode(ct) + '.' + b64urlEncode(tag);
  }

  /* Returns the text, or null if the message is not authentic. */
  function open(key, wire) {
    try {
      var parts = String(wire).replace(/^\s+|\s+$/g, '').split('.');
      if (parts.length !== 4 || parts[0] !== 'v1') return null;
      var nonce = b64urlDecode(parts[1]), ct = b64urlDecode(parts[2]), tag = b64urlDecode(parts[3]);
      if (nonce.length !== 12 || tag.length !== 16) return null;
      var k = keys(key);
      var expect = hmac(k.mac, utf8Encode('v1').concat(nonce, ct)).slice(0, 16);
      var diff = 0;
      for (var i = 0; i < 16; i++) diff |= expect[i] ^ tag[i];
      if (diff !== 0) return null;
      return utf8Decode(xorStream(k.enc, nonce, ct));
    } catch (e) {
      return null;
    }
  }

  return {
    sha256: sha256, hmac: hmac, utf8Encode: utf8Encode, utf8Decode: utf8Decode,
    b64urlEncode: b64urlEncode, b64urlDecode: b64urlDecode, randomBytes: randomBytes,
    seal: seal, open: open
  };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = PairCrypto;
