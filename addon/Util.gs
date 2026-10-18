/**
 * Small helpers. Everything the backend returns is derived from attacker-written email,
 * so every dynamic string is cleaned and HTML-escaped before it reaches a card widget.
 */

var HIDDEN_CHARS_ = /[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/g;
var CONTROL_CHARS_ = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

/** Remove invisible/bidi characters, collapse whitespace and truncate. */
function clean_(value, maxLen) {
  var s = String(value === null || value === undefined ? '' : value)
    .replace(HIDDEN_CHARS_, '')
    .replace(CONTROL_CHARS_, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  maxLen = maxLen || 300;
  return s.length > maxLen ? s.slice(0, maxLen - 1) + '\u2026' : s;
}

/**
 * For widget *labels* (top/bottom labels): they may not render HTML, so escaping would
 * show "&amp;" literally. Instead, characters that could form markup are swapped for
 * look-alike typography - safe whether or not the label is HTML-rendered.
 */
function label_(value, maxLen) {
  return clean_(value, maxLen)
    .replace(/&/g, '+')
    .replace(/</g, '\u2039')
    .replace(/>/g, '\u203A')
    .replace(/"/g, '\u201D');
}

/** String.slice that never cuts a UTF-16 surrogate pair in half (which yields invalid JSON). */
function safeSlice_(value, maxLen) {
  var s = String(value || '');
  if (s.length <= maxLen) {
    return s;
  }
  var cut = s.slice(0, maxLen);
  var last = cut.charCodeAt(cut.length - 1);
  return last >= 0xD800 && last <= 0xDBFF ? cut.slice(0, -1) : cut;
}

/** Escape for the limited HTML that card text widgets render. */
function esc_(value, maxLen) {
  return clean_(value, maxLen)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function bytesToHex_(bytes) {
  return bytes.map(function (b) {
    var v = (b < 0 ? b + 256 : b).toString(16);
    return v.length === 1 ? '0' + v : v;
  }).join('');
}

function sha256Hex_(bytes) {
  return bytesToHex_(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes));
}

function hmacHex_(message, secret) {
  return bytesToHex_(Utilities.computeHmacSha256Signature(message, secret, Utilities.Charset.UTF_8));
}

function extensionOf_(filename) {
  var i = String(filename || '').lastIndexOf('.');
  return i === -1 ? '' : String(filename).slice(i + 1).toLowerCase();
}

/** Strict address check. Also protects the Gmail search query from operator injection. */
function isPlainEmail_(value) {
  return /^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,63}$/.test(String(value || ''));
}

function emailFromHeader_(fromHeader) {
  var m = String(fromHeader || '').match(/<([^<>\s]+@[^<>\s]+)>\s*$/);
  return (m ? m[1] : String(fromHeader || '').trim()).toLowerCase();
}
