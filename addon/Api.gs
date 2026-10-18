/**
 * Signed calls to the backend.
 *
 * Signature: HMAC-SHA256(secret, timestamp + "." + nonce + "." + client + "." + body)
 *  - timestamp + nonce: the backend rejects stale or replayed requests;
 *  - client: a pseudonymous per-user id (HMAC of the user's address) used only for
 *    rate limiting, so the backend never learns who the user is.
 */

function BackendError_(kind, status, detail) {
  this.name = 'BackendError';
  this.kind = kind; // auth | rate | busy | too_large | invalid | server | network | bad_response | untrusted
  this.status = status || 0;
  // Short technical reason shown in the error card, so a setup problem can be diagnosed
  // (e.g. "URL not in urlFetchWhitelist"). Never contains the secret or email content.
  this.detail = clean_(detail || '', 200);
  this.message = 'backend error: ' + kind + (status ? ' (' + status + ')' : '');
}

function clientId_(secret) {
  var email = Session.getActiveUser().getEmail() || 'unknown';
  return hmacHex_('client:' + email.toLowerCase(), secret).slice(0, 32);
}

function callBackend_(payload, config) {
  return validateResult_(signedPost_('/v1/analyze', payload, config));
}

function reportToSecOps_(payload, config) {
  var data = signedPost_('/v1/report', payload, config);
  if (!data || !/^MG-[0-9A-F]{8}$/.test(String(data.report_id))) {
    throw new BackendError_('bad_response', 200);
  }
  return data.report_id;
}

/** POST a JSON payload with an HMAC signature; returns the parsed JSON body. */
function signedPost_(path, payload, config) {
  var body = JSON.stringify(payload);
  var ts = String(Math.floor(Date.now() / 1000));
  var nonce = Utilities.getUuid();
  var client = clientId_(config.secret);
  var signature = hmacHex_(ts + '.' + nonce + '.' + client + '.' + body, config.secret);

  var resp;
  try {
    resp = UrlFetchApp.fetch(config.backendUrl + path, {
      method: 'post',
      contentType: 'application/json; charset=utf-8',
      payload: Utilities.newBlob(body).getBytes(), // exact UTF-8 bytes that were signed
      headers: {
        'X-MG-Timestamp': ts,
        'X-MG-Nonce': nonce,
        'X-MG-Client': client,
        'X-MG-Signature': signature,
        // ngrok's free plan answers "browser-like" clients (Apps Script's user agent counts) with an
        // HTML warning page instead of forwarding the request. This header skips it; elsewhere it's ignored.
        'ngrok-skip-browser-warning': '1'
      },
      muteHttpExceptions: true,
      followRedirects: false,
      validateHttpsCertificates: true
    });
  } catch (err) {
    throw new BackendError_('network', 0, explainFetchError_(err, config.backendUrl));
  }

  var code = resp.getResponseCode();
  if (code === 200) {
    var bytes = resp.getContent();
    var sigProblem = responseSignatureProblem_(resp, bytes, nonce, config.secret);
    if (sigProblem) {
      // Not from our backend (or tampered with in transit): never show its verdict.
      throw new BackendError_('untrusted', code, sigProblem);
    }
    try {
      return JSON.parse(Utilities.newBlob(bytes).getDataAsString('UTF-8'));
    } catch (err) {
      throw new BackendError_('bad_response', code);
    }
  }
  if (code === 403 || code === 404) {
    // 403 from Google's front end: the Cloud Run service does not allow unauthenticated calls.
    throw new BackendError_(code === 403 ? 'forbidden' : 'not_found', code, 'HTTP ' + code + ' from ' + config.backendUrl + path);
  }
  var kinds = { 401: 'auth', 413: 'too_large', 422: 'invalid', 429: 'rate', 503: 'busy' };
  throw new BackendError_(kinds[code] || (code >= 500 ? 'server' : 'invalid'), code);
}

/**
 * Verdict integrity: the backend signs HMAC(secret, "resp." + nonce + "." + body). Binding
 * to this request's fresh nonce means a stale (replayed) "safe" answer is rejected too.
 */
function responseSignatureValid_(resp, bodyBytes, nonce, secret) {
  return !responseSignatureProblem_(resp, bodyBytes, nonce, secret);
}

/** '' when the signature is valid; otherwise a short reason for the error card. */
function responseSignatureProblem_(resp, bodyBytes, nonce, secret) {
  var headers = resp.getHeaders() || {};
  var got = '';
  Object.keys(headers).forEach(function (k) {
    if (String(k).toLowerCase() === 'x-mg-response-signature') {
      got = String(headers[k]).toLowerCase();
    }
  });
  if (!got && bodyBytes.length && (bodyBytes[0] === 60 || /html/i.test(String(headerOf_(resp, 'content-type'))))) {
    return 'got a web page instead of MailGuard\'s answer - a tunnel or proxy (e.g. the ngrok warning page) ' +
      'is in the way, or BACKEND_URL points to the wrong server';
  }
  if (!got) {
    return 'the answer has no signature: the backend has no MG_HMAC_SECRET (development mode) or is an older ' +
      'version - redeploy it from this package';
  }
  if (!/^[0-9a-f]{64}$/.test(got)) {
    return 'malformed response signature';
  }
  var message = Utilities.newBlob('resp.' + nonce + '.').getBytes().concat(bodyBytes);
  var expected = bytesToHex_(Utilities.computeHmacSha256Signature(message, Utilities.newBlob(secret).getBytes()));
  return constantTimeEquals_(expected, got) ? '' : 'response signed with a different secret, or changed in transit';
}

function constantTimeEquals_(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Never trust the response shape either. Beyond types, every list and string is bounded,
 * so even a buggy or compromised backend cannot build a giant or malformed card.
 * Applied to cached results as well.
 */
function validateResult_(d) {
  var verdicts = ['safe', 'suspicious', 'malicious'];
  var str = function (v, max) { return typeof v === 'string' && v.length <= max; };
  var list = function (v, max) { return Array.isArray(v) && v.length <= max; };
  var technique;
  var link;
  var finding = function (f) {
    return f && str(f.id, 64) && str(f.category, 80) && str(f.title, 200) && str(f.detail, 2000) &&
      typeof f.points === 'number' && isFinite(f.points) &&
      list(f.evidence || [], 10) && (f.evidence || []).every(function (e) { return str(e, 400); }) &&
      list(f.attack || [], 10) && (f.attack || []).every(function (a) { return technique(a); });
  };
  technique = function (a) {
    return a && /^(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?)$/.test(a.id) && str(a.name, 120) && str(a.framework, 10);
  };
  link = function (l) {
    return l && str(l.text, 200) && str(l.destination, 300) && str(l.domain, 300) &&
      list(l.flags, 20) && l.flags.every(function (x) { return str(x, 60); });
  };
  var ok = d && typeof d.score === 'number' && d.score >= 0 && d.score <= 100 &&
    verdicts.indexOf(d.verdict) !== -1 &&
    str(d.headline, 400) && str(d.summary, 1000) &&
    (d.subject === undefined || str(d.subject, 300)) &&
    (d.language === undefined || (typeof d.language === 'string' && /^[a-z]{0,3}$/.test(d.language))) &&
    list(d.findings, 60) && d.findings.every(finding) &&
    list(d.mitigations, 20) && d.mitigations.every(finding) &&
    list(d.exposures || [], 20) && (d.exposures || []).every(finding) &&
    list(d.attack_techniques || [], 30) && (d.attack_techniques || []).every(technique) &&
    list(d.recommendations, 15) && d.recommendations.every(function (r) { return str(r, 500); }) &&
    list(d.links, 20) && d.links.every(link) &&
    typeof d.coverage === 'object' && d.coverage !== null && Object.keys(d.coverage).length <= 20 &&
    Object.keys(d.coverage).every(function (k) { return str(k, 80) && str(d.coverage[k], 160); }) &&
    typeof d.analysis_ms === 'number' && isFinite(d.analysis_ms) && d.analysis_ms >= 0 &&
    (d.sender === null || (typeof d.sender === 'object' && str(d.sender.email, 320)));
  if (!ok) {
    throw new BackendError_('bad_response', 200);
  }
  return d;
}

/** Turns Apps Script's fetch exceptions into a hint about what to fix. */
function explainFetchError_(err, backendUrl) {
  var msg = String((err && err.message) || err || '');
  var hint;
  if (/whitelist|allowlist|urlFetchWhitelist|not allowed/i.test(msg)) {
    hint = 'URL is not in urlFetchWhitelist in appsscript.json';
  } else if (/permission|authori[sz]/i.test(msg)) {
    hint = 'missing permission - run diagnose() once from the script editor to re-authorise';
  } else if (/DNS|Address unavailable|resolve|unknown host/i.test(msg)) {
    hint = 'host not found - check BACKEND_URL';
  } else if (/timed? ?out|timeout/i.test(msg)) {
    hint = 'the backend did not answer in time';
  } else {
    hint = 'request failed';
  }
  return hint + ' (' + backendUrl + '): ' + msg.slice(0, 120);
}

function headerOf_(resp, name) {
  var headers = resp.getHeaders() || {};
  var key = Object.keys(headers).filter(function (k) { return String(k).toLowerCase() === name; })[0];
  return key ? headers[key] : '';
}
