/**
 * Offline smoke test for the add-on: loads the .gs files into a Node VM with strict
 * mocks of the Apps Script services, then renders cards for real backend responses.
 * Catches typos in CardService method names and runtime errors before deploying.
 *   node addon/test/harness.js <response.json>...
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const API = {
  CardBuilder: ['setName', 'setHeader', 'addSection', 'setFixedFooter', 'build', 'setPeekCardHeader', 'addCardAction'],
  CardHeader: ['setTitle', 'setSubtitle', 'setImageUrl', 'setImageStyle', 'setImageAltText'],
  CardSection: ['setHeader', 'addWidget', 'setCollapsible', 'setNumUncollapsibleWidgets'],
  TextParagraph: ['setText', 'setMaxLines'],
  DecoratedText: ['setTopLabel', 'setText', 'setBottomLabel', 'setWrapText', 'setStartIcon', 'setEndIcon', 'setButton'],
  IconImage: ['setIcon', 'setIconUrl', 'setMaterialIcon', 'setAltText'],
  MaterialIcon: ['setName', 'setFill', 'setWeight', 'setGrade'],
  TextButton: ['setText', 'setOnClickAction', 'setTextButtonStyle', 'setBackgroundColor', 'setDisabled'],
  ButtonSet: ['addButton'],
  Notification: ['setText'],
  Action: ['setFunctionName', 'setParameters'],
  FixedFooter: ['setPrimaryButton', 'setSecondaryButton'],
  ActionResponseBuilder: ['setNavigation', 'setNotification', 'build'],
  Navigation: ['pushCard', 'updateCard', 'popCard'],
  Divider: [],
};
const texts = [];
function builder(type) {
  const obj = { __type: type, calls: [] };
  for (const m of API[type]) {
    obj[m] = (...args) => {
      if (m === 'setText' || m === 'setTopLabel' || m === 'setBottomLabel' || m === 'setHeader' && typeof args[0] === 'string') {
        texts.push(String(args[0]));
      }
      obj.calls.push([m, args]);
      return m === 'build' ? { built: type, calls: obj.calls } : obj;
    };
  }
  return new Proxy(obj, {
    get(t, p) {
      if (p in t || typeof p === 'symbol') return t[p];
      throw new Error(`${type}.${String(p)} is not a CardService method`);
    },
  });
}
const CardService = new Proxy({
  ImageStyle: { SQUARE: 'SQUARE', CIRCLE: 'CIRCLE' },
  TextButtonStyle: { FILLED: 'FILLED', TEXT: 'TEXT', OUTLINED: 'OUTLINED' },
  Icon: { EMAIL: 'EMAIL', PERSON: 'PERSON', BOOKMARK: 'BOOKMARK', DESCRIPTION: 'DESCRIPTION', CLOCK: 'CLOCK', STAR: 'STAR' },
}, {
  get(t, p) {
    if (p in t) return t[p];
    const type = String(p).replace(/^new/, '');
    if (API[type]) return () => builder(type);
    throw new Error(`CardService.${String(p)} does not exist`);
  },
});
const toBytes = (s) => Array.from(Buffer.from(s, 'utf8')).map((b) => (b > 127 ? b - 256 : b));
const Utilities = {
  DigestAlgorithm: { SHA_256: 'sha256' }, Charset: { UTF_8: 'utf8' },
  // Same overloads as Apps Script: (alg, byte[]) or (alg, string, charset).
  computeDigest: (alg, v) => Array.from(crypto.createHash('sha256').update(Array.isArray(v) ? Buffer.from(v.map((b) => b & 255)) : Buffer.from(String(v), 'utf8')).digest()).map((b) => (b > 127 ? b - 256 : b)),
  // Same overloads as Apps Script: (string, string) or (byte[], byte[]).
  computeHmacSha256Signature: (msg, key) => {
    const buf = (v) => (Array.isArray(v) ? Buffer.from(v.map((b) => b & 255)) : Buffer.from(String(v), 'utf8'));
    return Array.from(crypto.createHmac('sha256', buf(key)).update(buf(msg)).digest()).map((b) => (b > 127 ? b - 256 : b));
  },
  getUuid: () => crypto.randomUUID(),
  base64DecodeWebSafe: (str) => Array.from(Buffer.from(String(str), 'base64url')).map((b) => (b > 127 ? b - 256 : b)),
  base64Encode: (bytes) => Buffer.from(bytes.map((b) => b & 255)).toString('base64'),
  newBlob: (s) => {
    const bytes = Array.isArray(s) ? s : toBytes(s);
    return { getBytes: () => bytes, getDataAsString: () => Buffer.from(bytes.map((b) => b & 255)).toString('utf8') };
  },
};
// A fake backend that signs its answers exactly like the real one (see app/security.py).
const SECRET = 'x'.repeat(40);
let backendMode = 'ok'; // ok | unsigned | tampered | replayed
let lastNonce = null;
let analyzeResponse = null; // what /v1/analyze returns (set by the background-alert checks)
const analyzePayloads = [];
let fetchThrows = null;
let healthBody = '{"status":"ok","version":"1.4.0","signing":"on"}';
function fakeBackend(url, opts) {
  if (fetchThrows) throw new Error(fetchThrows);
  if (url.endsWith('/healthz')) return { getResponseCode: () => 200, getContentText: () => healthBody, getHeaders: () => ({}) };
  const isAnalyze = url.endsWith('/v1/analyze');
  if (isAnalyze) analyzePayloads.push(JSON.parse(Buffer.from(opts.payload.map((b) => b & 255)).toString('utf8')));
  const body = Buffer.from(JSON.stringify(isAnalyze ? analyzeResponse : { report_id: 'MG-1A2B3C4D', status: 'received' }), 'utf8');
  const nonce = opts.headers['X-MG-Nonce'];
  const signNonce = backendMode === 'replayed' && lastNonce ? lastNonce : nonce;
  lastNonce = nonce;
  const sig = crypto.createHmac('sha256', SECRET).update(Buffer.concat([Buffer.from('resp.' + signNonce + '.'), body])).digest('hex');
  const sent = backendMode === 'tampered' ? Buffer.from(body.toString().replace('MG-1A2B3C4D', 'MG-FFFFFFFF')) : body;
  const headers = backendMode === 'unsigned' ? {} : { 'x-mg-response-signature': sig };
  return {
    getResponseCode: () => 200,
    getHeaders: () => headers,
    getContent: () => Array.from(sent).map((b) => (b > 127 ? b - 256 : b)),
    getContentText: () => sent.toString('utf8'),
  };
}
const gmailCalls = [];
const gmailQueries = [];
let gmailListResult = () => [];
const userProps = {};
const apiMessages = {};
const apiAttachments = {};
const scriptProps = { BACKEND_URL: 'https://example.run.app', HMAC_SECRET: 'x'.repeat(40) };
const triggers = [];
const sentMail = [];
const ScriptApp = {
  getProjectTriggers: () => triggers.slice(),
  deleteTrigger: (t) => triggers.splice(triggers.indexOf(t), 1),
  newTrigger: (fn) => {
    const spec = { fn };
    const b = { timeBased: () => b, everyMinutes: (n) => { spec.every = n + 'm'; return b; }, everyHours: (n) => { spec.every = n + 'h'; return b; },
      create: () => { const t = { getHandlerFunction: () => fn, spec }; triggers.push(t); return t; } };
    return b;
  },
};
const MailApp = { sendEmail: (m) => sentMail.push(m) };
const UserProperties = {
  getProperty: (k) => (k in userProps ? userProps[k] : null),
  setProperty: (k, v) => { userProps[k] = String(v); },
  setProperties: (o) => { Object.keys(o).forEach((k) => { userProps[k] = String(o[k]); }); },
  deleteProperty: (k) => { delete userProps[k]; },
  getProperties: () => Object.assign({}, userProps),
};
const cacheStore = {};
let fromHeader = 'Mallory <mallory@evil.example>';
const Gmail = { Users: {
  Messages: {
    get: (me, id, opts) => (opts.format === 'full' ? apiMessages[id] : { payload: { headers: (opts.metadataHeaders || ['From']).map((n) =>
      ({ name: n, value: n === 'From' ? fromHeader : '<x@evil.example>' })) } }),
    trash: (me, id) => gmailCalls.push(['trash', id]),
    untrash: (me, id) => gmailCalls.push(['untrash', id]),
    list: (me, opts) => { gmailQueries.push(opts); return { messages: gmailListResult(opts) }; },
    modify: (res, me, id) => gmailCalls.push(['modify', id, res]),
    Attachments: { get: (me, mid, aid) => ({ data: apiAttachments[aid] }) },
  },
  Labels: {
    list: () => ({ labels: gmailCalls.filter((c) => c[0] === 'label').map((c) => c[1]) }),
    create: (res) => { const l = Object.assign({ id: 'Label_' + gmailCalls.length }, res); gmailCalls.push(['label', l]); return l; },
  },
  Settings: {
    SendAs: { list: () => ({ sendAs: [{ sendAsEmail: 'demo@acme.com' }, { sendAsEmail: 'alias@acme.com' }] }) },
    Filters: {
    list: () => ({ filter: gmailCalls.filter((c) => c[0] === 'filter').map((c) => ({ criteria: c[1].criteria })) }),
    create: (resource, me) => gmailCalls.push(['filter', resource]),
  } },
} };
const ctx = vm.createContext({
  CardService, Utilities, console, Gmail,
  PropertiesService: {
    getScriptProperties: () => ({ getProperty: (k) => scriptProps[k] || null }),
    getUserProperties: () => UserProperties,
  },
  LockService: { getUserLock: () => ({ tryLock: () => true, releaseLock: () => {} }) },
  Session: { getActiveUser: () => ({ getEmail: () => 'demo@acme.com' }) },
  CacheService: { getUserCache: () => ({ get: (k) => cacheStore[k] || null, put: (k, v) => { cacheStore[k] = v; } }) },
  UrlFetchApp: { fetch: (url, opts) => fakeBackend(url, opts) },
  ScriptApp, MailApp,
});
const dir = process.env.MG_ADDON_DIR || path.join(__dirname, '..'); // MG_ADDON_DIR=addon_bundle tests the one-file bundle
for (const f of fs.readdirSync(dir).filter((f) => f.endsWith('.gs')).sort()) {
  vm.runInContext(fs.readFileSync(path.join(dir, f), 'utf8'), ctx, { filename: f });
}

let failures = 0;
function check(name, fn) {
  try { fn(); console.log('ok   ', name); } catch (e) { failures++; console.log('FAIL ', name, '-', e.message); }
}
check('homepage card', () => ctx.buildHomepageCard_());
check('methodology card', () => ctx.buildMethodologyCard_());
check('config error card', () => ctx.buildErrorCard_(new ctx.ConfigError_('x')));
for (const kind of ['auth', 'rate', 'network', 'weird']) {
  check(`backend error card (${kind})`, () => ctx.buildErrorCard_(new ctx.BackendError_(kind, 500)));
}
check('escaping', () => {
  const out = ctx.esc_('<script>"x"</script>\u202Egnp.exe');
  if (out.includes('<') || out.includes('\u202E')) throw new Error('not escaped: ' + out);
});
check('labels cannot carry markup', () => {
  const out = ctx.label_('<a href="x">Terms & Conditions</a>');
  if (/[<>&"]/.test(out)) throw new Error(out);
});
check('truncation never splits a surrogate pair', () => {
  const out = ctx.safeSlice_('ab\ud83d\ude00cd', 3);
  if (out !== 'ab') throw new Error(JSON.stringify(out));
});
check('email validation blocks query injection', () => {
  if (ctx.isPlainEmail_('a@b.com OR in:anywhere') || !ctx.isPlainEmail_('a.b+c@d.co.il')) throw new Error('bad');
});
check('sha256 of attachment bytes is hex-64 and correct', () => {
  const data = [77, 90, -112, 0]; // "MZ\x90\x00" as Apps Script signed bytes
  const expected = crypto.createHash('sha256').update(Buffer.from([77, 90, 144, 0])).digest('hex');
  if (ctx.sha256Hex_(data) !== expected) throw new Error(ctx.sha256Hex_(data));
});
check('hmac matches backend algorithm', () => {
  const expected = crypto.createHmac('sha256', 'k').update('1.n.c.{}').digest('hex');
  if (ctx.hmacHex_('1.n.c.{}', 'k') !== expected) throw new Error('mismatch');
});
for (const file of process.argv.slice(2)) {
  const resp = JSON.parse(fs.readFileSync(file, 'utf8'));
  check(`result card: ${path.basename(file)}`, () => {
    ctx.validateResult_(resp);
    ctx.buildResultCard_(Object.assign({ client_ms: 1234 }, resp), { cached: false, messageId: '18f0abcdef012345' });
    ctx.buildResultCard_(resp, { cached: true, messageId: '18f0abcdef012345' });
  });
}
// ---- response actions, against the mocked Gmail API
const MID = '18f0abcdef012345';
const notifText = (resp) => {
  const n = resp.calls.find((c) => c[0] === 'setNotification');
  return n ? n[1][0].calls.find((c) => c[0] === 'setText')[1][0] : '';
};
const sample = process.argv[2] ? JSON.parse(fs.readFileSync(process.argv[2], 'utf8')) : null;
if (sample) {
  ctx.cacheResult_(MID, Object.assign({}, sample, { sender: { email: 'mallory@evil.example', display_name: 'M', domain: 'evil.example', authenticated: false, spoofed: true } }));
  check('trash moves the message and offers undo', () => {
    const resp = ctx.onTrashMessage({ parameters: { messageId: MID } });
    if (!gmailCalls.some((c) => c[0] === 'trash' && c[1] === MID)) throw new Error('not trashed');
    if (!/Trash/.test(notifText(resp))) throw new Error('no notification');
  });
  check('undo restores the message', () => {
    ctx.onUndoTrash({ parameters: { messageId: MID } });
    if (!gmailCalls.some((c) => c[0] === 'untrash')) throw new Error('not restored');
  });
  check('block asks for confirmation first', () => {
    const before = gmailCalls.length;
    const resp = ctx.onConfirmBlock({ parameters: { messageId: MID } });
    if (gmailCalls.length !== before) throw new Error('blocked without confirmation');
    if (!resp.calls.some((c) => c[0] === 'setNavigation')) throw new Error('no confirm card');
  });
  check('confirmed block creates a from-filter to Trash, once', () => {
    ctx.onBlockSender({ parameters: { messageId: MID } });
    ctx.onBlockSender({ parameters: { messageId: MID } });
    const filters = gmailCalls.filter((c) => c[0] === 'filter');
    if (filters.length !== 1) throw new Error(filters.length + ' filters');
    const f = filters[0][1];
    if (f.criteria.from !== 'mallory@evil.example' || f.action.addLabelIds[0] !== 'TRASH') throw new Error(JSON.stringify(f));
  });
  check('block refuses an injected From address', () => {
    fromHeader = '"x" <a@b.com OR from:boss@acme.com>';
    const n = gmailCalls.length;
    const resp = ctx.onBlockSender({ parameters: { messageId: MID } });
    fromHeader = 'Mallory <mallory@evil.example>';
    if (gmailCalls.length !== n || !/malformed/.test(notifText(resp))) throw new Error('filter created for bad address');
  });
  check('report returns a reference and marks the card', () => {
    const resp = ctx.onReportSecOps({ parameters: { messageId: MID } });
    if (!/MG-1A2B3C4D/.test(notifText(resp))) throw new Error(notifText(resp));
    if (ctx.cachedResult_(MID).reported_as !== 'MG-1A2B3C4D') throw new Error('not recorded');
    // the cached sample's sender is spoofed: the report must NOT taint the address's real owner
    if (ctx.verdictRecord_('mallory@evil.example', 'x').reported) throw new Error('forged sender was marked as reported');
    if (!ctx.verdictRecord_('mallory@evil.example', 'x').blocked) throw new Error('block not remembered');
  });
  check('reporting an authenticated sender is remembered', () => {
    ctx.cacheResult_(MID, Object.assign({}, sample, { sender: { email: 'mallory@evil.example', display_name: 'M', domain: 'evil.example', authenticated: true, spoofed: false } }));
    ctx.onReportSecOps({ parameters: { messageId: MID } });
    if (!ctx.verdictRecord_('mallory@evil.example', 'x').reported) throw new Error('report not remembered');
  });
  check('invalid message id is rejected', () => {
    let threw = false;
    try { ctx.onTrashMessage({ parameters: { messageId: '../../x' } }); } catch (e) { threw = true; }
    if (!threw) throw new Error('accepted');
  });
}
for (const mode of ['unsigned', 'tampered', 'replayed']) {
  check(`rejects a ${mode} backend response`, () => {
    backendMode = mode;
    lastNonce = 'an-earlier-request-nonce';
    let kind = null;
    try {
      ctx.reportToSecOps_({ score: 1, verdict: 'safe' }, { backendUrl: 'https://example.run.app', secret: SECRET });
    } catch (e) { kind = e.kind; }
    backendMode = 'ok';
    if (kind !== 'untrusted') throw new Error('accepted: ' + kind);
  });
}
check('an unsigned answer is explained (dev backend or old version), not just rejected', () => {
  backendMode = 'unsigned';
  let err = null;
  try { ctx.reportToSecOps_({ score: 1, verdict: 'safe' }, { backendUrl: 'https://example.run.app', secret: SECRET }); } catch (e) { err = e; }
  backendMode = 'ok';
  if (!err || err.kind !== 'untrusted' || !/no signature/.test(err.detail)) throw new Error(JSON.stringify(err));
});
check('requests skip the ngrok warning page, and an HTML page instead of an answer is named', () => {
  const seen = [];
  const orig = ctx.UrlFetchApp.fetch;
  ctx.UrlFetchApp.fetch = (url, opts) => {
    seen.push(opts.headers);
    const page = Buffer.from('<!DOCTYPE html><html>ngrok: You are about to visit</html>');
    return { getResponseCode: () => 200, getHeaders: () => ({ 'Content-Type': 'text/html' }),
      getContent: () => Array.from(page), getContentText: () => page.toString() };
  };
  let err = null;
  try { ctx.reportToSecOps_({ score: 1, verdict: 'safe' }, { backendUrl: 'https://x.ngrok-free.dev', secret: SECRET }); } catch (e) { err = e; }
  ctx.UrlFetchApp.fetch = orig;
  if (seen[0]['ngrok-skip-browser-warning'] !== '1') throw new Error('no ngrok header');
  if (!err || err.kind !== 'untrusted' || !/web page/.test(err.detail)) throw new Error(JSON.stringify(err));
});
check('accepts a correctly signed response', () => {
  const id = ctx.reportToSecOps_({ score: 1, verdict: 'safe' }, { backendUrl: 'https://example.run.app', secret: SECRET });
  if (id !== 'MG-1A2B3C4D') throw new Error(id);
});
check('rejects oversized or malformed results (incl. from cache)', () => {
  const base = sample || {};
  const bad = Object.assign({}, base, { findings: new Array(500).fill(base.findings && base.findings[0]) });
  let threw = false;
  try { ctx.validateResult_(bad); } catch (e) { threw = true; }
  if (!threw) throw new Error('accepted 500 findings');
  cacheStore[ctx.cacheKey_('poisoned0001')] = JSON.stringify(bad);
  if (ctx.cachedResult_('poisoned0001') !== null) throw new Error('poisoned cache entry was trusted');
});
check('MITRE technique ids are shown on findings', () => {
  if (sample && sample.findings.some((f) => f.attack && f.attack.length) && !texts.some((t) => /T1\d{3}/.test(t))) {
    throw new Error('no technique id rendered');
  }
});
check('banner and gauge texts', () => {
  // Render a malicious and a safe card explicitly, so this check never depends on CLI arguments.
  const base = { engine_version: 't', confidence: 'high', headline: 'x', summary: 's', findings: [], mitigations: [],
    exposures: [], attack_techniques: [], recommendations: [], links: [], coverage: {}, sender: null, analysis_ms: 1 };
  texts.length = 0;
  ctx.buildResultCard_(Object.assign({}, base, { score: 92, verdict: 'malicious' }), {});
  ctx.buildResultCard_(Object.assign({}, base, { score: 3, verdict: 'safe', headline: '' }), {});
  const t = texts.join('\n');
  for (const needle of ['DO NOT CLICK ANY LINKS', 'NO THREATS DETECTED', '█', '/100', '⚡']) {
    if (!t.includes(needle)) throw new Error('missing ' + needle);
  }
});

check('locale: Hebrew Gmail gets a Hebrew card, unknown locales fall back to English', () => {
  if (ctx.setLocale_({ commonEventObject: { userLocale: 'iw' } }) !== 'he') throw new Error('iw');
  if (ctx.setLocale_({ commonEventObject: { userLocale: 'he-IL' } }) !== 'he') throw new Error('he-IL');
  const base = { engine_version: 't', confidence: 'high', headline: 'x', summary: 's', findings: [], mitigations: [],
    exposures: [], attack_techniques: [], recommendations: [], links: [], coverage: {}, sender: null, analysis_ms: 1,
    subject: 'דחוף <b>', language: 'he' };
  texts.length = 0;
  ctx.buildResultCard_(Object.assign({}, base, { score: 92, verdict: 'malicious' }), {});
  const t = texts.join('\n');
  for (const needle of ['אזהרה', 'האיום העיקרי', 'נושא:', 'עברית', 'כנראה זדוני']) {
    if (!t.includes(needle)) throw new Error('missing ' + needle);
  }
  if (t.includes('<b>\u0000') || t.includes('דחוף <b>')) throw new Error('subject not escaped');
  if (ctx.setLocale_({ commonEventObject: { userLocale: 'xx' } }) !== 'en') throw new Error('fallback');
  if (ctx.setLocale_({}) !== 'en') throw new Error('no locale');
  ctx.setLocale_({ commonEventObject: { userLocale: 'he' } });
  const heKey = ctx.cacheKey_('abc');
  ctx.setLocale_({ commonEventObject: { userLocale: 'en' } });
  if (heKey === ctx.cacheKey_('abc')) throw new Error('cache key ignores the language');
  ctx.setLocale_({});
});
check('every Hebrew string has an English original and vice versa', () => {
  const en = Object.keys(ctx.STRINGS_.en).sort().join(',');
  const he = Object.keys(ctx.STRINGS_.he).sort().join(',');
  if (en !== he) throw new Error('key sets differ');
});
check('verdict memory: malicious verdicts, reports and blocks are remembered per sender', () => {
  const who = 'repeat@phish.example';
  const fresh = ctx.verdictRecord_(who, 'msgA00001');
  if (fresh.malicious || fresh.reported) throw new Error('not empty');
  ctx.recordVerdict_(who, 'msgA00001', 'malicious');
  ctx.recordVerdict_(who, 'msgB00002', 'suspicious');
  let rec = ctx.verdictRecord_(who, 'msgC00003');
  if (rec.malicious !== 1 || rec.suspicious !== 1 || rec.domainMalicious !== 1) throw new Error(JSON.stringify(rec));
  // the message being analysed never counts against itself
  if (ctx.verdictRecord_(who, 'msgA00001').malicious !== 0) throw new Error('counted itself');
  // a re-scan replaces the earlier verdict of the same message
  ctx.recordVerdict_(who, 'msgA00001', 'safe');
  if (ctx.verdictRecord_(who, 'msgC00003').malicious !== 0) throw new Error('re-scan not applied');
  ctx.recordSenderAction_(who, 'r');
  if (!ctx.verdictRecord_(who, 'x').reported) throw new Error('report not remembered');
  // the store never contains the address in clear text
  if (JSON.stringify(userProps).includes('phish')) throw new Error('address stored in clear');
  // free-mail domains get no domain record
  ctx.recordVerdict_('someone@gmail.com', 'msgD00004', 'malicious');
  if (ctx.verdictRecord_('other@gmail.com', 'x').domainMalicious !== 0) throw new Error('gmail.com domain record');
});
check('verdict memory is bounded', () => {
  for (let i = 0; i < 420; i++) ctx.recordVerdict_(`s${i}@bulk${i}.example`, `m${i}xxxxxxx`, 'suspicious');
  const n = Object.keys(userProps).filter((k) => k.startsWith('mg:s:') || k.startsWith('mg:d:')).length;
  if (n > 400) throw new Error(n + ' records');
});
check('sender history sends counts and flags, and searches Spam explicitly', () => {
  gmailQueries.length = 0;
  gmailListResult = (o) => (/in:spam/.test(o.q) ? [{ id: 'spam1' }, { id: 'cur' }] : []);
  const who = 'again@phish2.example';
  ctx.recordVerdict_(who, 'old1xxxxx', 'malicious');
  ctx.recordSenderAction_(who, 'b');
  const h = ctx.getSenderHistory_(who, 'cur');
  gmailListResult = () => [];
  if (h.prior_malicious_verdicts !== 1 || !h.blocked_sender || h.prior_spam_messages !== 1) throw new Error(JSON.stringify(h));
  const spamQ = gmailQueries.find((q) => /in:spam/.test(q.q));
  if (!spamQ || spamQ.includeSpamTrash !== true) throw new Error('spam search without includeSpamTrash');
  if (ctx.getSenderHistory_('x@y.com OR in:anywhere', 'cur') !== null) throw new Error('query injection');
});


// ---- background alerts (Alerts.gs)
const b64u = (t) => Buffer.from(t, 'utf8').toString('base64url');
function apiMessage(id, subject, html, extra) {
  apiMessages[id] = { id, payload: { mimeType: 'multipart/mixed', headers: [
    { name: 'From', value: 'PayPal <service@paypa1-secure.example>' }, { name: 'Subject', value: subject },
    { name: 'Message-ID', value: '<' + id + '@x>' }], parts: [
    { mimeType: 'multipart/alternative', parts: [
      { mimeType: 'text/plain', headers: [{ name: 'Content-Type', value: 'text/plain; charset="UTF-8"' }], body: { data: b64u('plain ' + subject) } },
      { mimeType: 'text/html', headers: [], body: { data: b64u(html) } }] },
    ...(extra || [])] } };
}
const verdictResp = (score, verdict) => ({ engine_version: '1.4.0', score, verdict, confidence: 'high',
  headline: 'Link shows paypal.com but opens hxxps[://]evil[.]example', summary: 's',
  findings: [{ id: 'LINK_TEXT_MISMATCH', category: 'Links', title: 'Link text <b>disguises</b> the destination', detail: 'd', points: 30, evidence: [], attack: [] }],
  mitigations: [], exposures: [], attack_techniques: [], recommendations: ["Don't click the links."], links: [],
  coverage: {}, sender: { email: 'service@paypa1-secure.example', display_name: 'PayPal', domain: 'paypa1-secure.example', authenticated: true, spoofed: false },
  subject: 'x', language: 'en', analysis_ms: 3 });
check('alerts: the home card offers a switch, which creates and removes one trigger', () => {
  ctx.onToggleAlerts({ commonEventObject: { userLocale: 'en' } });
  if (triggers.length !== 1 || triggers[0].getHandlerFunction() !== 'scanNewMailForAlerts') throw new Error('no trigger');
  if (triggers[0].spec.every !== '10m') throw new Error(triggers[0].spec.every);
  ctx.onToggleAlerts({ commonEventObject: { userLocale: 'en' } });
  if (triggers.length !== 0) throw new Error('not removed');
  texts.length = 0;
  ctx.buildHomepageCard_();
  if (!texts.some((t) => /Background alerts/.test(t))) throw new Error('no alerts section');
});
check('alerts: payload is rebuilt from the Gmail API view (bodies, attachments, hashes)', () => {
  const pdf = '%PDF-1.4 /JavaScript (app.alert(1))';
  apiAttachments.att1 = b64u(pdf);
  apiMessage('m1aaaaaaaa', 'Hi', '<p>hello <b>html</b></p>', [{ mimeType: 'application/pdf', filename: 'inv.pdf', headers: [], body: { attachmentId: 'att1', size: pdf.length } }]);
  const p = ctx.payloadFromApiMessage_(apiMessages.m1aaaaaaaa, 'm1aaaaaaaa', { senderHistory: false });
  if (p.html_body !== '<p>hello <b>html</b></p>' || p.text_body !== 'plain Hi') throw new Error('bodies');
  const a = p.attachments[0];
  if (a.filename !== 'inv.pdf' || a.sha256 !== crypto.createHash('sha256').update(pdf).digest('hex') || !a.content_b64) throw new Error(JSON.stringify(a));
  if (!/^From: PayPal/m.test(p.raw_headers)) throw new Error('headers');
});
check('alerts: a malicious email is labelled and the user gets one escaped, link-free alert', () => {
  userProps['mg:locale'] = 'en';
  apiMessage('m2bbbbbbbb', 'Verify <script>x</script>', '<a href="https://evil.example/steal">https://paypal.com</a>');
  gmailListResult = (o) => (/in:inbox/.test(o.q) ? [{ id: 'm2bbbbbbbb' }] : []);
  analyzeResponse = verdictResp(92, 'malicious');
  sentMail.length = 0; gmailQueries.length = 0;
  ctx.scanNewMailForAlerts();
  const q = gmailQueries.find((x) => /in:inbox/.test(x.q)).q;
  if (!/after:\d+/.test(q) || !/-subject:"MailGuard alert"/.test(q)) throw new Error(q);
  if (sentMail.length !== 1) throw new Error(sentMail.length + ' alerts');
  const m = sentMail[0];
  if (m.to !== 'demo@acme.com' || !/MailGuard alert/.test(m.subject)) throw new Error(m.subject);
  if (m.htmlBody.includes('<script>') || m.htmlBody.includes('<b>disguises') || m.htmlBody.includes('evil.example/steal')) throw new Error('unsafe alert body');
  if (!m.htmlBody.includes('https://mail.google.com/mail/u/0/#all/m2bbbbbbbb')) throw new Error('no open link');
  const mod = gmailCalls.find((c) => c[0] === 'modify' && c[1] === 'm2bbbbbbbb');
  if (!mod || mod[2].removeLabelIds.length !== 0) throw new Error('not labelled / quarantined without consent');
  ctx.scanNewMailForAlerts();
  if (sentMail.length !== 1) throw new Error('alerted twice');
  if (!ctx.cachedResult_('m2bbbbbbbb')) throw new Error('result not cached for the side panel');
});
check('alerts: safe mail and malicious mail below the threshold raise nothing', () => {
  sentMail.length = 0;
  apiMessage('m3cccccccc', 'Lunch', '<p>see you</p>');
  apiMessage('m4dddddddd', 'Meh', '<p>x</p>');
  gmailListResult = (o) => (/in:inbox/.test(o.q) ? [{ id: 'm3cccccccc' }] : []);
  analyzeResponse = verdictResp(5, 'safe');
  ctx.scanNewMailForAlerts();
  gmailListResult = (o) => (/in:inbox/.test(o.q) ? [{ id: 'm4dddddddd' }] : []);
  analyzeResponse = verdictResp(66, 'malicious');
  ctx.scanNewMailForAlerts();
  if (sentMail.length) throw new Error('alerted');
});
check('alerts: quarantine is opt-in, and the alert follows the user language', () => {
  scriptProps.ALERT_QUARANTINE = 'true';
  userProps['mg:locale'] = 'he';
  sentMail.length = 0;
  apiMessage('m5eeeeeeee', 'חשבונית', '<p>x</p>');
  gmailListResult = (o) => (/in:inbox/.test(o.q) ? [{ id: 'm5eeeeeeee' }] : []);
  analyzeResponse = verdictResp(95, 'malicious');
  ctx.scanNewMailForAlerts();
  delete scriptProps.ALERT_QUARANTINE;
  userProps['mg:locale'] = 'en';
  gmailListResult = () => [];
  const mod = gmailCalls.find((c) => c[0] === 'modify' && c[1] === 'm5eeeeeeee');
  if (!mod || mod[2].removeLabelIds[0] !== 'INBOX') throw new Error('not quarantined');
  if (sentMail.length !== 1 || !/מסוכן/.test(sentMail[0].htmlBody) || !/dir="rtl"/.test(sentMail[0].htmlBody)) throw new Error('not Hebrew');
  ctx.setLocale_({});
});


check('setup errors explain what to fix (whitelist, permission, DNS)', () => {
  const e1 = ctx.explainFetchError_(new Error('Exception: You do not have permission to call UrlFetchApp.fetch'), 'https://a.run.app');
  const e2 = ctx.explainFetchError_(new Error('Exception: The URL https://a.run.app/v1/analyze is not allowlisted. Add it to urlFetchWhitelist'), 'https://a.run.app');
  const e3 = ctx.explainFetchError_(new Error('Exception: DNS error: https://a.run.app'), 'https://a.run.app');
  if (!/permission/.test(e1) || !/urlFetchWhitelist/.test(e2) || !/BACKEND_URL/.test(e3)) throw new Error([e1, e2, e3].join(' | '));
  fetchThrows = 'Exception: URL not allowlisted <b>x</b>';
  let err = null;
  try { ctx.callBackend_({}, { backendUrl: 'https://a.run.app', secret: SECRET }); } catch (e) { err = e; }
  fetchThrows = null;
  if (!err || err.kind !== 'network' || !/urlFetchWhitelist/.test(err.detail)) throw new Error(JSON.stringify(err));
  texts.length = 0;
  ctx.buildErrorCard_(err);
  const t = texts.join('\n');
  if (!/urlFetchWhitelist/.test(t) || t.includes('<b>x</b>')) throw new Error('detail missing or unescaped');
});
check('diagnose() passes on a working setup and names the whitelist when blocked', () => {
  analyzeResponse = verdictResp(3, 'safe');
  scriptProps.HMAC_SECRET = SECRET;
  const logs = [];
  const orig = console.log;
  console.log = (m) => logs.push(String(m));
  const good = ctx.diagnose();
  fetchThrows = 'Exception: not allowlisted, add to urlFetchWhitelist';
  const bad = ctx.diagnose();
  fetchThrows = null;
  console.log = orig;
  scriptProps.HMAC_SECRET = 'x'.repeat(40);
  if (good !== true) throw new Error(logs.join('\n'));
  if (bad !== false || !logs.some((l) => /urlFetchWhitelist/.test(l))) throw new Error('no whitelist hint');
  for (const [body, needle] of [['{"status":"ok","version":"1.4.0","signing":"off"}', /MG_HMAC_SECRET/], ['{"status":"ok","version":"1.1.0"}', /older version/]]) {
    healthBody = body; logs.length = 0;
    console.log = (m) => logs.push(String(m));
    const r = ctx.diagnose();
    console.log = orig;
    if (r !== false || !logs.some((l) => needle.test(l))) throw new Error('no hint for ' + body);
  }
  healthBody = '{"status":"ok","version":"1.4.0","signing":"on"}';
  if (logs.some((l) => l.includes(SECRET))) throw new Error('secret printed');
});

const leaked = texts.filter((t) => /<script|javascript:/i.test(t));
check('no raw script/javascript: text reached a widget', () => { if (leaked.length) throw new Error(leaked[0]); });
process.exit(failures ? 1 : 0);
