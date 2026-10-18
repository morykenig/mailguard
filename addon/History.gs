/**
 * The user's history with the sender, computed inside the user's own Google account.
 *
 * Two sources:
 *  1. Gmail itself - how many earlier messages came from this address, whether the user
 *     ever wrote to it, and whether Gmail already put mail from it in Spam.
 *  2. MailGuard's own memory - earlier verdicts for this sender (and its domain), and
 *     whether the user reported or blocked it. A sender who sent you a malicious email
 *     last week should not start from zero today.
 *
 * Privacy of the memory:
 *  - It lives in the user's own UserProperties (never on the backend, never shared).
 *  - Addresses, domains and message ids are stored only as salted SHA-256 hashes; the
 *    salt is random per user. Reading the store does not reveal who wrote to you.
 *  - It is bounded (MG.HISTORY_MAX_RECORDS) and the oldest records are pruned.
 *
 * The backend receives only counts and flags (see SenderHistory in the backend schemas).
 */

var FREE_MAIL_ = ['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com', 'icloud.com',
  'me.com', 'aol.com', 'proton.me', 'protonmail.com', 'gmx.com', 'gmx.net', 'mail.ru', 'yandex.ru', 'walla.co.il',
  'walla.com', 'zoho.com'];

function getSenderHistory_(senderEmail, currentMessageId) {
  // Validating the address also prevents Gmail-search operator injection
  // (e.g. a From of "x@y.com OR in:anywhere").
  if (!isPlainEmail_(senderEmail)) {
    return null;
  }
  // Mail "from yourself" is never familiar: of course you have written to your own address,
  // and spoofing the victim's own address is a common scam ("I hacked your account").
  if (ownAddresses_().indexOf(canonicalGmail_(senderEmail)) !== -1) {
    return null;
  }
  try {
    var received = gmailSearchIds_('from:' + senderEmail + ' -in:chats', MG.HISTORY_LOOKBACK, false)
      .filter(function (id) { return id !== currentMessageId; });
    var sent = gmailSearchIds_('in:sent to:' + senderEmail, 1, false);
    var spam = gmailSearchIds_('in:spam from:' + senderEmail, 10, true)
      .filter(function (id) { return id !== currentMessageId; });
    var record = verdictRecord_(senderEmail, currentMessageId);
    return {
      prior_messages_from_sender: received.length,
      user_has_emailed_sender: sent.length > 0,
      prior_malicious_verdicts: record.malicious,
      prior_suspicious_verdicts: record.suspicious,
      reported_sender: record.reported,
      blocked_sender: record.blocked,
      prior_spam_messages: spam.length,
      domain_prior_malicious: record.domainMalicious
    };
  } catch (err) {
    console.warn('sender history unavailable: ' + err.name);
    return null; // the backend reports "not provided" instead of guessing
  }
}

function gmailSearchIds_(query, maxResults, includeSpamTrash) {
  var resp = Gmail.Users.Messages.list('me', { q: query, maxResults: maxResults, includeSpamTrash: !!includeSpamTrash });
  return ((resp && resp.messages) || []).map(function (m) { return m.id; });
}

/** gmail.com and googlemail.com are the same mailbox. */
function canonicalGmail_(email) {
  return String(email || '').toLowerCase().replace(/@googlemail\.com$/, '@gmail.com');
}

/** The user's own address plus their send-as aliases (cached for 6 hours). */
function ownAddresses_() {
  var cache = CacheService.getUserCache();
  var hit = cache.get('mg:own-addresses');
  if (hit) {
    return JSON.parse(hit);
  }
  var out = [canonicalGmail_(Session.getActiveUser().getEmail())];
  try {
    (Gmail.Users.Settings.SendAs.list('me').sendAs || []).forEach(function (a) {
      if (isPlainEmail_(a.sendAsEmail)) {
        out.push(canonicalGmail_(a.sendAsEmail));
      }
    });
  } catch (err) {
    console.warn('send-as aliases unavailable: ' + err.name);
  }
  cache.put('mg:own-addresses', JSON.stringify(out), 6 * 3600);
  return out;
}

// ----------------------------------------------------------------------------- verdict memory

/** Per-user random salt, created on first use. */
function historySalt_() {
  var props = PropertiesService.getUserProperties();
  var salt = props.getProperty('mg:salt');
  if (!salt) {
    salt = Utilities.getUuid() + Utilities.getUuid();
    props.setProperty('mg:salt', salt);
  }
  return salt;
}

function saltedHash_(value, length) {
  var bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, historySalt_() + '|' + value,
    Utilities.Charset.UTF_8);
  return bytesToHex_(bytes).slice(0, length || 24);
}

function senderKey_(email) {
  return 'mg:s:' + saltedHash_('s:' + canonicalGmail_(email));
}

/** Domain records only for organisation domains: "gmail.com sent malware" says nothing. */
function domainKey_(email) {
  var domain = String(email).split('@')[1] || '';
  return !domain || FREE_MAIL_.indexOf(domain) !== -1 ? null : 'mg:d:' + saltedHash_('d:' + domain);
}

function readRecord_(props, key) {
  try {
    var r = JSON.parse(props.getProperty(key) || 'null');
    return r && typeof r === 'object' ? r : {};
  } catch (err) {
    return {};
  }
}

/** Counts for the current analysis; the message being analysed never counts against itself. */
function verdictRecord_(senderEmail, currentMessageId) {
  var empty = { malicious: 0, suspicious: 0, reported: false, blocked: false, domainMalicious: 0 };
  try {
    var props = PropertiesService.getUserProperties();
    var self = currentMessageId ? saltedHash_('m:' + currentMessageId, 16) : '';
    var notSelf = function (h) { return h !== self; };
    var s = readRecord_(props, senderKey_(senderEmail));
    var dk = domainKey_(senderEmail);
    var d = dk ? readRecord_(props, dk) : {};
    return {
      malicious: (s.m || []).filter(notSelf).length,
      suspicious: (s.s || []).filter(notSelf).length,
      reported: !!s.r,
      blocked: !!s.b,
      domainMalicious: (d.m || []).filter(notSelf).length
    };
  } catch (err) {
    console.warn('verdict memory unavailable: ' + err.name);
    return empty;
  }
}

/** Remember this message's verdict (a re-scan replaces the earlier verdict for the same message). */
function recordVerdict_(senderEmail, messageId, verdict) {
  if (!isPlainEmail_(senderEmail) || !messageId || ownAddresses_().indexOf(canonicalGmail_(senderEmail)) !== -1) {
    return; // your own address is never "a sender" (see getSenderHistory_)
  }
  updateRecords_(senderEmail, function (s, d) {
    var h = saltedHash_('m:' + messageId, 16);
    var without = function (list) { return (list || []).filter(function (x) { return x !== h; }); };
    s.m = without(s.m);
    s.s = without(s.s);
    if (verdict === 'malicious') {
      s.m = s.m.concat([h]).slice(-MG.HISTORY_MAX_PER_SENDER);
    } else if (verdict === 'suspicious') {
      s.s = s.s.concat([h]).slice(-MG.HISTORY_MAX_PER_SENDER);
    }
    if (d) {
      d.m = without(d.m);
      if (verdict === 'malicious') {
        d.m = d.m.concat([h]).slice(-MG.HISTORY_MAX_PER_SENDER);
      }
    }
  });
}

/** flag: 'r' (reported) or 'b' (blocked). */
function recordSenderAction_(senderEmail, flag) {
  if (!isPlainEmail_(senderEmail) || (flag !== 'r' && flag !== 'b')) {
    return;
  }
  updateRecords_(senderEmail, function (s) { s[flag] = 1; });
}

/** Read-modify-write under a user lock, then prune. Never throws: memory is best effort. */
function updateRecords_(senderEmail, mutate) {
  var lock = LockService.getUserLock();
  if (!lock.tryLock(3000)) {
    console.warn('verdict memory busy; not recorded');
    return;
  }
  try {
    var props = PropertiesService.getUserProperties();
    var sk = senderKey_(senderEmail);
    var dk = domainKey_(senderEmail);
    var s = readRecord_(props, sk);
    var d = dk ? readRecord_(props, dk) : null;
    mutate(s, d);
    var now = Math.floor(Date.now() / 1000);
    var writes = {};
    if ((s.m || []).length || (s.s || []).length || s.r || s.b) {
      s.t = now;
      writes[sk] = JSON.stringify(s);
    } else {
      props.deleteProperty(sk);
    }
    if (dk && d) {
      if ((d.m || []).length) {
        d.t = now;
        writes[dk] = JSON.stringify(d);
      } else {
        props.deleteProperty(dk);
      }
    }
    if (Object.keys(writes).length) {
      props.setProperties(writes, false);
    }
    pruneRecords_(props);
  } catch (err) {
    console.warn('verdict memory not updated: ' + err.name);
  } finally {
    lock.releaseLock();
  }
}

/** Keep the store well inside the UserProperties quota by dropping the oldest records. */
function pruneRecords_(props) {
  var all = props.getProperties();
  var keys = Object.keys(all).filter(function (k) { return k.indexOf('mg:s:') === 0 || k.indexOf('mg:d:') === 0; });
  if (keys.length <= MG.HISTORY_MAX_RECORDS) {
    return;
  }
  var age = function (k) {
    try {
      return JSON.parse(all[k]).t || 0;
    } catch (err) {
      return 0;
    }
  };
  keys.sort(function (a, b) { return age(a) - age(b); });
  keys.slice(0, keys.length - MG.HISTORY_MAX_RECORDS).forEach(function (k) { props.deleteProperty(k); });
}
