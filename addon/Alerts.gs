/**
 * Background protection: scan new mail on a schedule and alert the user about dangerous emails
 * they have not opened yet.
 *
 * A Gmail add-on normally runs only while the user is looking at a message. A phishing email
 * that is never opened in the side panel would never be scored. With alerts switched on (button
 * on the home card), a time-driven trigger scans new inbox mail and, for every email at or above
 * the alert threshold:
 *   1. labels it "MailGuard/⚠ Malicious" so it stands out in the inbox,
 *   2. sends the user an alert email (to themselves) explaining why - with no clickable link
 *      from the dangerous email, only a link that opens it in Gmail,
 *   3. optionally (ALERT_QUARANTINE=true) moves it out of the inbox - reversible: it keeps the
 *      label, and "Move to Inbox" brings it back,
 *   4. optionally (ALERT_AUTO_REPORT=true) files a SecOps report through the backend.
 *
 * Script properties (all optional):
 *   ALERT_MIN_SCORE     score that requires intervention (default 70; 65-100 is "malicious")
 *   ALERT_QUARANTINE    "true" to also move alerted mail out of the inbox
 *   ALERT_AUTO_REPORT   "true" to also report alerted mail to SecOps automatically
 *   ALERT_INTERVAL_MIN  scan interval in minutes: 5, 10, 15 or 30 (default 10). Google may limit
 *                       add-on triggers to once an hour; then the hourly schedule is used.
 *
 * Safety: the scan reads mail with the same Gmail API scope as the history lookup; nothing is
 * stored except salted hashes of alerted message ids (to never alert twice) and the scan time.
 */

var ALERT_LABEL_ = 'MailGuard/⚠ Malicious';
var ALERT_SUBJECT_TAG_ = 'MailGuard alert'; // also used to skip our own alert emails
var ALERT_MAX_PER_RUN_ = 15; // stays well under the backend's per-client rate limit and the 6-minute run limit
var ALERT_MAX_REMEMBERED_ = 300;

// ----------------------------------------------------------------------------- settings

function alertSettings_() {
  var p = PropertiesService.getScriptProperties();
  var min = parseInt(p.getProperty('ALERT_MIN_SCORE') || '70', 10);
  var interval = parseInt(p.getProperty('ALERT_INTERVAL_MIN') || '10', 10);
  return {
    minScore: isFinite(min) ? Math.max(30, Math.min(100, min)) : 70, // never alert on "safe"
    quarantine: p.getProperty('ALERT_QUARANTINE') === 'true',
    autoReport: p.getProperty('ALERT_AUTO_REPORT') === 'true',
    interval: [5, 10, 15, 30].indexOf(interval) !== -1 ? interval : 10
  };
}

function alertsEnabled_() {
  return ScriptApp.getProjectTriggers().some(function (t) {
    return t.getHandlerFunction() === 'scanNewMailForAlerts';
  });
}

/** Home-card button: switch background alerts on or off for this user. */
function onToggleAlerts(e) {
  setLocale_(e);
  var on;
  try {
    on = alertsEnabled_() ? disableAlerts_() : enableAlerts_();
  } catch (err) {
    console.warn('alerts toggle failed: ' + err.name);
    return notify_(t_('alerts.toggle_fail'));
  }
  return notify_(t_(on ? 'alerts.enabled' : 'alerts.disabled'),
    CardService.newNavigation().updateCard(buildHomepageCard_()));
}

function enableAlerts_() {
  disableAlerts_();
  var interval = alertSettings_().interval;
  try {
    ScriptApp.newTrigger('scanNewMailForAlerts').timeBased().everyMinutes(interval).create();
  } catch (err) {
    // Add-on time-driven triggers may be limited to once an hour.
    ScriptApp.newTrigger('scanNewMailForAlerts').timeBased().everyHours(1).create();
  }
  // Start from "now": alerts are about new mail, not a sweep of the whole mailbox.
  PropertiesService.getUserProperties().setProperty('mg:alerts:since', String(Math.floor(Date.now() / 1000) - 3600));
  return true;
}

function disableAlerts_() {
  ScriptApp.getProjectTriggers().forEach(function (t) {
    if (t.getHandlerFunction() === 'scanNewMailForAlerts') {
      ScriptApp.deleteTrigger(t);
    }
  });
  return false;
}

// ----------------------------------------------------------------------------- the scan

/**
 * Time-driven entry point. Never throws: a failing run is logged and the next one retries,
 * because the "since" mark only moves forward after a successful run.
 */
function scanNewMailForAlerts() {
  var lock = LockService.getUserLock();
  if (!lock.tryLock(1000)) {
    return; // a previous run is still going
  }
  try {
    MG_LOCALE_ = normalizeLocale_(PropertiesService.getUserProperties().getProperty('mg:locale') || 'en');
    var config = getConfig_();
    var settings = alertSettings_();
    var props = PropertiesService.getUserProperties();
    var startedAt = Math.floor(Date.now() / 1000);
    var since = parseInt(props.getProperty('mg:alerts:since') || String(startedAt - 3600), 10);
    // after: takes epoch seconds. Our own alert emails are excluded by subject.
    var query = 'in:inbox after:' + since + ' -subject:"' + ALERT_SUBJECT_TAG_ + '"';
    var ids = gmailSearchIds_(query, ALERT_MAX_PER_RUN_, false);
    var alerted = 0;
    for (var i = 0; i < ids.length; i++) {
      if (alreadyAlerted_(ids[i])) {
        continue;
      }
      try {
        if (scanOne_(ids[i], config, settings)) {
          alerted++;
        }
      } catch (err) {
        console.warn('background scan of one message failed: ' + err.name + ' ' + (err.kind || ''));
      }
    }
    // If the page was full, more mail may be waiting: keep the mark so the next run continues.
    if (ids.length < ALERT_MAX_PER_RUN_) {
      props.setProperty('mg:alerts:since', String(startedAt - 120)); // small overlap; duplicates are skipped
    }
    console.info('background scan: checked=' + ids.length + ' alerted=' + alerted);
  } catch (err) {
    console.warn('background scan failed: ' + err.name);
  } finally {
    lock.releaseLock();
  }
}

/** Analyse one message; alert if it requires intervention. Returns true when an alert was raised. */
function scanOne_(messageId, config, settings) {
  var msg = Gmail.Users.Messages.get('me', messageId, { format: 'full' });
  var payload = payloadFromApiMessage_(msg, messageId, config);
  if (!payload) {
    return false;
  }
  var started = Date.now();
  var result = callBackend_(payload, config);
  result.client_ms = Date.now() - started;
  cacheResult_(messageId, result); // opening the email later is instant
  var fromEmail = emailFromHeader_(headerValue_(msg, 'From'));
  if (config.senderHistory && result.sender && result.sender.authenticated && result.sender.email === fromEmail) {
    recordVerdict_(fromEmail, messageId, result.verdict);
  }
  if (!requiresIntervention_(result, settings)) {
    return false;
  }
  rememberAlerted_(messageId);
  labelAndQuarantine_(messageId, settings.quarantine);
  if (settings.autoReport) {
    try {
      result.reported_as = reportToSecOps_(reportPayload_(result, headerValue_(msg, 'Message-ID')), config);
      cacheResult_(messageId, result);
    } catch (err) {
      console.warn('auto-report failed: ' + err.name);
    }
  }
  sendAlertEmail_(messageId, result, headerValue_(msg, 'Subject'), settings);
  return true;
}

function requiresIntervention_(result, settings) {
  return result.verdict === 'malicious' && result.score >= settings.minScore;
}

// ----------------------------------------------------------------------------- Gmail API -> payload

function headerValue_(msg, name) {
  var lower = name.toLowerCase();
  var h = ((msg && msg.payload && msg.payload.headers) || []).filter(function (x) {
    return String(x.name).toLowerCase() === lower;
  })[0];
  return h ? String(h.value || '') : '';
}

function decodeBody_(data, charset) {
  var bytes = Utilities.base64DecodeWebSafe(String(data || ''));
  try {
    return Utilities.newBlob(bytes).getDataAsString(charset || 'UTF-8');
  } catch (err) {
    return Utilities.newBlob(bytes).getDataAsString('UTF-8');
  }
}

function charsetOf_(part) {
  var ct = ((part.headers || []).filter(function (h) { return String(h.name).toLowerCase() === 'content-type'; })[0] || {}).value;
  var m = String(ct || '').match(/charset="?([A-Za-z0-9_\-]{1,40})"?/i);
  return m ? m[1] : 'UTF-8';
}

/**
 * The same request the side panel builds (Extract.gs), but from the Gmail API's "full" view,
 * because a background run has no "current message" to read through GmailApp.
 */
function payloadFromApiMessage_(msg, messageId, config) {
  if (!msg || !msg.payload) {
    return null;
  }
  var text = '';
  var html = '';
  var attachments = [];
  var inspectedBytes = 0;
  var stack = [msg.payload];
  var visited = 0;
  while (stack.length && visited++ < 500) { // bounded walk: a crafted MIME tree can't loop us
    var part = stack.shift();
    (part.parts || []).forEach(function (p) { stack.push(p); });
    var mime = String(part.mimeType || '').toLowerCase();
    var body = part.body || {};
    if (part.filename && attachments.length < MG.MAX_ATTACHMENTS) {
      var bytes = null;
      if (body.attachmentId && (body.size || 0) <= 25 * 1024 * 1024) {
        var att = Gmail.Users.Messages.Attachments.get('me', messageId, body.attachmentId);
        bytes = Utilities.base64DecodeWebSafe(att.data || '');
      } else if (body.data) {
        bytes = Utilities.base64DecodeWebSafe(body.data);
      }
      if (!bytes) {
        continue; // too large to fetch here; the side panel (opening the email) still sees it
      }
      var name = String(part.filename);
      var item = {
        filename: safeSlice_(name, 512),
        content_type: String(part.mimeType || 'application/octet-stream').slice(0, 255),
        size: bytes.length,
        sha256: sha256Hex_(bytes),
        content_b64: null
      };
      if (MG.INSPECTABLE_EXT.indexOf(extensionOf_(name)) !== -1 && bytes.length <= MG.MAX_INSPECT_BYTES &&
          inspectedBytes + bytes.length <= MG.MAX_INSPECT_TOTAL_BYTES) {
        item.content_b64 = Utilities.base64Encode(bytes);
        inspectedBytes += bytes.length;
      }
      attachments.push(item);
    } else if (mime === 'text/plain' && body.data && !text) {
      text = decodeBody_(body.data, charsetOf_(part));
    } else if (mime === 'text/html' && body.data && !html) {
      html = decodeBody_(body.data, charsetOf_(part));
    }
  }
  var headers = (msg.payload.headers || []).map(function (h) { return h.name + ': ' + h.value; }).join('\r\n');
  var senderEmail = emailFromHeader_(headerValue_(msg, 'From'));
  var userEmail = Session.getActiveUser().getEmail() || '';
  return {
    client_version: 'addon-' + MG.VERSION,
    raw_headers: safeSlice_(headers, MG.MAX_HEADER_CHARS),
    text_body: safeSlice_(text, MG.MAX_TEXT_CHARS),
    html_body: safeSlice_(html, MG.MAX_HTML_CHARS),
    attachments: attachments,
    sender_history: config.senderHistory ? getSenderHistory_(senderEmail, messageId) : null,
    recipient_domain: userEmail.indexOf('@') > 0 ? userEmail.split('@')[1].toLowerCase() : '',
    locale: MG_LOCALE_
  };
}

// ----------------------------------------------------------------------------- actions

function alertLabelId_() {
  var labels = (Gmail.Users.Labels.list('me').labels || []);
  var existing = labels.filter(function (l) { return l.name === ALERT_LABEL_; })[0];
  if (existing) {
    return existing.id;
  }
  var label = { name: ALERT_LABEL_, labelListVisibility: 'labelShow', messageListVisibility: 'show' };
  try {
    return Gmail.Users.Labels.create(Object.assign({ color: { backgroundColor: '#cc3a21', textColor: '#ffffff' } }, label),
      'me').id;
  } catch (err) {
    return Gmail.Users.Labels.create(label, 'me').id; // colour palettes differ between accounts
  }
}

function labelAndQuarantine_(messageId, quarantine) {
  try {
    var change = { addLabelIds: [alertLabelId_()], removeLabelIds: quarantine ? ['INBOX'] : [] };
    Gmail.Users.Messages.modify(change, 'me', messageId);
  } catch (err) {
    console.warn('could not label the message: ' + err.name);
  }
}

function reportPayload_(r, messageIdHeader) {
  var indicators = r.links
    .filter(function (l) { return l.flags && l.flags.length; })
    .map(function (l) { return l.destination; });
  if (r.sender && r.sender.domain) {
    indicators.unshift('sender-domain:' + r.sender.domain);
  }
  return {
    message_id_header: clean_(messageIdHeader, 256),
    score: r.score,
    verdict: r.verdict,
    engine_version: r.engine_version,
    sender_email: r.sender ? r.sender.email : '',
    indicators: indicators.slice(0, 15).map(function (i) { return clean_(i, 200); }),
    attack_techniques: (r.attack_techniques || []).map(function (t) { return t.id; }).slice(0, 20),
    user_note: ''
  };
}

/**
 * The alert goes to the user's own address. Everything in it that came from the email is
 * escaped, and it contains no link from the dangerous email - only a link that opens the email
 * in Gmail, where MailGuard's side panel explains it.
 */
function sendAlertEmail_(messageId, r, subject, settings) {
  var me = Session.getActiveUser().getEmail();
  if (!isPlainEmail_(me)) {
    return;
  }
  var rtl = MG_LOCALE_ === 'he';
  var open = 'https://mail.google.com/mail/u/0/#all/' + encodeURIComponent(messageId);
  var sender = r.sender ? esc_(r.sender.email, 120) : t_('sender.unknown');
  var reasons = (r.findings || []).slice(0, 4).map(function (f) {
    return '<li><b>' + esc_(f.title, 120) + '</b> <span style="color:#5f6368">(+' + f.points + ')</span></li>';
  }).join('');
  var recs = (r.recommendations || []).slice(0, 4).map(function (x) { return '<li>' + esc_(x, 300) + '</li>'; }).join('');
  var body =
    '<div dir="' + (rtl ? 'rtl' : 'ltr') + '" style="font-family:Arial,sans-serif;font-size:14px;max-width:620px">' +
    '<div style="background:#d93025;color:#fff;padding:12px 16px;border-radius:8px;font-weight:bold">' +
    t_('banner.malicious') + '</div>' +
    '<p style="font-size:16px"><b>' + t_('alert.intro') + '</b></p>' +
    '<table style="border-collapse:collapse">' +
    '<tr><td style="padding:2px 8px;color:#5f6368">' + t_('alert.from') + '</td><td>' + sender + '</td></tr>' +
    '<tr><td style="padding:2px 8px;color:#5f6368">' + t_('subject') + '</td><td>' + esc_(subject, 160) + '</td></tr>' +
    '<tr><td style="padding:2px 8px;color:#5f6368">' + t_('alert.score') + '</td><td><b style="color:#d93025">' +
    r.score + '/100 · ' + verdictLabel_(r.verdict) + '</b></td></tr></table>' +
    (r.headline ? '<p><b>' + t_('banner.main_threat') + '</b> ' + esc_(r.headline, 300) + '</p>' : '') +
    '<p><b>' + t_('alert.why') + '</b></p><ul>' + reasons + '</ul>' +
    '<p><b>' + t_('section.recommendations') + '</b></p><ul>' + recs + '</ul>' +
    '<p>' + t_(settings.quarantine ? 'alert.done_quarantine' : 'alert.done_label', { label: esc_(ALERT_LABEL_, 60) }) +
    (r.reported_as ? ' ' + t_('alert.done_report', { ref: esc_(r.reported_as, 20) }) : '') + '</p>' +
    '<p><a href="' + open + '" style="background:#1a73e8;color:#fff;padding:8px 14px;border-radius:6px;' +
    'text-decoration:none">' + t_('alert.open') + '</a></p>' +
    '<p style="color:#5f6368;font-size:12px">' + t_('alert.footer') + '</p></div>';
  MailApp.sendEmail({
    to: me,
    subject: '⛔ ' + ALERT_SUBJECT_TAG_ + ': ' + clean_(subject || '', 80) + ' (' + r.score + '/100)',
    htmlBody: body,
    body: t_('alert.intro') + '\n' + clean_(subject, 160) + '\n' + r.score + '/100\n' + open,
    name: 'MailGuard'
  });
}

// ----------------------------------------------------------------------------- never alert twice

function alertedList_() {
  try {
    var v = JSON.parse(PropertiesService.getUserProperties().getProperty('mg:alerts:done') || '[]');
    return Array.isArray(v) ? v : [];
  } catch (err) {
    return [];
  }
}

function alreadyAlerted_(messageId) {
  return alertedList_().indexOf(saltedHash_('a:' + messageId, 16)) !== -1;
}

function rememberAlerted_(messageId) {
  var list = alertedList_().concat([saltedHash_('a:' + messageId, 16)]).slice(-ALERT_MAX_REMEMBERED_);
  PropertiesService.getUserProperties().setProperty('mg:alerts:done', JSON.stringify(list));
}
