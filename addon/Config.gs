/**
 * Configuration and limits.
 *
 * Secrets live in Script Properties (Project Settings -> Script properties), never in
 * source. They are readable by people who can edit this script project, not by the
 * users who install the add-on.
 *   BACKEND_URL            https://<your-service>.run.app
 *   HMAC_SECRET            same value as the backend's MG_HMAC_SECRET (>= 32 chars)
 *   ENABLE_SENDER_HISTORY  "false" to skip the mailbox-history lookup and verdict memory (optional)
 *   ENABLE_ACTIONS         "false" to hide Trash / Block / Report buttons (optional)
 *   ALERT_MIN_SCORE, ALERT_QUARANTINE, ALERT_AUTO_REPORT, ALERT_INTERVAL_MIN
 *                          background alerts, see Alerts.gs (optional)
 */

var MG = Object.freeze({
  VERSION: '1.4.4',
  MAX_HEADER_CHARS: 128 * 1024,
  MAX_TEXT_CHARS: 200000,
  MAX_HTML_CHARS: 600000,
  MAX_ATTACHMENTS: 25,
  // Contents are sent only for small, statically inspectable types; everything else
  // is represented by name, type, size and SHA-256 hash.
  MAX_INSPECT_BYTES: 2 * 1024 * 1024,
  MAX_INSPECT_TOTAL_BYTES: 6 * 1024 * 1024, // ~8 MB as base64: stays under the backend's 12 MB cap
  INSPECTABLE_EXT: ['doc', 'docx', 'docm', 'dotm', 'xls', 'xlsx', 'xlsm', 'xlsb', 'ppt', 'pptx', 'pptm',
                    'pdf', 'zip', 'rtf', 'jpg', 'jpeg', 'png', 'txt'],
  HISTORY_LOOKBACK: 50,
  HISTORY_MAX_RECORDS: 400, // salted-hash verdict records kept in UserProperties (~100 KB of the 500 KB quota)
  HISTORY_MAX_PER_SENDER: 10,
  CACHE_TTL_SECONDS: 600,
  COLORS: { safe: '#188038', suspicious: '#e37400', malicious: '#d93025', muted: '#5f6368' }
});

/** Thrown for problems the person installing the add-on must fix (not the end user). */
function ConfigError_(message) {
  this.name = 'ConfigError';
  this.message = message;
}

function getConfig_() {
  var props = PropertiesService.getScriptProperties();
  var backendUrl = String(props.getProperty('BACKEND_URL') || '').replace(/\/+$/, '');
  var secret = String(props.getProperty('HMAC_SECRET') || '').trim(); // a pasted space or newline breaks signing
  if (!/^https:\/\/[a-z0-9.-]+(:\d+)?$/i.test(backendUrl)) {
    throw new ConfigError_('BACKEND_URL is missing or is not an https:// origin.');
  }
  if (secret.length < 32) {
    throw new ConfigError_('HMAC_SECRET is missing or shorter than 32 characters.');
  }
  return {
    backendUrl: backendUrl,
    secret: secret,
    senderHistory: props.getProperty('ENABLE_SENDER_HISTORY') !== 'false',
    actions: props.getProperty('ENABLE_ACTIONS') !== 'false'
  };
}

/** Feature flags readable without a valid backend configuration (used by the UI). */
function actionsEnabled_() {
  return PropertiesService.getScriptProperties().getProperty('ENABLE_ACTIONS') !== 'false';
}
