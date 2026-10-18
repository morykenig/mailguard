/**
 * Builds the request for the backend from the open message.
 *
 * Data minimisation: we send headers, bodies, attachment metadata + SHA-256, the
 * contents of small inspectable attachments, the recipient's *domain* and a two-number
 * summary of the sender history (counts and flags only). We never send the recipient address, other messages,
 * or large attachment contents.
 */

function buildPayload_(message, messageId, config) {
  var fromHeader = message.getFrom();
  var senderEmail = emailFromHeader_(fromHeader);
  var userEmail = Session.getActiveUser().getEmail() || '';

  return {
    client_version: 'addon-' + MG.VERSION,
    raw_headers: safeSlice_(rawHeaders_(message, messageId), MG.MAX_HEADER_CHARS),
    text_body: safeSlice_(message.getPlainBody(), MG.MAX_TEXT_CHARS),
    html_body: safeSlice_(message.getBody(), MG.MAX_HTML_CHARS),
    attachments: attachmentsOf_(message),
    sender_history: config.senderHistory ? getSenderHistory_(senderEmail, messageId) : null,
    recipient_domain: userEmail.indexOf('@') > 0 ? userEmail.split('@')[1].toLowerCase() : '',
    locale: MG_LOCALE_ // explanations come back in the user's Gmail language
  };
}

/**
 * The header block exactly as Gmail stored it, in order. Order matters: the backend only
 * trusts the top-most Authentication-Results header (the one Gmail added).
 * Uses the Gmail API's metadata view via the Gmail advanced service (no body or attachment
 * bytes are downloaded); falls back to slicing the raw message if that call is unavailable.
 */
function rawHeaders_(message, messageId) {
  try {
    var meta = Gmail.Users.Messages.get('me', messageId, { format: 'metadata' });
    var headers = (meta && meta.payload && meta.payload.headers) || [];
    if (headers.length) {
      return headers.map(function (h) { return h.name + ': ' + h.value; }).join('\r\n');
    }
  } catch (err) {
    console.warn('metadata fetch failed, falling back to raw content: ' + err.name);
  }
  var raw = message.getRawContent();
  var end = raw.search(/\r?\n\r?\n/);
  return end === -1 ? raw.slice(0, MG.MAX_HEADER_CHARS) : raw.slice(0, end);
}

function attachmentsOf_(message) {
  var out = [];
  var inspectedBytes = 0;
  var atts = message.getAttachments({ includeInlineImages: false, includeAttachments: true });
  for (var i = 0; i < atts.length && out.length < MG.MAX_ATTACHMENTS; i++) {
    var att = atts[i];
    var bytes = att.getBytes();
    var name = String(att.getName() || '');
    var item = {
      filename: safeSlice_(name, 512),
      content_type: String(att.getContentType() || 'application/octet-stream').slice(0, 255),
      size: bytes.length,
      sha256: sha256Hex_(bytes),
      content_b64: null
    };
    var inspectable = MG.INSPECTABLE_EXT.indexOf(extensionOf_(name)) !== -1;
    if (inspectable && bytes.length <= MG.MAX_INSPECT_BYTES &&
        inspectedBytes + bytes.length <= MG.MAX_INSPECT_TOTAL_BYTES) {
      item.content_b64 = Utilities.base64Encode(bytes);
      inspectedBytes += bytes.length;
    }
    out.push(item);
  }
  return out;
}
