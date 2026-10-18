/**
 * Response actions: Move to Trash (with Undo), Block sender (with confirmation) and
 * Report to SecOps.
 *
 * Security rules for every action:
 *  - The target is re-derived on the server side of Apps Script from the message itself
 *    (by id), never taken from text the card carried, and the sender address is strictly
 *    validated before it goes into a Gmail filter.
 *  - Destructive actions are reversible (Undo for Trash) or confirmed (Block).
 *  - Blocking a *forged* address is discouraged: it would filter mail from the real owner,
 *    not from the attacker. The confirmation card says so and offers "Report" instead.
 *  - Every action is logged by type only (no addresses, no content).
 */

function actionMessageId_(e) {
  var id = (e && e.gmail && e.gmail.messageId) || (e && e.parameters && e.parameters.messageId) || '';
  if (!/^[0-9a-zA-Z_-]{8,64}$/.test(id)) {
    throw new Error('invalid message id');
  }
  return id;
}

function notify_(text, navigation) {
  var b = CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(text));
  if (navigation) {
    b.setNavigation(navigation);
  }
  return b.build();
}

function audit_(action, outcome) {
  console.info('action=' + action + ' outcome=' + outcome); // never the address or content
}

/** The sender address from the message's own From header, or null if it isn't a plain address. */
function senderOf_(messageId) {
  var meta = Gmail.Users.Messages.get('me', messageId, { format: 'metadata', metadataHeaders: ['From'] });
  var from = ((meta && meta.payload && meta.payload.headers) || []).filter(function (h) {
    return String(h.name).toLowerCase() === 'from';
  })[0];
  var email = emailFromHeader_(from && from.value);
  return isPlainEmail_(email) ? email : null;
}

function messageIdHeaderOf_(messageId) {
  try {
    var meta = Gmail.Users.Messages.get('me', messageId, { format: 'metadata', metadataHeaders: ['Message-ID'] });
    var h = ((meta && meta.payload && meta.payload.headers) || [])[0];
    return h ? clean_(h.value, 256) : '';
  } catch (err) {
    return '';
  }
}

function onCancel(e) {
  setLocale_(e);
  return CardService.newActionResponseBuilder().setNavigation(CardService.newNavigation().popCard()).build();
}

// ----------------------------------------------------------------------------- Trash

function onTrashMessage(e) {
  setLocale_(e);
  if (!actionsEnabled_()) {
    return notify_(t_('n.disabled'));
  }
  var id = actionMessageId_(e);
  try {
    Gmail.Users.Messages.trash('me', id);
  } catch (err) {
    audit_('trash', 'error');
    return notify_(t_('n.trash_fail'));
  }
  audit_('trash', 'ok');
  return notify_(t_('n.trashed'), CardService.newNavigation().updateCard(buildTrashedCard_(id)));
}

function onUndoTrash(e) {
  setLocale_(e);
  var id = actionMessageId_(e);
  try {
    Gmail.Users.Messages.untrash('me', id);
  } catch (err) {
    audit_('untrash', 'error');
    return notify_(t_('n.untrash_fail'));
  }
  audit_('untrash', 'ok');
  var r = cachedResult_(id);
  var card = r ? buildResultCard_(r, { cached: true, messageId: id }) : buildHomepageCard_();
  return notify_(t_('n.restored'), CardService.newNavigation().updateCard(card));
}

// ----------------------------------------------------------------------------- Block

/** Step 1: show what will happen, with a warning when the address is forged. */
function onConfirmBlock(e) {
  setLocale_(e);
  if (!actionsEnabled_()) {
    return notify_(t_('n.disabled'));
  }
  var id = actionMessageId_(e);
  var sender = senderOf_(id);
  if (!sender) {
    return notify_(t_('n.malformed_report'));
  }
  var r = cachedResult_(id);
  var identity = r && r.sender && r.sender.email === sender ? r.sender : null;
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(buildBlockConfirmCard_(id, sender, identity)))
    .build();
}

/** Step 2: create a Gmail filter that sends future mail from this exact address to Trash. */
function onBlockSender(e) {
  setLocale_(e);
  if (!actionsEnabled_()) {
    return notify_(t_('n.disabled'));
  }
  var id = actionMessageId_(e);
  var sender = senderOf_(id); // re-derived, never taken from the card
  if (!sender) {
    return notify_(t_('n.malformed'));
  }
  var me = String(Session.getActiveUser().getEmail() || '').toLowerCase();
  if (sender === me) {
    return notify_(t_('n.own'));
  }
  try {
    var existing = (Gmail.Users.Settings.Filters.list('me').filter || []).some(function (f) {
      return f.criteria && String(f.criteria.from || '').toLowerCase() === sender;
    });
    if (existing) {
      audit_('block', 'already');
      recordSenderAction_(sender, 'b');
      return notify_(t_('n.already'), CardService.newNavigation().popCard());
    }
    Gmail.Users.Settings.Filters.create({
      criteria: { from: sender },
      action: { addLabelIds: ['TRASH'], removeLabelIds: ['INBOX'] }
    }, 'me');
  } catch (err) {
    audit_('block', 'error');
    return notify_(t_('n.block_fail'));
  }
  audit_('block', 'ok');
  recordSenderAction_(sender, 'b');
  return notify_(t_('n.blocked', { sender: clean_(sender, 80) }),
    CardService.newNavigation().popCard());
}

// ----------------------------------------------------------------------------- Report

function onReportSecOps(e) {
  setLocale_(e);
  var id = actionMessageId_(e);
  try {
    var config = getConfig_();
    var r = cachedResult_(id) || analyzeMessage_(e, id);
    var reportId = reportToSecOps_(reportPayload_(r, messageIdHeaderOf_(id)), config);
    r.reported_as = reportId;
    // Remember the report against the sender only if the address is genuine (authenticated):
    // reporting a forged email must not mark the real owner of the address.
    var reportedSender = senderOf_(id); // re-derived from the message, like Block
    if (reportedSender && r.sender && r.sender.authenticated && r.sender.email === reportedSender) {
      recordSenderAction_(reportedSender, 'r');
    }
    cacheResult_(id, r);
    audit_('report', 'ok');
    return notify_(t_('n.reported', { ref: reportId }),
      CardService.newNavigation().updateCard(buildResultCard_(r, { cached: true, messageId: id })));
  } catch (err) {
    audit_('report', 'error');
    return notify_(t_('n.report_fail'));
  }
}
