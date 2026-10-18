/**
 * Card UI. Design goals:
 *  - the verdict is readable in one second: a hazard banner, a traffic-light gauge, a number;
 *  - the single most important threat is named concretely, right under the banner;
 *  - every point of the score is traceable to a plain-language, specific reason;
 *  - the user can act immediately (Trash, Block, Report), with safe defaults;
 *  - nothing from the email is ever clickable here (links are shown de-fanged).
 */

var VERDICT_LIGHT_ = { safe: '🟢', suspicious: '🟠', malicious: '🔴' };
var VERDICT_ICON_ = { safe: 'verified_user', suspicious: 'warning', malicious: 'report' };
function verdictLabel_(v) {
  return t_('verdict.' + v);
}
var CATEGORY_ICON_ = {
  'Sender authentication': ['verified_user', 'EMAIL'],
  'Sender identity': ['person', 'PERSON'],
  'Subject line': ['subject', 'EMAIL'],
  'Images & emojis': ['image', 'DESCRIPTION'],
  'Links': ['link', 'BOOKMARK'],
  'Attachments': ['attach_file', 'DESCRIPTION'],
  'Message content': ['chat', 'DESCRIPTION'],
  'Social engineering pattern': ['psychology', 'DESCRIPTION'],
  'Your history with the sender': ['history', 'CLOCK'],
  'Threat intelligence': ['public', 'STAR'],
  'Cloud & identity attacks': ['cloud', 'STAR'],
  'Hidden content & AI manipulation': ['visibility_off', 'DESCRIPTION'],
  'Sensitive data exposure': ['vpn_key', 'MEMBERSHIP']
};

/**
 * Icons as image URLs from Google's Material icon set. (setMaterialIcon is not rendered by
 * Gmail add-ons - it shows the icon's *name* as text - so it is not used.)
 */
function icon_(materialName, knownIconName) {
  var url = 'https://www.gstatic.com/images/icons/material/system/2x/' + materialName + '_black_48dp.png';
  try {
    return CardService.newIconImage().setIconUrl(url).setAltText(materialName);
  } catch (err) {
    return CardService.newIconImage().setIcon(CardService.Icon[knownIconName] || CardService.Icon.DESCRIPTION);
  }
}

/** Collapse a section, keeping the first n widgets visible. */
function collapsible_(section, visible) {
  section.setCollapsible(true);
  if (visible > 0) {
    section.setNumUncollapsibleWidgets(visible);
  }
  return section;
}

function headerImage_(name) {
  return 'https://www.gstatic.com/images/icons/material/system/2x/' + name + '_black_48dp.png';
}

function action_(fn, messageId) {
  var a = CardService.newAction().setFunctionName(fn);
  return messageId ? a.setParameters({ messageId: String(messageId) }) : a;
}

function button_(text, fn, messageId, color) {
  var b = CardService.newTextButton().setText(text).setOnClickAction(action_(fn, messageId));
  if (color) {
    b.setTextButtonStyle(CardService.TextButtonStyle.FILLED).setBackgroundColor(color);
  }
  return b;
}

// ----------------------------------------------------------------------------- building blocks

/** Traffic-light gauge, e.g. [█████████░] 92/100 🔴 */
function gauge_(score, verdict) {
  var filled = Math.max(0, Math.min(10, Math.round(score / 10)));
  return '<font color="' + MG.COLORS[verdict] + '">[' + new Array(filled + 1).join('█') +
    new Array(10 - filled + 1).join('░') + ']</font>  <b>' + score + '</b>/100  ' + VERDICT_LIGHT_[verdict];
}

/**
 * The banner is the first thing on the card. It follows the engine's verdict rather than a
 * separate threshold, so banner, gauge colour and score never disagree.
 * The safe state deliberately says "No threats detected", not "Verified": a scanner can
 * only report the absence of evidence, and overstating safety is how users get phished.
 */
function bannerSection_(r) {
  var text;
  if (r.verdict === 'malicious') {
    text = '<font color="' + MG.COLORS.malicious + '"><b>' + t_('banner.malicious') + '</b></font>';
  } else if (r.verdict === 'suspicious') {
    text = '<font color="' + MG.COLORS.suspicious + '"><b>' + t_('banner.suspicious') + '</b></font>';
  } else {
    text = '<font color="' + MG.COLORS.safe + '"><b>' + t_('banner.safe') + '</b></font><br>' +
      '<font color="' + MG.COLORS.muted + '">' +
      t_(r.confidence === 'high' ? 'banner.safe_note' : 'banner.safe_note_partial') + '</font>';
  }
  if (r.headline) {
    text += '<br><br><b>' + t_('banner.main_threat') + '</b> ' + esc_(r.headline, 300);
  }
  if (r.reported_as) {
    text += '<br><br><font color="' + MG.COLORS.muted + '">' + t_('banner.reported', { ref: esc_(r.reported_as, 20) }) +
      '</font>';
  }
  // The subject is attacker-written: shown escaped, so the user can match the verdict to the email.
  if (r.subject) {
    text += '<br><br><font color="' + MG.COLORS.muted + '">' + t_('subject') + '</font> ' + esc_(r.subject, 160);
  }
  if (r.language && languageName_(r.language)) {
    text += '<br><font color="' + MG.COLORS.muted + '">' + t_('language', { lang: languageName_(r.language) }) + '</font>';
  }
  return CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(text));
}

function gaugeSection_(r) {
  return CardService.newCardSection()
    .addWidget(CardService.newDecoratedText()
      .setTopLabel(t_('gauge.label', { verdict: verdictLabel_(r.verdict) }))
      .setText(gauge_(r.score, r.verdict))
      .setBottomLabel(t_('confidence.' + r.confidence))
      .setWrapText(true))
    .addWidget(CardService.newTextParagraph().setText(esc_(r.summary, 600)));
}

function findingWidget_(f, isMitigation) {
  var cat = CATEGORY_ICON_[f.category] || ['info', 'DESCRIPTION'];
  var points = isMitigation ? '−' + Math.abs(f.points) : '+' + f.points;
  var text = '<b>' + esc_(f.title, 120) + '</b><br>' + esc_(f.detail, 500);
  (f.evidence || []).slice(0, 3).forEach(function (ev) {
    text += '<br><font color="' + MG.COLORS.muted + '">▸ ' + esc_(ev, 140) + '</font>';
  });
  var attack = (f.attack || [])[0];
  return CardService.newDecoratedText()
    .setTopLabel(label_(categoryLabel_(f.category), 60) + '  ·  ' + points + (attack ? '  ·  ' + label_(attack.id, 16) : ''))
    .setText(text)
    .setWrapText(true)
    .setStartIcon(icon_(cat[0], cat[1]));
}

function exposureWidget_(f) {
  var text = '<b>' + esc_(f.title, 120) + '</b><br>' + esc_(f.detail, 500);
  (f.evidence || []).slice(0, 3).forEach(function (ev) {
    text += '<br><font color="' + MG.COLORS.muted + '">▸ ' + esc_(ev, 80) + '</font>';
  });
  return CardService.newDecoratedText()
    .setTopLabel(t_('exposure.label'))
    .setText(text)
    .setWrapText(true)
    .setStartIcon(icon_('vpn_key', 'MEMBERSHIP'));
}

/** MITRE ATT&CK / ATLAS techniques seen in this email - the analyst's vocabulary. */
function attackSection_(r) {
  var refs = (r.attack_techniques || []).slice(0, 12);
  if (!refs.length || r.verdict === 'safe') {
    return null;
  }
  var lines = refs.map(function (t) {
    return '<b>' + esc_(t.id, 16) + '</b>  ' + esc_(t.name, 120) +
      (t.framework === 'ATLAS' ? ' <font color="' + MG.COLORS.muted + '">(MITRE ATLAS)</font>' : '');
  });
  return collapsible_(CardService.newCardSection().setHeader('MITRE ATT&CK (' + refs.length + ')'), 0)
    .addWidget(CardService.newTextParagraph().setText(lines.join('<br>')));
}

function senderLine_(sender) {
  if (!sender) {
    return t_('sender.unknown');
  }
  var status = t_(sender.authenticated ? 'sender.authenticated' : sender.spoofed ? 'sender.spoofed' : 'sender.unverified');
  return t_('sender.line', { email: esc_(sender.email, 120), status: status });
}

/** Response actions. What is offered depends on the verdict and on whether the sender is real. */
function actionsSection_(r, messageId) {
  var section = CardService.newCardSection().setHeader(t_('section.actions'));
  section.addWidget(CardService.newTextParagraph().setText(senderLine_(r.sender)));
  var buttons = CardService.newButtonSet();
  if (r.verdict === 'safe') {
    buttons.addButton(button_(t_('btn.report_safe'), 'onReportSecOps', messageId));
  } else {
    var danger = r.verdict === 'malicious' ? MG.COLORS.malicious : null;
    buttons.addButton(button_(t_('btn.trash'), 'onTrashMessage', messageId, danger));
    if (r.sender) {
      buttons.addButton(button_(t_('btn.block'), 'onConfirmBlock', messageId));
    }
    if (!r.reported_as) {
      buttons.addButton(button_(t_('btn.report'), 'onReportSecOps', messageId));
    }
  }
  return section.addWidget(buttons);
}

function performanceLine_(r, meta) {
  var engine = (r.analysis_ms / 1000).toFixed(2) + ' s';
  if (meta && meta.cached) {
    return t_('perf.cached', { engine: engine });
  }
  var total = typeof r.client_ms === 'number' ? (r.client_ms / 1000).toFixed(2) + ' s' : engine;
  return t_('perf.fresh', { total: total, engine: engine });
}

// ----------------------------------------------------------------------------- result card

function buildResultCard_(r, meta) {
  var messageId = meta && meta.messageId;
  var card = CardService.newCardBuilder()
    .setName('result')
    .setHeader(CardService.newCardHeader()
      .setTitle('MailGuard')
      .setSubtitle(VERDICT_LIGHT_[r.verdict] + ' ' + verdictLabel_(r.verdict) + '  ·  ' + r.score + '/100')
      .setImageUrl(headerImage_(VERDICT_ICON_[r.verdict]))
      .setImageStyle(CardService.ImageStyle.SQUARE));

  // 1. Hazard banner + the concrete main threat, then the gauge.
  card.addSection(bannerSection_(r));
  card.addSection(gaugeSection_(r));

  // 2. Secrets exposed in the email: a separate concern from maliciousness.
  if ((r.exposures || []).length) {
    var exp = CardService.newCardSection().setHeader(t_('section.exposures', { n: r.exposures.length }));
    r.exposures.forEach(function (f) { exp.addWidget(exposureWidget_(f)); });
    card.addSection(exp);
  }

  // 3. Specific threats, strongest first. The top three are always visible.
  if (r.findings.length) {
    var why = CardService.newCardSection()
      .setHeader(t_(r.verdict === 'safe' ? 'section.notes' : 'section.findings', { n: r.findings.length }));
    r.findings.forEach(function (f) { why.addWidget(findingWidget_(f, false)); });
    if (r.findings.length > 3) {
      collapsible_(why, 3);
    }
    card.addSection(why);
  }

  // 3. What to do, then the buttons to do it.
  if (r.recommendations.length) {
    card.addSection(CardService.newCardSection().setHeader(t_('section.recommendations'))
      .addWidget(CardService.newTextParagraph().setText(
        r.recommendations.map(function (t) { return '• ' + esc_(t, 300); }).join('<br>'))));
  }
  if (messageId && actionsEnabled_()) {
    card.addSection(actionsSection_(r, messageId));
  }

  // 4. Supporting detail, collapsed.
  if (r.mitigations.length) {
    var good = collapsible_(CardService.newCardSection().setHeader(t_('section.mitigations')), r.findings.length ? 0 : 1);
    r.mitigations.forEach(function (f) { good.addWidget(findingWidget_(f, true)); });
    card.addSection(good);
  }
  if (r.links.length) {
    var flagged = r.links.filter(function (l) { return l.flags && l.flags.length; }).length;
    var links = collapsible_(CardService.newCardSection()
      .setHeader(t_('section.links', { n: r.links.length })), Math.min(flagged, 2));
    r.links.forEach(function (l) {
      var w = CardService.newDecoratedText()
        .setText(esc_(l.destination, 120))
        .setWrapText(true)
        .setBottomLabel(l.flags && l.flags.length ? '⚠ ' + label_(l.flags.join(', '), 120) : t_('link.ok'))
        .setStartIcon(icon_(l.flags && l.flags.length ? 'link_off' : 'link', 'BOOKMARK'));
      if (l.text) {
        w.setTopLabel(t_('link.shown_as', { text: label_(l.text, 60) }));
      }
      links.addWidget(w);
    });
    card.addSection(links);
  }

  var attack = attackSection_(r);
  if (attack) {
    card.addSection(attack);
  }

  // 5. Coverage and performance: say plainly what was checked and how long it took.
  var coverage = collapsible_(CardService.newCardSection().setHeader(t_('section.coverage')), 1);
  coverage.addWidget(CardService.newTextParagraph().setText(
    '<font color="' + MG.COLORS.muted + '">' + esc_(performanceLine_(r, meta), 120) + '</font>'));
  var lines = Object.keys(r.coverage).map(function (k) {
    return '<b>' + esc_(k, 60) + '</b>: ' + esc_(r.coverage[k], 80);
  });
  lines.push('<font color="' + MG.COLORS.muted + '">' + t_('engine', { v: esc_(r.engine_version, 20) }) + '</font>');
  coverage.addWidget(CardService.newTextParagraph().setText(lines.join('<br>')));
  card.addSection(coverage);

  card.setFixedFooter(CardService.newFixedFooter()
    .setPrimaryButton(CardService.newTextButton().setText(t_('btn.rescan')).setOnClickAction(action_('onRescan', messageId)))
    .setSecondaryButton(CardService.newTextButton().setText(t_('btn.methodology'))
      .setOnClickAction(action_('onShowMethodology'))));
  return card.build();
}

// ----------------------------------------------------------------------------- action cards

function buildBlockConfirmCard_(messageId, sender, identity) {
  var spoofed = identity && identity.spoofed;
  var unverified = !identity || (!identity.authenticated && !identity.spoofed);
  var who = esc_(sender, 120);
  var text = t_('block.body', { sender: who });
  if (spoofed) {
    text = '<font color="' + MG.COLORS.malicious + '">' + t_('block.spoofed') + '</font><br>' +
      t_('block.spoofed_more', { sender: who }) + '<br><br>' + text;
  } else if (unverified) {
    text = '<font color="' + MG.COLORS.suspicious + '">' + t_('block.unverified') + '</font> ' +
      t_('block.unverified_more') + '<br><br>' + text;
  }
  var footer = CardService.newFixedFooter();
  if (spoofed) {
    footer.setPrimaryButton(button_(t_('btn.report_instead'), 'onReportSecOps', messageId))
      .setSecondaryButton(button_(t_('btn.block_anyway'), 'onBlockSender', messageId));
  } else {
    footer.setPrimaryButton(button_(t_('btn.block'), 'onBlockSender', messageId, MG.COLORS.malicious))
      .setSecondaryButton(CardService.newTextButton().setText(t_('btn.cancel')).setOnClickAction(action_('onCancel')));
  }
  return CardService.newCardBuilder()
    .setName('confirm-block')
    .setHeader(CardService.newCardHeader().setTitle(t_('block.title')))
    .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(text)))
    .setFixedFooter(footer)
    .build();
}

function buildTrashedCard_(messageId) {
  return CardService.newCardBuilder()
    .setName('trashed')
    .setHeader(CardService.newCardHeader().setTitle('MailGuard').setSubtitle(t_('trashed.subtitle'))
      .setImageUrl(headerImage_('delete')))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(t_('trashed.body')))
      .addWidget(CardService.newButtonSet()
        .addButton(button_(t_('btn.undo'), 'onUndoTrash', messageId))
        .addButton(button_(t_('btn.report'), 'onReportSecOps', messageId))))
    .build();
}

// ----------------------------------------------------------------------------- other cards

function buildHomepageCard_() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('MailGuard').setSubtitle(t_('home.subtitle'))
      .setImageUrl(headerImage_('security')))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(
        t_('home.intro') + '<br><br><b>' + t_('home.checks_title') + '</b><br>• ' + t_('home.checks'))))
    .addSection(alertsSection_())
    .addSection(CardService.newCardSection().setHeader(t_('home.privacy_title'))
      .addWidget(CardService.newTextParagraph().setText(t_('home.privacy'))))
    .build();
}

/** On/off switch for background alerts (Alerts.gs). */
function alertsSection_() {
  var on = false;
  try {
    on = alertsEnabled_();
  } catch (err) {
    // trigger state unavailable (e.g. scope not granted yet): show as off
  }
  return CardService.newCardSection().setHeader(t_('alerts.title'))
    .addWidget(CardService.newTextParagraph().setText(
      on ? t_('alerts.on', { min: alertSettings_().minScore }) : t_('alerts.off')))
    .addWidget(CardService.newButtonSet().addButton(
      button_(t_(on ? 'alerts.btn_off' : 'alerts.btn_on'), 'onToggleAlerts', null, on ? null : MG.COLORS.safe)));
}

function buildMethodologyCard_() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle(t_('method.title')))
    .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(t_('method.body'))))
    .build();
}

function buildErrorCard_(err) {
  var reason;
  if (err instanceof ConfigError_) {
    reason = t_('error.config', { msg: esc_(err.message) });
  } else if (err instanceof BackendError_) {
    var known = ['auth', 'rate', 'busy', 'untrusted', 'too_large', 'invalid', 'server', 'network', 'bad_response',
      'forbidden', 'not_found'];
    reason = known.indexOf(err.kind) !== -1 ? t_('error.' + err.kind) : t_('error.unexpected');
    if (err.detail) {
      reason += '<br><br><font color="' + MG.COLORS.muted + '">' + t_('error.details') + ' ' + esc_(err.detail, 200) +
        '</font>';
    }
  } else {
    reason = t_('error.reading');
  }
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('MailGuard').setSubtitle(t_('error.subtitle'))
      .setImageUrl(headerImage_('error_outline')))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(reason))
      .addWidget(CardService.newTextParagraph().setText(t_('error.not_safe'))))
    .setFixedFooter(CardService.newFixedFooter().setPrimaryButton(
      CardService.newTextButton().setText(t_('btn.retry')).setOnClickAction(action_('onRescan'))))
    .build();
}
