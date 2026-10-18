/**
 * UI strings in English and Hebrew.
 *
 * The language follows the user's Gmail language (e.commonEventObject.userLocale, which needs
 * "useLocaleFromApp": true and the script.locale scope in the manifest). The backend gets
 * the same locale and writes its findings, summary and recommendations in that language,
 * so the whole card is in one language. Anything without a translation falls back to English.
 *
 * Strings are templates: t_('key', { name: value }) replaces {name}. Values are inserted
 * as-is, so callers escape dynamic values (esc_/label_) *before* passing them in.
 */

var MG_LOCALE_ = 'en'; // set once per execution by setLocale_(e)

/** 'he', 'he-IL' and 'iw' (Java's legacy Hebrew code) -> 'he'; everything else -> 'en'. */
function normalizeLocale_(locale) {
  var code = String(locale || 'en').toLowerCase().replace('_', '-').split('-')[0];
  if (code === 'iw') {
    code = 'he';
  }
  return STRINGS_[code] ? code : 'en';
}

function setLocale_(e) {
  var raw = (e && e.commonEventObject && e.commonEventObject.userLocale) ||
    (e && e.userLocale) || // older event shape
    '';
  MG_LOCALE_ = normalizeLocale_(raw);
  if (raw) {
    // Remembered for background alerts, which run without an event (Alerts.gs).
    try {
      var props = PropertiesService.getUserProperties();
      if (props.getProperty('mg:locale') !== MG_LOCALE_) {
        props.setProperty('mg:locale', MG_LOCALE_);
      }
    } catch (err) {
      // best effort
    }
  }
  return MG_LOCALE_;
}

function t_(key, vars) {
  var table = STRINGS_[MG_LOCALE_] || STRINGS_.en;
  var s = table[key] !== undefined ? table[key] : STRINGS_.en[key];
  if (s === undefined) {
    return key;
  }
  return !vars ? s : s.replace(/\{(\w+)\}/g, function (m, name) {
    return vars[name] !== undefined ? String(vars[name]) : m;
  });
}

/** Category names come from the backend in English (they are also icon keys). */
function categoryLabel_(category) {
  return (MG_LOCALE_ === 'he' && CATEGORY_HE_[category]) || category;
}

var CATEGORY_HE_ = {
  'Sender authentication': 'אימות שולח',
  'Sender identity': 'זהות השולח',
  'Subject line': 'שורת הנושא',
  'Links': 'קישורים',
  'Attachments': 'קבצים מצורפים',
  'Message content': 'תוכן ההודעה',
  'Social engineering pattern': 'דפוס הנדסה חברתית',
  'Your history with the sender': 'ההיסטוריה שלכם עם השולח',
  'Threat intelligence': 'מודיעין איומים',
  'Images & emojis': "תמונות ואימוג'י",
  'Cloud & identity attacks': 'מתקפות ענן וזהות',
  'Hidden content & AI manipulation': 'תוכן נסתר ומניפולציה על AI',
  'Sensitive data exposure': 'חשיפת מידע רגיש'
};

var STRINGS_ = {
  en: {
    'verdict.safe': 'Looks safe',
    'verdict.suspicious': 'Suspicious',
    'verdict.malicious': 'Likely malicious',
    'confidence.high': 'Confidence: high - all checks completed',
    'confidence.medium': 'Confidence: medium - some checks were unavailable',
    'confidence.low': 'Confidence: low - treat this verdict with extra caution',
    'banner.malicious': '⛔ WARNING: DO NOT CLICK ANY LINKS OR OPEN ATTACHMENTS',
    'banner.suspicious': '⚠️ CAUTION: VERIFY BEFORE YOU CLICK, PAY OR REPLY',
    'banner.safe': '✅ NO THREATS DETECTED',
    'banner.safe_note': 'Automated checks found nothing suspicious. This is not a guarantee.',
    'banner.safe_note_partial': 'Automated checks found nothing suspicious, but some checks could not run. This is not a guarantee.',
    'banner.main_threat': 'Main threat:',
    'banner.reported': '📣 Reported to SecOps · {ref}',
    'subject': 'Subject:',
    'language': 'Language: {lang}',
    'gauge.label': 'Risk score  ·  {verdict}',
    'section.exposures': '🔑 Sensitive data in this email ({n})',
    'section.findings': 'Detected threats ({n})',
    'section.notes': 'Minor notes ({n}) - not enough to be suspicious',
    'section.recommendations': 'Recommended actions',
    'section.actions': 'Take action',
    'section.mitigations': 'Reassuring signs',
    'section.links': 'Where the links really go ({n})',
    'section.coverage': 'What was checked',
    'exposure.label': 'Exposure · not part of the risk score',
    'link.ok': 'No issues found',
    'link.shown_as': 'Shown as: {text}',
    'sender.unknown': 'Sender: unknown',
    'sender.line': 'Sender: <b>{email}</b> - {status}',
    'sender.authenticated': '✔ genuine address (authenticated) - which says nothing about intent',
    'sender.spoofed': '✖ failed authentication - likely forged',
    'sender.unverified': '? could not be verified',
    'btn.report_safe': '📣 Report as suspicious',
    'btn.trash': '🗑️ Move to Trash',
    'btn.block': '🚫 Block sender',
    'btn.report': '📣 Report to SecOps',
    'btn.rescan': 'Re-scan',
    'btn.methodology': 'How scoring works',
    'btn.report_instead': '📣 Report instead',
    'btn.block_anyway': 'Block anyway',
    'btn.cancel': 'Cancel',
    'btn.undo': '↩️ Undo',
    'btn.retry': 'Try again',
    'perf.cached': '⚡ Cached result · engine time {engine} · Re-scan for a fresh check',
    'perf.fresh': '⚡ Analyzed in {total} (engine {engine})',
    'engine': 'Engine {v}',
    'block.title': 'Block this sender?',
    'block.body': 'Future emails from <b>{sender}</b> will skip your inbox and go straight to Trash. You can remove the block any time in Gmail Settings → Filters and Blocked Addresses.',
    'block.spoofed': '<b>This address failed authentication - it is almost certainly forged.</b>',
    'block.spoofed_more': 'Blocking it would send future mail from the <b>real</b> owner of {sender} to Trash, while the attacker simply forges a different address next time. Reporting is the better action.',
    'block.unverified': '<b>This address could not be verified.</b>',
    'block.unverified_more': 'It may belong to someone other than the sender of this email.',
    'trashed.subtitle': '🗑️ Moved to Trash',
    'trashed.body': 'This email is in Trash and will be deleted automatically after 30 days. If it targeted you, consider reporting it so the security team can protect others.',
    'home.subtitle': 'Phishing & malware check for Gmail',
    'home.intro': 'Open any email and MailGuard will score it from 0 to 100, name the exact threat, map it to MITRE ATT&amp;CK, and let you trash, block or report it in one click.',
    'home.checks_title': 'What it checks',
    'home.checks': [
      'Sender authentication (SPF, DKIM, DMARC)',
      'Look-alike, spoofed and fake-"verified" senders',
      'The subject line: fake "RE:" replies, alarm tags, disguised letters',
      'Where links really lead',
      'Dangerous attachments (macros, disguised programs, fake images)',
      'Pressure, payment-fraud and parcel-fee language - in English, Hebrew, Arabic, Russian, Spanish, French and German',
      'Images and emojis: picture-only emails, copied brand logos, alarm emojis',
      'Your history with the sender - including earlier malicious verdicts, reports and blocks',
      'Threat intelligence (VirusTotal, Google Safe Browsing, domain age)',
      'Cloud &amp; identity attacks: device-code and OAuth consent phishing, fake cloud consoles',
      'Hidden text and prompt injection aimed at AI assistants',
      'Exposed secrets (cloud keys, tokens, private keys)'
    ].join('<br>• '),
    'home.privacy_title': 'Privacy',
    'home.privacy': 'Emails are analysed in memory and never stored. Only URLs, domains and file hashes are checked with threat-intelligence services; nothing is uploaded to them. Your verdict history stays in your own Google account, and addresses are stored only as salted hashes.',
    'method.title': 'How scoring works',
    'method.body': [
      '<b>Evidence, not a black box.</b> Each warning sign adds points; reassuring signs subtract a little.',
      '<b>Breadth matters.</b> Points are capped per category, so many urgent words alone cannot make an email "malicious" - that takes evidence from several angles.',
      '<b>Some evidence is conclusive.</b> A disguised program, several antivirus engines agreeing, or a sender you already reported set a minimum score on their own.',
      '<b>Thresholds:</b> 🟢 0-29 looks safe · 🟠 30-64 suspicious · 🔴 65-100 likely malicious.',
      '<b>Confidence</b> drops when a check could not run - a missing check is never shown as a clean one.',
      '<b>Memory.</b> Verdicts, reports and blocks are remembered (as salted hashes, in your account), so a sender who sent you malicious mail before is flagged next time.',
      '<b>Blocking</b> is only recommended when the sender is authenticated: blocking a forged address hurts its real owner, not the attacker.'
    ].join('<br><br>'),
    'error.subtitle': 'Could not analyse this email',
    'error.config': 'The add-on is not configured: {msg} Set it in Project Settings → Script properties.',
    'error.auth': 'The analysis service rejected the request. The shared secret in the add-on and the backend probably differ.',
    'error.rate': 'Too many scans in a short time. Wait a minute and try again.',
    'error.busy': 'The analysis service is busy. Try again in a few seconds.',
    'error.untrusted': 'The answer did not carry a valid signature from the MailGuard backend, so it was discarded. Someone may be tampering with the connection, or BACKEND_URL points to the wrong server.',
    'error.too_large': 'This email is too large to analyse.',
    'error.invalid': 'The analysis service could not read this email.',
    'error.server': 'The analysis service had a problem.',
    'error.network': 'The analysis service is unreachable right now.',
    'error.bad_response': 'The analysis service returned an unexpected answer.',
    'error.unexpected': 'Unexpected error.',
    'error.forbidden': 'The analysis service refused the connection (HTTP 403). The Cloud Run service must allow unauthenticated invocations - MailGuard authenticates every request itself.',
    'error.not_found': 'The analysis service address is wrong (HTTP 404). Check BACKEND_URL.',
    'error.details': 'Technical details (run diagnose() in the script editor for a full check):',
    'error.reading': 'Unexpected error while reading this email.',
    'error.not_safe': '<b>No result is not a safe result.</b> Be careful with links, attachments and requests for money or passwords until the email can be checked.',
    'n.disabled': 'Actions are disabled by your administrator.',
    'n.trash_fail': 'Could not move this email to Trash. Please try again.',
    'n.trashed': '🗑️ Moved to Trash.',
    'n.untrash_fail': 'Could not restore this email.',
    'n.restored': '↩️ Restored from Trash.',
    'n.malformed_report': 'The sender address is malformed, so it cannot be blocked safely. Report it instead.',
    'n.malformed': 'The sender address is malformed, so it cannot be blocked safely.',
    'n.own': "That's your own address - not blocked.",
    'n.already': 'This sender is already blocked.',
    'n.block_fail': 'Could not create the block filter. Please try again.',
    'n.blocked': '🚫 Blocked {sender}. Future emails go to Trash (undo in Gmail Settings → Filters).',
    'n.reported': '📣 Reported to SecOps · reference {ref}',
    'n.report_fail': 'Could not send the report right now. Please try again.',
    'alerts.title': 'Background alerts',
    'alerts.on': '🔔 <b>On.</b> New mail is scanned every few minutes. Emails scoring {min}+ are labelled "MailGuard/⚠ Malicious" and you get an alert email - even if you never open them.',
    'alerts.off': '🔕 <b>Off.</b> Emails are scored only when you open them. Turn alerts on to be warned about dangerous mail you have not opened yet.',
    'alerts.btn_on': '🔔 Turn on alerts',
    'alerts.btn_off': '🔕 Turn off alerts',
    'alerts.enabled': '🔔 Background alerts are on.',
    'alerts.disabled': '🔕 Background alerts are off.',
    'alerts.toggle_fail': 'Could not change the alert setting. Please try again.',
    'alert.intro': 'MailGuard found a dangerous email in your inbox.',
    'alert.from': 'From:',
    'alert.score': 'Risk:',
    'alert.why': 'Why:',
    'alert.done_label': 'It was labelled "{label}" in your inbox.',
    'alert.done_quarantine': 'It was moved out of your inbox and labelled "{label}". To restore it, open it and choose "Move to Inbox".',
    'alert.done_report': 'It was reported to SecOps (reference {ref}).',
    'alert.open': 'Open the email in Gmail',
    'alert.footer': 'This alert contains no links from the suspicious email. Open it in Gmail to see the full MailGuard analysis, then trash, block or report it.'
  },

  he: {
    'verdict.safe': 'נראה בטוח',
    'verdict.suspicious': 'חשוד',
    'verdict.malicious': 'כנראה זדוני',
    'confidence.high': 'רמת ודאות: גבוהה - כל הבדיקות הושלמו',
    'confidence.medium': 'רמת ודאות: בינונית - חלק מהבדיקות לא היו זמינות',
    'confidence.low': 'רמת ודאות: נמוכה - התייחסו לתוצאה בזהירות יתרה',
    'banner.malicious': '⛔ אזהרה: אל תלחצו על קישורים ואל תפתחו קבצים מצורפים',
    'banner.suspicious': '⚠️ זהירות: אמתו לפני שאתם לוחצים, משלמים או עונים',
    'banner.safe': '✅ לא זוהו איומים',
    'banner.safe_note': 'הבדיקות האוטומטיות לא מצאו שום דבר חשוד. זו לא התחייבות.',
    'banner.safe_note_partial': 'הבדיקות האוטומטיות לא מצאו שום דבר חשוד, אבל חלק מהבדיקות לא רצו. זו לא התחייבות.',
    'banner.main_threat': 'האיום העיקרי:',
    'banner.reported': '📣 דווח ל-SecOps · {ref}',
    'subject': 'נושא:',
    'language': 'שפת המייל: {lang}',
    'gauge.label': 'ציון סיכון  ·  {verdict}',
    'section.exposures': '🔑 מידע רגיש במייל ({n})',
    'section.findings': 'איומים שזוהו ({n})',
    'section.notes': 'הערות קלות ({n}) - לא מספיק כדי להיחשב חשוד',
    'section.recommendations': 'מה מומלץ לעשות',
    'section.actions': 'פעולות',
    'section.mitigations': 'סימנים מרגיעים',
    'section.links': 'לאן הקישורים באמת מובילים ({n})',
    'section.coverage': 'מה נבדק',
    'exposure.label': 'חשיפה · לא חלק מציון הסיכון',
    'link.ok': 'לא נמצאו בעיות',
    'link.shown_as': 'מוצג כ: {text}',
    'sender.unknown': 'שולח: לא ידוע',
    'sender.line': 'שולח: <b>{email}</b> - {status}',
    'sender.authenticated': '✔ כתובת אמיתית (מאומתת) - מה שלא אומר דבר על הכוונות',
    'sender.spoofed': '✖ נכשל באימות - כנראה מזויף',
    'sender.unverified': '? לא ניתן לאמת',
    'btn.report_safe': '📣 דווח כחשוד',
    'btn.trash': '🗑️ העבר לאשפה',
    'btn.block': '🚫 חסום שולח',
    'btn.report': '📣 דווח ל-SecOps',
    'btn.rescan': 'סרוק שוב',
    'btn.methodology': 'איך מחושב הציון',
    'btn.report_instead': '📣 דווח במקום',
    'btn.block_anyway': 'חסום בכל זאת',
    'btn.cancel': 'ביטול',
    'btn.undo': '↩️ בטל',
    'btn.retry': 'נסה שוב',
    'perf.cached': '⚡ תוצאה שמורה · זמן מנוע {engine} · "סרוק שוב" לבדיקה טרייה',
    'perf.fresh': '⚡ נותח תוך {total} (מנוע {engine})',
    'engine': 'מנוע {v}',
    'block.title': 'לחסום את השולח?',
    'block.body': 'מיילים עתידיים מ-<b>{sender}</b> ידלגו על תיבת הדואר ויעברו ישר לאשפה. אפשר לבטל את החסימה בכל רגע בהגדרות Gmail ← מסננים וכתובות חסומות.',
    'block.spoofed': '<b>הכתובת הזו נכשלה באימות - כמעט בוודאות היא מזויפת.</b>',
    'block.spoofed_more': 'חסימה תשלח לאשפה דואר עתידי מהבעלים <b>האמיתיים</b> של {sender}, והתוקף פשוט יזייף כתובת אחרת בפעם הבאה. עדיף לדווח.',
    'block.unverified': '<b>לא ניתן לאמת את הכתובת הזו.</b>',
    'block.unverified_more': 'ייתכן שהיא שייכת למישהו אחר ולא לשולח של המייל הזה.',
    'trashed.subtitle': '🗑️ הועבר לאשפה',
    'trashed.body': 'המייל נמצא באשפה וימחק אוטומטית אחרי 30 יום. אם הוא כוון אליכם, כדאי לדווח עליו כדי שצוות האבטחה יוכל להגן על אחרים.',
    'home.subtitle': 'בדיקת פישינג ונוזקות ל-Gmail',
    'home.intro': 'פתחו מייל כלשהו ו-MailGuard ייתן לו ציון בין 0 ל-100, יגיד מה בדיוק האיום, ימפה אותו ל-MITRE ATT&amp;CK, ויאפשר להעביר לאשפה, לחסום או לדווח בלחיצה אחת.',
    'home.checks_title': 'מה נבדק',
    'home.checks': [
      'אימות השולח (SPF, DKIM, DMARC)',
      'שולחים מתחזים, מזויפים ועם תג "מאומת" מזויף',
      'שורת הנושא: תשובות "RE:" מזויפות, תגיות בהלה, אותיות מוסוות',
      'לאן הקישורים באמת מובילים',
      'קבצים מצורפים מסוכנים (מאקרו, תוכנות מוסוות, תמונות מזויפות)',
      'שפה של לחץ, הונאת תשלום ודמי משלוח - בעברית, אנגלית, ערבית, רוסית, ספרדית, צרפתית וגרמנית',
      "תמונות ואימוג'י: מיילים שכולם תמונה, לוגו מועתק של מותג, אימוג'י של אזהרה",
      'ההיסטוריה שלכם עם השולח - כולל מיילים קודמים שסווגו כזדוניים, דיווחים וחסימות',
      'מודיעין איומים (VirusTotal, Google Safe Browsing, גיל הדומיין)',
      'מתקפות ענן וזהות: פישינג קוד מכשיר והרשאות OAuth, קונסולות ענן מזויפות',
      'טקסט נסתר והזרקת הוראות לעוזרי AI',
      'סודות חשופים (מפתחות ענן, טוקנים, מפתחות פרטיים)'
    ].join('<br>• '),
    'home.privacy_title': 'פרטיות',
    'home.privacy': 'המיילים מנותחים בזיכרון ולא נשמרים. רק כתובות, דומיינים וטביעות אצבע (hash) של קבצים נבדקים מול שירותי מודיעין - שום דבר לא מועלה אליהם. היסטוריית הסיווגים נשמרת בחשבון Google שלכם בלבד, והכתובות נשמרות רק כ-hash עם מלח.',
    'method.title': 'איך מחושב הציון',
    'method.body': [
      '<b>ראיות, לא קופסה שחורה.</b> כל סימן אזהרה מוסיף נקודות; סימנים מרגיעים מורידים מעט.',
      '<b>רוחב הראיות חשוב.</b> לכל קטגוריה יש תקרת נקודות, כך שהרבה מילים דחופות לבדן לא יהפכו מייל ל"זדוני" - צריך ראיות מכמה כיוונים.',
      '<b>יש ראיות חד-משמעיות.</b> תוכנה מוסווית, כמה מנועי אנטי-וירוס שמסכימים, או שולח שכבר דיווחתם עליו - קובעים ציון מינימלי בעצמם.',
      '<b>ספים:</b> 🟢 0-29 נראה בטוח · 🟠 30-64 חשוד · 🔴 65-100 כנראה זדוני.',
      '<b>רמת הוודאות</b> יורדת כשבדיקה לא רצה - בדיקה חסרה לעולם לא מוצגת כבדיקה נקייה.',
      '<b>זיכרון.</b> סיווגים, דיווחים וחסימות נשמרים (כ-hash עם מלח, בחשבון שלכם), כך ששולח ששלח לכם מייל זדוני בעבר יסומן בפעם הבאה.',
      '<b>חסימה</b> מומלצת רק כשהשולח מאומת: חסימת כתובת מזויפת פוגעת בבעלים האמיתיים שלה, לא בתוקף.'
    ].join('<br><br>'),
    'error.subtitle': 'לא ניתן לנתח את המייל',
    'error.config': 'התוסף לא מוגדר: {msg} הגדירו זאת ב-Project Settings ← Script properties.',
    'error.auth': 'שירות הניתוח דחה את הבקשה. כנראה שהסוד המשותף בתוסף ובשרת שונה.',
    'error.rate': 'יותר מדי סריקות בזמן קצר. המתינו דקה ונסו שוב.',
    'error.busy': 'שירות הניתוח עמוס. נסו שוב בעוד כמה שניות.',
    'error.untrusted': 'התשובה לא נחתמה בחתימה תקפה של שרת MailGuard ולכן נזרקה. ייתכן שמישהו מתערב בחיבור, או ש-BACKEND_URL מצביע לשרת שגוי.',
    'error.too_large': 'המייל גדול מדי לניתוח.',
    'error.invalid': 'שירות הניתוח לא הצליח לקרוא את המייל.',
    'error.server': 'הייתה בעיה בשירות הניתוח.',
    'error.network': 'אין כרגע גישה לשירות הניתוח.',
    'error.bad_response': 'שירות הניתוח החזיר תשובה לא צפויה.',
    'error.unexpected': 'שגיאה לא צפויה.',
    'error.forbidden': 'שירות הניתוח סירב לחיבור (HTTP 403). שירות ה-Cloud Run חייב לאפשר קריאות ללא אימות של Google - MailGuard מאמת כל בקשה בעצמו.',
    'error.not_found': 'כתובת שירות הניתוח שגויה (HTTP 404). בדקו את BACKEND_URL.',
    'error.details': 'פרטים טכניים (להרצת בדיקה מלאה: diagnose() בעורך הסקריפט):',
    'error.reading': 'שגיאה לא צפויה בקריאת המייל.',
    'error.not_safe': '<b>אין תוצאה זה לא תוצאה בטוחה.</b> היזהרו מקישורים, מקבצים מצורפים ומבקשות לכסף או לסיסמאות עד שאפשר יהיה לבדוק את המייל.',
    'n.disabled': 'הפעולות הושבתו על ידי המנהל.',
    'n.trash_fail': 'לא ניתן להעביר את המייל לאשפה. נסו שוב.',
    'n.trashed': '🗑️ הועבר לאשפה.',
    'n.untrash_fail': 'לא ניתן לשחזר את המייל.',
    'n.restored': '↩️ שוחזר מהאשפה.',
    'n.malformed_report': 'כתובת השולח פגומה ולכן אי אפשר לחסום אותה בבטחה. דווחו במקום.',
    'n.malformed': 'כתובת השולח פגומה ולכן אי אפשר לחסום אותה בבטחה.',
    'n.own': 'זו הכתובת שלכם - לא נחסמה.',
    'n.already': 'השולח הזה כבר חסום.',
    'n.block_fail': 'לא ניתן ליצור את מסנן החסימה. נסו שוב.',
    'n.blocked': '🚫 {sender} נחסם. מיילים עתידיים יעברו לאשפה (ביטול בהגדרות Gmail ← מסננים).',
    'n.reported': '📣 דווח ל-SecOps · מספר פנייה {ref}',
    'n.report_fail': 'לא ניתן לשלוח את הדיווח כרגע. נסו שוב.',
    'alerts.title': 'התראות ברקע',
    'alerts.on': '🔔 <b>פעיל.</b> דואר חדש נסרק כל כמה דקות. מייל שמקבל ציון {min} ומעלה מסומן בתווית "MailGuard/⚠ Malicious" ונשלחת אליכם התראה במייל - גם אם לא פתחתם אותו.',
    'alerts.off': '🔕 <b>כבוי.</b> מיילים נבדקים רק כשפותחים אותם. הפעילו התראות כדי לקבל אזהרה על מייל מסוכן שעוד לא פתחתם.',
    'alerts.btn_on': '🔔 הפעל התראות',
    'alerts.btn_off': '🔕 כבה התראות',
    'alerts.enabled': '🔔 התראות הרקע הופעלו.',
    'alerts.disabled': '🔕 התראות הרקע כובו.',
    'alerts.toggle_fail': 'לא ניתן לשנות את הגדרת ההתראות. נסו שוב.',
    'alert.intro': 'MailGuard מצא מייל מסוכן בתיבת הדואר שלכם.',
    'alert.from': 'מאת:',
    'alert.score': 'רמת סיכון:',
    'alert.why': 'למה:',
    'alert.done_label': 'המייל סומן בתווית "{label}" בתיבת הדואר.',
    'alert.done_quarantine': 'המייל הוצא מתיבת הדואר הנכנס וסומן בתווית "{label}". כדי להחזיר אותו - פתחו אותו ובחרו "העבר לתיבת הדואר הנכנס".',
    'alert.done_report': 'המייל דווח ל-SecOps (מספר פנייה {ref}).',
    'alert.open': 'פתחו את המייל ב-Gmail',
    'alert.footer': 'ההתראה הזו לא מכילה אף קישור מהמייל החשוד. פתחו אותו ב-Gmail כדי לראות את הניתוח המלא של MailGuard, ואז העבירו לאשפה, חסמו או דווחו.'
  }
};

var LANGUAGE_NAME_ = {
  en: { en: 'English', he: 'Hebrew', ar: 'Arabic', ru: 'Russian', es: 'Spanish', fr: 'French', de: 'German' },
  he: { en: 'אנגלית', he: 'עברית', ar: 'ערבית', ru: 'רוסית', es: 'ספרדית', fr: 'צרפתית', de: 'גרמנית' }
};

function languageName_(code) {
  return (LANGUAGE_NAME_[MG_LOCALE_] || LANGUAGE_NAME_.en)[code] || '';
}
