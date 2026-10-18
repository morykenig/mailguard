/**
 * Setup self-check. In the Apps Script editor choose "diagnose" in the function list and press
 * Run, then read the Execution log. It checks, in order, everything the side panel needs and
 * says exactly what to fix. Running it also (re)grants the add-on's permissions.
 * It never prints the shared secret.
 */
function diagnose() {
  var ok = true;
  var say = function (good, en, he) {
    ok = ok && good;
    console.log((good ? '✅ ' : '❌ ') + en + '\n   ' + he);
  };
  var props = PropertiesService.getScriptProperties();
  var url = String(props.getProperty('BACKEND_URL') || '');
  var secret = String(props.getProperty('HMAC_SECRET') || '').trim();

  // 1. Script properties
  var urlOk = /^https:\/\/[a-z0-9.-]+(:\d+)?$/i.test(url);
  say(urlOk, 'BACKEND_URL = "' + url + '"' + (urlOk ? '' : ' - must be https://host with no path and no trailing slash'),
    urlOk ? 'כתובת השרת מוגדרת' : 'כתובת השרת חסרה או שגויה: צריכה להיות https://... בלי / בסוף');
  say(secret.length >= 32, 'HMAC_SECRET length ' + secret.length + (secret.length >= 32 ? '' : ' - must be the 64-char value from Secret Manager'),
    secret.length >= 32 ? 'הסוד המשותף מוגדר' : 'הסוד המשותף חסר או קצר מדי - העתיקי אותו מ-gcloud secrets');
  if (!urlOk) {
    return finishDiagnose_(false);
  }

  // 2. Reachability (also proves urlFetchWhitelist and the external_request permission)
  var health;
  try {
    health = UrlFetchApp.fetch(url + '/healthz', {
      muteHttpExceptions: true, followRedirects: false, headers: { 'ngrok-skip-browser-warning': '1' }
    });
  } catch (err) {
    var why = explainFetchError_(err, url);
    say(false, 'Cannot reach ' + url + '/healthz: ' + why,
      /whitelist/.test(why)
        ? 'הכתובת לא מופיעה ב-urlFetchWhitelist בקובץ appsscript.json. כתבי שם בדיוק: "' + url + '/" (עם / בסוף)'
        : 'אין גישה לשרת. בדקי שהכתובת נכונה ושהשירות פרוס (פתחי את ' + url + '/healthz בדפדפן)');
    return finishDiagnose_(false);
  }
  var code = health.getResponseCode();
  say(code === 200, 'GET /healthz -> HTTP ' + code + ' ' + health.getContentText().slice(0, 80),
    code === 200 ? 'השרת זמין' : code === 403
      ? 'השרת חוסם (403): צריך לאפשר גישה ללא אימות - הריצי שוב את deploy_backend.sh או: gcloud run services add-iam-policy-binding mailguard --member=allUsers --role=roles/run.invoker'
      : 'השרת החזיר שגיאה - בדקי ב-Cloud Run ← Logs');
  if (code !== 200 || secret.length < 32) {
    return finishDiagnose_(false);
  }
  var info = {};
  try {
    info = JSON.parse(health.getContentText()) || {};
  } catch (err) {
    say(false, 'GET /healthz returned a web page, not MailGuard: ' + health.getContentText().slice(0, 60),
      'במקום השרת חזר דף אינטרנט - כנראה דף האזהרה של ngrok, או שהכתובת מצביעה למקום אחר. ודאי שהשרת רץ ושה-ngrok מפנה אליו');
    return finishDiagnose_(false);
  }
  if (info.signing === 'off') {
    say(false, 'The backend has no MG_HMAC_SECRET (development mode), so it cannot sign its answers',
      'בשרת לא מוגדר סוד משותף (מצב פיתוח), ולכן התשובות לא חתומות. בפריסה ל-Cloud Run הריצי שוב את deploy_backend.sh; ' +
      'בהרצה מקומית הגדירי MG_HMAC_SECRET בקובץ .env עם אותו ערך כמו HMAC_SECRET בתוסף');
    return finishDiagnose_(false);
  }
  if (!info.signing) {
    say(false, 'The backend is an older version (' + (info.version || '?') + ') without signed answers - redeploy it',
      'השרת הפרוס הוא גרסה ישנה שלא חותמת תשובות. פרסי מחדש: ./scripts/deploy_backend.sh מתוך החבילה החדשה');
    return finishDiagnose_(false);
  }

  // 3. A signed analysis of a tiny synthetic email (checks the secret and response signing)
  try {
    var r = callBackend_({
      client_version: 'diagnose', raw_headers: 'From: Test <test@example.com>\r\nSubject: MailGuard self-check',
      text_body: 'hello', html_body: '', attachments: [], sender_history: null, recipient_domain: '', locale: 'en'
    }, getConfig_());
    say(true, 'Signed analysis works: score ' + r.score + ' (' + r.verdict + '), engine ' + r.engine_version,
      'בקשה חתומה עובדת - הסוד תואם והתשובה חתומה כראוי');
  } catch (err) {
    var hints = {
      auth: 'הסוד בתוסף שונה מהסוד בשרת. העתיקי שוב: gcloud secrets versions access latest --secret mg-hmac-secret',
      untrusted: 'התשובה לא נחתמה בסוד הזה. ' + (err.detail || '') + ' - פרסי מחדש את השרת מהחבילה החדשה וודאי ש-HMAC_SECRET זהה לסוד בשרת',
      rate: 'יותר מדי בקשות - חכי דקה ונסי שוב',
      busy: 'השרת עמוס - נסי שוב בעוד כמה שניות'
    };
    say(false, 'Signed analysis failed: ' + (err.kind || err.name) + ' ' + (err.detail || ''),
      hints[err.kind] || 'הבקשה החתומה נכשלה - ראי ב-Cloud Run ← Logs');
  }

  // 4. Gmail API advanced service (sender history, actions, alerts)
  try {
    Gmail.Users.Labels.list('me');
    say(true, 'Gmail API advanced service is enabled', 'שירות Gmail API מופעל');
  } catch (err) {
    say(false, 'Gmail API advanced service: ' + String(err.message || err).slice(0, 100),
      'הפעילי את Gmail API: בעורך ← Services (+) ← Gmail API ← Add');
  }
  return finishDiagnose_(ok);
}

function finishDiagnose_(ok) {
  console.log(ok
    ? '\n🎉 Everything MailGuard needs is working. Refresh Gmail and open an email.\n   הכול תקין. רענני את Gmail ופתחי מייל.'
    : '\n🔧 Fix the first ❌ above and run diagnose() again.\n   תקני את ה-❌ הראשון ברשימה והריצי שוב.');
  return ok;
}
