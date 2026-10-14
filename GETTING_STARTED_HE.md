# MailGuard - רשימת צעדים מההתחלה

רשימה מסודרת מהרגע שהחבילה אצלך ועד הגשה. כל שלב מסתיים בבדיקה קצרה, כדי שתדעי שהוא עבד לפני שממשיכים.
זמן משוער: 2-3 שעות, רובן התקנות וחשבונות.

---

## שלב 0 - מה צריך להכין (פעם אחת)

- [ ] **Python 3.12+** - בדיקה: `python3 --version`
- [ ] **Node.js 20+** (בשביל בדיקת התוסף) - בדיקה: `node --version`
- [ ] **Git** וחשבון **GitHub**
- [ ] **חשבון Google Cloud** עם חיוב פעיל (Cloud Run נכנס בדרך כלל במכסה החינמית, אבל צריך כרטיס אשראי)
- [ ] **gcloud CLI** - התקנה: https://cloud.google.com/sdk/docs/install, ואז `gcloud auth login`
- [ ] (מומלץ) **מפתח VirusTotal** - נרשמים בחינם ב-virustotal.com ← Profile ← API Key
- [ ] (מומלץ) **מפתח Google Safe Browsing** - ב-Google Cloud Console: APIs & Services ← Enable "Safe Browsing API" ← Credentials ← Create API key

> המערכת עובדת גם בלי שני המפתחות (רק עם החוקים המקומיים). הם מוסיפים מודיעין איומים אמיתי.

---

## שלב 1 - לפתוח את החבילה ולוודא שהכול עובד מקומית (15 דקות)

```bash
unzip mailguard.zip && cd mailguard
cd backend
python3 -m venv .venv && source .venv/bin/activate      # ב-Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cd ..
make test lint            # צריך להסתיים ב-"passed" ובלי שגיאות ruff
make score                # ציונים לכל 15 המיילים לדוגמה
LOCALE=he make score      # אותו דבר, עם הסברים בעברית
make addon-test           # בדיקת התוסף (כרטיסים, כפתורים, עברית, זיכרון סיווגים)
```

- [ ] `make test` - כל הבדיקות עוברות (5 מסומנות `xfail` - אלה פערים מתועדים, זה תקין)
- [ ] `make score` - הציונים תואמים לטבלה בראש README.md
- [ ] `make addon-test` - כל השורות מתחילות ב-`ok`

**אם `make` לא קיים (Windows):** הריצי את הפקודות מתוך ה-Makefile ידנית, או השתמשי ב-WSL.

---

## שלב 2 - להעלות ל-GitHub (10 דקות)

```bash
git init && git add . && git commit -m "MailGuard"
# צרי repository חדש ב-GitHub (private או public), ואז:
git remote add origin https://github.com/<user>/mailguard.git
git branch -M main && git push -u origin main
```

- [ ] בדקי שאין סודות בקוד: הקובץ `.env` **לא** נכנס ל-git (הוא ב-.gitignore). רק `.env.example` עם ערכים ריקים.
- [ ] בלשונית **Actions** ב-GitHub - ה-CI רץ ועובר (בדיקות, lint, CodeQL, gitleaks).

---

## שלב 3 - לפרוס את השרת ל-Cloud Run (20 דקות)

```bash
gcloud projects create mailguard-<משהו-ייחודי>      # או פרויקט קיים
gcloud billing projects link mailguard-<...> --billing-account <ID>   # או דרך ה-Console

export PROJECT_ID=mailguard-<...>
export MG_VIRUSTOTAL_API_KEY=<המפתח שלך>         # אופציונלי
export MG_SAFE_BROWSING_API_KEY=<המפתח שלך>      # אופציונלי
export MG_PROTECTED_DOMAINS=<הדומיין של הארגון>  # אופציונלי, למשל upwind.io
./scripts/deploy_backend.sh
```

הסקריפט מדפיס בסוף את כתובת השירות (`https://mailguard-xxxx.me-west1.run.app`).

- [ ] שמרי את הכתובת
- [ ] בדיקה: `curl https://<הכתובת>/healthz` מחזיר `{"status":"ok","version":"1.4.0","signing":"on"}`
- [ ] קבלי את הסוד המשותף (תצטרכי אותו בשלב 4):
  ```bash
  gcloud secrets versions access latest --secret mg-hmac-secret
  ```
  **אל תשמרי אותו בקובץ בפרויקט ואל תשלחי אותו במייל.**

---

## שלב 3ב (חלופה ל-Cloud Run) - שרת מקומי דרך ngrok

אפשר להריץ את השרת על המחשב ולחשוף אותו עם ngrok, במקום לפרוס אותו. זה נוח לפיתוח, אבל המחשב צריך להישאר דלוק.

1. [ ] צרי סוד ארוך: `python3 -c "import secrets; print(secrets.token_hex(32))"`
2. [ ] העתיקי את `backend/.env.example` ל-`backend/.env`, והגדירי בו:
   ```
   MG_ENV=dev
   MG_HMAC_SECRET=<הסוד מסעיף 1>
   ```
   **חובה להגדיר את הסוד.** בלעדיו השרת לא חותם על התשובות, והתוסף זורק אותן ("התשובה לא נחתמה...").
3. [ ] הריצי את השרת: `make run`. הוא מאזין בפורט 8080 וטוען את `.env` אוטומטית.
4. [ ] בחלון טרמינל נוסף: `ngrok http 8080 --url=<הדומיין הקבוע שלך>.ngrok-free.dev`
5. [ ] בתוסף:
   - `BACKEND_URL` = `https://<הדומיין>.ngrok-free.dev`, **בלי** `/` בסוף
   - `HMAC_SECRET` = אותו סוד מסעיף 1
   - ב-`appsscript.json` ← `urlFetchWhitelist`: `"https://<הדומיין>.ngrok-free.dev/"`, **עם** `/` בסוף
6. [ ] הריצי `diagnose`. התוסף שולח כותרת שמדלגת על דף האזהרה של ngrok. אם עדיין חוזר דף HTML, ה-diagnose יגיד את זה.

> בכל פעם שמשנים את `.env` צריך לעצור את `make run` (Ctrl+C) ולהריץ אותו שוב.
> להגשה עדיף Cloud Run: הוא זמין תמיד, גם כשהמחשב כבוי.

---

## שלב 4 - להתקין את התוסף ב-Gmail (20 דקות)

### הדרך הפשוטה (מומלצת): קובץ אחד
בתיקייה `addon_bundle/` יש **קובץ אחד**, `MailGuard.gs`, שמכיל את כל קוד התוסף. כך אי אפשר לשכוח קובץ, להשאיר גרסה ישנה, או להדביק חצי קובץ.
1. [ ] script.google.com ← **New project** ← קראי לו MailGuard
2. [ ] בקובץ `Code.gs` שנפתח: סמני הכול (Ctrl+A), מחקי, הדביקי את **כל** התוכן של `addon_bundle/MailGuard.gs`, ושמרי (Ctrl+S). אם מופיעה שגיאת Syntax error, ההדבקה לא הייתה מלאה. נסי שוב.
3. [ ] ⚙️ Project Settings ← סמני **Show "appsscript.json"**. חזרי לעורך ‹›, פתחי את `appsscript.json`, החליפי את כל התוכן ב-`addon_bundle/appsscript.json`, ותקני בו את הכתובת ב-`urlFetchWhitelist`
4. [ ] ⚙️ Project Settings ← Script properties ← `BACKEND_URL` ו-`HMAC_SECRET`
5. [ ] בעורך: ברשימה הנפתחת שליד **▶ Run** בחרי `diagnose` ← Run ← אשרי הרשאות ← קראי את ה-Execution log
6. [ ] Deploy ← Test deployments ← Install, ואז רענני את Gmail

(הדרך המפורטת, עם קבצים נפרדים, מופיעה מיד בהמשך. אין צורך לעשות את שתיהן.)


1. [ ] היכנסי ל-https://script.google.com ← **New project** ← קראי לו MailGuard
2. [ ] ⚙️ Project Settings ← סמני **Show "appsscript.json" manifest file**
3. [ ] העתיקי את **כל** הקבצים מתיקיית `addon/`: `Code.gs`, `Api.gs`, `Cards.gs`, `Actions.gs`, `Config.gs`, `Extract.gs`, `History.gs`, `Strings.gs`, `Alerts.gs`, `Diagnose.gs`, `Util.gs` ואת `appsscript.json`
   (בכל קובץ: ➕ ← Script ← אותו שם בלי `.gs` ← הדבקה). את התיקייה `test/` לא מעתיקים.
   - חלופה: `npm i -g @google/clasp`, `clasp login`, ואז בתיקייה `addon/`: `cp .clasp.json.example .clasp.json` (עם ה-Script ID) ו-`clasp push`
4. [ ] ב-`appsscript.json`: החליפי את `REPLACE-WITH-YOUR-CLOUD-RUN-HOST` בכתובת השרת שלך (רק ה-host, עם `/` בסוף)
5. [ ] Project Settings ← **Script properties** ← הוסיפי:
   - `BACKEND_URL` = כתובת השרת, **בלי** `/` בסוף
   - `HMAC_SECRET` = הסוד משלב 3
6. [ ] **Deploy ← Test deployments ← Google Workspace Add-on ← Install**
7. [ ] רענני את Gmail, פתחי מייל כלשהו ← אייקון MailGuard בסרגל הימני ← אשרי הרשאות

- [ ] בדיקה: מייל רגיל (למשל מ-GitHub או מהבנק) מקבל ציון ירוק
- [ ] **עברית:** ב-Gmail ⚙️ ← See all settings ← Language ← עברית ← שמירה. פתחי מייל - הכרטיס וכל ההסברים בעברית. (אפשר לחזור לאנגלית אחר כך לצורך הדמו.)

**אם מופיעה שגיאה בכרטיס** - היא אומרת מה לא תקין (סוד שגוי, כתובת שגויה, השרת לא זמין). ב-Apps Script ← Executions רואים לוגים (בלי תוכן מיילים).

---

## שלב 4.5 - להפעיל התראות ברקע (5 דקות)

1. [ ] ב-Gmail פתחי את MailGuard **בלי** לבחור מייל (מסך הבית של התוסף)
2. [ ] לחצי **🔔 הפעל התראות** ואשרי את ההרשאות הנוספות (יצירת טריגר ושליחת מייל לעצמך)
3. [ ] (אופציונלי) ב-Script properties:
   - `ALERT_MIN_SCORE` - מאיזה ציון להתריע (ברירת מחדל 70)
   - `ALERT_QUARANTINE=true` - גם להוציא את המייל מתיבת הדואר הנכנס (הפיך)
   - `ALERT_AUTO_REPORT=true` - גם לדווח אוטומטית ל-SecOps
   - `ALERT_INTERVAL_MIN` - כל כמה דקות לסרוק: 5/10/15/30 (ברירת מחדל 10)
4. [ ] בדיקה: ב-Apps Script ← Triggers (⏰) מופיע הטריגר `scanNewMailForAlerts`. ב-Executions רואים שורה כמו `background scan: checked=3 alerted=0`

> אם Google מגביל את הטריגר של התוסף, הוא עובר אוטומטית לסריקה פעם בשעה. לדמו אפשר להריץ ידנית את `scanNewMailForAlerts` מתוך העורך (בחירת הפונקציה ← Run).

---

## שלב 5 - מיילים לדמו (10 דקות)

1. [ ] צרי פרויקט Apps Script **נפרד** (לא בתוך התוסף), הדביקי את `scripts/send_demo_emails.gs`
2. [ ] הריצי `sendDemoEmails` ואשרי הרשאה. יישלחו 7 מיילים **רק לתיבה שלך**: קוד מכשיר, הוראות נסתרות ל-AI, קישור מוסווה, קונסולת AWS מזויפת, מפתח AWS חשוף, מכס בעברית, ו-RE: מזויף עם אימוג'י
3. [ ] פתחי כל אחד וודאי שהציון והסיבות הגיוניים
4. [ ] **התראות:** אחרי שליחת מיילי הדמו, הריצי `scanNewMailForAlerts` מהעורך (או חכי לסריקה הבאה). המיילים המסוכנים יקבלו תווית אדומה `MailGuard/⚠ Malicious` ותגיע אלייך התראה במייל עם הסבר. ההתראות עצמן לא נסרקות.
5. [ ] **זיכרון:** פתחי מייל זדוני ← "דווח ל-SecOps". שימי לב: מייל שנשלח מהכתובת שלך לא נשמר בזיכרון (היא לא נחשבת "שולח"). כדי להדגים זיכרון, שלחי מחשבון Gmail שני מייל זדוני, דווחי עליו, ושלחי ממנו מייל נוסף - הוא יסומן "כבר דיווחתם על השולח הזה".

---

## שלב 6 - צילומי מסך והשלמת README (20 דקות)

- [ ] צלמי 4-5 מסכים: מייל זדוני (באנר אדום + מד), מייל בטוח (ירוק), כרטיס בעברית, כרטיס חסימה, ומייל התראה + התווית האדומה בתיבה
- [ ] (מומלץ) GIF קצר של פתיחת מייל וקבלת ציון - למשל עם ScreenToGif או Kap
- [ ] שמרי בתיקייה `docs/` ועדכני את השורה `<!-- Add a screenshot ... -->` בראש README.md
- [ ] בדקי שהטבלה בראש README תואמת את מה ש-`make score` מדפיס
- [ ] `git add . && git commit -m "Screenshots" && git push`

---

## שלב 7 - הגשה

- [ ] קישור ל-GitHub (אם ה-repo פרטי - הוסיפי את המראיינים כ-collaborators)
- [ ] סרטון דמו קצר (2-3 דקות) - מומלץ מאוד: מייל זדוני ← למה ← פעולה; מייל בעברית; מייל עם הוראות נסתרות ל-AI
- [ ] משפט אחד בגוף המייל: מה בנית ומה מייחד אותו (ראו "המסר המרכזי" למטה)
- [ ] אחרי ההגשה: **אל תמחקי את שירות ה-Cloud Run** עד אחרי הראיון - ייתכן שירצו לנסות

---

## שלב 8 - הכנה לראיון

**המסר המרכזי (30 שניות):**
> "MailGuard נותן לכל מייל ציון 0-100 שאפשר להסביר עד הנקודה האחרונה. הוא מתמקד במתקפות שעובדות היום על חברות ענן - פישינג קוד מכשיר ו-OAuth שעוקפים MFA, קונסולות ענן מזויפות, והזרקת הוראות נסתרות לעוזרי AI - ממפה כל ממצא ל-MITRE ATT&CK, מבין 7 שפות כולל עברית, זוכר שולחים שכבר היו זדוניים, מתריע ברקע גם על מיילים שלא נפתחו, ותקפתי אותו בעצמי כדי למצוא ולתקן עקיפות."

**שאלות שכדאי להתכונן אליהן** (התשובות ב-README, בסעיפים בסוגריים):

| שאלה | תשובה בקצרה |
|---|---|
| למה לא AI/LLM? | הסבריות, זמן תגובה, פרטיות, ובעיקר - מודל שפה אפשר להזריק לו הוראות. אצלנו אי אפשר "לשכנע" את המנוע (§2, §4) |
| איך נקבעו המשקלים? | ידנית, עם תקרות לכל קטגוריה ורצפות לראיות חד-משמעיות. בהמשך - כיול על קורפוס מתויג עם רגרסיה לוגיסטית (§5, §9) |
| DMARC עבר - למה עדיין זדוני? | אימות מוכיח *מי* שלח, לא שאפשר לסמוך עליו. תוקפים רושמים דומיינים מתחזים עם אימות מלא (דוגמה 01) |
| מה עם פרטיות? | השרת לא שומר כלום, לא מקבל גישה לתיבה, רק אינדיקטורים יוצאים למודיעין. הזיכרון נשמר כ-hash עם מלח בחשבון של המשתמש (§6) |
| איך מונעים הרעלה של הזיכרון? | זוכרים סיווג ודיווח רק כשהשולח מאומת - אחרת אפשר היה לזייף מייל "מהבוס" ולפגוע בשמו (§6) |
| מה החולשות? | פרק 8 ופרק 10 - פערים ידועים מתועדים כבדיקות `xfail`. להגיד אותם בעצמך זה יתרון |
| מה היית מוסיפה? | פרק 9 - כיול, זהות OIDC, סגירת מעגל ל-SOC, ארגז חול לקישורים, OCR לתמונות |
| איך ההתראה עצמה לא הופכת לפישינג? | אין בה אף קישור מהמייל המקורי, כל הטקסט מנוטרל (escaped), היא נשלחת רק לכתובת שלך ולא נסרקת שוב |
| למה לא מומלץ לחסום כתובת מזויפת? | החסימה פוגעת בבעלים האמיתיים של הכתובת, והתוקף פשוט יזייף כתובת אחרת |

**לפני הראיון:** תרגלי את הדמו פעמיים, ודאי שהשירות למעלה (`/healthz`), והכיני מייל אחד "חי" לשלוח מול המראיינים.

---

## פתרון תקלות נפוצות

**הצעד הראשון בכל תקלה:** בעורך Apps Script בחרי את הפונקציה `diagnose` (ברשימה שליד Run) ← Run, ואשרי הרשאות אם מתבקש. ב-Execution log יופיעו ✅/❌ לכל שלב, עם הסבר בעברית מה לתקן: הגדרות, `urlFetchWhitelist`, גישה לשרת, סוד משותף ו-Gmail API. כרטיס השגיאה בתוסף מציג עכשיו גם "פרטים טכניים".


| בעיה | פתרון |
|---|---|
| "The add-on is not configured" | חסר `BACKEND_URL` או `HMAC_SECRET` ב-Script properties, או שיש `/` בסוף הכתובת |
| "rejected the request" | הסוד בתוסף שונה מהסוד בשרת. העתיקי שוב משלב 3 |
| "אין כרגע גישה לשירות הניתוח" / "unreachable" | הריצי `diagnose` בעורך (ראו למעלה). הסיבה הנפוצה: ב-`appsscript.json` נשאר `REPLACE-WITH-YOUR-CLOUD-RUN-HOST`, או שהכתובת שם לא זהה ל-`BACKEND_URL` (צריך `/` בסוף בקובץ ובלי `/` ב-property). סיבות נוספות: הרשאות לא אושרו מחדש אחרי עדכון, או שהשירות לא פרוס |
| "התשובה לא נחתמה בחתימה תקפה" / "did not carry a valid signature" | התוסף מגיע לשרת, אבל התשובה לא חתומה בסוד שלו. ברוב המקרים השרת הפרוס הוא גרסה ישנה, או שהוא רץ במצב פיתוח בלי `MG_HMAC_SECRET`. פרסי מחדש עם `./scripts/deploy_backend.sh` מהחבילה החדשה, ובדקי ש-`/healthz` מחזיר `"version":"1.4.0","signing":"on"`. אם זה עדיין קורה, הסוד ב-`HMAC_SECRET` שונה מהסוד בשרת. `diagnose` אומר בדיוק איזה מהמקרים |
| הכרטיס באנגלית למרות ש-Gmail בעברית | רענני את Gmail; ודאי ש-`script.locale` ב-`oauthScopes` וש-`useLocaleFromApp: true` ב-manifest; אחרי שינוי הרשאות - הסירי והתקיני מחדש את ה-test deployment |
| לא מגיעות התראות | ודאי שהטריגר קיים (Triggers ⏰), שהמייל עבר את `ALERT_MIN_SCORE`, ושב-Executions אין שגיאה. המייל נסרק פעם אחת בלבד |
| אין היסטוריית שולח / זיכרון | ודאי ש-Gmail API מופעל: ב-Apps Script ← Services ← Gmail API (מופיע כבר ב-manifest) |
| הפריסה נכשלת | ודאי שחיוב מופעל בפרויקט ושיש לך הרשאת Owner/Editor |
