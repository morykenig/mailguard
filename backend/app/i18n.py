"""User-interface language for findings, recommendations and the summary.

Detection is always multilingual (see app/analyzers/content.py); this module only decides the
language the *explanation* is written in. English is the source; Hebrew is a full translation.

In Hebrew each finding shows a translated title plus a translated explanation of the
technique, and its evidence - the exact link, phrase, file or domain - is shown as-is, so
the explanation stays specific to *this* email. Anything not translated falls back to English,
so a new rule can never break the UI.
"""

from __future__ import annotations

import re

SUPPORTED_UI = ("en", "he")


def ui_language(locale: str) -> str:
    """'he-IL' -> 'he'; 'iw' (Java's legacy code for Hebrew) -> 'he'; anything else -> 'en'."""
    code = (locale or "en").lower().replace("_", "-").split("-")[0]
    code = "he" if code == "iw" else code
    return code if code in SUPPORTED_UI else "en"


LANGUAGE_NAMES_HE = {
    "en": "אנגלית",
    "he": "עברית",
    "ar": "ערבית",
    "ru": "רוסית",
    "es": "ספרדית",
    "fr": "צרפתית",
    "de": "גרמנית",
}

_LANG_BY_ENGLISH_NAME = {
    "English": "אנגלית",
    "Hebrew": "עברית",
    "Arabic": "ערבית",
    "Russian": "רוסית",
    "Spanish": "ספרדית",
    "French": "צרפתית",
    "German": "גרמנית",
}

# finding id (or "PREFIX*") -> (title, explanation). Titles may use {params} from Finding.params.
FINDINGS_HE: dict[str, tuple[str, str]] = {
    # --- Sender authentication
    "AUTH_FORGED_HEADER": (
        "כותרת אימות מזויפת בתוך ההודעה",
        "ההודעה כוללת כותרת שמתחזה לתוצאת אימות של Gmail. שולחים לגיטימיים לא עושים את זה - זה ניסיון לעבוד על מסננים. המערכת התעלמה ממנה.",
    ),
    "AUTH_DMARC_FAIL": (
        "דומיין השולח נכשל בבדיקת DMARC",
        "ההודעה טוענת שהיא מגיעה מהדומיין הזה, אבל נכשלה בבדיקת ההגנה מפני זיוף שבעל הדומיין הגדיר. זה הסימן הקלאסי לשולח מזויף.",
    ),
    "AUTH_SPF_FAIL": (
        "נשלח משרת שהדומיין לא מאשר",
        "בדיקת SPF נכשלה: השרת ששלח את ההודעה לא ברשימת השרתים המורשים לשלוח בשם הדומיין.",
    ),
    "AUTH_SPF_SOFTFAIL": ("SPF: כישלון רך", "כנראה שהשרת ששלח את ההודעה לא מורשה לשלוח בשם הדומיין."),
    "AUTH_DKIM_FAIL": ("החתימה הדיגיטלית שבורה", "חתימת ה-DKIM לא מאומתת: ההודעה שונתה בדרך או שהחתימה זויפה."),
    "AUTH_DKIM_NONE": (
        "ההודעה לא חתומה דיגיטלית",
        "רוב הארגונים הלגיטימיים חותמים על הדואר שלהם ב-DKIM; להודעה הזו אין חתימה.",
    ),
    "AUTH_DKIM_UNALIGNED": ("חתום על ידי דומיין אחר", "ההודעה חתומה על ידי דומיין שאינו הדומיין שמופיע בכתובת השולח."),
    "AUTH_MISSING": (
        "לא ניתן לאמת את השולח",
        "Gmail לא רשם תוצאות SPF/DKIM/DMARC להודעה, ולכן אי אפשר לוודא שהדומיין באמת שלח אותה.",
    ),
    "AUTH_DMARC_PASS": (
        "דומיין השולח מאומת",
        "DMARC עבר בהצלחה - ההודעה באמת הגיעה מהדומיין הזה. שימו לב: זה מוכיח מי שלח, לא שאפשר לסמוך עליו. תוקפים מאמתים גם דומיינים מתחזים שרשמו.",
    ),
    # --- Sender identity
    "SENDER_INVALID": (
        "כתובת השולח חסרה או פגומה",
        "לא ניתן לפענח את כתובת השולח - מערכות דואר לגיטימיות לא מייצרות דבר כזה.",
    ),
    "SENDER_LOOKALIKE": (
        "דומיין השולח מתחזה ל-{target}",
        "הדומיין נבנה כך שייראה כמו דומיין מוכר (אותיות דומות, שגיאת כתיב או שם המותג בתוך דומיין אחר). דומיינים כאלה נרשמים במיוחד כדי להטעות.",
    ),
    "SENDER_IDN": (
        "דומיין השולח כתוב בתווים בינלאומיים",
        "הדומיין כתוב באותיות שאינן לטיניות, שיטה שמשמשת לחיקוי דומיינים מוכרים.",
    ),
    "SENDER_NAME_HAS_EMAIL": (
        "שם התצוגה מציג כתובת אחרת",
        "בשם התצוגה מופיעה כתובת מייל שונה מהכתובת שממנה ההודעה נשלחה באמת - טריק זיוף נפוץ.",
    ),
    "SENDER_BRAND_IMPERSONATION": (
        "השם טוען להיות {brand}",
        "שם התצוגה מציג מותג מוכר, אבל הדומיין ששלח את ההודעה לא שייך למותג.",
    ),
    "SENDER_FREEMAIL_ROLE": (
        "שם רשמי על חשבון דואר חינמי",
        'השם נשמע כמו מנהל או מחלקה בארגון, אבל ההודעה נשלחה מחשבון פרטי שכל אחד יכול לפתוח - אופייני להונאת מנכ"ל (BEC).',
    ),
    "SENDER_HIDDEN_CHARS": ("תווים נסתרים בשם השולח", "שם התצוגה מכיל תווים בלתי נראים או תווים שהופכים כיוון טקסט."),
    "SENDER_REPLYTO_MISMATCH": (
        "תשובות יישלחו לכתובת אחרת",
        "אם תלחצו 'השב', התשובה תגיע לכתובת אחרת מזו של השולח. תוקפים עושים זאת כדי לקבל תשובות בזמן שהם מתחזים לשולח אמין.",
    ),
    "SENDER_RETURN_PATH_MISMATCH": (
        "כתובת החזרה בדומיין אחר",
        "השולח הטכני שונה מהשולח הנראה. נפוץ גם בפלטפורמות דיוור לגיטימיות, ולכן זה סימן חלש.",
    ),
    "SENDER_FAKE_BADGE": (
        "תג 'מאומת' מזויף בשם השולח",
        "בשם השולח יש וי, מגן או המילה 'מאומת'. אין במייל תגי אימות בתוך השם - כל אחד יכול להקליד אותם - והם שם רק כדי לשדר אמינות.",
    ),
    # --- History
    "HISTORY_SPOOFED_CONTACT": (
        "מתחזה למישהו שאתם מכירים",
        "אתם מכירים את הכתובת, אבל ההודעה נכשלה באימות השולח - כנראה שהיא לא נשלחה על ידו. התחזות לאיש קשר מוכר היא שיטת הונאה קלאסית.",
    ),
    "HISTORY_FIRST_CONTACT": (
        "הודעה ראשונה מהשולח הזה",
        "מעולם לא קיבלתם מייל מהכתובת הזו ולא כתבתם אליה. רוב הפישינג מגיע משולחים שאין לכם היסטוריה איתם.",
    ),
    "HISTORY_KNOWN_CORRESPONDENT": (
        "כבר כתבתם לשולח הזה",
        "הכתובת מופיעה בדואר היוצא שלכם וההודעה מאומתת. עדיין כדאי להיזהר מבקשות חריגות - גם חשבונות אמיתיים נפרצים.",
    ),
    "HISTORY_REGULAR_SENDER": ("שולח קבוע", "קיבלתם בעבר כמה הודעות מהכתובת הזו."),
    "HISTORY_REPORTED_BEFORE": (
        "כבר דיווחתם על השולח הזה או חסמתם אותו",
        "בעבר דיווחתם על הכתובת הזו או חסמתם אותה. שיקול הדעת שלכם לגבי שולח הוא הראיה החזקה ביותר.",
    ),
    "HISTORY_PREVIOUSLY_MALICIOUS": (
        "מיילים קודמים מהשולח היו זדוניים",
        "MailGuard סיווג מיילים קודמים מהכתובת הזו כזדוניים. תוקפים שולחים לעיתים כמה גלים מאותה כתובת.",
    ),
    "HISTORY_PREVIOUSLY_SUSPICIOUS": (
        "מיילים קודמים מהשולח היו חשודים",
        "MailGuard סיווג כמה מיילים קודמים מהכתובת הזו כחשודים.",
    ),
    "HISTORY_GMAIL_SPAM": (
        "Gmail כבר העביר מיילים מהשולח לספאם",
        "יש בתיקיית הספאם שלכם מיילים קודמים מהכתובת הזו - המסננים של Gmail כבר שפטו את השולח.",
    ),
    "HISTORY_DOMAIN_MALICIOUS": (
        "כבר הגיע דואר זדוני מהדומיין הזה",
        "כתובות אחרות באותו דומיין שלחו לכם בעבר מיילים ש-MailGuard סיווג כזדוניים.",
    ),
    # --- Subject
    "SUBJECT_FAKE_REPLY": (
        "מתחזה לתשובה אליכם",
        "הנושא נראה כמו תשובה (RE:), אבל אין בהודעה את הכותרות שיש לתשובה אמיתית. תשובה מזויפת גורמת לפנייה ראשונה להיראות כמו שיחה מוכרת.",
    ),
    "SUBJECT_ALARM": (
        "שורת נושא מבהילה",
        "הנושא נכתב כדי להלחיץ (תגיות כמו [דחוף], סימני קריאה, אותיות גדולות) - כדי שתפעלו לפני שתקראו בעיון.",
    ),
    "SUBJECT_OBFUSCATED": (
        "אותיות מוסוות בנושא",
        "בנושא יש מילים שמערבבות אותיות מאלפביתים שונים (למשל א' קירילית שנראית כמו a לטינית) - כך הן נראות רגיל לכם אבל לא למסנני ספאם.",
    ),
    "SUBJECT_HIDDEN_CHARS": (
        "תווים בלתי נראים בנושא",
        "הנושא מכיל תווים ברוחב אפס או תווים שהופכים כיוון, כדי לפצל מילים ולעקוף מסננים.",
    ),
    # --- Links
    "LINK_TEXT_MISMATCH": (
        "טקסט הקישור מסתיר את היעד האמיתי",
        "הקישור מציג כתובת אחת אבל פותח כתובת אחרת - שיטת הפישינג הנפוצה ביותר.",
    ),
    "LINK_LOOKALIKE": ("קישור לדומיין מתחזה", "הקישור מוביל לדומיין שנבנה כדי להיראות כמו דומיין מוכר."),
    "LINK_BRAND_IN_SUBDOMAIN": (
        "שם מותג מוסתר בכתובת אחרת",
        "הכתובת מתחילה בשם מותג מוכר (למשל paypal.com.something.xyz), אבל בפועל שייכת לאתר אחר.",
    ),
    "LINK_SCRIPT_SCHEME": (
        "קישור שמריץ קוד במקום לפתוח דף",
        "הקישור משתמש בכתובת מסוג javascript: או data:, שיכולה להריץ קוד או להציג דף מזויף.",
    ),
    "LINK_USERINFO": (
        "הכתובת מסתירה את האתר האמיתי אחרי '@'",
        "דפדפן מתעלם מכל מה שלפני ה-'@' בכתובת; זה משמש כדי שהקישור ייראה כאילו הוא מוביל למקום אחר.",
    ),
    "LINK_IP_ADDRESS": (
        "קישור לכתובת IP",
        "ארגונים לגיטימיים מקשרים לאתרים עם שם, לא לכתובות IP - לפעמים גם כתובות IP מוסוות כמספר אחד.",
    ),
    "LINK_DOWNLOAD": ("קישור שמוריד קובץ מסוכן", "הקישור מוביל ישירות לקובץ הרצה, סקריפט או ארכיון."),
    "LINK_IDN": ("קישור עם תווים בינלאומיים", "הדומיין בקישור כתוב באותיות שיכולות לחקות אותיות מוכרות."),
    "LINK_HIDDEN_CHARS": ("תווים נסתרים בקישור", "הקישור מכיל תווים בלתי נראים או תווים שהופכים כיוון."),
    "LINK_FREE_HOSTING": (
        "קישור לאחסון חינמי או לטופס",
        "שירותי אחסון וטפסים חינמיים לגיטימיים, אבל משמשים הרבה לאחסון דפי פישינג כי יש להם מוניטין טוב.",
    ),
    "LINK_SHORTENER": ("קישור מקוצר מסתיר את היעד", "שירות קיצור כתובות מסתיר לאן הקישור מוביל באמת."),
    "LINK_REDIRECT": ("הקישור מפנה דרך כתובת אחרת", "הקישור מכיל בתוכו כתובת אחרת ומעביר אליה."),
    "LINK_HTTP_LOGIN": ("קישור לא מוצפן לדף התחברות", "קישור http:// רגיל מוביל למה שנראה כמו דף התחברות או אימות."),
    "LINK_SUSPICIOUS_TLD": (
        "סיומת דומיין שמשמשת הרבה לרעה",
        "יש סיומות דומיין זולות שמשמשות באופן לא פרופורציונלי לאתרים זדוניים.",
    ),
    "LINK_EMBEDDED_FORM": (
        "המייל מכיל טופס שאוסף מידע",
        "בגוף המייל יש טופס להזנת פרטים. מיילים לגיטימיים מפנים לאתר; טפסים בתוך מייל משמשים לגניבת סיסמאות ופרטי אשראי.",
    ),
    "LINK_BAIT_SWITCH": (
        "קישור 'מתוקן' מחליף קישור אמין",
        "המייל מציג קודם קישור לאתר מוכר, ואז 'מתקן' את עצמו ('אופס, הנה הקישור הנכון') ומפנה לאתר אחר. הקישור המוכר נועד לשדר אמינות, והקישור ה'מתוקן' הוא הפיתיון.",
    ),
    "LINK_META_REFRESH": ("קוד הפניה אוטומטית בהודעה", "ה-HTML מכיל הוראת meta-refresh שמפנה אוטומטית לכתובת אחרת."),
    # --- Attachments
    "ATT_DISGUISED_EXE": (
        "הקובץ המצורף הוא תוכנה מוסווית",
        "הקובץ מתחזה למסמך או תמונה, אבל התוכן שלו הוא קובץ הרצה של Windows.",
    ),
    "ATT_RTLO": (
        "שם הקובץ מסתיר את הסוג האמיתי שלו",
        "שם הקובץ מכיל תווים בלתי נראים שהופכים כיוון, כך שהסיומת שאתם רואים אינה הסיומת האמיתית.",
    ),
    "ATT_EXECUTABLE": ("הקובץ המצורף הוא קובץ הרצה", "קובץ מהסוג הזה מריץ קוד במחשב ברגע שפותחים אותו."),
    "ATT_HTML": (
        "דף אינטרנט שנשלח כקובץ מצורף",
        "קובץ HTML או SVG נפתח כדף בדפדפן - דרך נפוצה להציג דף התחברות מזויף ולעקוף סורקי קישורים.",
    ),
    "ATT_MACRO": (
        "המסמך מכיל מאקרו",
        "המסמך מכיל קוד VBA שרץ כשפותחים אותו ולוחצים 'הפעל תוכן' - אחת הדרכים הנפוצות להפצת נוזקות.",
    ),
    "ATT_MACRO_EXT": ("מסמך Office עם מאקרו", "סוג הקובץ מאפשר מאקרו."),
    "ATT_REMOTE_TEMPLATE": (
        "המסמך טוען תוכן מהאינטרנט",
        "המסמך מפנה לתבנית או לאובייקט חיצוניים - שיטה למשוך קוד זדוני אחרי שהמסמך כבר עבר סריקה.",
    ),
    "ATT_ENCRYPTED_ARCHIVE": (
        "ארכיון מוגן בסיסמה",
        "הקובץ מוצפן, כך שאף סורק אבטחה לא יכול לבדוק מה יש בו. תוקפים שולחים את הסיסמה בגוף המייל בדיוק בשביל זה.",
    ),
    "ATT_ARCHIVE_RISKY": (
        "הארכיון מכיל קבצי הרצה או דפי אינטרנט",
        "בתוך הקובץ הדחוס יש קבצים שמריצים קוד או נפתחים כדף.",
    ),
    "ATT_ARCHIVE": ("צורף קובץ דחוס", "ארכיונים משמשים להברחת נוזקות מעבר למסננים."),
    "ATT_PDF_ACTIVE": (
        "קובץ PDF עם תוכן פעיל",
        "ה-PDF מכיל הוראות שמריצות קוד או מפעילות תוכנות. חשבוניות ומסמכים רגילים לא צריכים את זה.",
    ),
    "ATT_FAKE_IMAGE": (
        "קובץ מצורף מתחזה לתמונה",
        "לקובץ יש סיומת של תמונה, אבל התוכן שלו הוא דף אינטרנט, ארכיון או משהו אחר.",
    ),
    # --- Content
    "CONTENT_ACCOUNT_THREAT": ("מאיים לנעול או לסגור את החשבון", "פחד מאובדן גישה גורם לאנשים לפעול לפני שהם חושבים."),
    "CONTENT_CREDENTIALS": (
        "מבקש סיסמאות או קודים",
        "שירותים לגיטימיים לעולם לא מבקשים לשלוח סיסמה או קוד חד-פעמי במייל.",
    ),
    "CONTENT_PAYMENT": (
        "בקשה להעברת כסף או לתשלום",
        'בקשות לשלם, לשנות פרטי בנק או לקנות כרטיסי מתנה הן הלב של הונאות חשבוניות והונאות מנכ"ל.',
    ),
    "CONTENT_DELIVERY_FEE": (
        "פיתיון של חבילה או דמי מכס",
        "'החבילה שלך ממתינה - יש לשלם דמי משלוח או מכס קטנים' הוא מהפיתיונות הנפוצים ביותר, במיוחד בישראל (התחזות לדואר ישראל, DHL ולמכס).",
    ),
    "CONTENT_URGENCY": ("יוצר דחיפות מלאכותית", "דדליין צפוף נועד למנוע מכם לבדוק פעמיים."),
    "CONTENT_SECRECY": (
        "מבקש סודיות או טובה מהירה",
        "'תשמור את זה בינינו' ו'אתה זמין?' הם משפטי פתיחה מוכרים של הונאת מנכ\"ל.",
    ),
    "CONTENT_PHISHING_ANATOMY": (
        "יש במייל את כל המרכיבים של פישינג",
        "המייל מאיים על החשבון, דורש לאמת או למסור פרטים, קובע מועד אחרון ונותן קישור לעשות את זה. כל אחד מהמרכיבים נפוץ לבד, אבל ארבעתם יחד הם המבנה הקלאסי של פישינג לגניבת פרטי התחברות.",
    ),
    "CONTENT_BEC_PATTERN": (
        'יש במייל את כל המרכיבים של הונאת מנכ"ל / תשלום',
        "המייל מבקש תשלום או העברה, לוחץ לפעול מהר, ומונע אימות ('אני בפגישה, לא יכול לדבר', 'תשמור את זה בינינו'). זה התסריט של הונאת BEC: תמיד אמתו בטלפון, במספר שאתם כבר מכירים.",
    ),
    "LINK_CREDENTIAL_WORDS": (
        "כתובת הקישור עמוסה במילים של חשבון והתחברות",
        "הקישור מוביל לכתובת שבנויה ממילים כמו login, security ו-update כדי להיראות רשמית. שירותים אמיתיים מחברים אתכם בדומיין המוכר שלהם.",
    ),
    "CONTENT_CLICK_PRESSURE": (
        "לוחץ עליכם ללחוץ על קישור",
        "מיילים שדוחקים 'פשוט ללחוץ' - בלי להסביר לאן הקישור מוביל - הם פיתיון טיפוסי.",
    ),
    "CONTENT_REWARD": (
        "מבטיח פרס או החזר כספי",
        "זכיות והחזרים לא צפויים הם פיתיון שנועד לגרום לכם ללחוץ או לשלם 'עמלה'.",
    ),
    "CONTENT_OBFUSCATED_TEXT": (
        "אותיות מאלפביתים שונים בתוך מילים",
        "יש מילים שמערבבות אותיות לטיניות עם אותיות קיריליות/יווניות דומות או אותיות ברוחב מלא. אנשים לא מקלידים כך - זה נועד לעקוף מסננים.",
    ),
    "CONTENT_AI_DIRECTED": ("טקסט שפונה לעוזרי AI", "המייל מכיל הוראות שמיועדות לכלי AI. דואר לגיטימי נכתב לבני אדם."),
    # --- Images & emojis
    "IMG_ONLY_BODY": (
        "ההודעה היא בעיקר תמונה",
        "כשהטקסט נמצא בתוך תמונה, מסנני ספאם ובדיקות מילות מפתח לא רואים אותו. לרוב כל התמונה היא קישור אחד.",
    ),
    "IMG_BRAND_LOGO": (
        "מציג את הלוגו של {brand} אבל לא נשלח מ-{brand}",
        "המייל נפתח בלוגו של מותג מוכר, אבל נשלח מדומיין שלא שייך למותג. לוגו אמיתי קל להעתיק, ולכן הוא לא מוכיח דבר על השולח.",
    ),
    "IMG_RISKY_SOURCE": (
        "תמונות נטענות מכתובת חשודה",
        "התמונות נטענות מכתובת IP או מדומיין מתחזה. טעינת התמונה גם מאותתת לשולח שפתחתם את המייל.",
    ),
    "IMG_ACTIVE_CONTENT": (
        "תוכן פעיל מוטמע במייל",
        "המייל מכיל סקריפטים או אובייקטים מוטמעים. Gmail מסיר אותם, אבל אף אחד לא שם אותם במייל בטעות.",
    ),
    "EMOJI_LURE": (
        "אימוג'י של אזהרה או כסף",
        "אימוג'י של אזהרה, מנעול, כסף או חבילה הם דרך זולה למשוך תשומת לב ולהוסיף לחץ.",
    ),
    # --- Threat intelligence
    "INTEL_SAFE_BROWSING": (
        "Google Safe Browsing מסמן קישור כמסוכן",
        "Google סימן קישור במייל הזה כמסוכן (פישינג או נוזקה).",
    ),
    "INTEL_VT_URL_MALICIOUS": (
        "קישור זדוני מוכר (VirusTotal)",
        "כמה מנועי אבטחה ב-VirusTotal מסמנים את הקישור הזה כזדוני.",
    ),
    "INTEL_VT_URL_SUSPICIOUS": (
        "חלק מהמנועים מסמנים את הקישור (VirusTotal)",
        "חלק ממנועי האבטחה ב-VirusTotal מסמנים את הקישור כזדוני או חשוד.",
    ),
    "INTEL_VT_FILE_MALICIOUS": (
        "קובץ מצורף זדוני מוכר (VirusTotal)",
        "כמה מנועי אבטחה ב-VirusTotal מזהים את הקובץ המצורף כזדוני.",
    ),
    "INTEL_VT_FILE_SUSPICIOUS": (
        "חלק מהמנועים מסמנים את הקובץ (VirusTotal)",
        "חלק ממנועי האבטחה ב-VirusTotal מסמנים את הקובץ כזדוני או חשוד.",
    ),
    "INTEL_NEW_SENDER_DOMAIN": (
        "דומיין השולח נרשם ממש לאחרונה",
        "דומיינים של פישינג משמשים בדרך כלל ימים ספורים אחרי הרישום, לפני שרשימות החסימה מספיקות להתעדכן.",
    ),
    "INTEL_NEW_LINK_DOMAIN": ("קישור לדומיין חדש לגמרי", "הקישור מוביל לדומיין שנרשם לפני זמן קצר - אופייני לפישינג."),
    # --- Cloud & identity
    "CLOUD_DEVICE_CODE": (
        "פישינג קוד מכשיר: מבקש לאשר התחברות",
        "דפי התחברות עם קוד מיועדים לקוד שמופיע אצלכם בטלוויזיה, בטרמינל או באפליקציה. הזנת קוד שמישהו שלח לכם במייל מחברת אותו: הוא מקבל גישה לחשבון בלי סיסמה, ו-MFA לא עוצר את זה.",
    ),
    "CLOUD_OAUTH_CONSENT": (
        "מבקש לתת לאפליקציה גישה לחשבון {provider}",
        "הקישור פותח את מסך ההרשאות האמיתי של הספק עבור אפליקציה שמבקשת גישה למייל או לקבצים. אישור נותן לה גישה שנשארת גם אחרי החלפת סיסמה - ובודקי קישורים לא רואים בעיה, כי הדף אמיתי.",
    ),
    "CLOUD_CONSOLE_LURE": (
        "התחברות מזויפת ל-{label}",
        "המייל עוסק בחשבון הענן שלכם, אבל קישור ההתחברות מוביל לאתר שאינו דף ההתחברות של הספק. קונסולות ענן מחזיקות את המפתחות לסביבת הייצור, ולכן הפרטים האלה שווים במיוחד לתוקפים.",
    ),
    # --- Hidden content & AI
    "HIDDEN_PROMPT_INJECTION": (
        "הוראות נסתרות שמיועדות לעוזרי AI",
        "המייל מסתיר מכם טקסט שמנסה לתת הוראות לכלי AI - למשל לומר שהמייל בטוח. MailGuard לא משתמש ב-AI בהחלטה, ולכן אי אפשר 'לשכנע' אותו לבטל את האזהרה.",
    ),
    "HIDDEN_TEXT_SALTING": (
        "הרבה טקסט נסתר",
        "חלק גדול מהטקסט במייל מוסתר מכם. מילוי נסתר כזה משמש כדי לבלבל מסנני ספאם ומסווגי AI.",
    ),
    # --- Exposure
    "EXPOSURE_*": (
        "{kind} במייל הזה",
        "המייל מכיל מה שנראה כמו מפתח או טוקן פעילים. כל מי שיכול לקרוא את התיבה הזו - או את התיבה של השולח - יכול להשתמש בו. בטלו והחליפו אותו עכשיו, ושתפו סודות דרך מנהל סודות ולא במייל.",
    ),
}

# Exact English recommendation -> Hebrew.
RECOMMENDATIONS_HE: dict[str, str] = {
    "Don't click the links. If you need the site, type its address yourself or use a bookmark.": "אל תלחצו על הקישורים. אם אתם צריכים את האתר, הקלידו את הכתובת בעצמכם או השתמשו בסימנייה.",
    'Don\'t download or open the attachments, and never click "Enable content".': "אל תורידו ואל תפתחו את הקבצים המצורפים, ולעולם אל תלחצו 'הפעל תוכן'.",
    "Verify any payment or bank-detail change by phone, using a number you already know - not one from this email.": "אמתו כל בקשת תשלום או שינוי פרטי בנק בטלפון, במספר שאתם כבר מכירים - לא במספר מהמייל.",
    "Never enter your password or codes from a link in an email.": "לעולם אל תזינו סיסמה או קוד דרך קישור שהגיע במייל.",
    "Report it to SecOps, then move it to Trash (buttons below).": "דווחו ל-SecOps ואז העבירו לאשפה (הכפתורים למטה).",
    "Block the sender: the address is authenticated, so blocking only stops this sender.": "חסמו את השולח: הכתובת מאומתת, ולכן החסימה תעצור רק אותו.",
    "Don't block this address - it is forged, so blocking it would filter mail from the real owner, not the attacker. Reporting is the right action.": "אל תחסמו את הכתובת - היא מזויפת, וחסימה תסנן דואר מבעליה האמיתיים ולא מהתוקף. הפעולה הנכונה היא דיווח.",
    "Think twice before blocking: the sender address could not be verified, so it may belong to someone else. Reporting is always safe.": "חשבו פעמיים לפני חסימה: לא ניתן לאמת את כתובת השולח, והיא עשויה להיות של מישהו אחר. דיווח תמיד בטוח.",
    "If you already clicked or entered details, change your password and tell your IT/security team.": "אם כבר לחצתם או הזנתם פרטים - החליפו סיסמה ועדכנו את צוות ה-IT/אבטחה.",
    "If you are unsure, contact the sender through a channel you already trust, or report it.": "אם אתם לא בטוחים, פנו לשולח בערוץ שאתם כבר סומכים עליו, או דווחו.",
    "No other action needed. If anything in the message surprises you, verify it with the sender.": "אין צורך בפעולה נוספת. אם משהו בהודעה מפתיע אתכם, אמתו מול השולח.",
    "Never enter a sign-in code that arrived by email. If you already did, sign out of all sessions and tell your security team - the attacker may hold a valid token.": "לעולם אל תזינו קוד התחברות שהגיע במייל. אם כבר הזנתם - התנתקו מכל ההתחברויות ועדכנו את צוות האבטחה, ייתכן שלתוקף יש גישה פעילה.",
    "Don't approve the app. If you already did, remove it from your account's third-party app access page and report it.": "אל תאשרו את האפליקציה. אם כבר אישרתם - הסירו אותה מדף הגישה של אפליקציות צד שלישי בחשבון ודווחו.",
    "Don't rely on an AI summary of this email - it contains hidden instructions written for AI tools.": "אל תסמכו על סיכום AI של המייל הזה - הוא מכיל הוראות נסתרות שנכתבו לכלי AI.",
}
_EXPOSURE_REC = re.compile(r"^🔑 Revoke and rotate the exposed (.+?) now")

SUMMARY_LEADS_HE = {
    "malicious": "נראה כמו מייל פישינג או נוזקה.",
    "suspicious": "התייחסו למייל הזה בזהירות.",
    "safe": "כנראה תקין, עם הערות קלות.",
}
NO_FINDINGS_HE = "לא נמצאו סימני אזהרה בהודעה."

COVERAGE_KEYS_HE = {
    "Sender authentication": "אימות שולח",
    "Sender identity": "זהות השולח",
    "Subject line": "שורת הנושא",
    "Links": "קישורים",
    "Attachments": "קבצים מצורפים",
    "Message content": "תוכן ההודעה",
    "Social engineering pattern": "דפוס הנדסה חברתית",
    "Sender history": "היסטוריה עם השולח",
    "Cloud & identity attacks": "מתקפות ענן וזהות",
    "Hidden content & AI manipulation": "תוכן נסתר ומניפולציה על AI",
    "Images & emojis": "תמונות ואימוג'י",
    "Language": "שפה",
    "Message parsing": "פענוח ההודעה",
    "Google Safe Browsing": "Google Safe Browsing",
    "VirusTotal": "VirusTotal",
    "Domain age (RDAP)": "גיל הדומיין (RDAP)",
}
_COVERAGE_VALUES_HE: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(p), r)
    for p, r in (
        (r"^checked$", "נבדק"),
        (r"^not provided$", "לא סופק"),
        (r"^not configured$", "לא מוגדר"),
        (r"^disabled$", "כבוי"),
        (r"^timed out$", "חרג מזמן"),
        (r"^rate-limited$", "הגבלת קצב"),
        (r"^unavailable$", "לא זמין"),
        (r"^error$", "שגיאה"),
        (r"^no links to check$", "אין קישורים לבדיקה"),
        (r"^nothing to check$", "אין מה לבדוק"),
        (r"^only well-known domains$", "רק דומיינים מוכרים"),
        (r"^checked (\d+) link\(s\)$", r"נבדקו \1 קישורים"),
        (r"^checked (\d+) of (\d+) indicator\(s\)(.*)$", r"נבדקו \1 מתוך \2 אינדיקטורים\3"),
        (r"^checked (\d+) of (\d+) domain\(s\)$", r"נבדקו \1 מתוך \2 דומיינים"),
        (r"^partial \(very large or malformed HTML\)$", "חלקי (HTML גדול מאוד או פגום)"),
    )
)


def _template(text: str, params: dict[str, str]) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: params.get(m.group(1), m.group(0)), text)


def finding_text(finding_id: str, params: dict[str, str], ui: str) -> tuple[str, str] | None:
    """(title, explanation) in the UI language, or None to keep the English original."""
    if ui != "he":
        return None
    entry = FINDINGS_HE.get(finding_id)
    if entry is None:
        entry = next((v for k, v in FINDINGS_HE.items() if k.endswith("*") and finding_id.startswith(k[:-1])), None)
    if entry is None:
        return None
    return _template(entry[0], params), _template(entry[1], params)


def recommendation(text: str, ui: str) -> str:
    if ui != "he":
        return text
    if text in RECOMMENDATIONS_HE:
        return RECOMMENDATIONS_HE[text]
    m = _EXPOSURE_REC.match(text)
    if m:
        return (
            f"🔑 בטלו והחליפו עכשיו את ה-{m.group(1)} שנחשפו - הניחו שכל מי שיש לו גישה למייל יכול להשתמש בהם - "
            "ובקשו מהשולח לשתף סודות דרך מנהל סודות."
        )
    return text


def coverage_entry(key: str, value: str, ui: str) -> tuple[str, str]:
    if ui != "he":
        return key, value
    for rx, repl in _COVERAGE_VALUES_HE:
        if rx.match(value):
            value = rx.sub(repl, value)
            break
    value = value.replace(" (rate-limited, rest skipped)", " (הגבלת קצב, השאר דולג)")
    if key == "Language":
        value = _LANG_BY_ENGLISH_NAME.get(value, "לא זוהתה")
    return COVERAGE_KEYS_HE.get(key, key), value


LINK_FLAGS_HE = {
    "text ≠ destination": "הטקסט ≠ היעד",
    "look-alike domain": "דומיין מתחזה",
    "brand in subdomain": "מותג בתת-דומיין",
    "runs code": "מריץ קוד",
    "'@' trick": "טריק '@'",
    "raw IP address": "כתובת IP",
    "file download": "הורדת קובץ",
    "international characters": "תווים בינלאומיים",
    "hidden characters": "תווים נסתרים",
    "free hosting": "אחסון חינמי",
    "shortener": "קיצור כתובת",
    "redirect": "הפניה",
    "unencrypted login": "התחברות לא מוצפנת",
    "risky domain ending": "סיומת מסוכנת",
    "device-code sign-in": "התחברות עם קוד מכשיר",
    "app consent request": "בקשת הרשאה לאפליקציה",
    "fake cloud sign-in": "התחברות ענן מזויפת",
}


def link_flag(label: str, ui: str) -> str:
    return LINK_FLAGS_HE.get(label, label) if ui == "he" else label


def summary(lead_key: str, titles: list[str], ui: str) -> str | None:
    """Hebrew summary, or None for English (scoring.summarize writes the English one)."""
    if ui != "he":
        return None
    if not titles:
        return NO_FINDINGS_HE
    return f"{SUMMARY_LEADS_HE[lead_key]} סיבות עיקריות: {'; '.join(t.rstrip('.') for t in titles)}."
