"""Social-engineering language in the subject and body - in seven languages.

Wording is a weak signal on its own - real banks also say "verify your account" - so this
category is capped low in scoring and mainly strengthens other evidence. Patterns exist for
English, Hebrew, Arabic, Russian, Spanish, French and German, and every language is always
checked: mixed-language lures ("Dear customer, החשבון שלך ננעל") are common.

Corporate footers say "this message is confidential" in every language, so secrecy patterns
target the *request* ("don't tell anyone", "keep it between us"), never the bare word.

Hebrew and Arabic attach prefixes to words (ו, ה, ש, ב / و, ال), so their patterns avoid
leading word boundaries; Latin-script patterns use them where a short word could appear
inside a longer one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..context import EmailContext
from ..domains import brand_for_domain
from ..language import LANG_NAMES, obfuscated_words
from ..redact import strip_format
from ..textutil import clean
from .base import Category, Finding

C = Category.CONTENT


@dataclass(frozen=True)
class Rule:
    title: str
    detail: str
    points: int
    patterns: dict[str, tuple[str, ...]]  # language code -> regexes


_HE_LOCKED = "(יושעה|הושעה|נחסם|ייחסם|ננעל|יינעל|הוגבל|יוגבל|יבוטל|בוטל|הוקפא|יוקפא)"

RULES: dict[str, Rule] = {
    "CONTENT_ACCOUNT_THREAT": Rule(
        "Threatens to lock or close your account",
        "Fear of losing access pushes people to act before thinking.",
        12,
        {
            "en": (
                r"account (has been|will be|was|is) (suspended|locked|closed|disabled|limited|restricted|deactivated)",
                r"unusual (sign-?in|login|activity)",
                r"suspicious activity",
                r"(verify|confirm|validate) your (account|identity)",
            ),
            "he": (
                rf"(החשבון|המנוי|הכרטיס) (שלך |שלכם )?{_HE_LOCKED}",
                rf"(חשבונך|חשבונכם|כרטיסך) {_HE_LOCKED}",
                r"(ניסיון|ניסיונות|נסיון) (התחברות|כניסה) (חריג|חשוד|לא מורשה|לא מזוהה)",
                r"(השהינו|הקפאנו|חסמנו|נעלנו|הגבלנו) את (הגישה|החשבון|חשבונך|הכרטיס)",
                r"(ייסגר|ייחסם|יימחק|יבוטל|יינעל) לצמיתות|מחיקת (החשבון|חשבונך)",
                r"פעילות (חריגה|חשודה)",
                r"(אמת|אשר|אמתו|אשרו) את (החשבון|זהותך|פרטיך|הפרטים)",
            ),
            "ar": (
                r"(تم|سيتم) (تعليق|إيقاف|حظر|قفل|تقييد) حساب",
                r"نشاط (غير عادي|مشبوه)",
                r"(تحقق|تأكيد|أكد) (من )?(حسابك|هويتك)",
            ),
            "ru": (
                r"(аккаунт|учетная запись|учётная запись) (будет )?(заблокирован|приостановлен|ограничен)",
                r"подозрительн\w* (активность|вход)",
                r"подтвердите (свой |свою )?(аккаунт|учетную запись|учётную запись|личность)",
            ),
            "es": (
                r"(su|tu) cuenta (ha sido|será|fue|está) (suspendida|bloqueada|cerrada|desactivada|limitada)",
                r"actividad (inusual|sospechosa)",
                r"verifi(que|ca) (su|tu) (cuenta|identidad)",
            ),
            "fr": (
                r"votre compte (a été|sera|est) (suspendu|bloqué|fermé|désactivé|limité|restreint)",
                r"activité (inhabituelle|suspecte)",
                r"(vérifiez|confirmez) votre (compte|identité)",
            ),
            "de": (
                r"ihr konto (wurde|wird|ist) (gesperrt|deaktiviert|eingeschränkt|geschlossen)",
                r"(ungewöhnliche|verdächtige) (aktivität|anmeldung)",
                r"(bestätigen|verifizieren) sie ihr(e)? (konto|identität)",
            ),
        },
    ),
    "CONTENT_CREDENTIALS": Rule(
        "Asks for passwords or codes",
        "Legitimate services never ask you to send a password or one-time code by email.",
        12,
        {
            "en": (
                r"(enter|confirm|update|provide|send) (your )?(password|passcode|credentials|login details)",
                r"(verify|confirm|update|validate) your (details|information|account details)[^.\n]{0,40}\blink\b",
                r"one[- ]time (code|password)|\botp\b|verification code|2fa code",
            ),
            "he": (
                r"(הזן|הזיני|הזינו|להזין|עדכן|עדכני|עדכנו|לעדכן|שלח|שלחי|שלחו|לשלוח|אשר|אשרו|לאשר) (את )?"
                r"(הסיסמה|הסיסמא|סיסמתך|פרטי הכניסה|פרטי ההתחברות|הקוד|פרטי האשראי)",
                r"קוד (אימות|חד[- ]פעמי|הזדהות)|קוד ש?קיבלת ב-?(SMS|סמס|הודעה)",
                r"(לאמת|אמת|אמתו|לעדכן|עדכנו|עדכן) את (פרטיך|פרטייך|פרטיכם|הפרטים שלך|פרטי החשבון)[^.\n]{0,40}קישור",
            ),
            "ar": (r"(أدخل|حدّث|حدث|أرسل) كلمة (المرور|السر)", r"رمز (التحقق|التأكيد)|كلمة مرور لمرة واحدة"),
            "ru": (r"(введите|обновите|отправьте|подтвердите) (ваш |свой )?пароль", r"код (подтверждения|проверки)"),
            "es": (r"(ingrese|introduzca|actualice|envíe|confirme) (su |tu )?contraseña", r"código de verificación"),
            "fr": (r"(saisissez|entrez|mettez à jour|envoyez|confirmez) votre mot de passe", r"code de vérification"),
            "de": (
                r"(geben sie|aktualisieren sie|bestätigen sie) ihr (passwort|kennwort)",
                r"(bestätigungs|verifizierungs)code",
            ),
        },
    ),
    "CONTENT_PAYMENT": Rule(
        "Money transfer or payment request",
        "Requests to pay, change bank details or buy gift cards are the core of invoice and CEO fraud.",
        12,
        {
            "en": (
                r"wire transfer",
                r"bank (details|account)( information)? (has|have)? ?(changed|updated)",
                r"new (bank )?account (details|number)",
                r"\biban\b",
                r"gift ?cards?",
                r"(bitcoin|crypto) wallet",
                r"(payment|invoice) (is )?(overdue|outstanding|pending|failed|declined)",
                r"update (your )?(payment|billing)",
            ),
            "he": (
                r"העברה בנקאית|העברת כספים",
                r"פרטי (חשבון )?הבנק (השתנו|עודכנו)",
                r"כרטיס(י)? מתנה|גיפט ?קארד",
                r"חשבונית (פתוחה|לתשלום)",
                r"התשלום (נכשל|נדחה)",
                r"עדכ(ן|ני|נו) (את )?(אמצעי|פרטי) (ה)?תשלום",
                r"ארנק (ביטקוין|קריפטו)",
            ),
            "ar": (
                r"تحويل (بنكي|مصرفي)",
                r"بطاقات? (هدايا|الهدايا)",
                r"(تفاصيل|بيانات) (الحساب )?البنك(ي|ية)? (تغيرت|الجديدة)",
            ),
            "ru": (
                r"банковск\w* перевод",
                r"подарочн\w* карт",
                r"новые (банковские )?реквизиты",
                r"оплат\w* (не прошла|просрочен)",
            ),
            "es": (
                r"transferencia bancaria",
                r"tarjetas? de regalo",
                r"(nuevos )?datos bancarios",
                r"pago (pendiente|rechazado|vencido)",
            ),
            "fr": (
                r"virement( bancaire)?",
                r"cartes? cadeaux?",
                r"(nouvelles )?coordonnées bancaires",
                r"paiement (en attente|refusé|échoué)",
            ),
            "de": (
                r"überweisung",
                r"geschenkkarten?|gutscheinkarten?",
                r"(neue )?bankverbindung",
                r"zahlung (fehlgeschlagen|überfällig|abgelehnt)",
            ),
        },
    ),
    "CONTENT_DELIVERY_FEE": Rule(
        "Package or customs-fee lure",
        "'Your parcel is waiting - pay a small customs or delivery fee' is one of the most common lures, "
        "especially in Israel (Israel Post, DHL and customs impersonation).",
        12,
        {
            "en": (
                r"(customs|delivery|shipping|redelivery) (fee|charge|duty)",
                r"(your )?(package|parcel|shipment) (is (on hold|waiting|pending)|could not be delivered|was returned)",
            ),
            "he": (
                r"(ה)?(חבילה|משלוח) (שלך )?(ממתינ|מעוכב|לא נמסר|הוחזר|בהמתנה)\w*",
                r"(תשלום|דמי) (מכס|משלוח|אחסנה|שחרור)",
            ),
            "ar": (r"رسوم (الجمارك|التوصيل|الشحن)", r"(طردك|شحنتك) (في الانتظار|معلق|لم يتم تسليم)"),
            "ru": (
                r"(таможенн\w*|доставк\w*) (пошлин\w*|сбор\w*|плат\w*)",
                r"(ваша )?посылка (ожидает|задержана|не доставлена)",
            ),
            "es": (
                r"(tasa|tarifa|gastos) de (aduana|envío|entrega)",
                r"(su|tu) (paquete|envío) (está retenido|no pudo ser entregado)",
            ),
            "fr": (
                r"frais (de douane|de livraison|d'expédition)",
                r"votre (colis|paquet) (est en attente|n'a pas pu être livré)",
            ),
            "de": (
                r"(zoll|liefer|versand)gebühr",
                r"ihr paket (wartet|konnte nicht zugestellt werden|wird zurückgehalten)",
            ),
        },
    ),
    "CONTENT_URGENCY": Rule(
        "Creates artificial urgency",
        "Tight deadlines are used to stop you from double-checking.",
        8,
        {
            "en": (
                r"\burgent(ly)?\b",
                r"immediately",
                r"within (24|48|12) hours",
                r"\bact now\b",
                r"final (notice|warning|reminder)",
                r"expires? (today|soon|in \d+)",
                r"as soon as possible|\basap\b",
                r"last chance",
            ),
            "he": (
                r"דחו(ף|פה|פים)",
                r"באופן מיידי|\bמיד\b",
                r"(תוך|בתוך|ב-?)\s?(24|48|12) שעות",
                r"עד סוף היום|בעוד \d{1,2} (שעות|דקות)",
                r"בדחיפות|אל (תעכב|תעכבי|תדחה)|לפני סוף (היום|יום העסקים)|זה קריטי",
                r"הודעה אחרונה|התראה אחרונה",
                r"בהקדם האפשרי",
            ),
            "ar": (r"عاجل", r"فور(ا|اً)", r"خلال (24|48|12) ساعة", r"(إشعار|تحذير) نهائي"),
            "ru": (r"срочно", r"немедленно", r"в течение (24|48|12) час", r"последнее (предупреждение|уведомление)"),
            "es": (r"\burgente\b", r"inmediatamente", r"en (las próximas )?(24|48|12) horas", r"último aviso"),
            "fr": (r"\burgent\b", r"immédiatement", r"(dans les|sous) (24|48|12) ?h(eures)?", r"dernier (avis|rappel)"),
            "de": (r"dringend", r"sofort", r"innerhalb von (24|48|12) stunden", r"letzte (mahnung|warnung)"),
        },
    ),
    "CONTENT_SECRECY": Rule(
        "Asks for secrecy or a quick favour",
        "'Keep this between us' and 'are you available?' are hallmark openers of CEO fraud.",
        10,
        {
            "en": (
                r"keep (this|it) (confidential|between us|private)",
                r"don'?t (tell|mention|discuss)",
                r"are you (available|at your desk)",
                r"i need (a|you to do a) (quick )?(favou?r|task)",
                r"(i'?m|i am) (in a meeting|on a flight|travell?ing)[^.\n]{0,40}"
                r"(can'?t|cannot|unable to) (talk|call|take calls)",
                r"(can'?t|cannot) (talk|take calls) (right )?now|(don'?t|do not) call me",
            ),
            "he": (
                r"(תשמור|שמרי|שמור|תשמרי) (את זה )?בינינו",
                r"\b(אתה|את) זמי(ן|נה)\b",
                r"(צריך|צריכה) ממך (טובה|משהו קטן)",
                r"אל ת(ספר|ספרי|גיד|גידי)",
                r"(בדיסקרטיות|בסודיות)",
                r"(אני )?(כרגע )?ב(פגישה|ישיבה|טיסה)( חשובה)?[^.\n]{0,30}(לא|אין לי) (יכול|יכולה|אפשרות|זמן) לדבר",
                r"(אין לי אפשרות|לא יכול|לא יכולה) לדבר (בטלפון|כרגע)|אל (תתקשר|תתקשרי|תצלצל)",
            ),
            "ar": (r"(هل أنت|هل انت) متاح", r"لا تخبر أحد|بيني وبينك", r"أحتاج (منك )?خدمة"),
            "ru": (
                r"вы (на месте|свободны)\?",
                r"никому не (говорите|сообщайте)|пусть это останется между нами",
                r"нужна (ваша )?помощь срочно",
            ),
            "es": (
                r"¿?(estás|está usted) disponible",
                r"no se lo (digas|diga) a nadie|mantenlo entre nosotros",
                r"necesito un favor",
            ),
            "fr": (
                r"êtes-vous disponible|es-tu disponible",
                r"n'en parlez à personne|gardez (ça|cela) entre nous",
                r"j'ai besoin d'un service",
            ),
            "de": (
                r"sind sie (gerade )?(verfügbar|erreichbar)",
                r"sagen sie (es )?niemandem|bleibt unter uns",
                r"ich brauche (einen )?gefallen",
            ),
        },
    ),
    "CONTENT_CLICK_PRESSURE": Rule(
        "Pushes you to click",
        "Messages that urge you to 'just click' - instead of telling you what the link is - are typical lures.",
        8,
        {
            "en": (
                r"\b(?:please |just )?click (?:this|here|on this|the link|below|now)\b[^.\n]{0,20}!",
                r"\bplease click (?:this|on this)\b",
            ),
            "he": (r"(?:לחצו|לחץ|לחצי) (?:כאן|על הקישור|עכשיו)[^.\n]{0,20}!",),
            "es": (r"haz clic aquí[^.\n]{0,20}!",),
        },
    ),
    "CONTENT_REWARD": Rule(
        "Promises a prize or refund",
        "Unexpected winnings and refunds are bait to get you to click or pay a 'fee'.",
        12,
        {
            "en": (
                r"\byou(?:'ve| have)? (?:just |already )?won\b",
                r"\bwon (?:some |a |the |free )?(?:cash|money|prize|gift ?card|iphone|voucher)",
                r"\bfree (?:cash|money)\b|\b(?:cash|money) prize\b",
                r"claim your (prize|reward|refund|gift)",
                r"\blottery\b",
                r"you are (the )?(lucky )?winner",
                r"refund (of|is) (pending|available)",
            ),
            "he": (r"\bזכית(ם|ן)?\b", r"(קבל|ממש|לממש) את (הפרס|ההטבה|ההחזר)", r"החזר כספי", r"הגרלה"),
            "ar": (r"(لقد )?(ربحت|فزت)", r"(استلم|اطلب) (جائزتك|المبلغ المسترد)", r"استرداد (أموال|المبلغ)"),
            "ru": (r"вы выиграли", r"получите (свой )?(приз|выигрыш|возврат)", r"возврат средств"),
            "es": (r"(has|ha) ganado", r"reclam(a|e) (tu|su) (premio|reembolso)", r"\blotería\b"),
            "fr": (r"vous avez gagné", r"réclamez votre (prix|remboursement|cadeau)", r"\bloterie\b"),
            "de": (r"sie haben gewonnen", r"fordern sie ihr(en)? (preis|gewinn|erstattung)", r"\blotterie\b"),
        },
    ),
}
_COMPILED = {
    rule_id: [(lang, re.compile(p, re.IGNORECASE)) for lang, pats in rule.patterns.items() for p in pats]
    for rule_id, rule in RULES.items()
}


def analyze(ctx: EmailContext) -> list[Finding]:
    haystack = strip_format(f"{ctx.subject}\n{ctx.text}")  # zero-width characters can't split a phrase
    out = []
    for rule_id, patterns in _COMPILED.items():
        hits: list[str] = []
        langs: list[str] = []
        for lang, pat in patterns:
            m = pat.search(haystack)
            if m:
                hits.append(clean(m.group(0), 40))
                langs.append(lang)
        if hits:
            # Two patterns often match the same phrase ("Please click this!" / "Please click this"):
            # keep only the longest wording so the evidence isn't repeated.
            uniq = list(dict.fromkeys(hits))
            hits = [h for h in uniq if not any(h != o and h.lower() in o.lower() for o in uniq)]
            rule = RULES[rule_id]
            quoted = ", ".join(f"'{h}'" for h in list(dict.fromkeys(hits))[:2])
            lang_names = ", ".join(LANG_NAMES[x] for x in dict.fromkeys(langs) if x != "en")
            out.append(
                Finding(
                    rule_id,
                    C,
                    rule.title,
                    f"The email says {quoted}{f' ({lang_names})' if lang_names else ''}. {rule.detail}",
                    rule.points,
                    tuple(dict.fromkeys(hits))[:3],
                )
            )
    ids = {f.id for f in out}
    out.extend(f for f in (_phishing_anatomy(ctx, ids), _bec_pattern(ids)) if f)
    words = obfuscated_words(ctx.text)
    if words:
        out.append(
            Finding(
                "CONTENT_OBFUSCATED_TEXT",
                C,
                "Letters from different alphabets mixed inside words",
                f"Words such as '{clean(words[0], 30)}' mix Latin letters with look-alike Cyrillic/Greek or "
                "full-width letters. People never type like this; it is done to slip past keyword filters.",
                15,
                tuple(clean(w, 30) for w in words[:3]),
            )
        )
    return out


def _phishing_anatomy(ctx: EmailContext, ids: set[str]) -> Finding | None:
    """Threat + a demand to verify/hand over details + a deadline + a link: the full anatomy of a
    credential-phishing email. Each part alone is common; together, in one email, they rarely
    are - so the combination scores on its own (outside the low content cap).

    Skipped for mail authenticated as a well-known brand: genuine security alerts from Google or a
    bank read exactly like this, and their senders can't be forged past DMARC.
    """
    if not ({"CONTENT_ACCOUNT_THREAT"} <= ids and ids & {"CONTENT_CREDENTIALS", "CONTENT_PAYMENT"}):
        return None
    if "CONTENT_URGENCY" not in ids or not ctx.links:
        return None
    sender = ctx.from_addr.host.registrable if ctx.from_addr and ctx.from_addr.host else ""
    if sender and ctx.sender_authenticated() and brand_for_domain(sender):
        return None
    return Finding(
        "CONTENT_PHISHING_ANATOMY",
        Category.SOCIAL,
        "Has every part of a phishing email",
        "The email threatens your account, demands that you verify or hand over details, sets a "
        "deadline, and gives a link to do it. Each of these alone is common; all four together are "
        "the classic structure of credential phishing.",
        20,
        ("threat + demand + deadline + link",),
    )


def _bec_pattern(ids: set[str]) -> Finding | None:
    """Payment request + urgency + 'I can't talk / keep it between us': the shape of CEO fraud (BEC).
    BEC has no link or attachment to scan, so its wording *is* the evidence - but only all three
    together, never one phrase alone."""
    if not {"CONTENT_PAYMENT", "CONTENT_URGENCY", "CONTENT_SECRECY"} <= ids:
        return None
    return Finding(
        "CONTENT_BEC_PATTERN",
        Category.SOCIAL,
        "Has every part of CEO / payment fraud",
        "The email asks for a payment or transfer, pushes for speed, and makes itself impossible to "
        "verify ('I'm in a meeting, can't talk', 'keep it between us'). That combination is the "
        "script of business email compromise: always confirm by phone, on a number you already know.",
        20,
        ("payment + urgency + can't-verify",),
    )
