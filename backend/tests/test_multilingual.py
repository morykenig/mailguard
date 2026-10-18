"""Subject line, images & emojis, multilingual content, verdict memory and the Hebrew UI."""

import re
from pathlib import Path

import pytest
from helpers import ctx_for, headers, make_request, run

from app import i18n
from app.analyzers import content, subject, visual
from app.analyzers.base import Category, Finding
from app.eml import request_from_eml
from app.language import detect, obfuscated_words
from app.pipeline import analyze_email
from app.schemas import SenderHistory, Verdict
from app.scoring import recommendations


def ids(findings):
    return {f.id for f in findings}


def subj_ctx(subj: str, extra: str = "", **kw):
    raw = headers("Alice <alice@example.org>", extra=extra).replace("Subject: test", f"Subject: {subj}")
    return ctx_for(raw_headers=raw, **kw)


# ----------------------------------------------------------------------------- subject line


@pytest.mark.parametrize(
    "subj", ["RE: Invoice 8812", "Re[2]: payment", "AW: Rechnung", "השב: חשבונית", "Fwd and RE: x"[8:]]
)
def test_fake_reply_without_threading_headers(subj):
    assert "SUBJECT_FAKE_REPLY" in ids(subject.analyze(subj_ctx(subj)))


def test_real_reply_is_not_flagged():
    ctx = subj_ctx("RE: Invoice 8812", extra="In-Reply-To: <abc@mail.example>\n")
    assert "SUBJECT_FAKE_REPLY" not in ids(subject.analyze(ctx))


def test_reply_from_someone_you_wrote_to_is_not_flagged():
    h = SenderHistory(prior_messages_from_sender=3, user_has_emailed_sender=True)
    assert "SUBJECT_FAKE_REPLY" not in ids(subject.analyze(subj_ctx("RE: lunch", sender_history=h)))


@pytest.mark.parametrize("subj", ["[URGENT] verify now", "FINAL NOTICE: YOUR ACCOUNT", "Act now!!", "[דחוף] חשבון"])
def test_alarm_subjects(subj):
    assert "SUBJECT_ALARM" in ids(subject.analyze(subj_ctx(subj)))


@pytest.mark.parametrize(
    "subj",
    [
        "Team lunch on Thursday",
        "Q3 report",
        "NASA",
        "Re-org update",
        'המותג הבינ"ל המוביל DYSON מצטרף למועדון DREAM CARD 🎉 פרסומת',  # real Israeli newsletter
    ],
)
def test_normal_subjects_are_quiet(subj):
    assert subject.analyze(subj_ctx(subj)) == []


def test_obfuscated_and_hidden_subject():
    found = ids(subject.analyze(subj_ctx("Your PаyPal account")))  # Cyrillic a
    assert "SUBJECT_OBFUSCATED" in found
    assert "SUBJECT_HIDDEN_CHARS" in ids(subject.analyze(subj_ctx("pay\u200bment due")))


def test_obfuscation_ignores_real_bilingual_text():
    assert obfuscated_words("Привет team, meeting at 10") == []
    assert obfuscated_words("שלום Dana, see you") == []
    assert obfuscated_words("Ｐａｙ now")  # full-width letters


# ----------------------------------------------------------------------------- language and content


@pytest.mark.parametrize(
    ("text", "lang"),
    [
        ("החבילה שלך ממתינה לתשלום", "he"),
        ("Ваш аккаунт будет заблокирован", "ru"),
        ("تم تعليق حسابك", "ar"),
        ("Su cuenta será bloqueada hoy y debe verificar", "es"),
        ("Votre compte sera suspendu, veuillez vérifier", "fr"),
        ("Ihr Konto wird gesperrt, bitte bestätigen Sie", "de"),
        ("Your account will be suspended, please verify", "en"),
    ],
)
def test_language_detection(text, lang):
    assert detect(text) == lang


@pytest.mark.parametrize(
    "text",
    [
        "החבילה שלך מעוכבת. יש לשלם דמי מכס בסך 9.90 ש״ח",
        "Your parcel is on hold, pay the delivery fee",
        "Su paquete está retenido, pague la tasa de aduana",
        "Ваша посылка задержана, оплатите таможенный сбор",
    ],
)
def test_delivery_fee_lure_in_several_languages(text):
    assert "CONTENT_DELIVERY_FEE" in ids(content.analyze(ctx_for(text_body=text)))


def test_hebrew_credential_and_account_threat():
    found = ids(content.analyze(ctx_for(text_body="חשבונך יינעל היום. יש להזין את הסיסמה והקוד שקיבלת ב-SMS")))
    assert {"CONTENT_ACCOUNT_THREAT", "CONTENT_CREDENTIALS"} <= found


def test_confidentiality_footer_is_not_a_secrecy_request():
    footer = "This email is confidential and intended only for the addressee. המידע בהודעה זו חסוי."
    assert "CONTENT_SECRECY" not in ids(content.analyze(ctx_for(text_body=footer)))


# ----------------------------------------------------------------------------- images & emojis


def test_image_only_email_with_brand_logo():
    html = (
        '<a href="https://x.example/r"><img src="https://cdn.x.example/paypal-logo.png" alt="PayPal" width="160">'
        '<img src="https://cdn.x.example/body.png" width="600"></a>'
    )
    found = visual.analyze(ctx_for(html_body=html))
    assert {"IMG_ONLY_BODY", "IMG_BRAND_LOGO"} <= ids(found)
    logo = next(f for f in found if f.id == "IMG_BRAND_LOGO")
    assert dict(logo.params)["brand"] == "PayPal"


def test_newsletter_with_text_and_footer_icons_is_quiet():
    text = "<p>" + "Here is our monthly product update with plenty of real text for readers. " * 5 + "</p>"
    html = (
        '<img src="https://cdn.example.org/header.png" alt="Example Corp" width="600">'
        + text
        + '<img src="https://cdn.example.org/linkedin.png" alt="LinkedIn" width="24">'
    )
    assert visual.analyze(ctx_for(html_body=html)) == []


def test_brand_logo_from_the_brand_itself_is_fine():
    raw = headers("PayPal <service@paypal.com>")
    html = '<img src="https://www.paypalobjects.com/logo.png" alt="PayPal logo" width="120">' + "<p>" + "text " * 60
    assert "IMG_BRAND_LOGO" not in ids(visual.analyze(ctx_for(raw_headers=raw, html_body=html)))


def test_tracking_pixel_alone_is_not_an_image_only_email():
    html = (
        "<p>Hi Dana, the notes from today are below.</p>" * 4
        + '<img src="https://t.example/o.gif" width="1" height="1">'
    )
    assert "IMG_ONLY_BODY" not in ids(visual.analyze(ctx_for(html_body=html)))


def test_active_content_and_risky_image_source():
    html = '<img src="http://198.51.100.7/a.png" onerror="x()" width="300"><p>' + "words " * 40 + "</p>"
    found = ids(visual.analyze(ctx_for(html_body=html)))
    assert {"IMG_ACTIVE_CONTENT", "IMG_RISKY_SOURCE"} <= found


@pytest.mark.parametrize("name", ["PayPal ✅", "Support 🛡", "Bank (Verified)", "שירות לקוחות מאומת"])
def test_fake_verified_badge(name):
    assert "SENDER_FAKE_BADGE" in ids(visual.analyze(ctx_for(raw_headers=headers(f'"{name}" <a@b-example.com>'))))


def test_lure_emojis():
    assert "EMOJI_LURE" in ids(visual.analyze(subj_ctx("⚠️ Account locked")))
    assert "EMOJI_LURE" not in ids(visual.analyze(subj_ctx("Happy birthday 🎂")))
    assert "EMOJI_LURE" not in ids(visual.analyze(subj_ctx("New brand joins the club 🎉")))
    assert "EMOJI_LURE" not in ids(visual.analyze(subj_ctx("Weekend sale 💰")))
    assert "EMOJI_LURE" in ids(visual.analyze(subj_ctx("Claim your refund 💰💳")))


def test_image_extension_that_is_not_an_image():
    import base64

    from app.schemas import Attachment

    data = b"<html><form action='https://x.example'><input type=password></form></html>"
    att = Attachment(
        filename="scan.jpg",
        content_type="image/jpeg",
        size=len(data),
        sha256="0" * 64,
        content_b64=base64.b64encode(data).decode(),
    )
    assert "ATT_FAKE_IMAGE" in ids(visual.analyze(ctx_for(attachments=[att])))


# ----------------------------------------------------------------------------- verdict memory


def _score(history: SenderHistory, sample: str = "05_github_legit.eml"):
    raw = (Path(__file__).parents[2] / "samples" / sample).read_bytes()
    return run(analyze_email(request_from_eml(raw, history=history)))


def test_reported_sender_is_malicious_even_when_the_message_looks_clean():
    res = _score(SenderHistory(prior_messages_from_sender=3, user_has_emailed_sender=False, reported_sender=True))
    assert res.verdict is Verdict.MALICIOUS
    assert res.findings[0].id == "HISTORY_REPORTED_BEFORE"


def test_earlier_malicious_verdicts_raise_the_score_and_remove_familiarity_credit():
    clean = _score(SenderHistory(prior_messages_from_sender=5, user_has_emailed_sender=False))
    flagged = _score(
        SenderHistory(prior_messages_from_sender=5, user_has_emailed_sender=False, prior_malicious_verdicts=2)
    )
    assert flagged.score >= clean.score + 25
    assert clean.verdict is Verdict.SAFE and flagged.verdict is Verdict.SUSPICIOUS
    assert "HISTORY_REGULAR_SENDER" not in {m.id for m in flagged.mitigations}


def test_spam_and_domain_history():
    res = _score(
        SenderHistory(
            prior_messages_from_sender=0, user_has_emailed_sender=False, prior_spam_messages=2, domain_prior_malicious=1
        )
    )
    assert {"HISTORY_GMAIL_SPAM", "HISTORY_DOMAIN_MALICIOUS"} <= {f.id for f in res.findings}
    assert res.verdict is not Verdict.SAFE


def test_history_fields_are_bounded():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        SenderHistory(prior_messages_from_sender=0, user_has_emailed_sender=False, prior_malicious_verdicts=-1)
    with pytest.raises(ValidationError):
        SenderHistory(prior_messages_from_sender=0, user_has_emailed_sender=False, extra_field=1)


# ----------------------------------------------------------------------------- Hebrew UI

HEBREW = re.compile(r"[֐-׿]")


def _finding_ids_in_code() -> set[str]:
    src = "\n".join(p.read_text() for p in Path(__file__).parents[1].joinpath("app", "analyzers").glob("*.py"))
    pattern = r'"((?:AUTH|SENDER|HISTORY|SUBJECT|LINK|ATT|CONTENT|IMG|EMOJI|INTEL|CLOUD|HIDDEN)_[A-Z_]+)"'
    found = {i for i in re.findall(pattern, src) if not i.endswith("_")}
    return found | {"INTEL_VT_URL_MALICIOUS", "INTEL_VT_FILE_SUSPICIOUS", "EXPOSURE_AWS_ACCESS_KEY"}


def test_every_finding_has_a_hebrew_title_and_explanation():
    missing = sorted(i for i in _finding_ids_in_code() if i18n.finding_text(i, {}, "he") is None)
    assert missing == []


def test_hebrew_templates_fill_their_parameters():
    title, _ = i18n.finding_text("IMG_BRAND_LOGO", {"brand": "PayPal"}, "he")
    assert "PayPal" in title and "{" not in title
    title, _ = i18n.finding_text("EXPOSURE_AWS_ACCESS_KEY", {"kind": "AWS access key"}, "he")
    assert "AWS access key" in title


@pytest.mark.parametrize("verdict", list(Verdict))
@pytest.mark.parametrize(("authenticated", "spoofed"), [(True, False), (False, True), (False, False)])
def test_every_recommendation_is_translated(verdict, authenticated, spoofed):
    def f(fid, cat):
        return Finding(fid, cat, "AWS access key in this email" if cat == Category.EXPOSURE else "t", "d", 10)

    findings = [
        f("CLOUD_DEVICE_CODE", Category.CLOUD),
        f("CLOUD_OAUTH_CONSENT", Category.CLOUD),
        f("HIDDEN_PROMPT_INJECTION", Category.EVASION),
        f("LINK_LOOKALIKE", Category.LINKS),
        f("ATT_MACRO", Category.ATTACHMENTS),
        f("CONTENT_PAYMENT", Category.CONTENT),
        f("CONTENT_CREDENTIALS", Category.CONTENT),
        f("EXPOSURE_AWS_ACCESS_KEY", Category.EXPOSURE),
    ]
    for rec in recommendations(verdict, findings, authenticated, spoofed):
        assert HEBREW.search(i18n.recommendation(rec, "he")), rec


def test_ui_language_normalisation():
    assert i18n.ui_language("he-IL") == "he"
    assert i18n.ui_language("iw") == "he"
    assert i18n.ui_language("fr") == "en"
    assert i18n.ui_language("") == "en"


def test_full_response_in_hebrew(samples_dir):
    req = request_from_eml(
        (samples_dir / "14_hebrew_customs_fee.eml").read_bytes(),
        history=SenderHistory(prior_messages_from_sender=0, user_has_emailed_sender=False),
    ).model_copy(update={"locale": "he"})
    res = run(analyze_email(req))
    assert res.language == "he" and "מכס" in res.subject
    assert HEBREW.search(res.summary) and HEBREW.search(res.headline)
    assert all(HEBREW.search(f.title) and HEBREW.search(f.detail) for f in res.findings)
    assert all(HEBREW.search(r) for r in res.recommendations)
    assert all(HEBREW.search(k) for k in res.coverage)
    # the engine's decision does not depend on the UI language
    en = run(analyze_email(req.model_copy(update={"locale": "en"})))
    assert (en.score, en.verdict, [f.id for f in en.findings]) == (res.score, res.verdict, [f.id for f in res.findings])


def test_locale_is_validated():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        make_request(locale="he<script>")


# ----------------------------------------------------------------------------- live-run regressions

BAIT_HTML = (
    '<div dir="ltr">Hey, looks like you won some cash! Please click this!&nbsp;<div>You can find us here:&nbsp;'
    '<a href="https://www.google.com/">https://www.google.com/</a></div><div>Oh oops, its here:&nbsp;'
    '<a href="https://www.danger.com">https://www.danger.com</a></div></div>'
)


def test_won_cash_click_this_oops_wrong_link_is_suspicious():
    """The exact test email from a live run, which scored 'safe' before."""
    req = make_request(html_body=BAIT_HTML, text_body="Hey, looks like you won some cash! Please click this!")
    res = run(analyze_email(req))
    found = {f.id for f in res.findings}
    assert {"LINK_BAIT_SWITCH", "CONTENT_REWARD", "CONTENT_CLICK_PRESSURE"} <= found
    assert res.verdict is Verdict.SUSPICIOUS
    bait = next(f for f in res.findings if f.id == "LINK_BAIT_SWITCH")
    assert bait.evidence == ["danger.com"]
    click = next(f for f in res.findings if f.id == "CONTENT_CLICK_PRESSURE")
    assert click.evidence == ["Please click this!"]  # overlapping matches are not repeated


@pytest.mark.parametrize(
    "html",
    [
        # two ordinary links, no "correction"
        '<p>Docs: <a href="https://docs.example.org">docs</a>, status: <a href="https://status.example.net">status</a></p>',
        # a correction with only one destination
        '<p>Oops, wrong date - the meeting is Monday. <a href="https://example.org/agenda">agenda</a></p>',
    ],
)
def test_bait_switch_needs_a_correction_and_a_second_destination(html):
    from app.analyzers import links

    assert "LINK_BAIT_SWITCH" not in ids(links.analyze(ctx_for(html_body=html)))


@pytest.mark.parametrize(
    "text",
    ["Click here to unsubscribe.", "To view in your browser, click here.", "Our robotics team won first place."],
)
def test_ordinary_newsletter_wording_is_not_a_lure(text):
    found = ids(content.analyze(ctx_for(text_body=text)))
    assert not found & {"CONTENT_CLICK_PRESSURE", "CONTENT_REWARD"}


def test_benign_plain_text_part_cannot_hide_an_html_lure():
    """Gmail shows the HTML part; the plain-text alternative is sender-written and never shown."""
    req = make_request(html_body=BAIT_HTML, text_body="Hi! Lunch on Thursday?")
    found = {f.id for f in run(analyze_email(req)).findings}
    assert {"CONTENT_REWARD", "LINK_BAIT_SWITCH"} <= found


HE_SECURITY_HTML = (
    '<div dir="rtl"><p>לקוח יקר,</p><p>זיהינו ניסיון התחברות חריג לחשבונך ממדינה זרה. מטעמי אבטחה, השהינו את '
    "הגישה שלך לשירות.</p><p>כדי לשחזר את הגישה ולמנוע את מחיקת החשבון, עליך לאמת את פרטיך באופן מיידי בקישור "
    'הבא:</p><p><a href="http://login-update-security.example.com">http://login-update-security.example.com</a>'
    "</p><p>אם לא תבצע זאת עד סוף היום, חשבונך ייסגר לצמיתות.</p><p>צוות התמיכה.</p></div>"
)


def test_hebrew_account_lockout_phish_sent_to_self_is_suspicious():
    """A live-run email that scored 0: Hebrew lockout lure, sent from the user's own address."""
    raw = headers(
        "Mory <mory.example@gmail.com>",
        extra="Delivered-To: mory.example@gmail.com\nTo: mory.example@gmail.com\n",
    ).replace("Subject: test", "Subject: אזהרת אבטחה: החשבון שלך יינעל בעוד 12 שעות")
    known = SenderHistory(prior_messages_from_sender=50, user_has_emailed_sender=True)
    res = run(analyze_email(make_request(raw_headers=raw, html_body=HE_SECURITY_HTML, sender_history=known)))
    found = {f.id for f in res.findings}
    assert {"CONTENT_PHISHING_ANATOMY", "CONTENT_CREDENTIALS", "LINK_CREDENTIAL_WORDS", "SUBJECT_ALARM"} <= found
    assert "HISTORY_KNOWN_CORRESPONDENT" not in {m.id for m in res.mitigations}  # your own address is no reassurance
    assert res.verdict is Verdict.SUSPICIOUS


def test_genuine_brand_security_alert_stays_safe():
    raw = headers("Google <no-reply@accounts.google.com>").replace("Subject: test", "Subject: Security alert")
    html = (
        "<p>We noticed a new sign-in to your Google Account. If this was you, you don't need to do anything. "
        'If not, we\'ll help you secure your account. <a href="https://myaccount.google.com/notifications">'
        "Check activity</a></p>"
    )
    regular = SenderHistory(prior_messages_from_sender=5, user_has_emailed_sender=False)
    res = run(analyze_email(make_request(raw_headers=raw, html_body=html, sender_history=regular)))
    assert res.verdict is Verdict.SAFE
    assert "CONTENT_PHISHING_ANATOMY" not in {f.id for f in res.findings}


def test_hebrew_ceo_fraud_without_links_is_suspicious_even_from_yourself():
    """A live-run email that scored 0: payment + urgency + 'in a meeting, can't talk', no link at all."""
    html = (
        '<div dir="rtl"><p>היי,</p><p>אני כרגע בפגישה חשובה ואין לי אפשרות לדבר בטלפון. אנחנו צריכים לסגור '
        'בדחיפות תשלום עבור ספק חדש בחו"ל לפני סוף יום העסקים שלהם.</p><p>אנא בצע העברה בנקאית של 15,000 '
        "דולר לחשבון המצורף מטה.</p><p>זה קריטי, אל תעכב את זה.</p><p>משה</p></div>"
    )
    raw = headers("Mory <mory.example@gmail.com>", extra="Delivered-To: mory.example@gmail.com\n")
    known = SenderHistory(prior_messages_from_sender=50, user_has_emailed_sender=True)
    res = run(analyze_email(make_request(raw_headers=raw, html_body=html, sender_history=known)))
    assert "CONTENT_BEC_PATTERN" in {f.id for f in res.findings}
    assert res.verdict is Verdict.SUSPICIOUS
    assert any("phone" in r for r in res.recommendations)


def test_a_payment_request_alone_is_not_bec():
    html = "<p>Please find attached invoice 2291. Payment by bank transfer within 30 days. Thanks, Accounts</p>"
    assert "CONTENT_BEC_PATTERN" not in {f.id for f in content.analyze(ctx_for(html_body=html))}
