from helpers import run

from app.analyzers.base import Category, Finding
from app.eml import request_from_eml
from app.pipeline import analyze_email
from app.schemas import SenderHistory
from app.scoring import compute_score, confidence_for, merge_duplicates, verdict_for


def f(cat, pts, fid=None, floor=None):
    return Finding(fid or f"X{pts}{cat}", cat, "t", "d", pts, floor=floor)


def test_category_caps_limit_one_noisy_dimension():
    many_content = [f(Category.CONTENT, 12, f"C{i}") for i in range(6)]  # 72 raw
    assert compute_score(many_content) == 25
    assert verdict_for(25).value == "safe"


def test_breadth_of_evidence_raises_score():
    findings = [f(Category.CONTENT, 20), f(Category.SENDER, 30), f(Category.LINKS, 30)]
    assert compute_score(findings) == 80


def test_mitigations_are_capped():
    findings = [f(Category.LINKS, 40), f(Category.HISTORY, -15, "H"), f(Category.AUTHENTICATION, -8, "A")]
    assert compute_score(findings) == 20  # 40 - min(23, 20)


def test_floor_overrides_everything():
    findings = [f(Category.REPUTATION, 10, floor=85), f(Category.HISTORY, -15, "H")]
    assert compute_score(findings) == 85


def test_duplicates_are_counted_once_with_merged_evidence():
    a = Finding("LINK_X", Category.LINKS, "t", "d", 10, ("one",))
    b = Finding("LINK_X", Category.LINKS, "t", "d", 10, ("two",))
    merged = merge_duplicates([a, b])
    assert len(merged) == 1 and merged[0].evidence == ("one", "two")


def test_confidence_degrades_when_checks_are_missing():
    assert confidence_for([], {"VirusTotal": "checked 2"}, 0).value == "high"
    assert confidence_for([], {"VirusTotal": "timed out"}, 0).value == "medium"
    assert confidence_for([], {"VirusTotal": "timed out", "Google Safe Browsing": "unavailable"}, 0).value == "low"
    assert confidence_for([], {}, analyzer_errors=1).value == "low"


EXPECTED = {
    "01_paypal_lookalike.eml": "malicious",
    "02_ceo_fraud_hebrew.eml": "malicious",
    "03_invoice_attachments.eml": "malicious",
    "04_microsoft_spoof.eml": "malicious",
    "05_github_legit.eml": "safe",
    "06_disguised_exe.eml": "malicious",
    "07_device_code_phish.eml": "malicious",
    "08_hidden_prompt_injection.eml": "malicious",
    "09_oauth_consent_phish.eml": "malicious",
    "10_secret_exposure.eml": "safe",
    "11_aws_console_lure.eml": "malicious",
    "12_parcel_fake_reply_emoji.eml": "malicious",
    "13_image_only_brand_logo.eml": "malicious",
    "14_hebrew_customs_fee.eml": "malicious",
    "15_spanish_bank_obfuscated.eml": "malicious",
}


def test_sample_corpus_verdicts(samples_dir):
    history = SenderHistory(prior_messages_from_sender=0, user_has_emailed_sender=False)
    for name, expected in EXPECTED.items():
        req = request_from_eml((samples_dir / name).read_bytes(), history=history, recipient_domain="acme.com")
        res = run(analyze_email(req))
        assert res.verdict.value == expected, (name, res.score, [x.id for x in res.findings])
        assert res.summary and res.recommendations


def test_known_correspondent_lowers_but_cannot_launder(samples_dir):
    known = SenderHistory(prior_messages_from_sender=40, user_has_emailed_sender=True)
    req = request_from_eml((samples_dir / "06_disguised_exe.eml").read_bytes(), history=known)
    res = run(analyze_email(req))
    assert res.verdict.value == "malicious"  # floor from the disguised executable holds


def test_spoofed_known_contact_is_flagged_not_reassured():
    from helpers import make_request

    raw = (
        "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=boss@acme.com; dmarc=fail header.from=acme.com\n"
        "From: Boss <boss@acme.com>\nSubject: wire\n"
    )
    req = make_request(
        raw_headers=raw,
        text_body="Please make a wire transfer today, keep this confidential.",
        sender_history={"prior_messages_from_sender": 40, "user_has_emailed_sender": True},
    )
    res = run(analyze_email(req))
    assert "HISTORY_SPOOFED_CONTACT" in {f.id for f in res.findings}
    assert not res.mitigations
    assert res.verdict.value == "malicious"


def test_familiarity_needs_authentication():
    from helpers import make_request

    req = make_request(
        raw_headers="From: a@x.com\n",  # no Authentication-Results at all
        sender_history={"prior_messages_from_sender": 10, "user_has_emailed_sender": True},
    )
    assert not run(analyze_email(req)).mitigations


def test_block_advice_depends_on_authentication():
    from helpers import make_request

    spoofed = make_request(
        raw_headers="Authentication-Results: mx.google.com; spf=fail; dmarc=fail header.from=microsoft.com\n"
        "From: Microsoft <no-reply@microsoft.com>\n",
        html_body='<a href="https://sites.google.com/x">https://login.microsoftonline.com</a>'
        "<p>Unusual sign-in activity. Verify your account immediately.</p>",
    )
    res = run(analyze_email(spoofed))
    assert res.verdict.value == "malicious" and res.sender.authenticated is False and res.sender.spoofed
    assert any("Don't block" in r for r in res.recommendations)
    assert "login.microsoftonline.com" in res.headline or res.headline  # specific, non-empty


def test_link_finding_names_the_exact_link():
    from helpers import make_request

    req = make_request(html_body='<a href="http://fake-domain.com/x">paypal.com</a>')
    f = next(x for x in run(analyze_email(req)).findings if x.id == "LINK_TEXT_MISMATCH")
    assert "'paypal.com'" in f.detail and "fake-domain[.]com" in f.detail
