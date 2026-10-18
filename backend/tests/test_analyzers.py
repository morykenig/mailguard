import base64
import io
import zipfile

from helpers import ctx_for, headers, sha

from app.analyzers import attachments, authentication, content, links, sender
from app.context import parse_auth_results


def ids(findings):
    return {f.id for f in findings}


# ----------------------------------------------------------------------------- authentication


def test_parses_gmail_authentication_results():
    ar = parse_auth_results(
        "mx.google.com;\r\n dkim=pass header.i=@acme.com header.s=k1 header.b=x;\r\n"
        " spf=softfail (google.com: domain of a@acme.com does not designate 1.2.3.4) smtp.mailfrom=a@acme.com;\r\n"
        " dmarc=fail (p=QUARANTINE sp=NONE dis=QUARANTINE) header.from=acme.com"
    )
    assert ar.authserv_id == "mx.google.com"
    assert ar.spf == "softfail" and ar.dmarc == "fail"
    assert ar.dkim_pass_domains == {"acme.com"}


def test_forged_authentication_header_is_ignored_and_reported():
    raw = (
        "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=x@bank.com; dmarc=fail header.from=bank.com\n"
        "Authentication-Results: mx.google.com; spf=pass; dkim=pass header.d=bank.com; "
        "dmarc=pass header.from=bank.com\n"
        "From: Bank <alerts@bank.com>\n"
    )
    ctx = ctx_for(raw_headers=raw)
    assert ctx.auth.dmarc == "fail"  # the first (Gmail's) header wins
    assert {"AUTH_FORGED_HEADER", "AUTH_DMARC_FAIL", "AUTH_SPF_FAIL"} <= ids(authentication.analyze(ctx))


def test_untrusted_authserv_id_is_not_trusted():
    raw = "Authentication-Results: evil.example; dmarc=pass header.from=bank.com\nFrom: a@bank.com\n"
    assert "AUTH_MISSING" in ids(authentication.analyze(ctx_for(raw_headers=raw)))


def test_dmarc_pass_is_a_mitigation():
    found = authentication.analyze(ctx_for())
    assert [f.id for f in found] == ["AUTH_DMARC_PASS"] and found[0].points < 0


# ----------------------------------------------------------------------------- sender


def test_display_name_brand_on_freemail():
    ctx = ctx_for(raw_headers=headers('"PayPal Support" <pp.support@gmail.com>'))
    assert "SENDER_BRAND_IMPERSONATION" in ids(sender.analyze(ctx))


def test_display_name_with_other_address():
    ctx = ctx_for(raw_headers=headers('"ceo@acme.com" <random@mailer.net>'))
    assert "SENDER_NAME_HAS_EMAIL" in ids(sender.analyze(ctx))


def test_reply_to_freemail_and_role_name():
    ctx = ctx_for(raw_headers=headers('"Dana | CEO" <dana.c@gmail.com>', "Reply-To: other@outlook.com\n"))
    found = ids(sender.analyze(ctx))
    assert {"SENDER_FREEMAIL_ROLE", "SENDER_REPLYTO_MISMATCH"} <= found


def test_lookalike_of_recipient_org():
    ctx = ctx_for(raw_headers=headers("IT <it@acrne.com>"), recipient_domain="acme.com")
    found = sender.analyze(ctx)
    assert any(f.id == "SENDER_LOOKALIKE" and "acme.com" in f.title for f in found)


def test_legit_brand_sender_is_clean():
    ctx = ctx_for(raw_headers=headers('"PayPal" <service@paypal.com>'))
    assert sender.analyze(ctx) == []


# ----------------------------------------------------------------------------- links


def _link_ids(html):
    return ids(links.analyze(ctx_for(html_body=html)))


def test_link_text_mismatch():
    assert "LINK_TEXT_MISMATCH" in _link_ids('<a href="https://evil.example/x">https://www.paypal.com</a>')


def test_link_text_matching_same_brand_is_fine():
    assert _link_ids('<a href="https://www.paypal.com/x">paypal.com</a>') == set()


def test_esp_click_tracking_is_not_a_mismatch():
    assert "LINK_TEXT_MISMATCH" not in _link_ids('<a href="https://x.list-manage.com/track">www.shop.com</a>')


def test_many_link_tricks():
    found = _link_ids(
        '<a href="http://192.168.1.10/login">a</a>'
        '<a href="https://www.paypal.com@evil.example/">b</a>'
        '<a href="https://paypal.com.secure-check.xyz/">c</a>'
        '<a href="https://bit.ly/abc">d</a>'
        '<a href="https://foo.web.app/">e</a>'
        '<a href="https://cdn.example/files/update.exe">f</a>'
        '<a href="javascript:alert(1)">g</a>'
        '<a href="https://www.google.com/url?q=https://evil.example/">h</a>'
        '<form action="https://x.example/p"><input type="password"></form>'
    )
    assert {
        "LINK_IP_ADDRESS",
        "LINK_USERINFO",
        "LINK_BRAND_IN_SUBDOMAIN",
        "LINK_SHORTENER",
        "LINK_FREE_HOSTING",
        "LINK_DOWNLOAD",
        "LINK_SCRIPT_SCHEME",
        "LINK_REDIRECT",
        "LINK_EMBEDDED_FORM",
        "LINK_SUSPICIOUS_TLD",
        "LINK_HTTP_LOGIN",
    } <= found


def test_plain_text_urls_are_extracted():
    ctx = ctx_for(text_body="Go to http://paypa1.com/verify now.")
    assert "LINK_LOOKALIKE" in ids(links.analyze(ctx))


def test_mailto_and_anchors_are_ignored():
    assert ctx_for(html_body='<a href="mailto:a@b.c">x</a><a href="#top">y</a>').links == []


# ----------------------------------------------------------------------------- attachments


def _att(name, data=b"x", inspect=True):
    return {
        "filename": name,
        "size": len(data),
        "sha256": sha(data),
        "content_b64": base64.b64encode(data).decode() if inspect else None,
    }


def _zip(entries, encrypt=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    raw = bytearray(buf.getvalue())
    if encrypt:  # set the "encrypted" flag bit in local and central headers
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = raw.find(sig)
            while i != -1:
                raw[i + off] |= 0x1
                i = raw.find(sig, i + 4)
    return bytes(raw)


def _att_ids(*atts):
    return ids(attachments.analyze(ctx_for(attachments=list(atts))))


def test_rtlo_and_executables():
    assert {"ATT_RTLO", "ATT_EXECUTABLE"} <= _att_ids(_att("invoice\u202efdp.exe", inspect=False))
    found = attachments.analyze(ctx_for(attachments=[_att("report.pdf.exe", inspect=False)]))
    assert found[0].title.startswith("Attachment is a program disguised")


def test_disguised_pe_has_floor():
    found = attachments.analyze(ctx_for(attachments=[_att("scan.pdf", b"MZ\x90\x00" + b"\0" * 64)]))
    assert found[0].id == "ATT_DISGUISED_EXE" and found[0].floor == 80


def test_ooxml_macro_and_remote_template():
    rels = (
        '<Relationships><Relationship Type="http://x/attachedTemplate" '
        'Target="https://evil.example/t.dotm" TargetMode="External"/></Relationships>'
    )
    doc = _zip({"[Content_Types].xml": "<Types/>", "word/vbaProject.bin": b"vba", "word/_rels/settings.xml.rels": rels})
    found = _att_ids(_att("invoice.docm", doc))
    assert {"ATT_MACRO", "ATT_REMOTE_TEMPLATE"} <= found and "ATT_MACRO_EXT" not in found


def test_encrypted_archive_and_risky_inner_files():
    found = _att_ids(_att("files.zip", _zip({"invoice.pdf.js": "x", "readme.txt": "y"}, encrypt=True)))
    assert {"ATT_ARCHIVE", "ATT_ENCRYPTED_ARCHIVE", "ATT_ARCHIVE_RISKY"} <= found


def test_pdf_active_content():
    assert "ATT_PDF_ACTIVE" in _att_ids(_att("doc.pdf", b"%PDF-1.7 /OpenAction /JavaScript (app.alert)"))


def test_html_and_svg_attachments():
    assert "ATT_HTML" in _att_ids(_att("statement.svg", inspect=False))


def test_corrupt_zip_does_not_crash():
    assert "ATT_ARCHIVE" in _att_ids(_att("x.zip", b"PK\x03\x04garbage"))


# ----------------------------------------------------------------------------- content


def test_hebrew_social_engineering():
    ctx = ctx_for(text_body="היי, אתה זמין? צריכה ממך טובה. העברה בנקאית דחוף. תשמור את זה בינינו")
    assert {"CONTENT_SECRECY", "CONTENT_PAYMENT", "CONTENT_URGENCY"} <= ids(content.analyze(ctx))


def test_hebrew_word_boundaries_avoid_false_positives():
    ctx = ctx_for(text_body="מצורף מידע על הפגישה")  # contains the letters of 'מיד' inside 'מידע'
    assert "CONTENT_URGENCY" not in ids(content.analyze(ctx))


def test_english_credential_phish():
    ctx = ctx_for(text_body="Your account will be suspended. Confirm your password immediately.")
    assert {"CONTENT_ACCOUNT_THREAT", "CONTENT_CREDENTIALS", "CONTENT_URGENCY"} <= ids(content.analyze(ctx))


# ----------------------------------------------------------------------------- regressions


def test_readme_hebrew_demo_phrase():
    ctx = ctx_for(text_body="היי, אתה זמין? צריך ממך טובה דחופה")
    assert {"CONTENT_SECRECY", "CONTENT_URGENCY"} <= ids(content.analyze(ctx))


def test_hebrew_ceo_title_with_gershayim():
    ctx = ctx_for(raw_headers=headers('"דנה כהן, מנכ\u05f4ל" <dana.c@gmail.com>'))
    assert "SENDER_FREEMAIL_ROLE" in ids(sender.analyze(ctx))


def test_lower_auth_header_from_forwarding_is_not_called_forged():
    raw = (
        "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=a@x.com; dmarc=pass header.from=x.com\n"
        "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=a@x.com; dmarc=pass header.from=x.com\n"
        "From: a@x.com\n"
    )
    assert "AUTH_FORGED_HEADER" not in ids(authentication.analyze(ctx_for(raw_headers=raw)))


def test_filename_link_text_is_not_a_domain_claim():
    assert "LINK_TEXT_MISMATCH" not in _link_ids(
        '<a href="https://github.com/acme/api/blob/main/README.md">README.md</a>'
    )


def test_brand_owned_hosts_are_not_brand_in_subdomain():
    found = _link_ids('<a href="https://acme.sharepoint.com/x">a</a><a href="https://meta.stackexchange.com/">b</a>')
    assert "LINK_BRAND_IN_SUBDOMAIN" not in found


def test_text_alternative_urls_ignored_when_html_present():
    ctx = ctx_for(text_body="https://www.paypal.com/signin", html_body='<a href="https://evil.example/">x</a>')
    assert [lk.host.registrable for lk in ctx.links] == ["evil.example"]


def test_crafted_relationships_part_is_fast():
    import time

    part = "<Relationship " + "a" * 200_000
    doc = _zip({"[Content_Types].xml": "<Types/>", **{f"word/_rels/p{i}.rels": part for i in range(20)}})
    start = time.perf_counter()
    attachments.analyze(ctx_for(attachments=[_att("x.docx", doc)]))
    assert time.perf_counter() - start < 1.0


def test_nested_comments_in_auth_header_are_fast():
    import time

    raw = "Authentication-Results: mx.google.com; " + "(" * 20_000 + ")" * 20_000 + " dmarc=pass\nFrom: a@b.com\n"
    start = time.perf_counter()
    ctx_for(raw_headers=raw)
    assert time.perf_counter() - start < 1.0
