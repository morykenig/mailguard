"""Map every finding to MITRE ATT&CK (and MITRE ATLAS for attacks on AI systems).

Why: a SOC analyst triages in ATT&CK terms. Tagging each finding lets a report be routed,
correlated and counted the same way as any other detection - "T1566.002 Spearphishing
Link" means the same thing in MailGuard, the SIEM and the incident write-up.

Every finding id must appear in ``FINDING_TECHNIQUES`` (an empty tuple is an explicit
"no technique" decision). A test enforces this, so a new rule cannot ship unmapped.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    framework: str = "ATT&CK"

    @property
    def url(self) -> str:
        if self.framework == "ATLAS":
            return f"https://atlas.mitre.org/techniques/{self.id}"
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"


def _t(tid: str, name: str, framework: str = "ATT&CK") -> Technique:
    return Technique(tid, name, framework)


TECHNIQUES: dict[str, Technique] = {
    t.id: t
    for t in (
        _t("T1566", "Phishing"),
        _t("T1566.001", "Phishing: Spearphishing Attachment"),
        _t("T1566.002", "Phishing: Spearphishing Link"),
        _t("T1598", "Phishing for Information"),
        _t("T1656", "Impersonation"),
        _t("T1036", "Masquerading"),
        _t("T1036.002", "Masquerading: Right-to-Left Override"),
        _t("T1036.008", "Masquerading: Masquerade File Type"),
        _t("T1204.001", "User Execution: Malicious Link"),
        _t("T1204.002", "User Execution: Malicious File"),
        _t("T1059.005", "Command and Scripting Interpreter: Visual Basic"),
        _t("T1221", "Template Injection"),
        _t("T1027", "Obfuscated Files or Information"),
        _t("T1027.006", "Obfuscated Files or Information: HTML Smuggling"),
        _t("T1027.013", "Obfuscated Files or Information: Encrypted/Encoded File"),
        _t("T1583.001", "Acquire Infrastructure: Domains"),
        _t("T1583.006", "Acquire Infrastructure: Web Services"),
        _t("T1528", "Steal Application Access Token"),
        _t("T1552", "Unsecured Credentials"),
        _t("T1657", "Financial Theft"),
        _t("AML.T0051.001", "LLM Prompt Injection: Indirect", "ATLAS"),
    )
}

# finding id (or "PREFIX*") -> technique ids, most specific first.
FINDING_TECHNIQUES: dict[str, tuple[str, ...]] = {
    # Sender authentication
    "AUTH_FORGED_HEADER": ("T1656",),
    "AUTH_DMARC_FAIL": ("T1656",),
    "AUTH_SPF_FAIL": ("T1656",),
    "AUTH_SPF_SOFTFAIL": ("T1656",),
    "AUTH_DKIM_FAIL": ("T1656",),
    "AUTH_DKIM_NONE": (),
    "AUTH_DKIM_UNALIGNED": (),
    "AUTH_MISSING": (),
    "AUTH_DMARC_PASS": (),
    # Sender identity
    "SENDER_INVALID": ("T1656",),
    "SENDER_LOOKALIKE": ("T1656", "T1583.001"),
    "SENDER_IDN": ("T1583.001", "T1036"),
    "SENDER_NAME_HAS_EMAIL": ("T1656",),
    "SENDER_BRAND_IMPERSONATION": ("T1656",),
    "SENDER_FREEMAIL_ROLE": ("T1656",),
    "SENDER_HIDDEN_CHARS": ("T1656", "T1036"),
    "SENDER_REPLYTO_MISMATCH": ("T1656",),
    "SENDER_RETURN_PATH_MISMATCH": (),
    # History
    "HISTORY_SPOOFED_CONTACT": ("T1656",),
    "HISTORY_FIRST_CONTACT": (),
    "HISTORY_KNOWN_CORRESPONDENT": (),
    "HISTORY_REGULAR_SENDER": (),
    # Links
    "LINK_TEXT_MISMATCH": ("T1566.002", "T1036"),
    "LINK_LOOKALIKE": ("T1566.002", "T1583.001"),
    "LINK_BRAND_IN_SUBDOMAIN": ("T1566.002", "T1036"),
    "LINK_SCRIPT_SCHEME": ("T1204.001",),
    "LINK_USERINFO": ("T1566.002", "T1036"),
    "LINK_IP_ADDRESS": ("T1566.002",),
    "LINK_DOWNLOAD": ("T1566.002", "T1204.002"),
    "LINK_IDN": ("T1566.002", "T1583.001"),
    "LINK_HIDDEN_CHARS": ("T1566.002", "T1036"),
    "LINK_FREE_HOSTING": ("T1566.002", "T1583.006"),
    "LINK_SHORTENER": ("T1566.002",),
    "LINK_REDIRECT": ("T1566.002",),
    "LINK_HTTP_LOGIN": ("T1566.002",),
    "LINK_SUSPICIOUS_TLD": ("T1566.002",),
    "LINK_EMBEDDED_FORM": ("T1598",),
    "LINK_META_REFRESH": ("T1566.002",),
    "LINK_BAIT_SWITCH": ("T1566.002", "T1036"),
    # Attachments
    "ATT_DISGUISED_EXE": ("T1566.001", "T1036.008", "T1204.002"),
    "ATT_RTLO": ("T1036.002", "T1566.001"),
    "ATT_EXECUTABLE": ("T1566.001", "T1204.002"),
    "ATT_HTML": ("T1566.001", "T1027.006"),
    "ATT_MACRO": ("T1566.001", "T1059.005"),
    "ATT_MACRO_EXT": ("T1566.001", "T1059.005"),
    "ATT_REMOTE_TEMPLATE": ("T1221", "T1566.001"),
    "ATT_ENCRYPTED_ARCHIVE": ("T1027.013", "T1566.001"),
    "ATT_ARCHIVE_RISKY": ("T1566.001", "T1204.002"),
    "ATT_ARCHIVE": ("T1566.001",),
    "ATT_PDF_ACTIVE": ("T1566.001", "T1204.002"),
    # Content
    "CONTENT_ACCOUNT_THREAT": ("T1566",),
    "CONTENT_CREDENTIALS": ("T1598",),
    "CONTENT_PAYMENT": ("T1657",),
    "CONTENT_SECRECY": ("T1656",),
    "CONTENT_URGENCY": (),
    "CONTENT_REWARD": (),
    "CONTENT_PHISHING_ANATOMY": ("T1566", "T1598"),
    "CONTENT_BEC_PATTERN": ("T1656", "T1657"),
    "LINK_CREDENTIAL_WORDS": ("T1566.002", "T1036"),
    "CONTENT_CLICK_PRESSURE": ("T1204.001",),
    # Threat intelligence
    "INTEL_SAFE_BROWSING": ("T1566.002",),
    "INTEL_VT_URL_*": ("T1566.002",),
    "INTEL_VT_FILE_*": ("T1566.001", "T1204.002"),
    "INTEL_NEW_SENDER_DOMAIN": ("T1583.001",),
    "INTEL_NEW_LINK_DOMAIN": ("T1583.001",),
    # Cloud & identity
    "CLOUD_DEVICE_CODE": ("T1528", "T1566.002"),
    "CLOUD_OAUTH_CONSENT": ("T1528", "T1566.002"),
    "CLOUD_CONSOLE_LURE": ("T1566.002", "T1656"),
    # Hidden content & AI manipulation
    "HIDDEN_PROMPT_INJECTION": ("AML.T0051.001", "T1027"),
    "HIDDEN_TEXT_SALTING": ("T1027",),
    "CONTENT_AI_DIRECTED": ("AML.T0051.001",),
    # Subject line
    "SUBJECT_FAKE_REPLY": ("T1566", "T1656"),
    "SUBJECT_ALARM": (),
    "SUBJECT_OBFUSCATED": ("T1027",),
    "SUBJECT_HIDDEN_CHARS": ("T1027",),
    # Content (multilingual additions)
    "CONTENT_DELIVERY_FEE": ("T1598",),
    "CONTENT_OBFUSCATED_TEXT": ("T1027",),
    # Images & emojis
    "IMG_ONLY_BODY": ("T1027",),
    "IMG_BRAND_LOGO": ("T1656",),
    "IMG_RISKY_SOURCE": (),
    "IMG_ACTIVE_CONTENT": ("T1027",),
    "EMOJI_LURE": (),
    "SENDER_FAKE_BADGE": ("T1656",),
    "ATT_FAKE_IMAGE": ("T1036.008", "T1566.001"),
    # Verdict history from the user's own mailbox
    "HISTORY_REPORTED_BEFORE": (),
    "HISTORY_PREVIOUSLY_MALICIOUS": (),
    "HISTORY_PREVIOUSLY_SUSPICIOUS": (),
    "HISTORY_GMAIL_SPAM": (),
    "HISTORY_DOMAIN_MALICIOUS": (),
    # Sensitive data exposure
    "EXPOSURE_*": ("T1552",),
}


def mapping_for(finding_id: str) -> tuple[str, ...] | None:
    """Technique ids for a finding, or None if the id is not mapped at all."""
    if finding_id in FINDING_TECHNIQUES:
        return FINDING_TECHNIQUES[finding_id]
    for key, ids in FINDING_TECHNIQUES.items():
        if key.endswith("*") and finding_id.startswith(key[:-1]):
            return ids
    return None


def techniques_for(finding_id: str) -> list[Technique]:
    return [TECHNIQUES[t] for t in (mapping_for(finding_id) or ())]
