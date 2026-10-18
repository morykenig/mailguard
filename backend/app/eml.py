"""Build an AnalyzeRequest from a raw RFC 822 message (.eml).

Mirrors what the Gmail add-on extracts, so the CLI and the tests exercise exactly the
same contract as production. Useful as an offline fallback during a demo, too.
"""

from __future__ import annotations

import base64
import hashlib
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

from .schemas import MAX_INSPECTED_ATTACHMENT_BYTES, AnalyzeRequest, Attachment, SenderHistory

# Same list as the add-on (addon/Extract.gs): file types we statically inspect.
INSPECTABLE_EXT = frozenset(
    """
    doc docm docx dotm jpeg jpg pdf png ppt pptm pptx rtf txt xls xlsb xlsm xlsx zip
    """.split()
)


def _split_headers(raw: bytes) -> str:
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx].decode("utf-8", "replace")
    return raw.decode("utf-8", "replace")


def request_from_eml(raw: bytes, history: SenderHistory | None = None, recipient_domain: str = "") -> AnalyzeRequest:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)  # type: ignore[assignment]
    text_body = html_body = ""
    attachments: list[Attachment] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename() or ""
        ctype = part.get_content_type()
        if disposition == "attachment" or (filename and disposition != "inline"):
            data = part.get_payload(decode=True) or b""
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            inspect = ext in INSPECTABLE_EXT and len(data) <= MAX_INSPECTED_ATTACHMENT_BYTES
            attachments.append(
                Attachment(
                    filename=filename[:512],
                    content_type=ctype[:255],
                    size=len(data),
                    sha256=hashlib.sha256(data).hexdigest(),
                    content_b64=base64.b64encode(data).decode() if inspect else None,
                )
            )
        elif ctype == "text/plain" and not text_body:
            text_body = str(part.get_content())[:200_000]
        elif ctype == "text/html" and not html_body:
            html_body = str(part.get_content())[:600_000]
    return AnalyzeRequest(
        client_version="eml-cli",
        raw_headers=_split_headers(raw)[: 128 * 1024],
        text_body=text_body,
        html_body=html_body,
        attachments=attachments[:25],
        sender_history=history,
        recipient_domain=recipient_domain,
    )
