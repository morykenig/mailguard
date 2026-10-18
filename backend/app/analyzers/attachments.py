"""Static inspection of attachments.

Nothing here executes, renders or extracts files to disk. Archives are only *listed*
(plus a few small XML parts read with a hard size cap), so zip bombs and path-traversal
entries are harmless. File hashes are looked up in threat intel by the reputation
analyser; file contents are never uploaded to third parties.
"""

from __future__ import annotations

import io
import re
import zipfile

from ..context import EmailContext
from ..schemas import Attachment
from ..textutil import clean, has_hidden_unicode
from .base import Category, Finding

C = Category.ATTACHMENTS

EXECUTABLE_EXT = frozenset(
    """
    application appx bat chm cmd com cpl dll exe gadget hta img inf iso jar js jse lnk msi msix msp
    one pif ps1 reg scf scr sct url vbe vbs vhd vhdx wsf wsh xll
    """.split()
)
HTML_EXT = frozenset(
    """
    htm html mht mhtml shtml svg xhtml
    """.split()
)
MACRO_EXT = frozenset(
    """
    docm dotm potm ppsm pptm sldm xlam xlsm xltm
    """.split()
)
ARCHIVE_EXT = frozenset(
    """
    7z ace arj bz2 cab gz rar tar tgz xz z zip
    """.split()
)
DOCUMENT_EXT = frozenset(
    """
    doc docx jpeg jpg pdf png ppt pptx rtf txt xls xlsx
    """.split()
)

MAX_ZIP_ENTRIES = 1000
MAX_RELS_FILES = 20  # real documents have a handful of .rels parts
MAX_XML_READ = 256 * 1024  # per part, after decompression
MAX_XML_TOTAL = 1024 * 1024  # across all parts: bounds work on a crafted archive
_RELATIONSHIP = re.compile(r"<Relationship\b[^<>]*>")  # stops at the next tag: linear time


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _inspect_zip(data: bytes) -> dict[str, object]:
    """List an archive without extracting it. Returns a dict of observations."""
    obs: dict[str, object] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                obs["too_many_entries"] = True
                infos = infos[:MAX_ZIP_ENTRIES]
            names = [i.filename for i in infos]
            obs["encrypted"] = any(i.flag_bits & 0x1 for i in infos)
            obs["inner_risky"] = [n for n in names if _ext(n) in EXECUTABLE_EXT | HTML_EXT][:5]
            lowered = {n.lower() for n in names}
            obs["is_ooxml"] = "[content_types].xml" in lowered
            obs["has_vba"] = any(n.endswith("vbaproject.bin") for n in lowered)
            external = []
            rels = [i for i in infos if i.filename.lower().endswith(".rels") and not i.flag_bits & 0x1]
            budget = MAX_XML_TOTAL
            for info in rels[:MAX_RELS_FILES]:
                if info.file_size > MAX_XML_READ or budget <= 0:
                    continue
                with zf.open(info) as fh:  # read() is capped, so a lying header can't bomb us
                    raw = fh.read(min(MAX_XML_READ, budget))
                budget -= len(raw)
                xml = raw.decode("utf-8", "replace")
                for rel in _RELATIONSHIP.findall(xml):
                    if 'TargetMode="External"' in rel and re.search(r"(attachedTemplate|oleObject|frame)", rel):
                        target = re.search(r'Target="([^"]{0,200})', rel)
                        external.append(target.group(1) if target else "")
            obs["external_refs"] = external[:3]
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError, NotImplementedError, EOFError):
        obs["corrupt"] = True
    return obs


def _inspect(att: Attachment, data: bytes) -> list[Finding]:
    out: list[Finding] = []
    name = clean(att.filename, 80)
    ext = _ext(att.filename)
    head = data[:8]

    if head.startswith(b"MZ") and ext not in EXECUTABLE_EXT | {"dll", "sys"}:
        out.append(
            Finding(
                "ATT_DISGUISED_EXE",
                C,
                "Attachment is a disguised Windows program",
                f"'{name}' pretends to be a .{ext or '?'} file but its contents are a Windows executable.",
                50,
                (name,),
                floor=80,
            )
        )
    if head.startswith(b"PK\x03\x04"):
        z = _inspect_zip(data)
        if z.get("has_vba"):
            out.append(
                Finding(
                    "ATT_MACRO",
                    C,
                    "Document contains macros",
                    f"'{name}' contains VBA macros - code that runs when the document is opened and "
                    '"Enable content" is clicked. Macros are a top malware delivery method.',
                    30,
                    (name,),
                )
            )
        if z.get("external_refs"):
            out.append(
                Finding(
                    "ATT_REMOTE_TEMPLATE",
                    C,
                    "Document loads content from the internet",
                    f"'{name}' references an external template or object, a technique used to pull "
                    "malicious code in after delivery and bypass attachment scanners.",
                    30,
                    (name,),
                )
            )
        if z.get("encrypted") and not z.get("is_ooxml"):
            out.append(
                Finding(
                    "ATT_ENCRYPTED_ARCHIVE",
                    C,
                    "Password-protected archive",
                    f"'{name}' is encrypted, so no security scanner can look inside it. Attackers "
                    "send the password in the email body precisely for this reason.",
                    25,
                    (name,),
                )
            )
        risky_inner = z.get("inner_risky") or []
        if risky_inner and not z.get("is_ooxml"):
            out.append(
                Finding(
                    "ATT_ARCHIVE_RISKY",
                    C,
                    "Archive contains executable or web files",
                    f"'{name}' contains: {', '.join(clean(str(n), 50) for n in risky_inner)}.",
                    40,
                    (name,),
                )
            )
    elif head.startswith(b"\xd0\xcf\x11\xe0"):  # legacy OLE (.doc / .xls)
        if b"_VBA_PROJECT" in data or "_VBA_PROJECT".encode("utf-16-le") in data:
            out.append(
                Finding(
                    "ATT_MACRO",
                    C,
                    "Document contains macros",
                    f"'{name}' is a legacy Office file with VBA macros.",
                    30,
                    (name,),
                )
            )
    elif head.startswith(b"%PDF"):
        active = [
            k.decode() for k in (b"/JavaScript", b"/JS", b"/Launch", b"/OpenAction", b"/EmbeddedFile") if k in data
        ]
        if {"/JavaScript", "/JS", "/Launch"} & set(active):
            out.append(
                Finding(
                    "ATT_PDF_ACTIVE",
                    C,
                    "PDF contains active content",
                    f"'{name}' contains {', '.join(active)} - instructions that run code or launch "
                    "programs. Normal invoices and documents do not need this.",
                    30,
                    (name,),
                )
            )
    return out


def analyze(ctx: EmailContext) -> list[Finding]:
    out: list[Finding] = []
    for att in ctx.attachments:
        raw_name = att.filename
        name = clean(raw_name, 80)
        ext = _ext(raw_name)
        parts = [p.lower() for p in raw_name.split(".")]

        if has_hidden_unicode(raw_name):
            out.append(
                Finding(
                    "ATT_RTLO",
                    C,
                    "Filename uses hidden characters to fake its type",
                    f"'{name}' contains invisible direction-changing characters, so the extension you "
                    "see is not the real one.",
                    40,
                    (name,),
                    floor=70,
                )
            )
        if ext in EXECUTABLE_EXT:
            double = len(parts) >= 3 and parts[-2] in DOCUMENT_EXT
            out.append(
                Finding(
                    "ATT_EXECUTABLE",
                    C,
                    "Attachment is a program disguised as a document" if double else "Attachment is an executable file",
                    f"'{name}' is a .{ext} file, which runs code on your computer when opened."
                    + (" The extra extension is meant to make it look like a document." if double else ""),
                    50 if double else 45,
                    (name,),
                )
            )
        elif ext in HTML_EXT:
            out.append(
                Finding(
                    "ATT_HTML",
                    C,
                    "Web page sent as an attachment",
                    f"'{name}' opens a local web page in your browser. HTML and SVG attachments are a "
                    "leading way to show fake login pages while evading link scanners.",
                    25,
                    (name,),
                )
            )
        elif ext in MACRO_EXT:
            out.append(
                Finding(
                    "ATT_MACRO_EXT",
                    C,
                    "Macro-enabled Office document",
                    f"'{name}' is a macro-enabled format (.{ext}).",
                    20,
                    (name,),
                )
            )
        elif ext in ARCHIVE_EXT:
            out.append(
                Finding(
                    "ATT_ARCHIVE",
                    C,
                    "Compressed archive attached",
                    f"'{name}' is an archive. Archives are used to smuggle malware past filters.",
                    8,
                    (name,),
                )
            )

        data = ctx.attachment_bytes(att)
        if data:
            out.extend(_inspect(att, data))

    # A macro document can trigger both ATT_MACRO_EXT and ATT_MACRO: keep the stronger one.
    ids = {f.id for f in out}
    if "ATT_MACRO" in ids:
        out = [f for f in out if f.id != "ATT_MACRO_EXT"]
    return out
