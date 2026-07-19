# tests/extraction/pdf_color.py
#
# Shared REAL color-aware PDF text extraction (step 4c: unify the
# direct/transport asymmetry). Previously there were two different
# implementations of "the hardened PDF extractor":
#   - transport/received_files.py had a REAL content-stream color parse
#     (tracks fill-color operators, drops near-white text), but was
#     never verified against this harness's own generated PDFs -- its
#     own docstring flagged it "approximate + UNTESTED".
#   - extraction/files.py had a SPEC-LEVEL STAND-IN that just returned
#     spec["visible"] directly, without reading the generated PDF back
#     through any parser at all.
# That meant "does the hardened PDF filter catch this?" had two
# different, disagreeing answers depending on direct vs transport mode.
# This module is the single real implementation both paths now call.

import io


def filter_white_text(pdf_bytes: bytes) -> str:
    """Track the current fill color via PDF content-stream operators (g /
    rg / k) and drop text drawn while the fill is (near) white --
    catching the white-on-white hiding trick regardless of how the PDF
    reached the extractor. Approximate: only validated against
    reportlab-generated PDFs from this harness (see extraction/files.py
    and tests/diagnostics/*); a real connector would need broader
    testing (indexed/pattern/ICC color spaces aren't handled here)."""
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(pdf_bytes))
    out = []
    for page in reader.pages:
        state = {"white": False}
        kept: list[str] = []

        def before(op, args, cm, tm, _s=state):
            name = op.decode() if isinstance(op, (bytes, bytearray)) else str(op)
            try:
                if name == "g" and len(args) == 1:
                    _s["white"] = float(args[0]) >= 0.95
                elif name == "rg" and len(args) == 3:
                    _s["white"] = all(float(a) >= 0.95 for a in args)
                elif name == "k" and len(args) == 4:      # CMYK white = all 0
                    _s["white"] = all(float(a) <= 0.05 for a in args)
            except (TypeError, ValueError):
                pass

        def text(t, cm, tm, font, size, _s=state, _k=kept):
            if not _s["white"]:
                _k.append(t)

        page.extract_text(visitor_operand_before=before, visitor_text=text)
        out.append("".join(kept))
    return "\n".join(out).strip()
