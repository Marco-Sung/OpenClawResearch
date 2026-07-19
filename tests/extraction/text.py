# tests/extraction/text.py
#
# Text-extraction layer. This is the step a REAL email/web connector
# performs BEFORE any content reaches your sanitizer: turning raw MIME
# bytes or raw HTML into the plain-text string that safe_write() then
# validates.
#
# Why this matters for your research: the SAME hidden-text payload can
# survive or die depending purely on HOW extraction is done. A naive
# regex tag-strip leaves HTML comments behind; a proper DOM parser
# drops comments but still returns CSS-hidden text. So "did the attack
# work" is partly a question about the PARSER, not just the sanitizer -
# and that's a finding you can only surface by running content through
# a real extractor instead of pre-flattened strings.
#
# Each extractor is deliberately a DIFFERENT strategy so you can
# compare bypass rates across them. Pass the strategy name per-attack
# (see the "extract" field added to web/email payloads) to test which
# extraction choices are vulnerable to which hiding techniques.
 
import re
from email import message_from_string
from email.message import Message
 
try:
    from bs4 import BeautifulSoup, Comment
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False
 
 
# ── HTML EXTRACTORS ───────────────────────────────────────────────
 
def extract_html_naive_regex(html: str) -> str:
    """NAIVE strategy: strip tags with a regex. This is what a quick,
    hand-rolled extractor might do. Critically, it does NOT remove
    the CONTENTS of HTML comments - `<!-- payload -->` becomes
    ` payload ` because the regex only deletes the <...> tag markers,
    not what's between comment delimiters. So comment-hidden payloads
    SURVIVE this extractor. CSS-hidden text also survives (regex has
    no idea what CSS is)."""
    # remove the comment delimiters but leave inner text
    no_comment_tags = html.replace("<!--", " ").replace("-->", " ")
    # strip all remaining tags
    text = re.sub(r"<[^>]+>", " ", no_comment_tags)
    # collapse whitespace
    return re.sub(r"\s+", " ", text).strip()
 
 
def extract_html_bs4_get_text(html: str) -> str:
    """DOM strategy: BeautifulSoup .get_text(). Walks the parsed DOM
    tree. By default this DROPS HTML comments (they're a separate node
    type BeautifulSoup skips in get_text). BUT it still returns text
    inside display:none / off-screen elements, because get_text does
    NOT evaluate CSS. So: comment-hidden payload DIES here, but
    CSS-hidden payload SURVIVES. Different failure mode than the naive
    regex - that contrast is the interesting finding."""
    if not _BS4_AVAILABLE:
        raise RuntimeError("beautifulsoup4 not installed - add it to requirements.txt")
    soup = BeautifulSoup(html, "html.parser")
    return re.sub(r"\s+", " ", soup.get_text(separator=" ")).strip()
 
 
def extract_html_bs4_visible_only(html: str) -> str:
    """HARDENED strategy: BeautifulSoup, but ALSO strip comments
    explicitly AND drop elements whose inline style hides them
    (display:none / off-screen positioning). This is closer to what a
    security-conscious connector SHOULD do. Both comment-hidden and
    the common CSS-hidden tricks DIE here. Included so you can show a
    'here's what the fix looks like' comparison in your writeup.
    Note: this only catches INLINE style hiding - hiding via an
    external/embedded stylesheet class would still slip through, which
    is itself a documentable scope limit."""
    if not _BS4_AVAILABLE:
        raise RuntimeError("beautifulsoup4 not installed - add it to requirements.txt")
    soup = BeautifulSoup(html, "html.parser")
 
    # drop comment nodes
    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        c.extract()
 
    # drop inline-style-hidden elements
    hidden_pattern = re.compile(
        r"display\s*:\s*none|visibility\s*:\s*hidden|left\s*:\s*-\d{3,}",
        re.IGNORECASE,
    )
    for el in soup.find_all(style=hidden_pattern):
        el.extract()
 
    return re.sub(r"\s+", " ", soup.get_text(separator=" ")).strip()
 
 
def extract_html_css_aware(html: str) -> str:
    """CSS-AWARE strategy (step 4): bs4_visible_only only drops elements
    hidden via an INLINE style="" attribute. It does NOT parse <style>
    blocks, so an attacker hiding a payload via a stylesheet CLASS/ID
    selector (e.g. `<style>.note{display:none}</style>` + a plain
    `<div class="note">`, no inline style at all) slips straight through
    it. This extractor closes that gap: it parses embedded <style> block
    rules with a regex, resolves which elements each hidden selector
    matches using BeautifulSoup's real CSS selector engine (soupsieve,
    already a bs4 dependency, via .select()), and drops those elements --
    on top of the same inline-style/off-screen check bs4_visible_only
    already does.

    Scope limits, documented rather than silently assumed away: external
    stylesheets (`<link rel=stylesheet href=...>` pointing off-page) are
    NOT fetched or parsed, so hiding via an external CSS file still
    survives here. Selectors bs4/soupsieve can't parse (e.g. inside an
    `@media` block, or a combinator soupsieve doesn't support) are
    skipped rather than raising, so unusual CSS degrades to "not caught"
    rather than crashing extraction."""
    if not _BS4_AVAILABLE:
        raise RuntimeError("beautifulsoup4 not installed - add it to requirements.txt")
    soup = BeautifulSoup(html, "html.parser")

    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        c.extract()

    hide_rule = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.IGNORECASE)
    hidden_selectors = []
    for style_tag in soup.find_all("style"):
        css_text = style_tag.string or ""
        for selector_group, decls in re.findall(r"([^{}]+)\{([^{}]*)\}", css_text):
            if hide_rule.search(decls):
                hidden_selectors.extend(
                    s.strip() for s in selector_group.split(",") if s.strip()
                )

    for selector in hidden_selectors:
        try:
            for el in soup.select(selector):
                el.extract()
        except Exception:
            continue  # selector soupsieve can't parse -- skip, don't crash

    inline_hidden = re.compile(
        r"display\s*:\s*none|visibility\s*:\s*hidden|left\s*:\s*-\d{3,}",
        re.IGNORECASE,
    )
    for el in soup.find_all(style=inline_hidden):
        el.extract()

    return re.sub(r"\s+", " ", soup.get_text(separator=" ")).strip()


# ── EMAIL (MIME) EXTRACTORS ───────────────────────────────────────
 
def extract_email_plaintext_only(raw_email: str) -> str:
    """Reads ONLY the text/plain part of a MIME message. If an attacker
    puts a clean plaintext part and a malicious HTML part, this
    extractor never sees the HTML payload - it's blind to it. That's a
    documentable gap: 'connector reads plaintext only, so HTML-part
    injections bypass entirely.'"""
    msg: Message = message_from_string(raw_email)
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                return payload.decode(errors="replace") if payload else ""
        return ""  # no plaintext part at all
    payload = msg.get_payload(decode=True)
    return payload.decode(errors="replace") if payload else msg.get_payload()
 
 
def extract_email_all_parts(raw_email: str) -> str:
    """Reads text/plain AND runs any text/html part through the DOM
    extractor, concatenating both. Catches the HTML-part-injection the
    plaintext-only extractor misses - but now inherits whatever the
    HTML extractor's own blind spots are (e.g. CSS-hidden text). Shows
    how fixing one layer's gap can expose another."""
    msg: Message = message_from_string(raw_email)
    chunks = []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        ctype = part.get_content_type()
        if ctype == "text/plain":
            payload = part.get_payload(decode=True)
            if payload:
                chunks.append(payload.decode(errors="replace"))
        elif ctype == "text/html":
            payload = part.get_payload(decode=True)
            if payload:
                html = payload.decode(errors="replace")
                chunks.append(extract_html_bs4_get_text(html))
    return "\n".join(chunks).strip()
 
 
# ── STRATEGY REGISTRY ─────────────────────────────────────────────
# Lets payloads/runner pick an extractor by name.
 
HTML_EXTRACTORS = {
    "naive_regex": extract_html_naive_regex,
    "bs4_get_text": extract_html_bs4_get_text,
    "bs4_visible_only": extract_html_bs4_visible_only,
    "css_aware": extract_html_css_aware,
}
 
EMAIL_EXTRACTORS = {
    "plaintext_only": extract_email_plaintext_only,
    "all_parts": extract_email_all_parts,
}
 
 
def extract(raw: str, kind: str, strategy: str) -> str:
    """Unified entry point. kind='html' or 'email'; strategy is a key
    from the matching registry above. Returns the plain-text string
    that would then be handed to safe_write()."""
    if kind == "html":
        if strategy not in HTML_EXTRACTORS:
            raise KeyError(f"Unknown HTML strategy '{strategy}'. Options: {list(HTML_EXTRACTORS)}")
        return HTML_EXTRACTORS[strategy](raw)
    elif kind == "email":
        if strategy not in EMAIL_EXTRACTORS:
            raise KeyError(f"Unknown email strategy '{strategy}'. Options: {list(EMAIL_EXTRACTORS)}")
        return EMAIL_EXTRACTORS[strategy](raw)
    raise KeyError(f"Unknown kind '{kind}' - expected 'html' or 'email'")