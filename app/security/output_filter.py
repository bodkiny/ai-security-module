import re

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?\d{1,3})?[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b")
KEY_RE = re.compile(r"\b(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b")


def redact_sensitive(text: str) -> tuple[str, list[str]]:
    redactions = []

    if EMAIL_RE.search(text):
        text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
        redactions.append("EMAIL")

    if PHONE_RE.search(text):
        text = PHONE_RE.sub("[REDACTED_PHONE]", text)
        redactions.append("PHONE")

    if KEY_RE.search(text):
        text = KEY_RE.sub("[REDACTED_KEY]", text)
        redactions.append("API_KEY")

    return text, redactions