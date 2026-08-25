import io
import os
import re
import shutil
from datetime import datetime, timezone
from typing import Optional
try:
    import pytesseract
    from PIL import Image
    _OCR_IMPORT_OK = True
except ImportError:
    _OCR_IMPORT_OK = False

def _locate_tesseract_binary() -> Optional[str]:
    env_override = os.environ.get('TESSERACT_CMD') or os.environ.get('TESSERACT_PATH')
    if env_override and os.path.isfile(env_override):
        return env_override
    on_path = shutil.which('tesseract') or shutil.which('tesseract.exe')
    if on_path:
        return on_path
    if os.name == 'nt':
        candidates = []
        for env_var in ('PROGRAMFILES', 'PROGRAMFILES(X86)', 'LOCALAPPDATA', 'APPDATA'):
            base = os.environ.get(env_var)
            if base:
                candidates.append(os.path.join(base, 'Tesseract-OCR', 'tesseract.exe'))
        candidates.append('C:\\Tesseract-OCR\\tesseract.exe')
        candidates.append('C:\\Program Files\\Tesseract-OCR\\tesseract.exe')
        candidates.append('C:\\Program Files (x86)\\Tesseract-OCR\\tesseract.exe')
    else:
        # Common install locations that don't always end up on PATH,
        # e.g. Homebrew on Apple Silicon, or apps launched outside a shell.
        candidates = ['/usr/bin/tesseract', '/usr/local/bin/tesseract', '/opt/homebrew/bin/tesseract', '/opt/local/bin/tesseract', '/snap/bin/tesseract']
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None

def set_tesseract_path(path: str) -> dict:
    """Let the app (e.g. a Settings field) point at a tesseract binary manually."""
    global _TESSERACT_PATH
    path = (path or '').strip()
    if not path:
        _TESSERACT_PATH = _locate_tesseract_binary()
    elif os.path.isfile(path):
        _TESSERACT_PATH = path
    else:
        return {'ok': False, 'path': None, 'error': f"No file found at '{path}'."}
    if _OCR_IMPORT_OK and _TESSERACT_PATH:
        pytesseract.pytesseract.tesseract_cmd = _TESSERACT_PATH
    return {'ok': bool(_TESSERACT_PATH), 'path': _TESSERACT_PATH, 'error': None if _TESSERACT_PATH else 'Still not found automatically.'}
_TESSERACT_PATH = None
if _OCR_IMPORT_OK:
    _TESSERACT_PATH = _locate_tesseract_binary()
    if _TESSERACT_PATH:
        pytesseract.pytesseract.tesseract_cmd = _TESSERACT_PATH
_MONTHS = {'jan': 1, 'january': 1, 'feb': 2, 'february': 2, 'mar': 3, 'march': 3, 'apr': 4, 'april': 4, 'may': 5, 'jun': 6, 'june': 6, 'jul': 7, 'july': 7, 'aug': 8, 'august': 8, 'sep': 9, 'sept': 9, 'september': 9, 'oct': 10, 'october': 10, 'nov': 11, 'november': 11, 'dec': 12, 'december': 12}
_DATE_PATTERN = re.compile('\\b(\\d{1,2})\\s+([A-Za-z]{3,9})\\s+(\\d{4})\\b')
URGENCY_PATTERNS = ['\\bact now\\b', '\\bact fast\\b', '\\bwithin 24 hours\\b', '\\burgent\\b', '\\bverify (?:your|now)\\b', '\\bsuspend(?:ed)?\\b', '\\bclick (?:here|below)\\b', '\\blimited time\\b', '\\bimmediately\\b', '\\bconfirm your (?:account|identity)\\b']
FINANCIAL_TERMS = ['\\$\\s?[\\d,]+(?:\\.\\d{2})?', '₹\\s?[\\d,]+', '\\bUPI\\b', '\\btransaction id\\b', '\\breference (?:no|number|#)\\b', '\\btxn\\b', '\\bsent you\\b', '\\breceived\\b', '\\bcompleted\\b', '\\bpending\\b']
SUSPICIOUS_REQUEST_PATTERNS = ['\\botp\\b', '\\bone[- ]time pass(?:word|code)\\b', '\\bpin\\b', '\\bcvv\\b', '\\bgift card\\b', '\\bwire transfer\\b', '\\bcrypto\\b', '\\bbitcoin\\b', '\\bsend (?:money|cash|funds)\\b', '\\bpassword\\b', '\\bsocial security\\b']
SUSPICIOUS_DOMAIN_PATTERN = re.compile('\\b(?:https?://)?(?:[a-z0-9-]+\\.){2,}(?:xyz|top|click|support|verify|secure[a-z0-9-]*)\\b|\\b(?:https?://)?\\d{1,3}(?:\\.\\d{1,3}){3}\\b', re.IGNORECASE)

def _count_matches(text: str, patterns) -> int:
    count = 0
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            count += 1
    return count

def extract_text(image_bytes: bytes) -> dict:
    if not _OCR_IMPORT_OK:
        return {'ok': False, 'text': '', 'error': 'pytesseract/Pillow not installed.'}
    if not _TESSERACT_PATH:
        return {'ok': False, 'text': '', 'error': "Tesseract OCR isn't installed, or it's installed somewhere this app couldn't auto-detect (checked PATH plus the common Windows install folders). Install it from https://github.com/UB-Mannheim/tesseract/wiki - no PATH changes needed, just restart the app afterwards."}
    try:
        img = Image.open(io.BytesIO(image_bytes))
        text = pytesseract.image_to_string(img)
        return {'ok': True, 'text': text, 'error': None}
    except Exception as e:
        return {'ok': False, 'text': '', 'error': f'OCR unavailable ({e}).'}

def analyze_scam_text(image_bytes: bytes) -> dict:
    extracted = extract_text(image_bytes)
    if not extracted['ok']:
        return {'label': 'Text Content Not Scanned', 'flagged': False, 'score': 0.0, 'detail': f"Couldn't read text from the image ({extracted['error']}). This check is skipped rather than counted against the image - install Tesseract OCR to enable it.", 'source': 'unavailable'}
    text = extracted['text']
    if not text.strip():
        return {'label': 'No Text Found', 'flagged': False, 'score': 0.0, 'detail': 'OCR ran but found no readable text in the image.', 'source': 'ocr'}
    urgency_hits = _count_matches(text, URGENCY_PATTERNS)
    request_hits = _count_matches(text, SUSPICIOUS_REQUEST_PATTERNS)
    domain_hits = len(SUSPICIOUS_DOMAIN_PATTERN.findall(text))
    financial_hits = _count_matches(text, FINANCIAL_TERMS)
    raw = urgency_hits * 0.25 + request_hits * 0.35 + domain_hits * 0.4
    score = float(min(1.0, raw))
    flagged = score > 0.3
    reasons = []
    if urgency_hits:
        reasons.append(f'{urgency_hits} urgency/pressure phrase(s)')
    if request_hits:
        reasons.append(f'{request_hits} sensitive-info request phrase(s) (OTP, PIN, gift card, etc.)')
    if domain_hits:
        reasons.append(f'{domain_hits} suspicious-looking link/domain pattern(s)')
    if financial_hits and (not reasons):
        reasons.append('financial/transaction terms present, no other red flags')
    detail = 'Found: ' + '; '.join(reasons) + '.' if reasons else 'No urgency language, sensitive-info requests, or suspicious links detected in the extracted text.'
    detail += " This reads the screenshot's text only - it doesn't verify the transaction actually happened."
    return {'label': 'Suspicious Text Patterns' if flagged else 'No Suspicious Text Patterns', 'flagged': flagged, 'score': score, 'detail': detail, 'source': 'ocr', 'extracted_text': text.strip()}

def _extract_dates(text: str):
    found = []
    for day_s, month_s, year_s in _DATE_PATTERN.findall(text):
        month = _MONTHS.get(month_s.lower())
        if not month:
            continue
        try:
            found.append(datetime(int(year_s), month, int(day_s), tzinfo=timezone.utc))
        except ValueError:
            continue
    return found

def check_date_freshness(image_bytes: bytes, ocr_text: str=None) -> dict:
    if ocr_text is None:
        extracted = extract_text(image_bytes)
        if not extracted['ok']:
            return {'label': 'Date Not Checked', 'flagged': False, 'score': 0.0, 'detail': f"Couldn't read text from the image ({extracted['error']}), so the printed date couldn't be checked.", 'source': 'unavailable'}
        ocr_text = extracted['text']
    dates = _extract_dates(ocr_text)
    if not dates:
        return {'label': 'No Date Found in Text', 'flagged': False, 'score': 0.0, 'detail': "Couldn't find a readable transaction date in the screenshot's text, so this check was skipped.", 'source': 'ocr'}
    newest = max(dates)
    age_days = (datetime.now(timezone.utc) - newest).days
    if age_days > 3650 or age_days < -1:
        return {'label': 'No Date Found in Text', 'flagged': False, 'score': 0.0, 'detail': f"Found a date-like string ({newest.strftime('%d %b %Y')}) but it's implausible, likely an OCR misread, so this check was skipped.", 'source': 'ocr'}
    if age_days <= 3:
        score = 0.0
    elif age_days >= 180:
        score = 1.0
    else:
        score = float((age_days - 3) / (180 - 3))
    flagged = bool(score > 0.3)
    date_str = newest.strftime('%d %b %Y')
    if flagged:
        detail = f"The date printed in the screenshot is {date_str} - {age_days} day(s) ago. A screenshot being shown as proof of a payment that 'just happened' should carry today's or yesterday's date; a much older timestamp is a strong sign this is a recycled image (a common tactic: the same real or fake screenshot gets re-sent to different people over months or years) rather than a fresh transaction."
    else:
        detail = f'The date printed in the screenshot is {date_str} - {age_days} day(s) ago, consistent with a screenshot taken around the time it was sent.'
    return {'label': 'Outdated/Recycled Screenshot Date' if flagged else 'Date Looks Current', 'flagged': flagged, 'score': score, 'detail': detail, 'source': 'ocr', 'date_found': date_str, 'age_days': age_days}
