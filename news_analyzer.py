import re
import requests
try:
    from bs4 import BeautifulSoup
    _BS4_OK = True
except ImportError:
    _BS4_OK = False
EMOTIONAL_WORDS = ['shocking', 'outrageous', 'devastating', 'explosive', 'bombshell', 'slams', 'destroys', 'blasts', 'terrifying', 'chilling', 'insane', 'unbelievable', "you won't believe", 'heartbreaking', 'furious', 'scandal', 'conspiracy', 'cover-up', 'exposed', 'sickening', 'disgusting', 'horrifying', 'alarming', 'stunning', 'jaw-dropping', 'mind-blowing', 'epic fail', 'meltdown', 'erupts', 'rages', 'slammed', 'brutal', 'savage', 'ripped apart', 'torn apart', 'annihilates', 'obliterates', 'warns', 'panic', 'chaos', 'crisis', 'catastrophe', 'nightmare', "won't believe what happens", 'goes viral', 'breaks the internet', 'secretly', 'shadowy', 'sinister', 'corrupt', 'rigged', 'hoax', 'fearmongering', 'wake up', "they don't want you to know", "mainstream media won't tell you", 'do your own research']
UNVERIFIED_ATTRIBUTION_PATTERNS = ['\\bsources say\\b', '\\bsome (?:say|claim|believe)\\b', '\\bit is (?:believed|said|rumored)\\b', '\\bmany people (?:think|believe|say)\\b', '\\ballegedly\\b', '\\breportedly\\b(?!.{0,40}(?:according to|,\\s*\\w+ said))', '\\baccording to (?:reports|sources)\\b(?!.{0,20}[A-Z][a-z]+ (?:News|Times|Post|Reuters|AP|Journal))', '\\binsiders (?:say|claim|reveal)\\b', '\\bexperts (?:say|warn|agree)\\b(?!.{0,30}(?:from|at)\\s+[A-Z])', '\\bcritics (?:say|argue|claim)\\b', "\\bwe've learned\\b", '\\bit has come to light\\b', '\\bwhispers (?:of|that)\\b', '\\bunnamed (?:official|source)s?\\b', '\\bpeople (?:are|have been) saying\\b', '\\bwidely (?:believed|reported|rumored)\\b', '\\bno one is talking about\\b', '\\bthe truth (?:is|about)\\b', "\\bwhat they don't want you to know\\b"]
LOW_EFFORT_DOMAIN_HINTS = ['\\.xyz$', '\\.top$', '\\.click$', '\\.info$', '\\bnews\\d+\\.', '\\btruth[- ]?\\w*\\.', '\\bdaily[a-z]*wire\\d*\\.', 'real[a-z]*news\\d*\\.']

def _fetch_article_text(url: str) -> dict:
    if not _BS4_OK:
        return {'ok': False, 'text': '', 'error': 'beautifulsoup4 is not installed.'}
    try:
        resp = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        return {'ok': False, 'text': '', 'error': f"Couldn't fetch the URL: {e}"}
    try:
        soup = BeautifulSoup(resp.text, 'html.parser')
        for tag in soup(['script', 'style', 'nav', 'header', 'footer', 'aside']):
            tag.decompose()
        paragraphs = [p.get_text(' ', strip=True) for p in soup.find_all('p')]
        text = '\n'.join((p for p in paragraphs if len(p) > 40))
        return {'ok': True, 'text': text, 'error': None}
    except Exception as e:
        return {'ok': False, 'text': '', 'error': f"Couldn't parse the page content: {e}"}

def _count_matches(text: str, patterns) -> int:
    count = 0
    lower = text.lower()
    for pat in patterns:
        count += len(re.findall(pat, lower, re.IGNORECASE))
    return count

def analyze_news(text: str='', url: str='') -> dict:
    source_note = None
    if url and (not text):
        fetched = _fetch_article_text(url)
        if not fetched['ok']:
            return {'ok': False, 'error': fetched['error']}
        text = fetched['text']
        source_note = url
        if len(text.strip()) < 100:
            return {'ok': False, 'error': "Fetched the page but couldn't find enough article text on it."}
    if not text or len(text.strip()) < 60:
        return {'ok': False, 'error': 'Please paste at least a few sentences of article text, or a URL.'}
    word_count = max(1, len(text.split()))
    emo_hits = sum((text.lower().count(w) for w in EMOTIONAL_WORDS))
    emo_density = emo_hits / (word_count / 100)
    emo_flag = emo_density > 0.7
    emo_score = float(min(1.0, emo_density / 2))
    caps_words = re.findall('\\b[A-Z]{3,}\\b', text)
    caps_ratio = len(caps_words) / word_count
    exclam_count = text.count('!')
    shout_flag = caps_ratio > 0.015 or exclam_count > 2
    shout_score = float(min(1.0, caps_ratio * 28 + exclam_count / 7))
    attribution_hits = _count_matches(text, UNVERIFIED_ATTRIBUTION_PATTERNS)
    attribution_flag = attribution_hits >= 1
    attribution_score = float(min(1.0, attribution_hits / 2))
    domain_flag = False
    domain_detail = 'No URL supplied, so the domain check was skipped.'
    if url:
        domain_flag = any((re.search(pat, url.lower()) for pat in LOW_EFFORT_DOMAIN_HINTS))
        domain_detail = f"The domain in '{url}' matches a shape sometimes seen on low-effort or content-farm sites. This is a shallow heuristic, not a credibility database - plenty of legitimate small outlets will also trip it." if domain_flag else f"The domain in '{url}' didn't match any of the low-effort domain shapes this tool checks for. That does not confirm it's a reputable source."
    domain_score = 1.0 if domain_flag else 0.0
    emotional_check = {'label': 'Heavy Emotional Language' if emo_flag else 'Neutral Tone', 'flagged': emo_flag, 'score': emo_score, 'detail': f'Found {emo_hits} emotionally loaded word(s) ({emo_density:.1f} per 100 words), which is on the higher end for straight news reporting.' if emo_flag else f'Found {emo_hits} emotionally loaded word(s) ({emo_density:.1f} per 100 words), within a typical range.'}
    shout_check = {'label': 'Clickbait-Style Formatting' if shout_flag else 'Standard Formatting', 'flagged': shout_flag, 'score': shout_score, 'detail': f'{len(caps_words)} ALL-CAPS word(s) and {exclam_count} exclamation mark(s) found - more shouting-style formatting than typical news writing.' if shout_flag else f'{len(caps_words)} ALL-CAPS word(s) and {exclam_count} exclamation mark(s) found - formatting looks like standard prose.'}
    attribution_check = {'label': 'Unverified/Vague Attribution' if attribution_flag else 'Attribution Looks Specific', 'flagged': attribution_flag, 'score': attribution_score, 'detail': f'Found {attribution_hits} instance(s) of vague sourcing ("sources say", "allegedly", "some believe") without a named, checkable source nearby.' if attribution_flag else f'Found {attribution_hits} instance(s) of vague sourcing - claims are mostly attributed to specific, named sources.'}
    domain_check = {'label': 'Domain Shape Flagged' if domain_flag else 'Domain Shape Not Flagged', 'flagged': domain_flag, 'score': domain_score, 'detail': domain_detail}
    weights = {'emotional': 0.5, 'formatting': 0.35, 'attribution': 0.55, 'domain': 0.35}
    risk = 1.0 - (1.0 - weights['emotional'] * emo_score) * (1.0 - weights['formatting'] * shout_score) * (1.0 - weights['attribution'] * attribution_score) * (1.0 - weights['domain'] * domain_score)
    risk_pct = round(risk * 100, 1)
    authenticity_pct = round(100 - risk_pct, 1)
    if risk_pct >= 60:
        verdict = 'High - several patterns associated with low-credibility content found.'
    elif risk_pct >= 30:
        verdict = 'Medium - some signals present, worth checking against other sources.'
    else:
        verdict = 'Low - writing style looks consistent with standard reporting.'
    return {'ok': True, 'word_count': word_count, 'source_note': source_note, 'emotional': emotional_check, 'formatting': shout_check, 'attribution': attribution_check, 'domain': domain_check, 'risk_pct': risk_pct, 'authenticity_pct': authenticity_pct, 'weights': weights, 'verdict': verdict}
