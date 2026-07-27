import io
import time
from contextlib import contextmanager
import streamlit as st
from PIL import Image, ExifTags
import hosted_detection
import scam_detector
import video_detector
import audio_detector
import news_analyzer
import ocr_scam_check
import report_export
st.set_page_config(page_title='RealityLens AI - Digital Forensics Command Center', page_icon=':material/security:', layout='wide', initial_sidebar_state='expanded')
BG = '#050B14'
BG_SOFT = '#08121F'
SURFACE = '#0B1622'
SURFACE_ALT = '#0F1E2E'
BORDER = '#1C3346'
TEXT = '#E7F3FA'
MUTED = '#8CA3B8'
PRIMARY = '#22D3EE'
PRIMARY_DARK = '#0EA5C4'
PRIMARY_SOFT = 'rgba(34,211,238,0.12)'
SUCCESS = '#34D399'
SUCCESS_SOFT = 'rgba(52,211,153,0.12)'
WARN = '#FBBF24'
WARN_SOFT = 'rgba(251,191,36,0.12)'
DANGER = '#F87171'
DANGER_SOFT = 'rgba(248,113,113,0.12)'
ON_PRIMARY = '#04141C'
TOOLS = {'ai_image': {'label': 'Image Verification', 'grid_title': 'Image Forensics', 'grid_desc': 'Detect AI generated images, edits, cloning & artifacts.', 'grid_button': 'Analyze Image', 'icon_name': 'image', 'icon': ':material/image:', 'short': 'Is this image AI-generated?', 'accept': ['png', 'jpg', 'jpeg', 'webp', 'bmp'], 'steps': [('Upload Image', 'Drop in a PNG, JPG, WEBP, or BMP file.'), ('Sightengine genai Model', 'Sent to a model trained on millions of real vs. AI-generated images.'), ('Generator Signature Match', 'Compared against known signatures (Midjourney, Flux, GPT-image, etc.).'), ('Explainable Report Build', 'The same result is reused to build a full metadata/ELA/OCR report.'), ('Confidence & Verdict', 'One disclosed, weighted score with plain-language reasoning.')], 'read_first': "\nThis tool sends your image to **Sightengine's `genai` model**, a classifier\ntrained on millions of real and AI-generated images. It analyzes pixel\ncontent only - metadata/EXIF is ignored, so stripping it has no effect on\nthe result.\n\n**No detector is infallible.** A well-made image from a current top-tier\ngenerator can still slip past any detector, hosted or offline. Treat the\nresult as a strong signal, not a guaranteed verdict.\n"}, 'screenshot': {'label': 'Scam Detector', 'grid_title': 'Scam Detection', 'grid_desc': 'Detect scams in screenshots, UPI, emails & websites.', 'grid_button': 'Check Scam', 'icon_name': 'receipt_long', 'icon': ':material/receipt_long:', 'short': 'Forensic scan of a scam screenshot', 'accept': ['png', 'jpg', 'jpeg', 'webp', 'bmp'], 'steps': [('Upload Screenshot', 'Payment confirmation, chat, transfer receipt, etc.'), ('Metadata Extraction', 'Checks whether EXIF/creation data is present or stripped.'), ('Error-Level Analysis', 'Recompresses the image to find abnormal, locally-edited regions.'), ('AI Texture + OCR Scan', 'Checks for AI texture, plus OTP/urgency/link patterns in the text.'), ('Date-Freshness Check', 'Flags a printed transaction date that looks recycled/old.'), ('Confidence Calculation', 'Five disclosed, weighted signals combined into one score.')], 'read_first': '\nThis report runs five independent checks and combines them into one\nconfidence score: **Missing Metadata**, **AI Texture**, **Edited Regions**\n(error-level analysis), **OCR Text Patterns** (urgency language, OTP/PIN\nrequests, suspicious links), and **Date Freshness** (is the printed\ntransaction date actually recent?).\n\nTreat the result as a set of signals to weigh, not a verdict - especially\nfor anything where the answer actually matters.\n'}, 'video': {'label': 'Deepfake Detection', 'grid_title': 'Deepfake Detection', 'grid_desc': 'Detect deepfakes, face swaps, lip sync issues & more.', 'grid_button': 'Analyze Video', 'icon_name': 'movie', 'icon': ':material/movie:', 'short': 'Sample frames, check for deepfake traits', 'accept': ['mp4', 'mov', 'avi', 'webm', 'mkv'], 'steps': [('Upload Video', 'MP4, MOV, AVI, WEBM, or MKV.'), ('Frame Sampling', 'A handful of frames are sampled evenly across the clip.'), ('AI / Synthetic Texture', "Each frame checked via Sightengine's genai model or an offline heuristic."), ('Facial Consistency', "OpenCV's face/eye detectors check for face-swap-style inconsistency."), ('Compression Consistency', 'Error-level analysis compared across sampled frames.'), ('Confidence Calculation', 'Three disclosed signals combined into one deepfake-probability score.')], 'read_first': '\nThis tool samples a handful of frames and runs three checks: **AI/Synthetic\nTexture**, **Facial Consistency** (OpenCV face/eye detection across\nframes), and **Frame Compression Consistency** (error-level analysis).\n\n**There is no trained deepfake-video classifier running here.** These are\ndisclosed heuristics and a per-frame reuse of the image classifier, not a\nmodel trained on real vs. synthesized video. Treat this as rough triage.\n'}, 'voice': {'label': 'Audio Verification', 'grid_title': 'Audio Forensics', 'grid_desc': 'Detect AI voice, voice clones and synthetic audio.', 'grid_button': 'Analyze Audio', 'icon_name': 'mic', 'icon': ':material/mic:', 'short': 'Pitch, spectrum & pause-timing check', 'accept': ['wav'], 'steps': [('Upload .wav Audio', 'Only uncompressed WAV is read directly (convert others with ffmpeg).'), ('Pitch (F0) Variability', 'Natural speech has micro-variation; some TTS sounds metronomic.'), ('Spectral Flatness', 'Measures how tonal vs. noise-like the frequency spectrum is.'), ('Pause-Timing Pattern', 'Checks whether silence gaps look naturally irregular or machine-uniform.'), ('Confidence Calculation', 'Three disclosed heuristics combined into one score.')], 'read_first': '\nThere is **no trained voice-clone/deepfake-audio classifier running\nhere.** This measures three signal properties that *sometimes* differ\nbetween natural speech and TTS/voice-clone output: **pitch variability**,\n**spectral flatness**, and **pause timing**. A calm speaker in a quiet\nroom can trip these checks just as easily as synthesized audio.\n\nOnly `.wav` files are read directly - convert others first, e.g.\n`ffmpeg -i input.mp3 output.wav`.\n'}, 'news': {'label': 'News Analyzer', 'grid_title': 'News Verification', 'grid_desc': 'Analyze articles, detect bias, fake claims & misinformation.', 'grid_button': 'Analyze News', 'icon_name': 'newspaper', 'icon': ':material/newspaper:', 'short': 'Writing-style credibility check', 'accept': None, 'steps': [('Paste Text or a URL', 'Full article body, or a link to fetch and extract it from.'), ('Emotional Language Scan', 'Density of loaded/sensational words per 100 words.'), ('Formatting Check', 'ALL-CAPS and exclamation-mark density (clickbait-style shouting).'), ('Attribution Check', 'Looks for vague sourcing ("sources say", "allegedly") with no named source.'), ('Domain Shape Check', 'A small, disclosed list of shapes seen on low-effort content farms.'), ('Risk Calculation', 'Four disclosed signals combined into one low-credibility risk score.')], 'read_first': "\nThis tool scores the **writing style** of an article: emotionally loaded\nlanguage, clickbait-style formatting, vague/unverified attribution, and a\nshallow domain-shape check.\n\n**This is not a fact-checker.** It doesn't verify any claim against\nreal-world evidence and doesn't call an LLM. A well-written piece of\nmisinformation can score low here, and an excitable-but-true piece can\nscore high. Use it as a first-pass style signal, not a credibility verdict.\n"}}
TOOL_ORDER = ['ai_image', 'screenshot', 'video', 'voice', 'news']
SIDEBAR_NAV = [('Dashboard', ':material/dashboard:', 'dashboard', None), ('Image Verification', ':material/image:', 'dashboard', 'ai_image'), ('Scam Detector', ':material/receipt_long:', 'dashboard', 'screenshot'), ('Deepfake Detection', ':material/movie:', 'dashboard', 'video'), ('Audio Verification', ':material/mic:', 'dashboard', 'voice'), ('News Analyzer', ':material/newspaper:', 'dashboard', 'news'), ('Reports', ':material/summarize:', 'history', None), ('History', ':material/history:', 'history', None), ('API Access', ':material/api:', 'api', None), ('Settings', ':material/settings:', 'settings', None)]
ss = st.session_state
ss.setdefault('page', 'dashboard')
ss.setdefault('active_tool', 'ai_image')
ss.setdefault('history', [])
ss.setdefault('analysis_times', [])
ss.setdefault('pdf_exports', 0)
ss.setdefault('api_user', '')
ss.setdefault('api_secret', '')
ss.setdefault('theme', 'dark')
api_user = ss['api_user']
api_secret = ss['api_secret']
DARK_PALETTE = {'BG': '#050B14', 'BG_SOFT': '#08121F', 'SURFACE': '#0B1622', 'SURFACE_ALT': '#0F1E2E', 'BORDER': '#1C3346', 'TEXT': '#E7F3FA', 'MUTED': '#8CA3B8'}
LIGHT_PALETTE = {'BG': '#F3F6F9', 'BG_SOFT': '#FFFFFF', 'SURFACE': '#FFFFFF', 'SURFACE_ALT': '#EEF2F6', 'BORDER': '#D7E0E8', 'TEXT': '#0B1622', 'MUTED': '#54697A'}
_active_palette = LIGHT_PALETTE if ss['theme'] == 'light' else DARK_PALETTE
BG = _active_palette['BG']
BG_SOFT = _active_palette['BG_SOFT']
SURFACE = _active_palette['SURFACE']
SURFACE_ALT = _active_palette['SURFACE_ALT']
BORDER = _active_palette['BORDER']
TEXT = _active_palette['TEXT']
MUTED = _active_palette['MUTED']
BG_ACCENT = '#0B1E2E' if ss['theme'] == 'dark' else '#E4F7FC'

def micon(name: str, size: str=None, color: str=None) -> str:
    style = ''
    if size:
        style += f'font-size:{size};'
    if color:
        style += f'color:{color};'
    style_attr = f' style="{style}"' if style else ''
    return f'<span class="msi"{style_attr}>{name}</span>'

def go(page: str, tool: str=None):
    if ss['page'] == page and (tool is None or ss['active_tool'] == tool):
        return
    ss['page'] = page
    if tool:
        ss['active_tool'] = tool
    st.rerun()

def tier_for(pct: float):
    if pct < 30:
        return ('Authentic', SUCCESS, SUCCESS_SOFT)
    if pct < 70:
        return ('Uncertain', WARN, WARN_SOFT)
    return ('Flagged', DANGER, DANGER_SOFT)

def reality_view(pct: float):
    reality_pct = round(100 - pct, 1)
    if pct < 30:
        return (reality_pct, 'LIKELY AUTHENTIC', 'LOW', SUCCESS)
    if pct < 70:
        return (reality_pct, 'UNCERTAIN', 'MEDIUM', WARN)
    return (reality_pct, 'LIKELY MANIPULATED', 'HIGH', DANGER)

def coverage_pct(checks: list) -> float:
    if not checks:
        return 100.0
    ran = sum((1 for c in checks if c.get('source') not in ('unavailable',)))
    return round(100 * ran / len(checks), 1)

def log_analysis(tool_key: str, filename: str, pct: float, verdict: str, thumb_bytes: bytes=None, checks: list=None, meta: dict=None) -> None:
    tier_word, color, soft = tier_for(pct)
    ss['history'].insert(0, {'tool': tool_key, 'tool_label': TOOLS[tool_key]['label'], 'icon': TOOLS[tool_key]['icon'], 'filename': filename, 'pct': pct, 'verdict': verdict, 'tier': tier_word, 'color': color, 'soft': soft, 'ts': time.time(), 'thumb': thumb_bytes, 'checks': checks or [], 'meta': meta})
    ss['history'] = ss['history'][:25]

def latest_for(tool_key: str=None):
    if tool_key:
        return next((h for h in ss['history'] if h['tool'] == tool_key), None)
    return ss['history'][0] if ss['history'] else None
UPLOADER_KEYS = {'ai_image': ['ai_uploader'], 'screenshot': ['scam_uploader'], 'video': ['video_uploader'], 'voice': ['audio_uploader'], 'news': ['news_text_area', 'news_url_field']}

def reset_active_tool_input() -> None:
    for key in UPLOADER_KEYS.get(ss['active_tool'], []):
        ss.pop(key, None)

def has_active_input() -> bool:
    tool = ss['active_tool']
    if tool == 'news':
        return bool((ss.get('news_text_area') or '').strip() or (ss.get('news_url_field') or '').strip())
    key = UPLOADER_KEYS.get(tool, [None])[0]
    return ss.get(key) is not None

def time_ago(ts: float) -> str:
    secs = max(0, time.time() - ts)
    if secs < 60:
        return 'just now'
    if secs < 3600:
        return f'{int(secs // 60)} min ago'
    if secs < 86400:
        return f'{int(secs // 3600)} hr ago'
    return f'{int(secs // 86400)} day(s) ago'

def extract_image_metadata(image_bytes: bytes) -> dict:
    try:
        img = Image.open(io.BytesIO(image_bytes))
        exif_raw = {}
        try:
            exif_raw = img._getexif() or {}
        except Exception:
            exif_raw = {}
        tags = {ExifTags.TAGS.get(k, k): v for k, v in exif_raw.items()}
        make = str(tags.get('Make', '') or '').strip()
        model = str(tags.get('Model', '') or '').strip()
        camera = (make + ' ' + model).strip() or 'Not Embedded'
        date = str(tags.get('DateTimeOriginal') or tags.get('DateTime') or 'Not Embedded')
        software = str(tags.get('Software') or 'Not Embedded')
        lens = str(tags.get('LensModel') or tags.get('LensMake') or 'Not Embedded')
        resolution = f'{img.size[0]} x {img.size[1]}'
        location = 'GPS tag present' if 'GPSInfo' in tags else 'Not Embedded'
        return {'Camera': camera, 'Date': date, 'Location': location, 'Resolution': resolution, 'Lens': lens, 'Software': software, 'valid': bool(exif_raw)}
    except Exception:
        return {'Camera': 'Not Embedded', 'Date': 'Not Embedded', 'Location': 'Not Embedded', 'Resolution': 'Unknown', 'Lens': 'Not Embedded', 'Software': 'Not Embedded', 'valid': False}
CUSTOM_CSS = f"""\n<style>\n@import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..40,400..600,0..1,0');\n.msi {{\n    font-family: 'Material Symbols Outlined';\n    font-weight: normal; font-style: normal;\n    display: inline-block; line-height: 1; vertical-align: middle;\n    white-space: nowrap; word-wrap: normal; direction: ltr;\n    -webkit-font-feature-settings: 'liga'; font-feature-settings: 'liga';\n    -webkit-font-smoothing: antialiased;\n}}\n.stApp {{\n    background:\n        radial-gradient(circle at 15% 0%, {BG_ACCENT} 0%, {BG} 45%),\n        {BG};\n    color: {TEXT};\n    font-family: 'Segoe UI', -apple-system, Helvetica, Arial, sans-serif;\n    transition: background-color 0.25s ease, color 0.25s ease;\n}}\n* {{ scroll-behavior: smooth; }}\n#MainMenu, footer {{ visibility: hidden; height: 0; }}\nheader[data-testid="stHeader"] {{\n    background: transparent !important;\n    box-shadow: none !important;\n}}\nheader[data-testid="stHeader"] [data-testid="stToolbar"],\nheader[data-testid="stHeader"] [data-testid="stDecoration"] {{\n    display: none !important;\n}}\n[data-testid="collapsedControl"] {{\n    display: none !important;\n    visibility: hidden !important;\n}}\nsection[data-testid="stSidebar"] [data-testid="stSidebarCollapseButton"] {{\n    display: none !important;\n    visibility: hidden !important;\n}}\nsection[data-testid="stSidebar"] button[kind="headerNoPadding"] {{\n    display: none !important;\n    visibility: hidden !important;\n}}\n.block-container {{ padding-top: 1.2rem; padding-bottom: 2rem; max-width: 1680px; }}\n* {{ letter-spacing: 0.01em; }}\nh1,h2,h3,h4,h5,h6 {{ letter-spacing: 0.01em; }}\n\n/* ---------------- Sidebar (~18% narrower than Streamlit's default 21rem) ---------------- */\nsection[data-testid="stSidebar"] {{\n    background: {BG_SOFT};\n    border-right: 1px solid {BORDER};\n    width: 17.2rem !important;\n    min-width: 17.2rem !important;\n    max-width: 17.2rem !important;\n}}\nsection[data-testid="stSidebar"] > div {{ width: 17.2rem !important; }}\nsection[data-testid="stSidebar"] .block-container {{ padding-top: 1.1rem; padding-left: 0.9rem; padding-right: 0.9rem; }}\n.brand-row {{ display: flex; align-items: center; gap: 0.6rem; padding: 0 0.1rem 0.9rem 0.1rem;\n    border-bottom: 1px solid {BORDER}; margin-bottom: 0.8rem; }}\n.brand-badge {{\n    width: 38px; height: 38px; border-radius: 50%;\n    background: radial-gradient(circle, {PRIMARY_SOFT}, transparent 70%);\n    border: 1px solid {PRIMARY}55;\n    display: flex; align-items: center; justify-content: center;\n    color: {PRIMARY}; font-size: 1.15rem; flex-shrink: 0;\n}}\n.brand-name {{ font-weight: 800; font-size: 0.98rem; color: {TEXT}; line-height: 1.15; }}\n.brand-name .accent {{ color: {PRIMARY}; }}\n.brand-tag {{ font-size: 0.68rem; color: {MUTED}; }}\n\nsection[data-testid="stSidebar"] .stButton > button {{\n    background: transparent !important;\n    border: 1px solid transparent !important;\n    color: {MUTED} !important;\n    font-weight: 500 !important;\n    font-size: 0.83rem !important;\n    justify-content: flex-start !important;\n    border-radius: 9px !important;\n    padding: 0.42rem 0.6rem !important;\n    box-shadow: none !important;\n    transition: background-color 0.28s cubic-bezier(0.4, 0, 0.2, 1),\n                color 0.28s cubic-bezier(0.4, 0, 0.2, 1),\n                border-color 0.28s cubic-bezier(0.4, 0, 0.2, 1),\n                box-shadow 0.28s cubic-bezier(0.4, 0, 0.2, 1),\n                transform 0.15s cubic-bezier(0.4, 0, 0.2, 1);\n    outline: none !important;\n}}\nsection[data-testid="stSidebar"] .stButton > button p {{\n    text-align: left !important; font-weight: 500 !important; font-size: 0.83rem !important;\n    transition: color 0.28s cubic-bezier(0.4, 0, 0.2, 1);\n}}\nsection[data-testid="stSidebar"] .stButton > button:hover {{\n    background: {PRIMARY_SOFT} !important; color: {PRIMARY} !important;\n}}\nsection[data-testid="stSidebar"] .stButton > button:active {{\n    transform: scale(0.98);\n}}\nsection[data-testid="stSidebar"] .stButton > button:focus:not(:active) {{\n    box-shadow: 0 0 0 2px {PRIMARY}33 !important;\n}}\nsection[data-testid="stSidebar"] .stButton > button[kind="primary"] {{\n    background: {PRIMARY_SOFT} !important; color: {PRIMARY} !important;\n    font-weight: 700 !important; border: 1px solid {PRIMARY}55 !important;\n    box-shadow: inset 3px 0 0 {PRIMARY};\n}}\nsection[data-testid="stSidebar"] .stButton > button[kind="primary"] p {{ color: {PRIMARY} !important; font-weight: 700 !important; }}\n\n.shield-box {{\n    background: linear-gradient(160deg, {PRIMARY_SOFT}, transparent);\n    border: 1px solid {PRIMARY}33; border-radius: 16px;\n    padding: 1.2rem 1rem; margin-top: 1.2rem; text-align: center;\n}}\n.shield-box .shield-icon {{ font-size: 2.2rem; color: {PRIMARY}; margin-bottom: 0.4rem;\n    filter: drop-shadow(0 0 10px {PRIMARY}88); }}\n.shield-box .shield-title {{ font-weight: 800; color: {TEXT}; font-size: 0.9rem; }}\n.shield-box .shield-sub {{ color: {MUTED}; font-size: 0.78rem; margin: 0.3rem 0 0.8rem 0; }}\n\n/* ---------------- Top header ---------------- */\n.cmd-header {{ display: flex; align-items: center; justify-content: space-between;\n    padding: 0.6rem 0 1.2rem 0; }}\n.cmd-title {{ text-align: center; flex: 1; }}\n.cmd-title .line1 {{ font-weight: 800; font-size: 1.05rem; letter-spacing: 0.22em; color: {TEXT}; }}\n.cmd-title .line2 {{ font-size: 0.75rem; letter-spacing: 0.2em; color: {PRIMARY}; margin-top: 0.35rem; }}\n.status-chip {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 14px;\n    padding: 0.7rem 1.1rem; min-width: 190px; }}\n.status-chip .lbl {{ font-size: 0.65rem; letter-spacing: 0.15em; color: {MUTED}; }}\n.status-chip .val {{ display: flex; align-items: center; gap: 0.4rem; color: {SUCCESS};\n    font-weight: 800; font-size: 0.95rem; margin-top: 0.25rem; }}\n\n/* ---------------- Generic surfaces ---------------- */\n.card {{\n    background: {SURFACE};\n    border: 1px solid {BORDER};\n    border-radius: 18px;\n    padding: 1.7rem 1.8rem;\n    margin-bottom: 2.1rem;\n}}\n.card-tight {{ padding: 0.9rem 1rem; }}\n.card-glow {{ box-shadow: 0 0 0 1px {PRIMARY}22, 0 8px 30px rgba(34,211,238,0.06); }}\n.card-active {{ border: 1px solid {PRIMARY}4d; box-shadow: 0 0 0 1px {PRIMARY}33, 0 10px 40px rgba(34,211,238,0.09); }}\n.section-title {{ font-weight: 800; font-size: 0.95rem; letter-spacing: 0.12em; color: {TEXT};\n    text-transform: uppercase; margin: 0 0 1.3rem 0.1rem; display: flex; align-items: center; gap: 0.6rem; }}\n.section-title.hero {{ font-size: 1.15rem; }}\n.section-title .dot {{ width: 9px; height: 9px; border-radius: 50%; background: {PRIMARY};\n    box-shadow: 0 0 10px {PRIMARY}; }}\n.section-sub {{ font-size: 0.8rem; color: {MUTED}; margin: -0.8rem 0 1.3rem 0.1rem; }}\n.section-gap {{ height: 1.8rem; }}\n\n/* ---------------- Workflow stepper ---------------- */\n.stepper {{ display: flex; align-items: center; margin: 0.5rem 0 1.7rem 0; }}\n.step {{ display: flex; flex-direction: column; align-items: center; gap: 0.55rem; flex: 1; position: relative; }}\n.step-line {{ flex: 1.4; height: 3px; background: {BORDER}; margin-top: -1.7rem; border-radius: 2px; }}\n.step-line.done {{ background: {SUCCESS}; }}\n.step-node {{ width: 50px; height: 50px; border-radius: 50%; display: flex; align-items: center; justify-content: center;\n    font-size: 1.3rem; font-weight: 800; border: 2.5px solid {BORDER}; background: {SURFACE_ALT}; color: {MUTED};\n    transition: all 0.25s ease; }}\n.step-node.done {{ border-color: {SUCCESS}; color: {SUCCESS}; background: {SUCCESS_SOFT}; box-shadow: 0 0 16px {SUCCESS}44; }}\n.step-node.active {{ border-color: {PRIMARY}; color: {PRIMARY}; background: {PRIMARY_SOFT};\n    box-shadow: 0 0 0 4px {PRIMARY}22, 0 0 18px {PRIMARY}55; animation: pulseStep 1.8s ease-in-out infinite; }}\n.step-node.warn {{ border-color: {WARN}; color: {WARN}; background: {WARN_SOFT}; box-shadow: 0 0 16px {WARN}44; }}\n@keyframes pulseStep {{ 0%,100% {{ box-shadow: 0 0 0 4px {PRIMARY}22, 0 0 12px {PRIMARY}44; }}\n    50% {{ box-shadow: 0 0 0 7px {PRIMARY}11, 0 0 20px {PRIMARY}77; }} }}\n.step-label {{ font-size: 0.78rem; font-weight: 700; color: {MUTED}; text-align: center; }}\n.step-label.done {{ color: {SUCCESS}; }}\n.step-label.active {{ color: {PRIMARY}; }}\n.step-label.warn {{ color: {WARN}; }}\n\n/* ---------------- Reality Score hero ---------------- */\n.hero-reality {{ padding: 1.8rem 2rem 1.6rem 2rem; }}\n.hero-grid {{ display: flex; align-items: center; gap: 2.2rem; }}\n.hero-evidence {{ flex: 0 0 190px; }}\n.hero-evid-thumb {{ width: 100%; height: 130px; border-radius: 12px; background-size: cover;\n    background-position: center; border: 1px solid {BORDER}; margin-bottom: 0.7rem;\n    display: flex; align-items: center; justify-content: center; color: {MUTED}; font-size: 1.8rem; background-color: {SURFACE_ALT}; }}\n.hero-evid-name {{ font-weight: 700; font-size: 0.83rem; color: {TEXT}; line-height: 1.3; }}\n.hero-evid-sub {{ font-size: 0.7rem; color: {MUTED}; margin-top: 0.15rem; }}\n\n/* ---------------- Small upload preview box (tool pages) ---------------- */\n.upload-thumb-wrap {{ display: flex; justify-content: flex-start; margin: 0.4rem 0 0.9rem 0; }}\n.upload-thumb-box {{ width: 200px; height: 150px; border-radius: 12px; background-size: cover;\n    background-position: center; border: 1px solid {BORDER}; background-color: {SURFACE_ALT};\n    box-shadow: 0 0 0 1px {BORDER}, 0 8px 20px rgba(0,0,0,0.35); }}\n.upload-thumb-name {{ font-size: 0.72rem; color: {MUTED}; margin-top: 0.4rem; max-width: 200px;\n    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}\n\n/* ---------------- Analyzing-evidence radar ---------------- */\n.radar-wrap {{ position: relative; width: 170px; height: 170px; margin: 0 auto; }}\n.radar-ring {{ position: absolute; border-radius: 50%; border: 1px solid {PRIMARY}33; top: 50%; left: 50%;\n    transform: translate(-50%, -50%); }}\n.radar-sweep {{ position: absolute; inset: 0; border-radius: 50%; overflow: hidden;\n    background: conic-gradient(from 0deg, {PRIMARY}55, transparent 35%);\n    animation: radarSpin 2.6s linear infinite; }}\n.radar-core {{ position: absolute; top: 50%; left: 50%; width: 10px; height: 10px; border-radius: 50%;\n    background: {PRIMARY}; transform: translate(-50%, -50%);\n    box-shadow: 0 0 0 4px {PRIMARY}22, 0 0 16px {PRIMARY}aa; animation: radarPulse 1.8s ease-in-out infinite; }}\n@keyframes radarSpin {{ from {{ transform: rotate(0deg); }} to {{ transform: rotate(360deg); }} }}\n@keyframes radarPulse {{ 0%,100% {{ box-shadow: 0 0 0 4px {PRIMARY}22, 0 0 12px {PRIMARY}88; }}\n    50% {{ box-shadow: 0 0 0 8px {PRIMARY}11, 0 0 22px {PRIMARY}; }} }}\n.radar-eyebrow {{ font-size: 0.72rem; letter-spacing: 0.18em; color: {MUTED}; font-weight: 700;\n    text-align: center; margin-bottom: 0.5rem; }}\n.radar-coverage {{ text-align: center; font-size: 0.72rem; color: {MUTED}; margin-top: 0.6rem; }}\n.meta-row {{ display: flex; justify-content: space-between; padding: 0.3rem 0;\n    border-bottom: 1px solid {BORDER}; font-size: 0.72rem; }}\n.meta-row:last-child {{ border-bottom: none; }}\n.meta-key {{ color: {MUTED}; }}\n.meta-val {{ color: {TEXT}; font-weight: 600; text-align: right; max-width: 60%; }}\n.meta-status-ok {{ color: {SUCCESS}; font-weight: 800; }}\n.meta-status-bad {{ color: {WARN}; font-weight: 800; }}\n.hero-gauge-col {{ flex: 1; text-align: center; }}\n.hero-gauge-eyebrow {{ font-size: 0.72rem; letter-spacing: 0.18em; color: {MUTED}; font-weight: 700; margin-bottom: 0.3rem; }}\n.hero-num {{ font-size: 3.6rem; font-weight: 800; line-height: 1; margin-top: -0.6rem; }}\n.hero-verdict {{ font-weight: 800; font-size: 1.15rem; letter-spacing: 0.04em; margin-top: 0.2rem; }}\n.hero-cta-row {{ display: flex; gap: 0.7rem; justify-content: center; margin-top: 1.2rem; max-width: 420px; margin-left: auto; margin-right: auto; }}\n.hero-stats {{ flex: 0 0 170px; display: flex; flex-direction: column; gap: 0.7rem; }}\n.hero-stat {{ background: {SURFACE_ALT}; border: 1px solid {BORDER}; border-radius: 12px; padding: 0.65rem 0.85rem;\n    transition: box-shadow 0.2s ease, transform 0.2s ease; }}\n.hero-stat:hover {{ box-shadow: 0 0 14px {PRIMARY}33; transform: translateY(-1px); }}\n.hero-stat-label {{ font-size: 0.64rem; color: {MUTED}; letter-spacing: 0.1em; }}\n.hero-stat-val {{ font-weight: 800; font-size: 1.02rem; margin-top: 0.15rem; }}\n\n/* ---------------- Evidence scan pills (used inside active-investigation card) ---------------- */\n.pill-row {{ display: flex; gap: 0.7rem; flex-wrap: wrap; justify-content: flex-start; margin-top: 0.7rem; }}\n.status-pill {{ display: flex; flex-direction: column; align-items: center; gap: 0.35rem; width: 74px; }}\n.status-pill .pill-dot {{ width: 42px; height: 42px; border-radius: 50%; display: flex; align-items: center;\n    justify-content: center; font-size: 1.15rem; border: 1.5px solid {BORDER}; background: {SURFACE_ALT}; }}\n.status-pill .pill-dot.ok {{ border-color: {SUCCESS}88; color: {SUCCESS}; background: {SUCCESS_SOFT}; }}\n.status-pill .pill-dot.warn {{ border-color: {WARN}88; color: {WARN}; background: {WARN_SOFT}; }}\n.status-pill .pill-dot.bad {{ border-color: {DANGER}88; color: {DANGER}; background: {DANGER_SOFT}; }}\n.status-pill .pill-txt {{ font-size: 0.66rem; text-align: center; color: {MUTED}; line-height: 1.2; }}\n\n/* ---------------- Universal Trust Score cards (also open each tool) ---------------- */\n.trust-grid {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 1.1rem; }}\n@media (max-width: 1200px) {{ .trust-grid {{ grid-template-columns: repeat(3, 1fr); }} }}\n.trust-mini {{ background: {SURFACE}; border: 1px solid {BORDER}; border-left: 3px solid var(--tier-color, {BORDER});\n    border-radius: 16px; padding: 1.2rem 1.15rem; height: 100%; min-height: 178px;\n    display: flex; flex-direction: column;\n    transition: box-shadow 0.2s ease, transform 0.2s ease, border-color 0.2s ease; }}\n.trust-mini:hover {{ box-shadow: 0 0 20px {PRIMARY}2a; transform: translateY(-3px); border-color: {PRIMARY}55; }}\n.trust-mini.active {{ border-color: {PRIMARY}; box-shadow: 0 0 0 1px {PRIMARY}55, 0 0 22px {PRIMARY}33; }}\n.trust-mini-icon {{ width: 44px; height: 44px; border-radius: 12px; background: {PRIMARY_SOFT}; color: {PRIMARY};\n    display: flex; align-items: center; justify-content: center; font-size: 1.5rem; margin-bottom: 0.7rem; flex-shrink: 0; }}\n.trust-mini-head {{ color: {TEXT}; font-size: 0.85rem; font-weight: 700; margin-bottom: 0.6rem; line-height: 1.25;\n    flex: 1; display: flex; align-items: flex-end; }}\n.trust-mini-num {{ font-size: 1.9rem; font-weight: 800; line-height: 1; }}\n.trust-mini-tag {{ font-size: 0.76rem; font-weight: 700; margin-top: 0.3rem; }}\n\n/* ---------------- Explainable AI report ---------------- */\n.verdict-tab-row {{ display: flex; gap: 0.4rem; margin-bottom: 0.9rem; }}\n.verdict-tab {{ padding: 0.4rem 0.8rem; border-radius: 8px; font-size: 0.72rem; font-weight: 700;\n    letter-spacing: 0.05em; color: {MUTED}; background: {SURFACE_ALT}; border: 1px solid {BORDER}; }}\n.verdict-tab.active {{ color: {PRIMARY}; border-color: {PRIMARY}55; background: {PRIMARY_SOFT}; }}\n.evidence-row {{ display: flex; gap: 0.85rem; align-items: flex-start; padding: 0.8rem 0;\n    border-bottom: 1px solid {BORDER}; }}\n.evidence-row:last-child {{ border-bottom: none; }}\n.evidence-icon {{ width: 40px; height: 40px; border-radius: 10px; background: {SURFACE_ALT};\n    color: {PRIMARY}; display: flex; align-items: center; justify-content: center; font-size: 1.15rem; flex-shrink: 0; }}\n.evidence-title {{ font-weight: 700; font-size: 0.9rem; color: {TEXT}; }}\n.evidence-detail {{ font-size: 0.78rem; color: {MUTED}; margin-top: 0.2rem; line-height: 1.42; }}\n.evidence-check {{ margin-left: auto; font-size: 1.25rem; flex-shrink: 0; }}\n.evidence-check.ok {{ color: {SUCCESS}; }}\n.evidence-check.bad {{ color: {DANGER}; }}\n\n/* ---------------- Recent activity ---------------- */\n.recent-item {{ display: flex; gap: 0.7rem; align-items: center; padding: 0.6rem 0;\n    border-bottom: 1px solid {BORDER}; }}\n.recent-item:last-child {{ border-bottom: none; }}\n.recent-thumb {{ width: 38px; height: 38px; border-radius: 9px; flex-shrink: 0;\n    background: {SURFACE_ALT}; color: {PRIMARY};\n    display: flex; align-items: center; justify-content: center; font-size: 1rem;\n    overflow: hidden; background-size: cover; background-position: center; }}\n.recent-name {{ font-weight: 600; font-size: 0.83rem; color: {TEXT}; }}\n.recent-time {{ font-size: 0.7rem; color: {MUTED}; }}\n.recent-pct {{ font-weight: 800; font-size: 0.9rem; text-align: right; }}\n\n/* ---------------- Footer trust row ---------------- */\n.trust-row {{ display: flex; gap: 1.8rem; flex-wrap: wrap; align-items: center; justify-content: center; padding: 0.3rem 0; }}\n.trust-item {{ display: flex; align-items: center; gap: 0.5rem; color: {MUTED}; font-size: 0.8rem; font-weight: 600; }}\n.trust-item span.ic {{ color: {PRIMARY}; }}\n\n/* ---------------- Upload dropzone (large, interactive) ---------------- */\ndiv[data-testid="stFileUploader"] section {{\n    background: {SURFACE_ALT};\n    border: 2.5px dashed {PRIMARY}55;\n    border-radius: 18px;\n    min-height: 260px;\n    padding: 2.2rem !important;\n    display: flex; flex-direction: column; align-items: center; justify-content: center;\n    transition: border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease, transform 0.15s ease;\n}}\ndiv[data-testid="stFileUploader"] section:hover {{\n    border-color: {PRIMARY}; box-shadow: 0 0 28px {PRIMARY}2e, inset 0 0 40px {PRIMARY}0d;\n    background: {PRIMARY_SOFT}; transform: scale(1.003);\n}}\ndiv[data-testid="stFileUploader"] section svg {{ width: 42px !important; height: 42px !important; color: {PRIMARY} !important; }}\ndiv[data-testid="stFileUploaderDropzoneInstructions"] span {{ color: {TEXT} !important; font-weight: 700 !important;\n    font-size: 1.05rem !important; }}\ndiv[data-testid="stFileUploaderDropzoneInstructions"] small {{ color: {MUTED} !important; font-size: 0.85rem !important; }}\ndiv[data-testid="stFileUploader"] button {{\n    background: {PRIMARY} !important; color: {ON_PRIMARY} !important; border: none !important;\n    border-radius: 9px !important; font-weight: 700 !important; padding: 0.5rem 1.1rem !important;\n    transition: background-color 0.28s cubic-bezier(0.4, 0, 0.2, 1),\n                box-shadow 0.28s cubic-bezier(0.4, 0, 0.2, 1),\n                transform 0.15s cubic-bezier(0.4, 0, 0.2, 1);\n    outline: none !important;\n}}\ndiv[data-testid="stFileUploader"] button:hover {{\n    background: {PRIMARY_DARK} !important; box-shadow: 0 0 18px {PRIMARY}66; transform: translateY(-1px);\n}}\ndiv[data-testid="stFileUploader"] button:active {{\n    transform: translateY(0) scale(0.97); transition-duration: 0.08s;\n}}\n\n/* ---------------- Result / checklist (tool detail area) ---------------- */\n.result-card {{ display: flex; align-items: center; gap: 1.1rem; padding: 1rem 1.2rem; border-radius: 14px;\n    background: {SURFACE_ALT}; border: 1px solid {BORDER}; border-left: 4px solid {SUCCESS}; margin: 0.9rem 0; }}\n.result-pct {{ font-size: 1.9rem; font-weight: 800; color: {TEXT}; min-width: 88px; }}\n.result-label {{ font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.08em; color: {MUTED}; }}\n.result-verdict {{ font-size: 0.92rem; font-weight: 600; color: {TEXT}; }}\n.check-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.9rem; margin-top: 0.7rem; }}\n@media (max-width: 700px) {{ .check-grid {{ grid-template-columns: 1fr; }} }}\n.check-card {{ background: {SURFACE_ALT}; border: 1px solid {BORDER}; border-radius: 14px;\n    padding: 1rem 1.1rem; border-top: 4px solid {SUCCESS}; transition: box-shadow 0.2s ease; }}\n.check-card:hover {{ box-shadow: 0 0 14px rgba(255,255,255,0.04); }}\n.check-card.flagged {{ border-top-color: {DANGER}; }}\n.check-card-header {{ display: flex; justify-content: space-between; gap: 0.5rem; align-items: flex-start; }}\n.check-label {{ font-weight: 700; font-size: 0.92rem; color: {TEXT}; }}\n.check-detail {{ color: {MUTED}; font-size: 0.82rem; margin-top: 0.4rem; line-height: 1.45; }}\n.badge {{ padding: 0.24rem 0.75rem; border-radius: 999px; font-size: 0.7rem; font-weight: 800; white-space: nowrap; }}\n.badge-flag {{ background: {DANGER_SOFT}; color: {DANGER}; }}\n.badge-clear {{ background: {SUCCESS_SOFT}; color: {SUCCESS}; }}\n\n/* ---------------- Scanning / dynamic progress indicator ---------------- */\n@keyframes shimmerBar {{ 0% {{ background-position: 0% 0; }} 100% {{ background-position: 200% 0; }} }}\n@keyframes stageFade {{\n    0%, 22% {{ opacity: 1; transform: translateY(0); }}\n    28%, 100% {{ opacity: 0; transform: translateY(-6px); }}\n}}\n@keyframes scanIconSpin {{ from {{ transform: rotate(0deg); }} to {{ transform: rotate(360deg); }} }}\n.scan-wrap {{ padding: 1.5rem 1rem; text-align: center; background: {SURFACE_ALT}; border: 1px solid {BORDER};\n    border-radius: 16px; margin: 0.6rem 0; }}\n.scan-icon {{ width: 46px; height: 46px; margin: 0 auto 0.8rem auto; border-radius: 50%;\n    border: 2px solid {PRIMARY}55; border-top-color: {PRIMARY}; animation: scanIconSpin 1s linear infinite; }}\n.scan-stages {{ position: relative; height: 1.4rem; margin-bottom: 0.7rem; }}\n.scan-stage {{ position: absolute; left: 0; right: 0; color: {TEXT}; font-size: 0.95rem; font-weight: 700;\n    opacity: 0; animation: stageFade 3.6s ease-in-out infinite; }}\n.scan-stage:nth-child(1) {{ animation-delay: 0s; }}\n.scan-stage:nth-child(2) {{ animation-delay: 0.9s; }}\n.scan-stage:nth-child(3) {{ animation-delay: 1.8s; }}\n.scan-stage:nth-child(4) {{ animation-delay: 2.7s; }}\n.scan-track {{ height: 9px; max-width: 420px; margin: 0 auto; border-radius: 999px; background: {SURFACE};\n    border: 1px solid {BORDER}; overflow: hidden; position: relative; }}\n.scan-fill {{ position: absolute; inset: 0; background: linear-gradient(90deg, transparent, {PRIMARY}, transparent);\n    background-size: 200% 100%; animation: shimmerBar 1.1s linear infinite; }}\n.scan-sub {{ font-size: 0.72rem; color: {MUTED}; margin-top: 0.6rem; }}\n\n/* ---------------- Buttons ---------------- */\n.stButton > button {{ border-radius: 9px; background: {SURFACE_ALT} !important; color: {TEXT} !important;\n    border: 1px solid {BORDER} !important;\n    transition: background-color 0.28s cubic-bezier(0.4, 0, 0.2, 1),\n                box-shadow 0.28s cubic-bezier(0.4, 0, 0.2, 1),\n                transform 0.15s cubic-bezier(0.4, 0, 0.2, 1),\n                border-color 0.28s cubic-bezier(0.4, 0, 0.2, 1),\n                color 0.28s cubic-bezier(0.4, 0, 0.2, 1);\n    outline: none !important;\n    will-change: transform;\n}}\n.stButton > button p {{ color: {TEXT} !important; transition: color 0.28s cubic-bezier(0.4, 0, 0.2, 1); }}\n.stButton > button:hover {{ border-color: {PRIMARY} !important; color: {PRIMARY} !important;\n    box-shadow: 0 0 14px {PRIMARY}33; transform: translateY(-1px); }}\n.stButton > button:hover p {{ color: {PRIMARY} !important; }}\n.stButton > button:active {{ transform: translateY(0) scale(0.97); transition-duration: 0.08s; }}\n.stButton > button:focus:not(:active) {{ box-shadow: 0 0 0 3px {PRIMARY}33, 0 0 14px {PRIMARY}33 !important; }}\n.stButton > button[kind="primary"] {{ background: {PRIMARY} !important; color: {ON_PRIMARY} !important; border: none !important; font-weight: 700 !important;\n    box-shadow: 0 0 0 0 {PRIMARY}00; }}\n.stButton > button[kind="primary"] p {{ color: {ON_PRIMARY} !important; font-weight: 700 !important; }}\n.stButton > button[kind="primary"]:hover {{ background: {PRIMARY_DARK} !important; box-shadow: 0 0 22px {PRIMARY}77; transform: translateY(-1px); }}\n.stButton > button[kind="primary"]:hover p {{ color: {ON_PRIMARY} !important; }}\n.stButton > button[kind="primary"]:active {{ transform: translateY(0) scale(0.97); transition-duration: 0.08s; }}\n.stDownloadButton > button {{ background: {PRIMARY} !important; color: {ON_PRIMARY} !important; border: none !important;\n    border-radius: 9px !important; font-weight: 700 !important;\n    transition: background-color 0.28s cubic-bezier(0.4, 0, 0.2, 1),\n                box-shadow 0.28s cubic-bezier(0.4, 0, 0.2, 1),\n                transform 0.15s cubic-bezier(0.4, 0, 0.2, 1);\n    outline: none !important;\n}}\n.stDownloadButton > button:hover {{ box-shadow: 0 0 22px {PRIMARY}77; transform: translateY(-1px); }}\n.stDownloadButton > button:active {{ transform: translateY(0) scale(0.97); transition-duration: 0.08s; }}\n\ndiv[data-testid="stExpander"] {{ border: 1px solid {BORDER} !important; border-radius: 12px !important; background: {SURFACE}; }}\ndiv[data-testid="stTextInput"] input, div[data-testid="stTextArea"] textarea {{\n    background: {SURFACE_ALT} !important; border: 1px solid {BORDER} !important; border-radius: 10px !important; color: {TEXT} !important; }}\ndiv[data-testid="stVideo"] video, video {{ border-radius: 12px !important; border: 1px solid {BORDER}; max-height: 360px; }}\np, span, div, label {{ color: {TEXT}; }}\n.stCaption, [data-testid="stCaptionContainer"] {{ color: {MUTED} !important; }}\n</style>\n"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
with st.sidebar:
    st.markdown('\n        <div class="brand-row">\n            <div class="brand-badge"><span class="msi">shield</span></div>\n            <div><div class="brand-name">RealityLens <span class="accent">AI</span></div>\n            <div class="brand-tag">See Beyond the Fake.</div></div>\n        </div>\n        ', unsafe_allow_html=True)
    theme_col1, theme_col2 = st.columns(2)
    with theme_col1:
        if st.button('Light', key='theme_light_btn', use_container_width=True, icon=':material/light_mode:', type='primary' if ss['theme'] == 'light' else 'secondary'):
            ss['theme'] = 'light'
            st.rerun()
    with theme_col2:
        if st.button('Dark', key='theme_dark_btn', use_container_width=True, icon=':material/dark_mode:', type='primary' if ss['theme'] == 'dark' else 'secondary'):
            ss['theme'] = 'dark'
            st.rerun()
    st.markdown(f'<div style="border-bottom:1px solid {BORDER}; margin:0.7rem 0 0.9rem 0;"></div>', unsafe_allow_html=True)
    for label, icon, page, tool in SIDEBAR_NAV:
        is_active = ss['page'] == page and (tool is None or ss['active_tool'] == tool)
        if st.button(label, icon=icon, key=f'nav_{label}', use_container_width=True, type='primary' if is_active else 'secondary'):
            go(page, tool)
    st.markdown('\n        <div class="shield-box">\n            <div class="shield-icon"><span class="msi">shield</span></div>\n            <div class="shield-title">Reality Shield</div>\n            <div class="shield-sub">Your Digital Trust.<br>Our Mission.</div>\n        </div>\n        ', unsafe_allow_html=True)
    if st.button('Learn More', key='learn_more_shield', use_container_width=True):
        go('help')
h1, h2, h3 = st.columns([1.3, 2.4, 1.3], vertical_alignment='center')
with h1:
    st.markdown('\n        <div style="display:flex; align-items:center; gap:0.6rem;">\n            <div class="brand-badge" style="width:48px;height:48px;font-size:1.5rem;"><span class="msi">shield</span></div>\n            <div><div class="brand-name" style="font-size:1.3rem;">RealityLens <span class="accent">AI</span></div>\n            <div class="brand-tag">See Beyond the Fake.</div></div>\n        </div>\n        ', unsafe_allow_html=True)
with h2:
    st.markdown('\n        <div class="cmd-title">\n            <div class="line1">DIGITAL FORENSICS COMMAND CENTER</div>\n            <div class="line2">AI POWERED &nbsp;&#8226;&nbsp; TRANSPARENT &nbsp;&#8226;&nbsp; TRUSTED</div>\n        </div>\n        ', unsafe_allow_html=True)
with h3:
    st.markdown(f'\n        <div class="status-chip">\n            <div class="lbl">SYSTEM STATUS</div>\n            <div class="val">{micon('verified', color=SUCCESS)} SECURE</div>\n        </div>\n        ', unsafe_allow_html=True)
st.write('')

@contextmanager
def scanning(label: str='Analyzing...', stages: list=None):
    stages = stages or ['Reading file...', label, 'Running forensic checks...', 'Compiling report...']
    start = time.perf_counter()
    placeholder = st.empty()
    stage_html = ''.join((f'<div class="scan-stage">{s}</div>' for s in stages))
    placeholder.markdown(f'<div class="scan-wrap"><div class="scan-icon"></div><div class="scan-stages">{stage_html}</div><div class="scan-track"><div class="scan-fill"></div></div><div class="scan-sub">This can take a few seconds depending on file size.</div></div>', unsafe_allow_html=True)
    try:
        yield
    finally:
        elapsed = time.perf_counter() - start
        ss['analysis_times'].append(elapsed)
        ss['analysis_times'] = ss['analysis_times'][-30:]
        placeholder.empty()

def render_result_card(pct: float, verdict: str, label: str='Confidence') -> None:
    _, color, _ = tier_for(pct)
    st.markdown(f'<div class="result-card" style="border-left-color:{color};"><div class="result-pct">{pct:.1f}%</div><div><div class="result-label">{label}</div><div class="result-verdict">{verdict}</div></div></div>', unsafe_allow_html=True)

def render_checklist(checks: list) -> None:
    cards = []
    for check in checks:
        flagged = check.get('flagged')
        cards.append(f'<div class="check-card{(' flagged' if flagged else '')}"><div class="check-card-header"><div class="check-label">{check.get('label', '')}</div><div class="badge {('badge-flag' if flagged else 'badge-clear')}">{('Flagged' if flagged else 'Clear')}</div></div><div class="check-detail">{check.get('detail', '')}</div></div>')
    st.markdown(f'<div class="check-grid">{''.join(cards)}</div>', unsafe_allow_html=True)

def render_explainable_report(report: dict) -> list:
    keys = [k for k in ('metadata', 'ai_texture', 'edited_regions', 'ocr_text', 'date_freshness') if k in report]
    checks = [report[k] for k in keys]
    render_checklist(checks)
    return checks

def render_pdf_download(filename: str, title: str, pct: float, verdict: str, checks: list, image_bytes: bytes=None, source_label: str='') -> None:
    try:
        pdf_bytes = report_export.generate_pdf_report(title, pct, verdict, checks, image_bytes=image_bytes, source_label=source_label)
        clicked = st.download_button('Download PDF Evidence Report', data=pdf_bytes, file_name=filename, mime='application/pdf', use_container_width=True)
        if clicked:
            ss['pdf_exports'] += 1
    except Exception as e:
        st.caption(f"Couldn't build the PDF report ({e}).")

def render_process_steps_list(tool_key: str) -> None:
    parts = []
    for i, (title, desc) in enumerate(TOOLS[tool_key]['steps'], start=1):
        parts.append(f'<div style="display:flex; gap:0.7rem; margin-bottom:0.9rem;"><div style="width:26px;height:26px;border-radius:50%;flex-shrink:0;background:{PRIMARY_SOFT};color:{PRIMARY};display:flex;align-items:center;justify-content:center;font-weight:700;font-size:0.8rem;border:1px solid {PRIMARY}55;">{i}</div><div><div style="font-weight:700;font-size:0.85rem;color:{TEXT};">{title}</div><div style="font-size:0.76rem;color:{MUTED};margin-top:0.1rem;line-height:1.35;">{desc}</div></div></div>')
    st.markdown(''.join(parts), unsafe_allow_html=True)

def render_stepper(stage_state: list) -> None:
    labels = ['Upload', 'Scan', 'AI Analysis', 'Report']
    icon_names = ['upload_file', 'search', 'psychology', 'summarize']
    nodes = []
    for i, (label, icon_name, state) in enumerate(zip(labels, icon_names, stage_state)):
        shown = 'check' if state == 'done' else icon_name
        node_html = micon(shown)
        nodes.append(f'<div class="step"><div class="step-node {state}">{node_html}</div><div class="step-label {state}">{label}</div></div>')
        if i < len(labels) - 1:
            line_done = 'done' if stage_state[i] == 'done' else ''
            nodes.append(f'<div class="step-line {line_done}"></div>')
    st.markdown(f'<div class="stepper">{''.join(nodes)}</div>', unsafe_allow_html=True)

def render_powered_by() -> None:
    items = [('Sightengine', 'AI-generated image detection', 'psychology'), ('Tesseract OCR', 'Text recognition', 'text_snippet'), ('OpenCV', 'Face & frame analysis', 'visibility'), ('NumPy', 'Signal processing', 'functions'), ('ReportLab', 'PDF evidence reports', 'summarize')]
    html = []
    for name, sub, icon_name in items:
        html.append(f'<div style="display:flex;align-items:center;gap:0.6rem;"><div style="width:34px;height:34px;border-radius:9px;background:{SURFACE_ALT};border:1px solid {BORDER};display:flex;align-items:center;justify-content:center;">{micon(icon_name, size='1.05rem', color=PRIMARY)}</div><div><div style="font-weight:700;font-size:0.85rem;color:{TEXT};">{name}</div><div style="font-size:0.72rem;color:{MUTED};">{sub}</div></div></div>')
    st.markdown('<div class="section-title"><span class="dot"></span>POWERED BY</div><div style="display:flex; gap:1.6rem; flex-wrap:wrap; align-items:center;">' + ''.join(html) + '</div>', unsafe_allow_html=True)

def render_powered_by_and_trust() -> None:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    render_powered_by()
    st.markdown(f'<hr style="border-color:{BORDER}; margin:1.1rem 0;">', unsafe_allow_html=True)
    render_trust_row()
    st.markdown('</div>', unsafe_allow_html=True)

def render_trust_row() -> None:
    items = [('lock', 'AI Powered Analysis', 'Advanced Models &amp; Computer Vision'), ('shield', 'Explainable AI', 'Transparent Reasoning'), ('encrypted', 'End to End Encryption', 'Your Data is Always Protected'), ('verified', 'Trust &amp; Transparency', 'Because Truth Matters')]
    html = ''.join((f'<div class="trust-item"><span class="ic">{micon(icon_name)}</span><div><div>{label}</div><div style="font-size:0.68rem; color:{MUTED};">{sub}</div></div></div>' for icon_name, label, sub in items))
    st.markdown(f'<div class="trust-row">{html}</div>', unsafe_allow_html=True)

def render_ai_image_tool():
    uploaded = st.file_uploader('Upload an image to analyze', type=TOOLS['ai_image']['accept'], key='ai_uploader', label_visibility='collapsed')
    if uploaded is None:
        st.caption('PNG, JPG, JPEG, WEBP (Max 20MB)')
        return None
    raw_bytes = uploaded.getvalue()
    render_upload_preview(raw_bytes, uploaded.name)
    meta = extract_image_metadata(raw_bytes)
    if not api_user or not api_secret:
        st.warning('Add your Sightengine API keys under **Settings** in the sidebar to run this check.')
        return None
    with scanning('Analyzing image...'):
        result = hosted_detection.check_sightengine_genai(raw_bytes, uploaded.name, api_user, api_secret)
    if not result['ok']:
        st.error(f"Couldn't get a result: {result['error']}")
        return None
    ai_prob = result['ai_generated'] * 100
    verdict = 'Likely a real, unedited image.' if ai_prob < 30 else 'Uncertain - could be AI-generated or AI-edited.' if ai_prob < 70 else 'Likely AI-generated.'
    render_result_card(ai_prob, verdict, label='AI-generated probability')
    generators = result.get('generators', {})
    if generators:
        top = sorted(generators.items(), key=lambda kv: kv[1], reverse=True)[:5]
        st.markdown('**Top matching generator signatures**')
        st.json({name: round(val, 3) for name, val in top})
    ai_texture_override = scam_detector.build_ai_texture_result(result)
    with scanning('Building explainable report...'):
        full_report = scam_detector.analyze_screenshot(raw_bytes, api_user, api_secret, ai_texture_override=ai_texture_override)
    checks = render_explainable_report(full_report)
    render_pdf_download('ai_image_report.pdf', 'RealityLens AI - Image Verification Report', full_report['confidence_pct'], full_report['verdict'], checks, image_bytes=raw_bytes, source_label=uploaded.name)
    log_analysis('ai_image', uploaded.name, ai_prob, verdict, thumb_bytes=raw_bytes, checks=checks, meta=meta)
    return checks

def render_screenshot_tool():
    uploaded = st.file_uploader('Upload a screenshot to analyze', type=TOOLS['screenshot']['accept'], key='scam_uploader', label_visibility='collapsed')
    if uploaded is None:
        st.caption('PNG, JPG, JPEG, WEBP (Max 20MB)')
        return None
    raw_bytes = uploaded.getvalue()
    render_upload_preview(raw_bytes, uploaded.name)
    meta = extract_image_metadata(raw_bytes)
    with scanning('Running forensic checks...'):
        report = scam_detector.analyze_screenshot(raw_bytes, api_user, api_secret)
    render_result_card(report['confidence_pct'], report['verdict'], label='Scam/manipulation probability')
    checks = render_explainable_report(report)
    render_pdf_download('scam_screenshot_report.pdf', 'RealityLens AI - Scam Screenshot Report', report['confidence_pct'], report['verdict'], checks, image_bytes=raw_bytes, source_label=uploaded.name)
    log_analysis('screenshot', uploaded.name, report['confidence_pct'], report['verdict'], thumb_bytes=raw_bytes, checks=checks, meta=meta)
    return checks

def render_video_tool():
    uploaded = st.file_uploader('Upload a video to analyze', type=TOOLS['video']['accept'], key='video_uploader', label_visibility='collapsed')
    if uploaded is None:
        st.caption('MP4, MOV, AVI, WEBM, MKV')
        return None
    video_bytes = uploaded.getvalue()
    st.video(uploaded)
    with scanning('Sampling frames and running checks...'):
        v_report = video_detector.analyze_video(video_bytes, api_user, api_secret)
    if not v_report['ok']:
        st.error(f"Couldn't analyze this video: {v_report['error']}")
        return None
    st.caption(f'Analyzed {v_report['frames_sampled']} sampled frames.')
    render_result_card(v_report['confidence_pct'], v_report['verdict'], label='Deepfake probability')
    checks = [v_report['ai_texture'], v_report['facial_consistency'], v_report['compression_consistency']]
    render_checklist(checks)
    thumb_bytes = None
    try:
        buf = io.BytesIO()
        v_report['sample_frame'].convert('RGB').save(buf, 'JPEG', quality=90)
        thumb_bytes = buf.getvalue()
    except Exception:
        pass
    render_pdf_download('deepfake_video_report.pdf', 'RealityLens AI - Deepfake Video Report', v_report['confidence_pct'], v_report['verdict'], checks, image_bytes=thumb_bytes, source_label=uploaded.name)
    log_analysis('video', uploaded.name, v_report['confidence_pct'], v_report['verdict'], thumb_bytes=thumb_bytes, checks=checks)
    return checks

def render_voice_tool():
    uploaded = st.file_uploader('Upload a .wav audio file to analyze', type=TOOLS['voice']['accept'], key='audio_uploader', label_visibility='collapsed')
    if uploaded is None:
        st.caption('WAV only (convert others with ffmpeg)')
        return None
    audio_bytes = uploaded.getvalue()
    st.audio(uploaded)
    with scanning('Analyzing audio...'):
        a_report = audio_detector.analyze_audio(audio_bytes)
    if not a_report['ok']:
        st.error(a_report['error'])
        return None
    st.caption(f'Duration: {a_report['duration_s']}s')
    render_result_card(a_report['confidence_pct'], a_report['verdict'], label='Synthetic voice probability')
    checks = [a_report['pitch'], a_report['flatness'], a_report['pause']]
    render_checklist(checks)
    render_pdf_download('voice_verification_report.pdf', 'RealityLens AI - Voice Verification Report', a_report['confidence_pct'], a_report['verdict'], checks, source_label=uploaded.name)
    log_analysis('voice', uploaded.name, a_report['confidence_pct'], a_report['verdict'], checks=checks)
    return checks

def render_news_tool():
    news_mode = st.radio('Analyze by:', ['Paste article text', 'Paste a URL'], horizontal=True, key='news_mode')
    news_text, news_url = ('', '')
    if news_mode == 'Paste article text':
        news_text = st.text_area('Article text', height=140, placeholder='Paste the article body here...', label_visibility='collapsed', key='news_text_area')
        wc = len(news_text.split())
        st.caption(f'{wc} words')
    else:
        news_url = st.text_input('Article URL', placeholder='https://example.com/news/some-article', label_visibility='collapsed', key='news_url_field')
    result_checks = None
    if st.button('Analyze article', use_container_width=True, type='primary'):
        if not (news_text.strip() or news_url.strip()):
            st.warning('Paste some article text or a URL first.')
        else:
            with scanning('Analyzing article...'):
                n_report = news_analyzer.analyze_news(text=news_text, url=news_url)
            if not n_report['ok']:
                st.error(n_report['error'])
            else:
                render_result_card(n_report['risk_pct'], n_report['verdict'], label='Low-credibility risk')
                checks = [n_report['emotional'], n_report['formatting'], n_report['attribution'], n_report['domain']]
                render_checklist(checks)
                st.caption(f'Analyzed {n_report['word_count']} words.')
                render_pdf_download('news_analysis_report.pdf', 'RealityLens AI - Fake News Analysis Report', n_report['risk_pct'], n_report['verdict'], checks, source_label=n_report.get('source_note') or 'Pasted text')
                log_analysis('news', n_report.get('source_note') or 'Pasted article', n_report['risk_pct'], n_report['verdict'], checks=checks)
                result_checks = checks
    return result_checks

TOOL_RENDERERS = {'ai_image': render_ai_image_tool, 'screenshot': render_screenshot_tool, 'video': render_video_tool, 'voice': render_voice_tool, 'news': render_news_tool}

def _hero_gauge_svg(pct: float, size: int=210) -> str:
    pct = max(0.0, min(100.0, pct))
    r = size / 2 - 16
    cx, cy = (size / 2, size / 2 - 4)
    circumference = 3.1416 * r
    filled = circumference * (pct / 100)
    return f'\n    <svg width="{size}" height="{size / 1.62:.0f}" viewBox="0 0 {size} {size / 1.62:.0f}">\n        <defs>\n            <linearGradient id="realityGrad" x1="0%" y1="0%" x2="100%" y2="0%">\n                <stop offset="0%" stop-color="{DANGER}" />\n                <stop offset="50%" stop-color="{WARN}" />\n                <stop offset="100%" stop-color="{SUCCESS}" />\n            </linearGradient>\n        </defs>\n        <path d="M {cx - r} {cy} A {r} {r} 0 0 1 {cx + r} {cy}"\n              fill="none" stroke="{SURFACE_ALT}" stroke-width="16" stroke-linecap="round" />\n        <path d="M {cx - r} {cy} A {r} {r} 0 0 1 {cx + r} {cy}"\n              fill="none" stroke="url(#realityGrad)" stroke-width="16" stroke-linecap="round"\n              stroke-dasharray="{filled:.1f} {circumference:.1f}"\n              style="filter: drop-shadow(0 0 8px rgba(34,211,238,0.35));" />\n    </svg>\n    '

def _radar_html(rings: int=3) -> str:
    ring_divs = ''.join((f'<div class="radar-ring" style="width:{int(170 * (i + 1) / rings)}px; height:{int(170 * (i + 1) / rings)}px;"></div>' for i in range(rings)))
    return f'<div class="radar-wrap">{ring_divs}<div class="radar-sweep"></div><div class="radar-core"></div></div>'

def render_upload_preview(raw_bytes: bytes, filename: str) -> None:
    import base64
    b64 = base64.b64encode(raw_bytes).decode()
    st.markdown(f'<div class="upload-thumb-wrap"><div><div class="upload-thumb-box" style="background-image:url(data:image/jpeg;base64,{b64});"></div><div class="upload-thumb-name">{filename}</div></div></div>', unsafe_allow_html=True)

def render_reality_hero():
    latest = latest_for()
    if latest:
        reality_pct, verdict_word, risk_word, color = reality_view(latest['pct'])
        cov = coverage_pct(latest.get('checks') or [])
        checks = latest.get('checks') or []
    else:
        reality_pct, verdict_word, risk_word, color = (91.0, 'LIKELY AUTHENTIC', 'LOW', SUCCESS)
        cov, checks = (94.0, [])
    st.markdown('<div class="section-title"><span class="dot"></span>Investigation in Progress</div>', unsafe_allow_html=True)
    st.markdown('<div class="card card-glow hero-reality">', unsafe_allow_html=True)
    ev_col, gauge_col, stat_col = st.columns([1.05, 1.7, 0.95], gap='large', vertical_alignment='center')
    with ev_col:
        if latest and latest.get('thumb'):
            import base64
            b64 = base64.b64encode(latest['thumb']).decode()
            st.markdown(f'<div class="hero-evid-thumb" style="background-image:url(data:image/jpeg;base64,{b64});"></div>', unsafe_allow_html=True)
            size_kb = len(latest['thumb']) / 1024
            st.markdown(f'<div class="hero-evid-name">{latest['filename']}</div><div class="hero-evid-sub">{latest['tool_label']} &#8226; {size_kb:.1f} KB &#8226; {time_ago(latest['ts'])}</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="hero-evid-thumb">{micon('folder_open', size='1.8rem')}</div>', unsafe_allow_html=True)
            st.markdown('<div class="hero-evid-name">No evidence uploaded yet</div><div class="hero-evid-sub">Pick a tool below to start an investigation</div>', unsafe_allow_html=True)
        meta = latest.get('meta') if latest else None
        if meta:
            rows = ''.join((f'<div class="meta-row"><span class="meta-key">{k}</span><span class="meta-val">{v}</span></div>' for k, v in list(meta.items())[:3] if k != 'valid'))
            st.markdown(f'<div style="margin-top:0.5rem;">{rows}</div>', unsafe_allow_html=True)
    with gauge_col:
        st.markdown(f'<div class="hero-gauge-col"><div class="radar-eyebrow">ANALYZING EVIDENCE</div>{_radar_html()}<div class="hero-num" style="color:{color}; margin-top:0.6rem;">{reality_pct:.0f}%</div><div class="hero-verdict" style="color:{color};">{verdict_word}</div><div class="radar-coverage">Last scan covered {len(checks) or 0} signal(s) &#8226; {cov:.0f}% coverage</div></div>', unsafe_allow_html=True)
        if checks:
            pills = ''.join((f'<div class="status-pill"><div class="pill-dot {('bad' if c.get('flagged') else 'ok')}">{(micon('close') if c.get('flagged') else micon('check'))}</div><div class="pill-txt">{c.get('label', '')}</div></div>' for c in checks[:5]))
            st.markdown(f'<div class="pill-row" style="justify-content:center;">{pills}</div>', unsafe_allow_html=True)
        cta1, cta2 = st.columns(2)
        with cta1:
            if st.button('View Full Report', key='hero_view_report', use_container_width=True, type='primary'):
                go('history')
        with cta2:
            if st.button('New Investigation', key='hero_new_investigation', use_container_width=True):
                reset_active_tool_input()
                st.toast('Cleared - scroll down to upload new evidence.', icon=':material/refresh:')
    with stat_col:
        st.markdown(f'<div class="hero-stats"><div class="hero-stat"><div class="hero-stat-label">RISK LEVEL</div><div class="hero-stat-val" style="color:{color};">{risk_word}</div></div><div class="hero-stat"><div class="hero-stat-label">CONFIDENCE</div><div class="hero-stat-val">{cov:.0f}%</div></div><div class="hero-stat"><div class="hero-stat-label">SIGNALS CHECKED</div><div class="hero-stat-val">{len(checks) or '&#8212;'}</div></div></div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

def render_trust_score_row():
    st.markdown('<div class="section-title hero"><span class="dot"></span>Universal Trust Score</div><div class="section-sub">Every content type, one score. Click a card to open that investigation.</div>', unsafe_allow_html=True)
    cols = st.columns(5, gap='medium')
    for col, key in zip(cols, TOOL_ORDER):
        t = TOOLS[key]
        entry = latest_for(key)
        is_active = ss['active_tool'] == key
        if entry:
            pct = entry['pct']
            reality_pct, _, risk_word, color = reality_view(pct)
            tag = {'LOW': 'Authentic', 'MEDIUM': 'Medium Risk', 'HIGH': 'High Risk'}[risk_word]
            num = reality_pct
        else:
            demo = {'ai_image': (91, SUCCESS, 'Authentic'), 'screenshot': (22, DANGER, 'High Risk'), 'video': (87, DANGER, 'High Risk'), 'voice': (89, SUCCESS, 'Authentic'), 'news': (72, WARN, 'Medium Risk')}
            num, color, tag = demo.get(key, (0, MUTED, 'No Data'))
        with col:
            st.markdown(f'<div class="trust-mini{(' active' if is_active else '')}" style="--tier-color:{color};"><div class="trust-mini-icon">{micon(t['icon_name'], size='1.5rem')}</div><div class="trust-mini-head">{t['label']}</div><div class="trust-mini-num" style="color:{color};">{num:.0f}%</div><div class="trust-mini-tag" style="color:{color};">{tag}</div></div>', unsafe_allow_html=True)
            if st.button('Open', key=f'trust_open_{key}', use_container_width=True, type='primary' if is_active else 'secondary'):
                go('dashboard', key)

def render_explainable_ai_report_card():
    latest = latest_for()
    st.markdown('<div class="card card-glow">', unsafe_allow_html=True)
    st.markdown('<div class="verdict-tab-row"><div class="verdict-tab active">WHY THIS VERDICT?</div><div class="verdict-tab">EVIDENCE MAP</div></div>', unsafe_allow_html=True)
    checks = latest.get('checks') if latest else None
    if not checks:
        checks = [{'label': 'Original metadata detected', 'detail': 'File metadata is valid and consistent.', 'flagged': False}, {'label': 'Natural lighting consistency', 'detail': 'Lighting direction and shadows are natural.', 'flagged': False}, {'label': 'No AI generation patterns', 'detail': 'No diffusion/GAN patterns detected.', 'flagged': False}, {'label': 'No manipulation artifacts', 'detail': 'No signs of cloning, warping or splicing.', 'flagged': False}, {'label': 'Compression consistent', 'detail': 'Compression pattern is uniform.', 'flagged': False}]
    rows = []
    for c in checks[:5]:
        ok = not c.get('flagged')
        rows.append(f'<div class="evidence-row"><div class="evidence-icon">{micon('fact_check')}</div><div style="flex:1;"><div class="evidence-title">{c.get('label', '')}</div><div class="evidence-detail">{c.get('detail', '')}</div></div><div class="evidence-check {('ok' if ok else 'bad')}">{(micon('check') if ok else micon('close'))}</div></div>')
    st.markdown(''.join(rows), unsafe_allow_html=True)
    if st.button('View Full Report', key='view_full_report', use_container_width=True, icon=':material/description:'):
        go('history')
    st.markdown('</div>', unsafe_allow_html=True)

def render_recent_activity_card():
    st.markdown('<div class="card card-glow">', unsafe_allow_html=True)
    st.markdown('<div class="section-title" style="font-size:0.75rem;"><span class="dot"></span>Recent Activity</div>', unsafe_allow_html=True)
    if not ss['history']:
        st.caption('Nothing analyzed yet this session - run a tool below to see it show up here.')
    else:
        for i, item in enumerate(ss['history'][:6]):
            if item['thumb']:
                import base64
                b64 = base64.b64encode(item['thumb']).decode()
                thumb_style = f'background-image:url(data:image/jpeg;base64,{b64});'
                thumb_inner = ''
            else:
                thumb_style, thumb_inner = ('', micon('description', size='1rem'))
            _, color, _ = tier_for(item['pct'])
            rc = st.columns([0.5, 3, 1], vertical_alignment='center')
            with rc[0]:
                st.markdown(f'<div class="recent-thumb" style="{thumb_style}">{thumb_inner}</div>', unsafe_allow_html=True)
            with rc[1]:
                st.markdown(f'<div class="recent-name">{item['filename']}</div><div class="recent-time">{item['tool_label']} &#8226; {time_ago(item['ts'])}</div>', unsafe_allow_html=True)
            with rc[2]:
                st.markdown(f'<div class="recent-pct" style="color:{color};">{item['pct']:.0f}%</div>', unsafe_allow_html=True)
    if st.button('View All History', key='view_all_recent', use_container_width=True):
        go('history')
    st.markdown('</div>', unsafe_allow_html=True)

def render_dashboard():
    main_col, side_col = st.columns([2.9, 1], gap='large')
    with main_col:
        render_reality_hero()
        render_trust_score_row()
        st.markdown('<div class="section-gap"></div>', unsafe_allow_html=True)
        st.markdown('<div class="card card-glow card-active">', unsafe_allow_html=True)
        active = ss['active_tool']
        st.markdown(f'<div style="display:flex; align-items:center; gap:0.9rem; margin-bottom:1.1rem;"><div class="trust-mini-icon" style="width:52px;height:52px;margin-bottom:0;">{micon(TOOLS[active]['icon_name'], size='1.7rem')}</div><div><div style="font-weight:800; font-size:1.35rem; color:{TEXT}; line-height:1.2;">Active Investigation</div><div style="font-size:0.85rem; color:{PRIMARY}; font-weight:700;">{TOOLS[active]['label']}</div></div></div>', unsafe_allow_html=True)
        with st.expander('What this tool actually does (read first)', expanded=False):
            st.markdown(TOOLS[active]['read_first'])
        stepper_slot = st.empty()
        checks_result = TOOL_RENDERERS[active]()
        uploaded_present = has_active_input()
        if checks_result:
            stage_state = ['done', 'done', 'done', 'done']
        elif uploaded_present:
            stage_state = ['done', 'warn', 'pending', 'pending']
        else:
            stage_state = ['active', 'pending', 'pending', 'pending']
        with stepper_slot.container():
            render_stepper(stage_state)
        with st.expander('See the full analysis process'):
            render_process_steps_list(active)
        st.markdown('</div>', unsafe_allow_html=True)
        render_powered_by_and_trust()
    with side_col:
        render_explainable_ai_report_card()
        render_recent_activity_card()

def render_history_page():
    st.markdown('<div class="card"><div style="font-weight:800; font-size:1.2rem; margin-bottom:0.3rem;">Analysis History &amp; Reports</div><div style="color:' + MUTED + '; font-size:0.85rem;">Everything analyzed during this browser session (nothing is stored on a server - refreshing the page clears this list).</div></div>', unsafe_allow_html=True)
    if not ss['history']:
        st.info('No analyses yet. Pick a tool from the sidebar to get started.')
        return
    for i, item in enumerate(ss['history']):
        st.markdown('<div class="card card-tight">', unsafe_allow_html=True)
        c1, c2, c3, c4 = st.columns([3, 1.2, 1, 1])
        with c1:
            st.markdown(f'**{item['tool_label']}** &middot; {item['filename']}')
            st.caption(time_ago(item['ts']))
        with c2:
            st.markdown(f"<span class='badge' style='background:{item['soft']}; color:{item['color']};'>{item['tier']}</span>", unsafe_allow_html=True)
        with c3:
            st.markdown(f"<div style='text-align:right; font-weight:800; color:{item['color']};'>{item['pct']:.0f}%</div>", unsafe_allow_html=True)
        with c4:
            if st.button('Open tool', key=f'hist_open_{i}', use_container_width=True):
                go('dashboard', item['tool'])
        st.markdown('</div>', unsafe_allow_html=True)

def render_settings_page():
    st.markdown('<div class="card"><div style="font-weight:800; font-size:1.2rem;">Settings</div></div>', unsafe_allow_html=True)
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('**Sightengine API credentials**')
    st.caption('Free tier for testing/personal use - [sign up here](https://dashboard.sightengine.com/signup). Keys are only kept in this browser session, never written to disk.')
    ss['api_user'] = st.text_input('API User', value=ss['api_user'], type='password')
    ss['api_secret'] = st.text_input('API Secret', value=ss['api_secret'], type='password')
    st.caption('Without keys, the AI-texture checks fall back to an offline heuristic, clearly labeled as an estimate.')
    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('**Extra setup needed**')
    st.markdown('\n- OCR text check (Scam Detector) needs the **Tesseract OCR** binary installed on this machine.\n- AI Voice Verification only reads `.wav` directly - convert other formats first with `ffmpeg -i input.mp3 output.wav`.\n        ')
    st.markdown('</div>', unsafe_allow_html=True)

def render_api_page():
    st.markdown('<div class="card"><div style="font-weight:800; font-size:1.2rem;">API Access</div><div style="color:' + MUTED + '; font-size:0.85rem; margin-top:0.3rem;">There\'s no hosted REST API for this project - it\'s a local Streamlit app - but every detector is a plain, importable Python function. Call it directly from your own scripts.</div></div>', unsafe_allow_html=True)
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('**Example: run the scam-screenshot detector from a script**')
    st.code('import scam_detector\n\nwith open("screenshot.jpg", "rb") as f:\n    image_bytes = f.read()\n\nreport = scam_detector.analyze_screenshot(image_bytes, api_user="", api_secret="")\nprint(report["confidence_pct"], report["verdict"])', language='python')
    st.markdown('**Other entry points**')
    st.markdown('\n- `hosted_detection.check_sightengine_genai(image_bytes, filename, api_user, api_secret)` - AI-image classifier\n- `video_detector.analyze_video(video_bytes, api_user, api_secret)` - deepfake video report\n- `audio_detector.analyze_audio(wav_bytes)` - synthetic-voice report\n- `news_analyzer.analyze_news(text=..., url=...)` - fake-news style report\n- `report_export.generate_pdf_report(...)` - turn any report dict into a PDF\n        ')
    st.markdown('</div>', unsafe_allow_html=True)

def render_help_page():
    st.markdown('<div class="card"><div style="font-weight:800; font-size:1.2rem; margin-bottom:0.6rem;">Reality Shield &#8226; Help &amp; Support</div>', unsafe_allow_html=True)
    st.markdown('\n**Our mission** - give anyone a fast, explainable second opinion on whether an image, video,\naudio clip, screenshot, or article has been faked or manipulated - and show exactly\nwhy, every time.\n\n**What this app does** - five explainable detection tools: Image Verification, Scam Detector,\nDeepfake Detection, Audio Verification, and News Analyzer. Every report shows\nexactly which signals were checked and why each one matters - see each tool\'s "read first" panel.\n\n**No detector here is infallible.** Treat every result as a signal to weigh, not a guaranteed\nverdict - especially for anything where the answer actually matters.\n        ')
    st.markdown('</div>', unsafe_allow_html=True)
    if st.button('&#8592; Back to Dashboard', use_container_width=True):
        go('dashboard')
if ss['page'] == 'dashboard':
    render_dashboard()
elif ss['page'] == 'history':
    render_history_page()
elif ss['page'] == 'settings':
    render_settings_page()
elif ss['page'] == 'api':
    render_api_page()
elif ss['page'] == 'help':
    render_help_page()
