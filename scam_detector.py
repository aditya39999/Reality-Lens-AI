import io
import numpy as np
from PIL import Image, ImageChops
import hosted_detection
import ocr_scam_check

def _check_metadata(image_bytes: bytes) -> dict:
    try:
        img = Image.open(io.BytesIO(image_bytes))
        exif = img.getexif()
        has_exif = bool(exif is not None and len(exif) > 0)
    except Exception:
        has_exif = False
    if has_exif:
        return {'label': 'Metadata Present', 'flagged': False, 'detail': "The file still carries EXIF/creation metadata. Most screenshots and re-shared images have this stripped by messaging apps, so its presence here isn't unusual on its own."}
    return {'label': 'Missing Metadata', 'flagged': True, 'detail': 'No EXIF/creation metadata was found. This is extremely common for ordinary screenshots too, so treat it as a weak signal on its own, not proof of tampering.'}

def _check_edited_regions(image_bytes: bytes, quality: int=90) -> dict:
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        buf = io.BytesIO()
        img.save(buf, 'JPEG', quality=quality)
        buf.seek(0)
        recompressed = Image.open(buf)
        diff = ImageChops.difference(img, recompressed)
        diff_arr = np.asarray(diff).astype(np.float32)
        error = diff_arr.mean(axis=2)
        mean_err = float(error.mean())
        std_err = float(error.std())
        h, w = error.shape
        grid_h = max(4, min(24, h // 8 or 1))
        grid_w = max(4, min(24, w // 8 or 1))
        row_edges = np.linspace(0, h, grid_h + 1).astype(int)
        col_edges = np.linspace(0, w, grid_w + 1).astype(int)
        block_means = []
        for r0, r1 in zip(row_edges[:-1], row_edges[1:]):
            if r1 <= r0:
                continue
            for c0, c1 in zip(col_edges[:-1], col_edges[1:]):
                if c1 <= c0:
                    continue
                block_means.append(float(error[r0:r1, c0:c1].mean()))
        hot_err = float(np.percentile(block_means, 95)) if block_means else mean_err
        spikiness = (hot_err - mean_err) / (std_err + 1e-06)
        score = float(min(1.0, max(0.0, spikiness / 10)))
    except Exception:
        return {'label': 'No Localized Edits Found', 'flagged': False, 'score': 0.0, 'detail': 'Could not run error-level analysis on this file.'}
    flagged = bool(score > 0.4)
    return {'label': 'Edited Regions' if flagged else 'No Localized Edits Found', 'flagged': flagged, 'score': score, 'detail': f'Error-level analysis found compression inconsistencies (spike score {score:.2f}) suggesting parts of the image may have been pasted in or altered after it was last saved.' if flagged else f'Error-level analysis found a fairly even compression pattern across the image (spike score {score:.2f}), with no strong sign of localized editing.'}

def _check_ai_texture(image_bytes: bytes, api_user: str, api_secret: str) -> dict:
    api_error = None
    if api_user and api_secret:
        result = hosted_detection.check_sightengine_genai(image_bytes, 'screenshot.jpg', api_user, api_secret)
        if result['ok']:
            score = result['ai_generated']
            flagged = score > 0.5
            return {'label': 'AI Texture Detected' if flagged else 'No AI Texture Detected', 'flagged': flagged, 'score': score, 'detail': f"Sightengine's trained genai model put this image at {score * 100:.1f}% likelihood of being AI-generated.", 'source': 'sightengine'}
        api_error = result.get('error', 'Unknown API error.')
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert('L')
        arr = np.asarray(img).astype(np.float32)
        gy, gx = np.gradient(arr)
        grad_mag = np.sqrt(gx ** 2 + gy ** 2)
        grad_std = float(grad_mag.std())
        if grad_std <= 0.4:
            score = 1.0
        elif grad_std >= 3.0:
            score = 0.0
        else:
            score = float((3.0 - grad_std) / (3.0 - 0.4))
    except Exception:
        score = 0.0
    flagged = bool(score > 0.6)
    if api_error:
        detail = f'Offline heuristic estimate: texture smoothness score {score:.2f}. Sightengine API keys were supplied but the call failed ({api_error}), so this result did NOT come from the trained model - check your API credentials/quota in the sidebar.'
    else:
        detail = f'Offline heuristic estimate (no Sightengine keys supplied): texture smoothness score {score:.2f}. This is a rough approximation, not a trained model - add Sightengine API keys in the sidebar for a real classifier result.'
    return {'label': 'AI Texture Detected' if flagged else 'No AI Texture Detected', 'flagged': flagged, 'score': score, 'detail': detail, 'source': 'offline_heuristic', 'api_error': api_error}

def build_ai_texture_result(sightengine_result: dict) -> dict:
    score = float(sightengine_result['ai_generated'])
    flagged = bool(score > 0.5)
    detail = f"Sightengine's trained genai model put this image at {score * 100:.1f}% likelihood of being AI-generated."
    generators = sightengine_result.get('generators') or {}
    if generators:
        top_name, top_score = max(generators.items(), key=lambda kv: kv[1])
        if top_score > 0.05:
            detail += f' Closest generator signature match: {top_name} ({top_score * 100:.1f}%).'
    return {'label': 'AI Texture Detected' if flagged else 'No AI Texture Detected', 'flagged': flagged, 'score': score, 'detail': detail, 'source': 'sightengine'}

def analyze_screenshot(image_bytes: bytes, api_user: str='', api_secret: str='', ai_texture_override: dict=None) -> dict:
    metadata = _check_metadata(image_bytes)
    edits = _check_edited_regions(image_bytes)
    ai_texture = ai_texture_override or _check_ai_texture(image_bytes, api_user, api_secret)
    ocr_text = ocr_scam_check.analyze_scam_text(image_bytes)
    date_check = ocr_scam_check.check_date_freshness(image_bytes, ocr_text=ocr_text.get('extracted_text'))
    ai_weight = 0.85 if ai_texture.get('source') == 'sightengine' else 0.65
    weights = {'metadata': 0.15, 'edits': 0.55, 'ai_texture': ai_weight, 'ocr_text': 0.6, 'date_freshness': 0.75}
    edit_score = edits.get('score', 0.0)
    ai_score = ai_texture.get('score', 0.0)
    ocr_score = ocr_text.get('score', 0.0)
    date_score = date_check.get('score', 0.0)
    meta_score = 1.0 if metadata['flagged'] else 0.0
    confidence = 1.0 - (1.0 - weights['metadata'] * meta_score) * (1.0 - weights['edits'] * edit_score) * (1.0 - weights['ai_texture'] * ai_score) * (1.0 - weights['ocr_text'] * ocr_score) * (1.0 - weights['date_freshness'] * date_score)
    confidence_pct = round(confidence * 100, 1)
    if confidence_pct >= 70:
        verdict = 'High risk - strong signs of a faked or manipulated screenshot.'
    elif confidence_pct >= 35:
        verdict = 'Uncertain - some signals present, worth a manual look.'
    else:
        verdict = 'Low risk - no strong signs of manipulation found.'
    return {'metadata': metadata, 'edited_regions': edits, 'ai_texture': ai_texture, 'ocr_text': ocr_text, 'date_freshness': date_check, 'confidence_pct': confidence_pct, 'weights': weights, 'verdict': verdict}
