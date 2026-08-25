import io
import tempfile
import os
import numpy as np
from PIL import Image, ImageChops
import hosted_detection
try:
    import cv2
    _CV2_OK = True
except ImportError:
    _CV2_OK = False

def _ramp_score(value: float, synthetic_at: float, natural_at: float) -> float:
    if synthetic_at == natural_at:
        return 0.0
    frac = (value - natural_at) / (synthetic_at - natural_at)
    return float(max(0.0, min(1.0, frac)))

def _sample_frames(video_bytes: bytes, max_frames: int=8):
    if not _CV2_OK:
        return ([], 'opencv-python is not installed.')
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as tmp:
            tmp.write(video_bytes)
            tmp_path = tmp.name
        cap = cv2.VideoCapture(tmp_path)
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        if total <= 0:
            cap.release()
            return ([], "Couldn't read frame count from this video file.")
        step = max(1, total // max_frames)
        frames = []
        idx = 0
        while len(frames) < max_frames and idx < total:
            cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
            ok, frame = cap.read()
            if ok:
                rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                frames.append(Image.fromarray(rgb))
            idx += step
        cap.release()
        return (frames, None)
    except Exception as e:
        return ([], f'Error reading video: {e}')
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)

def _frame_ai_score(frame: Image.Image, api_user: str, api_secret: str) -> dict:
    buf = io.BytesIO()
    frame.convert('RGB').save(buf, 'JPEG', quality=92)
    frame_bytes = buf.getvalue()
    if api_user and api_secret:
        result = hosted_detection.check_sightengine_genai(frame_bytes, 'frame.jpg', api_user, api_secret)
        if result['ok']:
            return {'score': float(result['ai_generated']), 'via_api': True, 'error': None}
        api_error = result.get('error', 'Unknown API error.')
    else:
        api_error = None
    # NOTE: this fallback only ever measures local gradient/sharpness, which is
    # driven far more by resolution and compression history than by whether
    # content is AI-generated. It is NOT a reliable AI-detection signal on its
    # own, and empirically runs backwards on real-world footage (compressed
    # real video reads as "low sharpness" -> falsely high AI score; crisp,
    # well-rendered AI video reads as "high sharpness" -> falsely low AI
    # score). We keep it only as a very weak, heavily-dampened tiebreaker
    # pinned near neutral (0.5), rather than letting it swing 0-1 and drive
    # the verdict when the real detector (Sightengine) isn't available.
    gray = frame.convert('L')
    arr = np.asarray(gray).astype(np.float32)
    gy, gx = np.gradient(arr)
    grad_mag = np.sqrt(gx ** 2 + gy ** 2)
    grad_std = float(grad_mag.std())
    raw_ramp = _ramp_score(grad_std, synthetic_at=6.0, natural_at=9.5)
    # Dampen toward 0.5 (neutral / "unknown") instead of letting it claim
    # near-0 ("definitely real") or near-1 ("definitely AI") confidence.
    dampening = 0.15
    heuristic_score = 0.5 + (raw_ramp - 0.5) * dampening
    return {'score': heuristic_score, 'via_api': False, 'error': api_error}

def _locate_haarcascade_dir() -> str:
    """cv2.data.haarcascades isn't reliably present as an attribute on every
    OpenCV build/environment (seen on some Streamlit Cloud deployments), so
    fall back to deriving the path from the installed package location."""
    try:
        return cv2.data.haarcascades
    except AttributeError:
        pass
    candidate = os.path.join(os.path.dirname(cv2.__file__), 'data')
    if os.path.isdir(candidate):
        return candidate + os.sep
    return ''

def _face_consistency_score(frames):
    if not _CV2_OK:
        return (0.0, 'OpenCV not available - facial consistency check skipped.')
    cascade_dir = _locate_haarcascade_dir()
    face_path = cascade_dir + 'haarcascade_frontalface_default.xml'
    eye_path = cascade_dir + 'haarcascade_eye.xml'
    if not cascade_dir or not os.path.isfile(face_path) or not os.path.isfile(eye_path):
        return (0.0, "Couldn't locate OpenCV's face-detection data files on this deployment - facial consistency check skipped.")
    face_cascade = cv2.CascadeClassifier(face_path)
    eye_cascade = cv2.CascadeClassifier(eye_path)
    if face_cascade.empty() or eye_cascade.empty():
        return (0.0, "OpenCV's face-detection classifiers failed to load - facial consistency check skipped.")
    face_counts = []
    eye_open_flags = []
    for frame in frames:
        arr = cv2.cvtColor(np.array(frame), cv2.COLOR_RGB2GRAY)
        faces = face_cascade.detectMultiScale(arr, scaleFactor=1.1, minNeighbors=5, minSize=(60, 60))
        face_counts.append(len(faces))
        if len(faces) > 0:
            x, y, w, h = faces[0]
            face_roi = arr[y:y + h, x:x + w]
            eyes = eye_cascade.detectMultiScale(face_roi, scaleFactor=1.1, minNeighbors=5)
            eye_open_flags.append(len(eyes) >= 2)
    if not any(face_counts):
        return (0.0, "No face was reliably detected in the sampled frames, so this check couldn't run.")
    frames_with_face = sum((1 for c in face_counts if c > 0))
    detection_rate = frames_with_face / len(face_counts)
    baseline_detection = 0.8
    inconsistency = _ramp_score(detection_rate, synthetic_at=0.0, natural_at=baseline_detection)
    blink_note = ''
    if len(eye_open_flags) >= 6:
        if all(eye_open_flags) or not any(eye_open_flags):
            inconsistency = min(1.0, inconsistency + 0.08)
            blink_note = ' Eye-open detection showed no variation across sampled frames.'
    detail = f'A face was detected in {frames_with_face}/{len(face_counts)} sampled frames (dropout below ~80% is treated as notable; ordinary head movement or lighting changes commonly cause some dropout even in real footage).{blink_note} This is a coarse consistency check, not real blink-rate or lip-sync analysis, and sparse frame sampling limits how much it can tell.'
    return (float(inconsistency), detail)

def _compression_consistency_score(frames):
    if len(frames) < 2:
        return (0.0, 'Not enough frames sampled for a compression-consistency check.')
    spikes = []
    for frame in frames:
        try:
            img = frame.convert('RGB')
            buf = io.BytesIO()
            img.save(buf, 'JPEG', quality=90)
            buf.seek(0)
            recompressed = Image.open(buf)
            diff = ImageChops.difference(img, recompressed)
            arr = np.asarray(diff).astype(np.float32).mean(axis=2)
            mean_e, std_e, max_e = (arr.mean(), arr.std(), arr.max())
            spikes.append((max_e - mean_e) / (std_e + 1e-06))
        except Exception:
            continue
    if not spikes:
        return (0.0, "Couldn't compute compression consistency for this video.")
    variability = float(np.std(spikes)) / (float(np.mean(spikes)) + 1e-06)
    score = float(min(1.0, max(0.0, variability / 3.5)))
    detail = f'Compression-error patterns varied noticeably between sampled frames (variability {variability:.2f}).' if score > 0.5 else f'Compression-error patterns were fairly stable between sampled frames (variability {variability:.2f}).'
    return (score, detail)

def analyze_video(video_bytes: bytes, api_user: str='', api_secret: str='', max_frames: int=8) -> dict:
    frames, err = _sample_frames(video_bytes, max_frames=max_frames)
    if err or not frames:
        return {'ok': False, 'error': err or 'Could not extract frames from this video.'}
    try:
        frame_results = [_frame_ai_score(f, api_user, api_secret) for f in frames]
        ai_scores = [r['score'] for r in frame_results]
        avg_ai_score = float(np.mean(ai_scores))
        api_attempted = bool(api_user and api_secret)
        api_success_count = sum((1 for r in frame_results if r['via_api']))
        api_success_frac = api_success_count / len(frame_results)
        api_errors = [r['error'] for r in frame_results if r['error']]
        first_api_error = api_errors[0] if api_errors else None
        face_score, face_detail = _face_consistency_score(frames)
        comp_score, comp_detail = _compression_consistency_score(frames)
        if api_success_count == len(frame_results):
            source = 'sightengine'
            method_note = f'Sightengine’s trained genai model on all {len(frames)} sampled frames'
        elif api_success_count > 0:
            source = 'mixed'
            method_note = f'Sightengine’s trained genai model on {api_success_count}/{len(frames)} frames (the rest fell back to an offline heuristic - error: {first_api_error})'
        elif api_attempted:
            source = 'offline_heuristic'
            method_note = f'an offline smoothness heuristic on all {len(frames)} frames - the Sightengine API call failed for every sampled frame ({first_api_error}), so no frames actually used the trained model despite keys being supplied'
        else:
            source = 'offline_heuristic'
            method_note = f'an offline smoothness heuristic on all {len(frames)} frames (no API keys supplied)'
        ai_texture = {'label': 'AI/Synthetic Texture Detected' if avg_ai_score > 0.5 else 'No AI/Synthetic Texture Detected', 'flagged': avg_ai_score > 0.5, 'score': avg_ai_score, 'detail': f'Averaged across {len(frames)} sampled frames using {method_note}: {avg_ai_score * 100:.1f}% likelihood of AI-generated/synthetic content.' + (' Note: without a working API result, this estimate leans partly on frame sharpness/detail level, which is also affected by resolution and how many times a clip has been re-compressed/re-shared - not AI-ness alone. Weighted accordingly, not treated as conclusive on its own.' if source == 'offline_heuristic' else ''), 'source': source, 'api_success_frac': api_success_frac}
        facial_consistency = {'label': 'Facial Inconsistencies' if face_score > 0.55 else 'Facial Detection Consistent', 'flagged': face_score > 0.55, 'score': face_score, 'detail': face_detail}
        compression_consistency = {'label': 'Frame Compression Inconsistencies' if comp_score > 0.5 else 'Frame Compression Consistent', 'flagged': comp_score > 0.5, 'score': comp_score, 'detail': comp_detail}
        # Base weight is low (0.15) when no frames used the real API, so the
        # dampened offline heuristic can't dominate the verdict on its own.
        # Weight scales up toward 0.65 only as more frames actually get a
        # real Sightengine result.
        ai_weight = 0.15 + (0.65 - 0.15) * api_success_frac
        face_eff = face_score if face_score > 0.5 else 0.0
        comp_eff = comp_score if comp_score > 0.45 else 0.0
        weights = {'ai_texture': ai_weight, 'facial_consistency': 0.15, 'compression_consistency': 0.12}
        confidence = 1.0 - (1.0 - weights['ai_texture'] * avg_ai_score) * (1.0 - weights['facial_consistency'] * face_eff) * (1.0 - weights['compression_consistency'] * comp_eff)
        confidence_pct = round(confidence * 100, 1)
        if confidence_pct >= 65:
            verdict = 'High risk - multiple signals suggest synthetic or manipulated video.'
        elif confidence_pct >= 35:
            verdict = 'Uncertain - some signals present, worth a manual look.'
        else:
            verdict = 'Low risk - no strong signs of synthetic/manipulated video found.'
        return {'ok': True, 'frames_sampled': len(frames), 'ai_texture': ai_texture, 'facial_consistency': facial_consistency, 'compression_consistency': compression_consistency, 'confidence_pct': confidence_pct, 'weights': weights, 'verdict': verdict, 'sample_frame': frames[len(frames) // 2]}
    except Exception as e:
        return {'ok': False, 'error': f'Unexpected error while analyzing this video: {e}'}
