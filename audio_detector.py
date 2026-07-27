import io
import wave
import numpy as np

def _ramp_score(value: float, synthetic_at: float, natural_at: float) -> float:
    if synthetic_at == natural_at:
        return 0.0
    frac = (value - natural_at) / (synthetic_at - natural_at)
    return float(max(0.0, min(1.0, frac)))

def _read_wav(audio_bytes: bytes):
    with wave.open(io.BytesIO(audio_bytes), 'rb') as wf:
        n_channels = wf.getnchannels()
        sample_width = wf.getsampwidth()
        framerate = wf.getframerate()
        n_frames = wf.getnframes()
        raw = wf.readframes(n_frames)
    dtype = {1: np.int8, 2: np.int16, 4: np.int32}.get(sample_width, np.int16)
    audio = np.frombuffer(raw, dtype=dtype).astype(np.float32)
    if n_channels > 1:
        audio = audio.reshape(-1, n_channels).mean(axis=1)
    max_val = float(np.iinfo(dtype).max)
    audio = audio / max_val
    return (audio, framerate)

def _estimate_pitch_track(audio: np.ndarray, sr: int, frame_ms: int=40):
    frame_len = int(sr * frame_ms / 1000)
    hop = frame_len // 2
    pitches = []
    for start in range(0, len(audio) - frame_len, hop):
        frame = audio[start:start + frame_len]
        if np.max(np.abs(frame)) < 0.02:
            continue
        frame = frame - frame.mean()
        corr = np.correlate(frame, frame, mode='full')
        corr = corr[len(corr) // 2:]
        min_lag = int(sr / 400)
        max_lag = int(sr / 70)
        if max_lag >= len(corr):
            continue
        segment = corr[min_lag:max_lag]
        if len(segment) == 0 or segment.max() <= 0:
            continue
        peak_lag = min_lag + int(np.argmax(segment))
        if peak_lag > 0:
            pitches.append(sr / peak_lag)
    return np.array(pitches)

def analyze_audio(audio_bytes: bytes) -> dict:
    try:
        audio, sr = _read_wav(audio_bytes)
    except Exception as e:
        return {'ok': False, 'error': f"Couldn't read this file as WAV ({e}). Convert to .wav first (e.g. `ffmpeg -i input.mp3 output.wav`) and try again."}
    if len(audio) < sr * 0.5:
        return {'ok': False, 'error': 'Audio is too short to analyze (need at least ~0.5s).'}
    duration_s = len(audio) / sr
    pitches = _estimate_pitch_track(audio, sr)
    if len(pitches) >= 5:
        pitch_cv = float(np.std(pitches) / (np.mean(pitches) + 1e-06))
        pitch_score = _ramp_score(pitch_cv, synthetic_at=0.03, natural_at=0.15)
        pitch_flag = pitch_score > 0.5
        pitch_detail = f'Pitch variability across voiced segments was unusually low (coefficient of variation {pitch_cv:.3f}), which can be a trait of synthesized speech - but a very calm, monotone speaker can look the same.' if pitch_flag else f'Pitch varied naturally across voiced segments (coefficient of variation {pitch_cv:.3f}), consistent with typical human speech.'
    else:
        pitch_score, pitch_flag = (0.0, False)
        pitch_detail = 'Not enough clearly voiced segments found to measure pitch variability.'
    freqs = np.fft.rfft(audio * np.hanning(len(audio)))
    mag = np.abs(freqs) + 1e-10
    geo_mean = np.exp(np.mean(np.log(mag)))
    arith_mean = np.mean(mag)
    flatness = float(geo_mean / arith_mean)
    flatness_score = _ramp_score(flatness, synthetic_at=0.005, natural_at=0.05)
    flatness_flag = flatness_score > 0.5
    flatness_detail = f'Spectral flatness was very low ({flatness:.4f}), meaning the recording has an unusually clean/tonal spectrum with little background noise - common in some TTS output, but also true of a quiet room and a good microphone.' if flatness_flag else f'Spectral flatness ({flatness:.4f}) showed a normal amount of background/ambient noise, consistent with a typical recording.'
    frame_len = int(sr * 0.02)
    energy = np.array([np.sqrt(np.mean(audio[i:i + frame_len] ** 2)) for i in range(0, len(audio) - frame_len, frame_len)])
    silence_thresh = np.percentile(energy, 20) if len(energy) else 0
    is_silent = energy < max(silence_thresh, 0.01)
    pause_lengths = []
    run = 0
    for s in is_silent:
        if s:
            run += 1
        elif run:
            pause_lengths.append(run)
            run = 0
    if len(pause_lengths) >= 4:
        pause_cv = float(np.std(pause_lengths) / (np.mean(pause_lengths) + 1e-06))
        pause_score = _ramp_score(pause_cv, synthetic_at=0.1, natural_at=0.35)
        pause_flag = pause_score > 0.5
        pause_detail = f'Pause/silence gaps between speech were unusually uniform in length (variability {pause_cv:.2f}), which can suggest machine-timed speech synthesis.' if pause_flag else f'Pause/silence gaps varied naturally (variability {pause_cv:.2f}), consistent with normal conversational speech.'
    else:
        pause_score, pause_flag = (0.0, False)
        pause_detail = 'Not enough distinct pauses found to assess pause-timing pattern.'
    pitch_check = {'label': 'Unnaturally Flat Pitch' if pitch_flag else 'Natural Pitch Variation', 'flagged': pitch_flag, 'score': pitch_score, 'detail': pitch_detail}
    flatness_check = {'label': 'Unusually Clean Spectrum' if flatness_flag else 'Normal Background Noise Floor', 'flagged': flatness_flag, 'score': flatness_score, 'detail': flatness_detail}
    pause_check = {'label': 'Uniform Pause Timing' if pause_flag else 'Natural Pause Timing', 'flagged': pause_flag, 'score': pause_score, 'detail': pause_detail}
    weights = {'pitch': 0.55, 'flatness': 0.45, 'pause': 0.45}
    confidence = 1.0 - (1.0 - weights['pitch'] * pitch_score) * (1.0 - weights['flatness'] * flatness_score) * (1.0 - weights['pause'] * pause_score)
    confidence_pct = round(confidence * 100, 1)
    if confidence_pct >= 60:
        verdict = 'Elevated - several traits associated with synthetic speech were found.'
    elif confidence_pct >= 30:
        verdict = 'Uncertain - a couple of weak signals present, not conclusive.'
    else:
        verdict = 'Low - audio traits look consistent with natural human speech.'
    return {'ok': True, 'duration_s': round(duration_s, 1), 'pitch': pitch_check, 'flatness': flatness_check, 'pause': pause_check, 'confidence_pct': confidence_pct, 'weights': weights, 'verdict': verdict}
