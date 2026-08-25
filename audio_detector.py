import io
import wave
import shutil
import subprocess
import tempfile
import os
import numpy as np

def _ramp_score(value: float, synthetic_at: float, natural_at: float) -> float:
    if synthetic_at == natural_at:
        return 0.0
    frac = (value - natural_at) / (synthetic_at - natural_at)
    return float(max(0.0, min(1.0, frac)))

def _read_wav_bytes(audio_bytes: bytes):
    """Parse standard PCM WAV bytes (8/16/24/32-bit) into a mono float32 array."""
    with wave.open(io.BytesIO(audio_bytes), 'rb') as wf:
        n_channels = wf.getnchannels()
        sample_width = wf.getsampwidth()
        framerate = wf.getframerate()
        n_frames = wf.getnframes()
        raw = wf.readframes(n_frames)
    if sample_width == 3:
        # 24-bit PCM has no native numpy dtype - unpack 3-byte little-endian
        # samples into int32 by hand instead of silently misreading them as int16.
        n_samples = len(raw) // 3
        buf = np.frombuffer(raw, dtype=np.uint8)[:n_samples * 3].reshape(-1, 3)
        padded = np.zeros((n_samples, 4), dtype=np.uint8)
        padded[:, :3] = buf
        audio = padded.view('<i4').astype(np.float32).flatten() / 256.0
        max_val = float(2 ** 23 - 1)
    else:
        dtype = {1: np.uint8, 2: np.int16, 4: np.int32}.get(sample_width)
        if dtype is None:
            raise ValueError(f'Unsupported WAV sample width: {sample_width * 8}-bit.')
        audio = np.frombuffer(raw, dtype=dtype).astype(np.float32)
        if sample_width == 1:
            audio -= 128.0  # 8-bit WAV is unsigned; center it like the others
        max_val = float(np.iinfo(dtype).max)
    if n_channels > 1:
        audio = audio.reshape(-1, n_channels).mean(axis=1)
    audio = audio / max_val
    return (audio, framerate)

def _convert_to_wav_via_ffmpeg(audio_bytes: bytes, suffix: str) -> bytes:
    """Best-effort conversion of any ffmpeg-readable audio (mp3, m4a, ogg/opus,
    aac, flac, ...) to 16-bit mono PCM WAV, so users don't have to pre-convert
    voice notes by hand."""
    ffmpeg_path = shutil.which('ffmpeg')
    if not ffmpeg_path:
        raise RuntimeError("ffmpeg isn't installed on this machine, so only native .wav files can be read directly. Install ffmpeg, or convert manually first (e.g. `ffmpeg -i input.mp3 output.wav`).")
    with tempfile.NamedTemporaryFile(suffix=suffix or '.audio', delete=False) as src:
        src.write(audio_bytes)
        src_path = src.name
    dst_path = src_path + '.converted.wav'
    try:
        result = subprocess.run([ffmpeg_path, '-y', '-i', src_path, '-ac', '1', '-ar', '16000', '-sample_fmt', 's16', dst_path], capture_output=True, timeout=60)
        if result.returncode != 0 or not os.path.exists(dst_path):
            stderr_tail = result.stderr.decode('utf-8', errors='ignore')[-300:]
            raise RuntimeError(f"ffmpeg couldn't convert this file - it may not be a supported audio format ({stderr_tail.strip() or 'unknown error'}).")
        with open(dst_path, 'rb') as f:
            return f.read()
    finally:
        for p in (src_path, dst_path):
            if os.path.exists(p):
                os.remove(p)

def _read_wav(audio_bytes: bytes, filename: str=''):
    try:
        return _read_wav_bytes(audio_bytes)
    except Exception as native_err:
        suffix = os.path.splitext(filename)[1] if filename else ''
        converted = _convert_to_wav_via_ffmpeg(audio_bytes, suffix)
        return _read_wav_bytes(converted)

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

def analyze_audio(audio_bytes: bytes, filename: str='') -> dict:
    try:
        audio, sr = _read_wav(audio_bytes, filename=filename)
    except Exception as e:
        return {'ok': False, 'error': f"Couldn't read this audio file ({e})."}
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
