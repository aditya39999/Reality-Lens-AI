import requests
SIGHTENGINE_ENDPOINT = 'https://api.sightengine.com/1.0/check.json'

def check_sightengine_genai(image_bytes: bytes, filename: str, api_user: str, api_secret: str, timeout: int=20) -> dict:
    if not api_user or not api_secret:
        return {'ok': False, 'error': 'Missing API credentials.'}
    try:
        files = {'media': (filename or 'image.jpg', image_bytes)}
        data = {'models': 'genai', 'api_user': api_user, 'api_secret': api_secret}
        resp = requests.post(SIGHTENGINE_ENDPOINT, files=files, data=data, timeout=timeout)
    except requests.exceptions.RequestException as e:
        return {'ok': False, 'error': f'Network error contacting Sightengine: {e}'}
    try:
        payload = resp.json()
    except ValueError:
        return {'ok': False, 'error': f'Sightengine returned a non-JSON response (HTTP {resp.status_code}).'}
    if payload.get('status') != 'success':
        err = payload.get('error', {})
        msg = err.get('message') if isinstance(err, dict) else None
        return {'ok': False, 'error': msg or f'Sightengine API error (HTTP {resp.status_code}).'}
    type_block = payload.get('type', {})
    ai_generated = type_block.get('ai_generated')
    generators = type_block.get('ai_generators', {}) or {}
    if ai_generated is None:
        return {'ok': False, 'error': "Response was missing the 'ai_generated' score."}
    return {'ok': True, 'ai_generated': float(ai_generated), 'generators': generators}
