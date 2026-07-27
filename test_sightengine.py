import sys
import video_detector as vd
API_USER = sys.argv[1]
API_SECRET = sys.argv[2]
files = {'REAL': 'VID_20260720_194514_860.mp4', 'FAKE 1': 'WhatsApp_Video_2026-07-25_at_9_56_07_PM.mp4', 'FAKE 2': 'WhatsApp_Video_2026-07-25_at_9_58_53_PM.mp4', 'FAKE 3': 'WhatsApp_Video_2026-07-25_at_9_59_00_PM.mp4'}
for label, fname in files.items():
    with open(fname, 'rb') as fh:
        vbytes = fh.read()
    print('=' * 60)
    print(label, fname)
    report = vd.analyze_video(vbytes, api_user=API_USER, api_secret=API_SECRET)
    if not report['ok']:
        print('ERROR:', report['error'])
        continue
    ai = report['ai_texture']
    print(f'  source: {ai['source']}  api_success_frac: {ai.get('api_success_frac')}')
    print(f'  ai_texture score: {ai['score']:.3f}')
    print(f'  detail: {ai['detail']}')
    print(f'  confidence_pct: {report['confidence_pct']}  verdict: {report['verdict']}')
