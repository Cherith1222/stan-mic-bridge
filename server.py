"""Private, memory-only browser microphone -> VB-CABLE bridge."""
import asyncio
import collections
import hmac
import json
from pathlib import Path
import threading
import time

import numpy as np
import sounddevice as sd
from aiohttp import web, WSMsgType
from mic_defaults import MicrophoneDefaults
from setup_receiver import validate_origin

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / 'config.json'
if not CONFIG.exists():
    raise RuntimeError('Run setup_receiver.py --origin https://YOUR-HOST:8443 before starting the receiver')
config = json.loads(CONFIG.read_text(encoding='utf-8'))
config['origin'] = validate_origin(config['origin'])
if not isinstance(config.get('token'), str) or len(config['token']) < 32:
    raise RuntimeError('Invalid receiver token; restore your private config.json')
ws_origin = config['origin'].replace('https://', 'wss://', 1)
active = None
metrics = {'connected': False, 'frames': 0, 'rms': 0.0, 'last_audio': None}
microphone = MicrophoneDefaults()
metrics.update(route='physical', route_error=None)
metrics.update(dropped_frames=0, last_disconnect_reason=None)

def event(kind, **fields):
    # Operational metadata only; never audio, credentials, IPs, or transcripts.
    print(json.dumps({'time': time.time(), 'event': kind, **fields}), flush=True)

def cable_device():
    devices = sd.query_devices()
    matches = [i for i, d in enumerate(devices) if d['name'].startswith('CABLE Input') and d['max_output_channels'] >= 2 and sd.query_hostapis(d['hostapi'])['name'] == 'Windows WASAPI']
    if len(matches) != 1:
        raise RuntimeError('Expected one WASAPI CABLE Input; install VB-CABLE first')
    return matches[0]

@web.middleware
async def headers(request, handler):
    response = await handler(request)
    response.headers.update({'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'Permissions-Policy': 'microphone=(self)', 'Content-Security-Policy': f"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' {ws_origin}; frame-ancestors 'none'"})
    return response

async def websocket(request):
    global active
    if not hmac.compare_digest(request.query.get('token', ''), config['token']):
        raise web.HTTPForbidden()
    if request.headers.get('Origin') != config['origin']:
        raise web.HTTPForbidden()
    if active is not None:
        raise web.HTTPConflict(text='Another microphone is connected')
    ws = web.WebSocketResponse(max_msg_size=32768, heartbeat=10, receive_timeout=8)
    active = ws
    stream = None
    routed = False
    queue = collections.deque()
    lock = threading.Lock()
    buffered = 0
    last_packet = time.monotonic()
    reason = 'client_closed'
    try:
        await ws.prepare(request)
        msg = await ws.receive_json(timeout=5)
        rate = msg.get('sampleRate')
        if rate not in (44100, 48000):
            raise ValueError('Only 44100 or 48000 Hz supported')

        def callback(outdata, frames, timing, status):
            nonlocal buffered
            outdata.fill(0)
            with lock:
                if time.monotonic() - last_packet > 0.5:
                    queue.clear()
                    buffered = 0
                    return
                offset = 0
                while queue and offset < frames:
                    data = queue.popleft()
                    count = min(len(data), frames - offset)
                    outdata[offset:offset+count, :] = data[:count, None]
                    offset += count
                    buffered -= count
                    if count < len(data):
                        queue.appendleft(data[count:])

        stream = sd.OutputStream(device=cable_device(), samplerate=rate, channels=2, dtype='float32', blocksize=0, latency='low', extra_settings=sd.WasapiSettings(auto_convert=True), callback=callback)
        stream.start()
        prepared_route = microphone.prepare()
        metrics.update(connected=True, frames=0, rms=0.0)
        event('connected')
        await ws.send_json({'ready': True})
        async for msg in ws:
            if msg.type != WSMsgType.BINARY:
                break
            if not msg.data or len(msg.data) % 4:
                raise ValueError('Invalid PCM size')
            data = np.frombuffer(msg.data, dtype='<f4').copy()
            if not np.isfinite(data).all():
                raise ValueError('Invalid PCM samples')
            np.clip(data, -1, 1, out=data)
            if not routed:
                microphone.activate(prepared_route)
                routed = True
                metrics.update(route='mac', route_error=None)
            with lock:
                if buffered + len(data) > rate // 4:
                    # Network jitter can deliver a burst. Keep current speech instead
                    # of disconnecting or replaying a growing backlog.
                    metrics['dropped_frames'] += buffered
                    queue.clear()
                    buffered = 0
                queue.append(data)
                buffered += len(data)
                last_packet = time.monotonic()
            metrics.update(frames=metrics['frames']+len(data), rms=float(np.sqrt(np.mean(data*data))), last_audio=time.time())
    except Exception as exc:
        reason = 'no_audio_timeout' if isinstance(exc, asyncio.TimeoutError) else type(exc).__name__
        event('connection_error', reason=reason)
        if ws.prepared and not ws.closed:
            await ws.send_json({'error': 'Audio connection unavailable; verify VB-CABLE and reconnect', 'reason': reason})
    finally:
        if stream is not None:
            for cleanup in (stream.abort, stream.close):
                try:
                    cleanup()
                except sd.PortAudioError:
                    pass
        queue.clear()
        try:
            microphone.restore()
            metrics.update(route='physical', route_error=None)
        except Exception:
            metrics.update(route='recovery-needed', route_error='Unable to restore physical microphone')
        metrics.update(connected=False, rms=0.0, last_disconnect_reason=reason)
        event('disconnected', reason=reason, frames=metrics['frames'], route=metrics['route'])
        active = None
        if ws.prepared:
            await ws.close()
    return ws

async def status(request):
    if not hmac.compare_digest(request.headers.get('Authorization', ''), 'Bearer ' + config['token']):
        raise web.HTTPForbidden()
    return web.json_response(metrics)

async def static(request):
    name = request.match_info.get('name', 'index.html')
    if name not in ('index.html', 'app.js', 'worklet.js'):
        raise web.HTTPNotFound()
    return web.FileResponse(ROOT / 'static' / name)

app = web.Application(middlewares=[headers])
app.router.add_get('/ws', websocket)
app.router.add_get('/status', status)
app.router.add_get('/', static)
app.router.add_get('/{name}', static)
async def shutdown(app):
    if active is not None:
        await active.close(code=1001, message=b'Receiver stopping')
    microphone.restore()

app.on_shutdown.append(shutdown)
if __name__ == '__main__':
    web.run_app(app, host='127.0.0.1', port=8765, access_log=None, print=None)
