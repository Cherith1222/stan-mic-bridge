"""Synthetic tone test through websocket and the real virtual microphone; no recording files."""
import asyncio
import json
from pathlib import Path
import time
import numpy as np
import sounddevice as sd
from aiohttp import ClientSession, WSServerHandshakeError
from mic_defaults import MicrophoneDefaults

async def main():
    config = json.loads(Path(__file__).with_name('config.json').read_text())
    rate = 48000
    mic = MicrophoneDefaults()
    original_defaults = mic.defaults()
    virtual_id = mic.cable_id()
    indices = [i for i,d in enumerate(sd.query_devices()) if d['name'].startswith('CABLE Output') and d['max_input_channels'] >= 1 and sd.query_hostapis(d['hostapi'])['name']=='Windows WASAPI']
    assert len(indices)==1, 'CABLE Output unavailable'
    async with ClientSession() as client:
        for token,origin in [('wrong', config['origin']), (config['token'], 'https://invalid.example')]:
            try:
                await client.ws_connect('http://127.0.0.1:8765/ws', params={'token':token}, origin=origin)
                raise AssertionError('Unauthorised connection accepted')
            except WSServerHandshakeError as exc:
                assert exc.status==403
        for cycle in range(2):
            captured=[]
            def callback(data,frames,timing,status):
                captured.append(data[:,0].copy())
            with sd.InputStream(device=indices[0], samplerate=rate, channels=1, dtype='float32', callback=callback, extra_settings=sd.WasapiSettings(auto_convert=True)):
                async with client.ws_connect('http://127.0.0.1:8765/ws',params={'token':config['token']},origin=config['origin']) as ws:
                    await ws.send_json({'sampleRate':rate})
                    assert (await ws.receive_json())['ready']
                    start=time.monotonic()
                    for i in range(100):
                        t=(np.arange(960)+i*960)/rate
                        tone=(0.1*np.sin(2*np.pi*997*t)).astype('<f4')
                        await ws.send_bytes(tone.tobytes())
                        await asyncio.sleep(max(0,start+(i+1)*0.02-time.monotonic()))
                        if i == 20:
                            assert mic.defaults() == [virtual_id] * 3, 'Windows did not switch to Mac microphone'
                    await asyncio.sleep(0.2)
            samples=np.concatenate(captured)
            rms=float(np.sqrt(np.mean(samples*samples)))
            spectrum=np.abs(np.fft.rfft(samples))
            peak=float(np.fft.rfftfreq(len(samples),1/rate)[np.argmax(spectrum)])
            assert rms>0.01 and abs(peak-997)<5, (rms,peak)
            await asyncio.sleep(0.3)
            state=await (await client.get('http://127.0.0.1:8765/status',headers={'Authorization':'Bearer '+config['token']})).json()
            assert not state['connected']
            assert mic.defaults() == original_defaults, 'Windows physical microphone was not restored'
            print(json.dumps({'cycle':cycle+1,'rms':round(rms,4),'peak_hz':round(peak,2),'disconnected':True}))

if __name__=='__main__':
    asyncio.run(main())
