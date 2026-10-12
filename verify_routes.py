import asyncio
import json
from pathlib import Path
import time

import numpy as np
from aiohttp import ClientSession
from pycaw.pycaw import AudioUtilities

async def main():
    root = Path(__file__).resolve().parent
    config = json.loads((root / 'config.json').read_text())
    e = AudioUtilities.GetDeviceEnumerator()
    def defaults():
        return [e.GetDefaultAudioEndpoint(1,r).GetId() for r in range(3)]
    before = defaults()
    headers = {'Authorization':'Bearer '+config['token']}
    async with ClientSession() as client:
        async with client.ws_connect('http://127.0.0.1:8765/ws',params={'token':config['token']},origin=config['origin']) as ws:
            await ws.send_json({'sampleRate':48000})
            assert (await ws.receive_json())['ready']
            packet=np.zeros(960,dtype='<f4').tobytes()
            for _ in range(80):
                await ws.send_bytes(packet)
            await asyncio.sleep(.5)
            async with client.get('http://127.0.0.1:8765/status',headers=headers) as response:
                state=await response.json()
            assert state['connected'] and state['dropped_frames']>0, state
            assert defaults()!=before
        await asyncio.sleep(.3)
        assert defaults()==before
        print('Jitter burst survived; physical microphone restored after stop',flush=True)
        for mode in ('timeout', 'invalid-packet'):
            async with client.ws_connect('http://127.0.0.1:8765/ws',params={'token':config['token']},origin=config['origin']) as ws:
                await ws.send_json({'sampleRate':48000})
                assert (await ws.receive_json())['ready']
                packet=(0.01*np.sin(2*np.pi*997*np.arange(960)/48000)).astype('<f4').tobytes()
                for i in range(400 if mode=='timeout' else 40):
                    await ws.send_bytes(packet)
                    await asyncio.sleep(.02)
                assert defaults() != before
                print(mode+': Windows default switched',flush=True)
                if mode=='invalid-packet':
                    await ws.send_bytes(b'bad')
                # Poll status; do not receive websocket pings that could mask no-audio timeout.
                deadline=time.monotonic()+12
                while time.monotonic()<deadline:
                    async with client.get('http://127.0.0.1:8765/status',headers=headers) as response:
                        state=await response.json()
                    if not state['connected']:
                        break
                    await asyncio.sleep(.2)
                assert not state['connected'], 'stale audio connection remained active'
                assert defaults()==before, 'physical microphone not restored'
                assert not (root/'active-mic-route.json').exists()
                print(mode+': physical microphone restored',flush=True)
        print('Both failure recovery paths passed',flush=True)

if __name__=='__main__':
    asyncio.run(main())
