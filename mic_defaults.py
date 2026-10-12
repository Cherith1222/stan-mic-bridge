"""Switch capture defaults only; journal changes for crash recovery."""
import json
from pathlib import Path
import warnings

from pycaw.pycaw import AudioUtilities
from pycaw.constants import ERole

ROOT = Path(__file__).resolve().parent

class MicrophoneDefaults:
    def __init__(self):
        self.journal = ROOT / 'active-mic-route.json'
        self.enumerator = AudioUtilities.GetDeviceEnumerator()
        self.restore()

    def defaults(self):
        return [self.enumerator.GetDefaultAudioEndpoint(1, role).GetId() for role in range(3)]

    def cable_id(self):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            devices = AudioUtilities.GetAllDevices()
        matches = [d.id for d in devices if d.FriendlyName == 'CABLE Output (VB-Audio Virtual Cable)' and d.state.value == 1]
        if len(matches) != 1:
            raise RuntimeError('Virtual microphone unavailable')
        return matches[0]

    def prepare(self):
        if self.journal.exists():
            raise RuntimeError('Previous microphone route still needs recovery')
        cable = self.cable_id()
        previous = self.defaults()
        # If a user had already selected the cable, fall back to the saved physical mic.
        saved_defaults = ROOT / 'audio-defaults.json'
        if not saved_defaults.exists():
            raise RuntimeError('Run setup_receiver.py before using the receiver')
        original = json.loads(saved_defaults.read_text(encoding='utf-8'))
        fallback = {x['role']: x['id'] for x in original if x['flow'] == 1}
        previous = [fallback[r] if endpoint == cable else endpoint for r, endpoint in enumerate(previous)]
        if any(endpoint == cable or self.enumerator.GetDevice(endpoint).GetState() != 1 for endpoint in previous):
            raise RuntimeError('Physical fallback microphone unavailable')
        return {'cable': cable, 'previous': previous}

    def activate(self, prepared=None):
        prepared = prepared or self.prepare()
        cable = prepared['cable']
        previous = prepared['previous']
        temporary = self.journal.with_suffix('.tmp')
        temporary.write_text(json.dumps({'cable': cable, 'previous': previous}), encoding='utf-8')
        temporary.replace(self.journal)
        try:
            AudioUtilities.SetDefaultDevice(cable, roles=list(ERole)[:3])
            if self.defaults() != [cable] * 3:
                raise RuntimeError('Default microphone switch did not persist')
        except Exception:
            self.restore()
            raise

    def restore(self):
        if not self.journal.exists():
            return
        saved = json.loads(self.journal.read_text(encoding='utf-8'))
        failures = []
        for role, previous in enumerate(saved['previous']):
            try:
                # Preserve a different microphone explicitly selected during the session.
                if self.enumerator.GetDefaultAudioEndpoint(1, role).GetId() == saved['cable']:
                    AudioUtilities.SetDefaultDevice(previous, roles=[ERole(role)])
                    if self.enumerator.GetDefaultAudioEndpoint(1, role).GetId() != previous:
                        raise RuntimeError('Microphone restore did not persist')
            except Exception as exc:
                failures.append(type(exc).__name__)
        if failures:
            raise RuntimeError('Physical microphone recovery pending: ' + ','.join(failures))
        self.journal.unlink()
