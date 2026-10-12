"""Create local receiver credentials and snapshot capture defaults without changing them."""
import argparse
import json
import ipaddress
from pathlib import Path
import re
import secrets
from urllib.parse import urlsplit


def validate_origin(value):
    """Accept an HTTPS origin, not a URL containing paths or credentials."""
    if not isinstance(value, str) or not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError('Origin must be an HTTPS origin without whitespace')
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path or parsed.query or parsed.fragment
            or '?' in value or '#' in value or '\\' in value):
        raise ValueError('Use an HTTPS origin such as https://host.tailnet.ts.net:8443 (no trailing slash)')
    # Accessing port also rejects malformed and out-of-range ports.
    if parsed.port == 0 or parsed.netloc.endswith(':'):
        raise ValueError('Origin port must be between 1 and 65535')
    host = parsed.hostname
    try:
        address = ipaddress.ip_address(host)
        host = f'[{address}]' if address.version == 6 else str(address)
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                     for label in host.split('.')):
            raise ValueError('Origin hostname must be a valid ASCII hostname or IP address')
    port = f':{parsed.port}' if parsed.port not in (None, 443) else ''
    return f'https://{host}{port}'


def capture_defaults():
    # Lazy import keeps config validation and tests independent of Windows/COM.
    from pycaw.pycaw import AudioUtilities
    enumerator = AudioUtilities.GetDeviceEnumerator()
    result = []
    for role in range(3):
        endpoint = enumerator.GetDefaultAudioEndpoint(1, role)
        device = AudioUtilities.CreateDevice(endpoint)
        if endpoint.GetState() != 1 or 'cable output' in device.FriendlyName.lower():
            raise RuntimeError('Select an available physical microphone for all Windows capture roles before setup')
        result.append({'flow': 1, 'role': role, 'id': endpoint.GetId()})
    return result


def initialize(root, origin, discover=None):
    origin = validate_origin(origin)
    root = Path(root)
    targets = [root / 'config.json', root / 'audio-defaults.json']
    if any(path.exists() for path in targets) or (root / 'active-mic-route.json').exists():
        raise FileExistsError('Receiver already configured or recovery pending; existing files were not changed')
    defaults = (discover or capture_defaults)()
    if (len(defaults) != 3 or {row['role'] for row in defaults} != {0, 1, 2}
            or any(row['flow'] != 1 or not row['id'] for row in defaults)):
        raise ValueError('Expected three valid capture-role defaults')
    config = {'origin': origin, 'token': secrets.token_urlsafe(32)}
    created = []
    try:
        for path, data in zip(targets, [config, defaults]):
            with path.open('x', encoding='utf-8') as handle:
                created.append(path)
                json.dump(data, handle, indent=2)
                handle.write('\n')
    except Exception:
        for path in created:
            path.unlink()
        raise
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin', required=True, help='External HTTPS origin, without a trailing slash')
    args = parser.parse_args()
    try:
        config = initialize(Path(__file__).resolve().parent, args.origin)
    except (ValueError, OSError, RuntimeError) as exc:
        parser.exit(1, f'Setup failed: {exc}\n')
    print('Configured. No audio defaults were changed. Keep this pairing URL private:')
    print(config['origin'] + '/#token=' + config['token'])


if __name__ == '__main__':
    main()
