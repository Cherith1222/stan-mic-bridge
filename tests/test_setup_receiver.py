import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from setup_receiver import initialize, validate_origin


class SetupTests(unittest.TestCase):
    def test_origin(self):
        for value in ('https://host.tailnet.ts.net:8443', 'https://example.com', 'https://[::1]:8443'):
            self.assertEqual(validate_origin(value), value)
        self.assertEqual(validate_origin('https://EXAMPLE.com:443'), 'https://example.com')

    def test_reject_non_origins(self):
        for value in ('http://example.com', 'https://', 'https://example.com/',
                      'https://user@example.com', 'https://user:pass@example.com',
                      'https://example.com?q=1', 'https://example.com?',
                      'https://example.com#token=secret', 'https://example.com#',
                      'https://example.com/path', 'https://example.com:0',
                      'https://example.com:99999', 'https://example.com:',
                      ' https://example.com', 'https://example.com\n',
                      'https://example.com\\evil', 'https://bad_host.example',
                      'https://example.com;evil', 'https://-bad.example'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_origin(value)

    def test_initialize_and_preserve_existing(self):
        defaults = [{'flow': 1, 'role': role, 'id': f'physical-{role}'} for role in range(3)]
        discover = Mock(return_value=defaults)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = initialize(root, 'https://example.com:8443', discover)
            self.assertGreaterEqual(len(config['token']), 43)
            self.assertEqual(json.loads((root / 'config.json').read_text()), config)
            self.assertEqual(json.loads((root / 'audio-defaults.json').read_text()), defaults)
            before = (root / 'config.json').read_bytes()
            with self.assertRaises(FileExistsError):
                initialize(root, 'https://other.example.com', discover)
            self.assertEqual((root / 'config.json').read_bytes(), before)
            discover.assert_called_once_with()

    def test_partial_setup_or_route_blocks_reinitialization(self):
        for filename in ('audio-defaults.json', 'active-mic-route.json'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / filename).write_text('preserve me')
                discover = Mock()
                with self.assertRaises(FileExistsError):
                    initialize(root, 'https://example.com', discover)
                discover.assert_not_called()
                self.assertFalse((root / 'config.json').exists())

    def test_discovery_failure_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                initialize(directory, 'https://example.com', Mock(side_effect=RuntimeError('No physical microphone')))
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
