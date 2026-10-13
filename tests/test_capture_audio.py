import json
from pathlib import Path
import tempfile
import unittest
import wave

import numpy as np

from capture_audio import RATE, analyze, parse_args, write_capture


class CaptureTests(unittest.TestCase):
    def test_arguments(self):
        self.assertEqual(parse_args(["--output", "test.wav"]).seconds, 20)
        self.assertTrue(parse_args(["--list-devices"]).list_devices)
        for value in ("0", "-1", "60.01", "nan", "inf", "0.0000001"):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                parse_args(["--output", "test.wav", "--seconds", value])
        with self.assertRaises(SystemExit):
            parse_args([])
        self.assertEqual(parse_args(["--output", "test.wav", "--seconds", "60"]).seconds, 60)

    def test_statistics(self):
        report = analyze(np.array([0, 0, 0.5, -0.5, 0, 1, -1], dtype=np.float32))
        self.assertEqual(report["captured_frames"], 7)
        self.assertAlmostEqual(report["rms"], np.sqrt(2.5 / 7))
        self.assertEqual(report["peak"], 1)
        self.assertAlmostEqual(report["clipping_fraction"], 2 / 7)
        self.assertEqual(report["exact_zero_run_count"], 2)
        self.assertEqual(report["longest_exact_zero_run_frames"], 2)
        self.assertEqual(analyze(np.zeros(20))["longest_exact_zero_run_frames"], 20)
        self.assertEqual(analyze(np.ones(20))["exact_zero_run_count"], 0)
        for samples in ([], [float("nan")], [[1, 2]]):
            with self.assertRaises(ValueError):
                analyze(samples)

    def test_wav_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.wav"
            samples = np.array([0, 0.5, -0.5, 1.1, -1.1], dtype=np.float32)
            write_capture(path, samples, {"complete": True})
            with wave.open(str(path), "rb") as reader:
                self.assertEqual((reader.getnchannels(), reader.getsampwidth(), reader.getframerate()), (1, 2, RATE))
                np.testing.assert_array_equal(np.frombuffer(reader.readframes(5), dtype="<i2"), [0, 16384, -16384, 32767, -32767])
            self.assertEqual(json.loads(path.with_suffix(".json").read_text())["captured_frames"], 5)
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                write_capture(path, samples, {})
            self.assertEqual(path.read_bytes(), original)
            path.unlink()
            with self.assertRaises(FileExistsError):
                write_capture(path, samples, {})
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
