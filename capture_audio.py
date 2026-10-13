"""Explicit, local-only CABLE Output recording for audio diagnostics.

Run with --output PATH to record, or --list-devices for read-only discovery.
Nothing is uploaded and no Windows default device is changed.
"""
import argparse
import json
import math
from pathlib import Path
import sys
import threading
import time
import wave

import numpy as np

RATE = 48000
MAX_SECONDS = 60


def bounded_seconds(value):
    try:
        seconds = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("seconds must be a number") from exc
    if not math.isfinite(seconds) or not 0 < seconds <= MAX_SECONDS:
        raise argparse.ArgumentTypeError("seconds must be greater than 0 and at most 60")
    if int(seconds * RATE) < 1:
        raise argparse.ArgumentTypeError("duration must contain at least one sample")
    return seconds


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=bounded_seconds, default=20.0)
    parser.add_argument("--output", type=Path, help="new .wav path; a .json sidecar is also created")
    parser.add_argument("--list-devices", action="store_true")
    args = parser.parse_args(argv)
    if not args.list_devices and args.output is None:
        parser.error("--output is required for recording")
    return args


def output_paths(output):
    output = Path(output).absolute()
    if output.suffix.lower() != ".wav":
        raise ValueError("output must have a .wav extension")
    sidecar = output.with_suffix(".json")
    for path in (output, sidecar):
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"Refusing to overwrite {path}")
    if not output.parent.is_dir():
        raise ValueError("output parent directory must already exist")
    return output, sidecar


def analyze(samples):
    samples = np.asarray(samples, dtype=np.float32)
    if samples.ndim != 1 or not len(samples) or not np.all(np.isfinite(samples)):
        raise ValueError("Expected nonempty, finite mono samples")
    # Exact zeros describe observed samples, not the cause (silence, gating, etc.).
    zeros = samples == 0
    edges = np.diff(np.r_[False, zeros, False].astype(np.int8))
    lengths = np.flatnonzero(edges == -1) - np.flatnonzero(edges == 1)
    return {
        "captured_frames": int(len(samples)),
        "captured_duration_seconds": len(samples) / RATE,
        "rms": float(np.sqrt(np.mean(samples.astype(np.float64) ** 2))),
        "peak": float(np.max(np.abs(samples))),
        "clipping_fraction": float(np.mean(np.abs(samples) >= 1.0)),
        "exact_zero_frames": int(np.sum(zeros)),
        "exact_zero_run_count": int(len(lengths)),
        "longest_exact_zero_run_frames": int(max(lengths, default=0)),
        "exact_zero_runs_note": "Observed exact zeros only; not evidence of network drops.",
    }


def write_capture(output, samples, metadata):
    output, sidecar = output_paths(output)
    report = dict(metadata)
    report.update(analyze(samples))
    report.update(sample_rate_hz=RATE, channels=1, wav_bits_per_sample=16)
    # Reserve both names exclusively, even if another process races the preflight.
    created = []
    try:
        with output.open("xb") as wav_file:
            created.append(output)
            with sidecar.open("x", encoding="utf-8") as json_file:
                created.append(sidecar)
                pcm = np.rint(np.clip(samples, -1.0, 1.0) * 32767).astype("<i2")
                with wave.open(wav_file, "wb") as writer:
                    writer.setnchannels(1)
                    writer.setsampwidth(2)
                    writer.setframerate(RATE)
                    writer.writeframes(pcm.tobytes())
                json.dump(report, json_file, ensure_ascii=False, indent=2)
                json_file.write("\n")
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return report


def capture(sd, device, seconds):
    target = int(seconds * RATE)
    # At most 11.52 MB for the 60-second float32 capture. No growing callback list.
    samples = np.empty(target, dtype=np.float32)
    position = 0
    overflows = 0
    status_callbacks = 0
    callback_error = None
    done = threading.Event()
    interrupted = False

    def callback(data, frames, timing, status):
        nonlocal position, overflows, status_callbacks, callback_error
        try:
            overflows += int(bool(status.input_overflow))
            status_callbacks += int(bool(status))
            take = min(frames, target - position)
            samples[position:position + take] = data[:take, 0]
            position += take
            if position == target:
                done.set()
                raise sd.CallbackStop
        except sd.CallbackStop:
            raise
        except Exception as exc:
            callback_error = str(exc)
            done.set()
            raise sd.CallbackAbort

    with sd.InputStream(device=device, samplerate=RATE, channels=1,
                        dtype="float32", callback=callback,
                        extra_settings=sd.WasapiSettings(exclusive=False, auto_convert=True)) as stream:
        deadline = time.monotonic() + seconds + 5
        try:
            while not done.wait(0.1):
                if time.monotonic() >= deadline or not stream.active:
                    break
        except KeyboardInterrupt:
            interrupted = True
        finally:
            stream.abort()
    if callback_error:
        raise RuntimeError(f"Capture callback failed: {callback_error}")
    complete = position == target and not interrupted
    return samples[:position], {
        "requested_duration_seconds": seconds,
        "complete": complete,
        "interrupted": interrupted,
        "callback_input_overflow_count": overflows,
        "callback_status_count": status_callbacks,
        "capture_point": "Windows WASAPI shared CABLE Output",
    }


def main(argv=None):
    args = parse_args(argv)
    try:
        import sounddevice as sd
        devices = sd.query_devices()
        hosts = sd.query_hostapis()
        if args.list_devices:
            for index, device in enumerate(devices):
                if device["max_input_channels"]:
                    print(json.dumps({"index": index, "name": device["name"],
                                      "host_api": hosts[device["hostapi"]]["name"]}))
            return 0
        output, _ = output_paths(args.output)
        matches = [i for i, d in enumerate(devices)
                   if d["name"].startswith("CABLE Output") and d["max_input_channels"] >= 1
                   and hosts[d["hostapi"]]["name"] == "Windows WASAPI"]
        if len(matches) != 1:
            raise RuntimeError(f"Expected exactly one WASAPI CABLE Output; found {len(matches)}")
        sd.check_input_settings(device=matches[0], channels=1, dtype="float32", samplerate=RATE,
                                extra_settings=sd.WasapiSettings(exclusive=False, auto_convert=True))
        print(f"Recording CABLE Output for {args.seconds:g} seconds to {output}", flush=True)
        samples, metadata = capture(sd, matches[0], args.seconds)
        report = write_capture(output, samples, metadata)
        print(json.dumps(report, indent=2))
        if metadata["interrupted"]:
            print("Interrupted: partial recording saved.", file=sys.stderr)
            return 130
        if not metadata["complete"]:
            print("Incomplete capture: partial recording saved.", file=sys.stderr)
            return 1
        return 0
    except Exception as exc:
        print(f"Capture failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
