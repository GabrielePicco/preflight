#!/usr/bin/env python3
"""Record the isolated demo as a local asciicast v2 file; never upload it."""
import json
import os
from pathlib import Path
import subprocess
import time

demo = Path(__file__).resolve().parent
env = dict(os.environ, PREFLIGHT_DEMO_PAUSE="3", COLOR="always")
with (demo / "demo.cast").open("w") as recording:
    recording.write(json.dumps({"version": 2, "width": 120, "height": 54,
                                "title": "preflight: BLOCKED → GO → BLOCKED",
                                "env": {"TERM": "xterm-256color"}}) + "\n")
    start = time.monotonic()
    process = subprocess.Popen([str(demo / "demo.sh")], cwd=demo, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while chunk := process.stdout.read1(65536):
        text = chunk.decode("utf-8").replace("\n", "\r\n")
        # Defense in depth: only demo output belongs in this recording.
        if str(demo.parent) in text or str(Path.home()) in text:
            process.terminate()
            raise SystemExit("Refusing to record an absolute machine path")
        recording.write(json.dumps([round(time.monotonic() - start, 3), "o", text]) + "\n")
    if process.wait():
        raise SystemExit("Demo failed; do not share this recording")
    recording.write(json.dumps([round(time.monotonic() - start + 3, 3), "o", "\r\n"]) + "\n")
print("Wrote demo/demo.cast (local playback only; no upload)")
