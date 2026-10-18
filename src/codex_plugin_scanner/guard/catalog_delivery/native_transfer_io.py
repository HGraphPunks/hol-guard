"""Bounded CLI progress IO; all transfer planning and verification are native."""

from __future__ import annotations

import json
import queue
import subprocess
import threading

from ..extension_builder import native_source_compiler as transport


def run(executable, payload):
    try:
        process = subprocess.Popen(
            [str(executable), "pack-lifecycle", "--stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except OSError as exc:
        raise ValueError("native transfer could not be started") from exc
    messages = queue.Queue()
    errors = bytearray()
    overflow = threading.Event()

    def output():
        consumed = 0
        try:
            while line := process.stdout.readline(65537):
                consumed += len(line)
                if len(line) > 65536 or consumed > transport._MAX_OUTPUT_BYTES:
                    overflow.set()
                    process.kill()
                    break
                messages.put(line)
        except (OSError, ValueError):
            pass
        finally:
            messages.put(None)

    def stderr():
        try:
            while chunk := process.stderr.read(65536):
                if len(errors) + len(chunk) > transport._MAX_STDERR_BYTES:
                    overflow.set()
                    process.kill()
                    return
                errors.extend(chunk)
        except (OSError, ValueError):
            pass

    def stdin():
        try:
            process.stdin.write(payload)
            process.stdin.close()
        except (OSError, ValueError):
            pass

    threads = [threading.Thread(target=target, daemon=True) for target in (output, stderr, stdin)]
    for thread in threads:
        thread.start()
    result = None
    copied = None
    total = None
    try:
        while True:
            try:
                line = messages.get(timeout=60)
            except queue.Empty as exc:
                raise ValueError("native transfer progress timed out") from exc
            if line is None:
                break
            row = json.loads(line)
            if result is not None or not isinstance(row, dict):
                raise ValueError("native transfer response invalid")
            if "copy_progress" in row:
                value, count = row["copy_progress"], row.get("files")
                if (
                    type(value) is not int
                    or type(count) is not int
                    or not 0 <= value <= count
                    or (total is not None and count != total)
                    or (copied is not None and value <= copied)
                ):
                    raise ValueError("native transfer progress invalid")
                copied, total = value, count
            elif total is not None and row.get("complete") is True and row.get("files") == total and copied == total:
                result = row
            else:
                raise ValueError("native transfer response invalid")
        code = process.wait(timeout=60)
        if overflow.is_set() or code or result is None:
            raise ValueError("native transfer failed: " + bytes(errors[:512]).decode("utf-8", errors="replace"))
        return result
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        for thread in threads:
            thread.join(timeout=1)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
        for thread in threads:
            thread.join()
