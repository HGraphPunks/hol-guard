"""Real SDK MCP server in a private controller thread with per-session pipes.

No process-wide stdin/stdout replacement and no signing authority serialization.
The supervisor supplies a trusted ServiceWorld object and owns authentication,
frame/count/time budgets, cancellation and explicit worker lifecycle evidence.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import os
import subprocess
import threading
import time
from uuid import uuid4

import anyio
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage

from .contracts import canonical_json
from .mcp_server import create_server
from .service_relay import validate_frame


class ServiceObservationLog:
    """Lifetime limits include metadata, rejected traffic and reconnect history."""

    def __init__(self, run_id, stop, observer, *, max_bytes, max_events, max_sessions):
        for value, maximum in ((max_bytes, 16 * 1024 * 1024), (max_events, 10000), (max_sessions, 64)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError('invalid service observation budget')
        self.run_id, self.stop, self.observer = run_id, stop, observer
        self.max_bytes, self.max_events, self.max_sessions = max_bytes, max_events, max_sessions
        self.events, self.bytes, self.count, self.sessions = [], 0, 0, 0
        self.reason = None
        self.failure_reported = self.observer_failed = False
        self._lock, self._emission_lock = threading.RLock(), threading.RLock()

    def start_session(self):
        with self._lock:
            if self.reason is not None or self.sessions >= self.max_sessions:
                self.reason = self.reason or 'lifetime-session-budget'
                self.stop.set()
                return False
            self.sessions += 1
            return True

    def emit(self, kind, *, timestamp=False, **fields):
        # Publish serially, without holding the state lock across a callback.
        with self._emission_lock:
            with self._lock:
                event = {'sequence': len(self.events) + 1, 'run_id': self.run_id, 'kind': kind, **fields}
                if timestamp:
                    event['observed_monotonic_ns'] = time.monotonic_ns()
                size = 0 if self.reason else len(canonical_json(event).encode('utf-8'))
                if self.reason or self.count >= self.max_events or size > self.max_bytes - self.bytes:
                    self.reason = self.reason or 'lifetime-observation-budget'
                    self.stop.set()
                    if self.failure_reported:
                        if 'message' in fields:
                            raise ValueError('service observation budget exhausted')
                        return
                    self.failure_reported = True
                    event = {'sequence': len(self.events) + 1, 'run_id': self.run_id,
                             'kind': 'observation-budget-exceeded', 'reason': self.reason}
                else:
                    self.bytes += size
                    self.count += 1
                self.events.append(event)
            if self.observer is not None:
                try:
                    self.observer(copy.deepcopy(event))
                except Exception as error:
                    with self._lock:
                        if not self.observer_failed:
                            self.events.append({'sequence': len(self.events) + 1, 'run_id': self.run_id,
                                                'kind': 'observer-error', 'reason': type(error).__name__})
                            self.observer_failed = True
                        self.stop.set()
            if self.reason and 'message' in fields:
                raise ValueError('service observation budget exhausted')


class ServiceThreadBackend:
    backend_kind = "controller-thread"
    pid = None

    def __init__(self, world, family, *, max_frame_bytes, observer=None, server_factory=None):
        self.worker_id = uuid4().hex
        self.returncode = None
        self._observer, self._maximum = observer, max_frame_bytes
        self._server_factory = server_factory or create_server
        self._loop = self._scope = None
        incoming, write_fd = os.pipe()
        read_fd, outgoing = os.pipe()
        self.stdin = os.fdopen(write_fd, "wb", buffering=0)
        self.stdout = os.fdopen(read_fd, "rb", buffering=0)
        self._incoming = os.fdopen(incoming, "rb", buffering=64 * 1024)
        self._outgoing = os.fdopen(outgoing, "wb", buffering=0)
        os.set_blocking(self.stdin.fileno(), False)
        os.set_blocking(self.stdout.fileno(), False)
        self._thread = threading.Thread(
            target=self._run, args=(world, family), name="mcp-controller-" + self.worker_id, daemon=True
        )
        self._thread.start()

    def alive(self):
        return self._thread.is_alive()

    def _run(self, world, family):
        try:
            anyio.run(self._serve, world, family)
            self.returncode = 0
        except BaseException as error:
            self.returncode = 1
            if self._observer is not None:
                self._observer(
                    {"kind": "server-worker-error", "worker_id": self.worker_id, "reason": type(error).__name__}
                )
        finally:
            self._incoming.close()
            self._outgoing.close()

    async def _serve(self, world, family):
        self._loop = asyncio.get_running_loop()
        server = self._server_factory(world, family)._mcp_server
        incoming_write, incoming_read = anyio.create_memory_object_stream[SessionMessage](0)
        outgoing_write, outgoing_read = anyio.create_memory_object_stream[SessionMessage](0)
        with anyio.CancelScope() as scope:
            self._scope = scope
            async with anyio.create_task_group() as group:

                async def receive():
                    async with incoming_write:
                        while True:
                            raw = await anyio.to_thread.run_sync(self._incoming.readline, self._maximum + 2)
                            if not raw:
                                group.cancel_scope.cancel()
                                return
                            if not raw.endswith(b"\n"):
                                raise ValueError("incomplete or oversized controller server frame")
                            validate_frame(raw[:-1], self._maximum)
                            await incoming_write.send(SessionMessage(JSONRPCMessage.model_validate_json(raw)))

                async def send():
                    async with outgoing_read:
                        async for message in outgoing_read:
                            record = message.message.model_dump(by_alias=True, mode="json", exclude_none=True)
                            raw = canonical_json(record).encode("utf-8")
                            validate_frame(raw, self._maximum)
                            await anyio.to_thread.run_sync(self._outgoing.write, raw + b"\n")

                group.start_soon(receive)
                group.start_soon(send)
                try:
                    await server.run(incoming_read, outgoing_write, server.create_initialization_options())
                finally:
                    group.cancel_scope.cancel()

    def _write(self, raw):
        pending = memoryview(raw)
        while pending:
            pending = pending[self._outgoing.write(pending) :]

    def wait(self, timeout=None):
        self._thread.join(timeout)
        if self._thread.is_alive():
            raise subprocess.TimeoutExpired("controller MCP worker", timeout)
        return self.returncode

    def terminate(self):
        self.stdin.close()
        self.stdout.close()
        if self._loop is not None and self._scope is not None:
            with contextlib.suppress(RuntimeError):
                self._loop.call_soon_threadsafe(self._scope.cancel)

    def kill(self):
        # A worker thread cannot be force-killed safely. Cancellation remains
        # explicit; a still-active worker must be reported as incomplete cleanup.
        self.terminate()


def finish_service_backend(process, emit, *, family, session_id):
    """Bound teardown while retaining a still-active worker as cleanup failure."""
    process.stdin.close()
    for action in (None, process.terminate, process.kill):
        if action is not None:
            action()
        try:
            process.wait(timeout=2)
            break
        except subprocess.TimeoutExpired:
            continue
    else:
        emit("cleanup-incomplete", family=family, session_id=session_id, reason="service-worker-still-active")
        return False
    process.stdout.close()
    if isinstance(process, ServiceThreadBackend):
        emit(
            "server-worker-stopped",
            family=family,
            session_id=session_id,
            worker_id=process.worker_id,
            returncode=process.returncode,
            active=process.alive(),
        )
    else:
        emit("child-reaped", family=family, session_id=session_id, pid=process.pid, returncode=process.returncode)
    return True
