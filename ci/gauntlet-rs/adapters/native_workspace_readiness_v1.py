"""One unprivileged normal-client readiness call; Rust checks the response.

The disposable product credential stays inside its own product namespace.
Body retained from private_cell_readiness.PROBE at product source 62aa7ba7.
"""

import http.client
import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token

token = load_guard_daemon_auth_token(Path("/product/guard"))
if type(token) is not str or not token:
    raise SystemExit(69)
connection = http.client.HTTPConnection("127.0.0.1", 18765, timeout=float(sys.argv[2]) - 1)
try:
    connection.request(
        "POST",
        "/v1/hooks/omp/readiness",
        body=json.dumps({"workspace": sys.argv[1]}).encode(),
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
    )
    response = connection.getresponse()
    body = response.read(4097)
    if len(body) > 4096:
        raise SystemExit(69)
    sys.stdout.buffer.write(body)
    raise SystemExit(0 if response.status == 200 else 69)
finally:
    connection.close()
