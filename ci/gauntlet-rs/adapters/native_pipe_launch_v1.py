"""Unprivileged launch instrumentation; Native identity and decisions stay intact.

Rust supplies the pinned bundled executable and owns the relay and all evidence.
Only subprocess launches of that exact executable use the apparatus connector.
This adapter has no policy, hashing, state, grading, or publication authority.
"""

import os
import runpy
import subprocess
import sys

native, mode, target = sys.argv[1:4]
if mode not in ("-m", "-c"):
    raise SystemExit(69)
connector = "/public/gauntlet-product-cell"


class _PipeLaunch(subprocess.Popen):
    def __init__(self, args, *positional, **options):
        executable = options.get("executable", positional[1] if len(positional) > 1 else None)
        shell = options.get("shell", positional[7] if len(positional) > 7 else False)
        if not shell and isinstance(args, (list, tuple)) and args:
            program = executable if executable is not None else args[0]
            if os.fsdecode(os.fspath(program)) == native:
                args = [connector, *args[1:]]
                if len(positional) > 1:
                    positional = (positional[0], connector, *positional[2:])
                elif executable is not None:
                    options["executable"] = connector
        super().__init__(args, *positional, **options)


subprocess.Popen = _PipeLaunch
arguments = sys.argv[4:]
if mode == "-m":
    sys.argv = [target, *arguments]
    runpy.run_module(target, run_name="__main__", alter_sys=True)
else:
    sys.argv = ["-c", *arguments]
    exec(compile(target, "<gauntlet-product-command>", "exec"), {"__name__": "__main__"})
