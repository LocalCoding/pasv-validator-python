import json
import os
import resource
import subprocess
import sys
import tempfile
from pathlib import Path

MEMORY_LIMIT_MB = 256
CPU_TIMEOUT_SEC = 10
WALL_TIMEOUT_SEC = 12

RUNNER_TEMPLATE = r'''
import json, sys, time, traceback, inspect

def _emit(event, payload):
    sys.stdout.write("__PASV__" + json.dumps({"event": event, "payload": payload}) + "\n")
    sys.stdout.flush()

_SOLUTION = __SOLUTION__
_TEST = __TEST__

_ns = {"__name__": "__pasv_sandbox__"}

try:
    exec(compile(_SOLUTION, "<solution>", "exec"), _ns)
except Exception as e:
    _emit("terminal", {"err": str(e) or type(e).__name__, "stack": traceback.format_exc()})
    _emit("__meta", {"tests": 0, "passes": 0})
    sys.exit(0)

try:
    exec(compile(_TEST, "<test>", "exec"), _ns)
except Exception as e:
    _emit("terminal", {"err": str(e) or type(e).__name__, "stack": traceback.format_exc()})
    _emit("__meta", {"tests": 0, "passes": 0})
    sys.exit(0)

_tests = []
for _name, _obj in list(_ns.items()):
    if _name.startswith("test_") and callable(_obj):
        _tests.append((_name, _name, _obj))
    elif _name.startswith("TestClass") and inspect.isclass(_obj):
        try:
            _inst = _obj()
        except Exception as e:
            _emit("fail", {
                "title": _name, "fullTitle": _name, "duration": 0, "currentRetry": 0,
                "err": "Could not instantiate " + _name + ": " + str(e),
                "stack": traceback.format_exc()
            })
            continue
        for _mname in sorted(dir(_inst)):
            if not _mname.startswith("test_"):
                continue
            _mobj = getattr(_inst, _mname)
            if not callable(_mobj):
                continue
            _doc = (inspect.getdoc(_mobj) or _mname).strip()
            _tests.append((_doc, _name + " " + _doc, _mobj))

_passes = 0
for _title, _full, _fn in _tests:
    _t0 = time.time()
    try:
        _fn()
        _dur = int((time.time() - _t0) * 1000)
        _emit("pass", {"title": _title, "fullTitle": _full, "duration": _dur, "currentRetry": 0})
        _passes += 1
    except AssertionError as e:
        _dur = int((time.time() - _t0) * 1000)
        _emit("fail", {
            "title": _title, "fullTitle": _full, "duration": _dur, "currentRetry": 0,
            "err": str(e) or "AssertionError",
            "stack": traceback.format_exc(),
        })
    except Exception as e:
        _dur = int((time.time() - _t0) * 1000)
        _emit("fail", {
            "title": _title, "fullTitle": _full, "duration": _dur, "currentRetry": 0,
            "err": type(e).__name__ + ": " + str(e),
            "stack": traceback.format_exc(),
        })

_emit("__meta", {"tests": len(_tests), "passes": _passes})
'''


def _set_limits():
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_TIMEOUT_SEC, CPU_TIMEOUT_SEC))
    mem = MEMORY_LIMIT_MB * 1024 * 1024
    if sys.platform != "darwin":
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    os.setsid()


def run(solution: str, test: str) -> dict:
    script = (
        RUNNER_TEMPLATE
        .replace("__SOLUTION__", json.dumps(solution))
        .replace("__TEST__", json.dumps(test))
    )

    with tempfile.TemporaryDirectory() as tmp:
        runner_path = Path(tmp) / "runner.py"
        runner_path.write_text(script)

        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-B", str(runner_path)],
                capture_output=True,
                text=True,
                timeout=WALL_TIMEOUT_SEC,
                cwd=tmp,
                preexec_fn=_set_limits,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            )
        except subprocess.TimeoutExpired:
            return {
                "results": [{
                    "event": "terminal",
                    "payload": {
                        "err": "Execution timed out after " + str(WALL_TIMEOUT_SEC) + "s",
                        "stack": "",
                    },
                }],
                "totalTests": 0,
                "passedTests": 0,
                "isPassed": False,
            }

    results = []
    meta = {"tests": 0, "passes": 0}
    for line in proc.stdout.splitlines():
        if not line.startswith("__PASV__"):
            continue
        try:
            obj = json.loads(line[len("__PASV__"):])
        except json.JSONDecodeError:
            continue
        if obj.get("event") == "__meta":
            meta = obj.get("payload", meta)
        else:
            results.append(obj)

    if proc.returncode != 0 and not results:
        if proc.returncode == -24:
            err = f"Execution exceeded CPU time limit ({CPU_TIMEOUT_SEC}s) — possible infinite loop"
        elif proc.returncode == -9:
            err = "Process killed (out of memory or system limit)"
        else:
            err = f"Runner crashed (exit {proc.returncode})"
        results.append({
            "event": "terminal",
            "payload": {"err": err, "stack": proc.stderr[-2000:]},
        })

    total = meta.get("tests", 0)
    passes = meta.get("passes", 0)
    return {
        "results": results,
        "totalTests": total,
        "passedTests": passes,
        "isPassed": total > 0 and total == passes,
    }
