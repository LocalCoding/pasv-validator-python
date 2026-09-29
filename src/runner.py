import json
import os
import random
import resource
import signal
import subprocess
import sys
import tempfile
import threading
import time
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


# --- Sandbox ---------------------------------------------------------------
# Solutions are untrusted: anything may be submitted. When the service runs as root on Linux
# (the production container), every solution runs under its own unprivileged uid:
#   - it cannot signal the service or other solutions, nor read their files;
#   - the host firewall rejects all network traffic from these uids, including localhost
#     (the range must match SANDBOX_UIDS in the server's sandbox-limits.sh);
#   - RLIMIT_NPROC caps forking, and every process of the uid is killed after the run;
#   - the only writable place is its own directory on the /dev/shm tmpfs (64 MB total).
# Locally (macOS, non-root) it falls back to plain rlimits.
SANDBOX_UID_MIN = 70000
SANDBOX_UID_MAX = 79999
SANDBOX_ROOT = "/dev/shm/pasv"
MAX_PROCS = 16
OUTPUT_LIMIT_BYTES = 1024 * 1024
MAX_CONCURRENT_RUNS = 6  # x MEMORY_LIMIT_MB must fit the container memory limit (2 GB)

SANDBOXED = sys.platform == "linux" and os.geteuid() == 0

_uid_lock = threading.Lock()
_uids_in_use: set[int] = set()
_run_slots = threading.BoundedSemaphore(MAX_CONCURRENT_RUNS)


def init_sandbox() -> None:
    """Close world-writable places the image has, so a solution can write only to its own dir."""
    if not SANDBOXED:
        return
    for d in ("/tmp", "/var/tmp", "/run/lock", "/dev/shm"):
        if os.path.isdir(d):
            os.chmod(d, 0o711)
    os.makedirs(SANDBOX_ROOT, mode=0o711, exist_ok=True)
    os.chmod(SANDBOX_ROOT, 0o711)


def _acquire_uid() -> int:
    with _uid_lock:
        while True:
            uid = random.randint(SANDBOX_UID_MIN, SANDBOX_UID_MAX)
            if uid not in _uids_in_use:
                _uids_in_use.add(uid)
                return uid


def _release_uid(uid: int) -> None:
    with _uid_lock:
        _uids_in_use.discard(uid)


def _preexec(uid: int | None):
    def apply():
        os.setsid()
        # soft < hard: at the soft limit the kernel sends SIGXCPU (reported as a CPU limit),
        # the hard limit is only a backstop SIGKILL.
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_TIMEOUT_SEC, CPU_TIMEOUT_SEC + 1))
        mem = MEMORY_LIMIT_MB * 1024 * 1024
        if sys.platform != "darwin":
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_LIMIT_BYTES, OUTPUT_LIMIT_BYTES))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if uid is not None:
            resource.setrlimit(resource.RLIMIT_NPROC, (MAX_PROCS, MAX_PROCS))
            with open("/proc/self/oom_score_adj", "w") as f:
                f.write("1000")
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)
    return apply


def _pids_of_uid(uid: int) -> list[int]:
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            if os.stat(f"/proc/{entry}").st_uid != uid:
                continue
            with open(f"/proc/{entry}/stat") as f:
                state = f.read().rsplit(")", 1)[1].split()[0]
        except (FileNotFoundError, ProcessLookupError):
            continue
        if state != "Z":  # zombies are already dead; tini (PID 1) reaps them
            pids.append(int(entry))
    return pids


def _kill_everything(proc: subprocess.Popen, uid: int | None) -> None:
    """Kill the solution and anything it spawned, even if it left the process group."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    if uid is not None:
        for _ in range(50):
            pids = _pids_of_uid(uid)
            if not pids:
                break
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            time.sleep(0.02)
    proc.wait()


def _read_capped(f) -> str:
    f.seek(0)
    return f.read(OUTPUT_LIMIT_BYTES).decode("utf-8", errors="replace")


def run(solution: str, test: str) -> dict:
    script = (
        RUNNER_TEMPLATE
        .replace("__SOLUTION__", json.dumps(solution))
        .replace("__TEST__", json.dumps(test))
    )

    with _run_slots:
        uid = _acquire_uid() if SANDBOXED else None
        try:
            return _run_script(script, uid)
        finally:
            if uid is not None:
                _release_uid(uid)


def _run_script(script: str, uid: int | None) -> dict:
    # stdout/stderr go to unlinked temp files owned by the service: the solution reaches them only
    # through the inherited descriptors, and RLIMIT_FSIZE caps them at 1 MB.
    with tempfile.TemporaryDirectory(dir=SANDBOX_ROOT if uid is not None else None) as tmp, \
            tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        runner_path = Path(tmp) / "runner.py"
        runner_path.write_text(script)
        runner_path.chmod(0o444)
        if uid is not None:
            os.chown(tmp, uid, uid)

        proc = subprocess.Popen(
            [sys.executable, "-I", "-B", str(runner_path)],
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            cwd=tmp,
            preexec_fn=_preexec(uid),
            close_fds=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": tmp, "TMPDIR": tmp},
        )
        timed_out = False
        try:
            proc.wait(timeout=WALL_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            _kill_everything(proc, uid)

        output_overflow = max(os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size) >= OUTPUT_LIMIT_BYTES
        stdout = _read_capped(out)
        stderr = _read_capped(err)

        if timed_out:
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
    for line in stdout.splitlines():
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
        if output_overflow or proc.returncode == -25:
            err = "Output limit exceeded (1 MB)"
        elif proc.returncode == -24:
            err = f"Execution exceeded CPU time limit ({CPU_TIMEOUT_SEC}s) — possible infinite loop"
        elif proc.returncode == -9:
            err = "Process killed (out of memory or system limit)"
        else:
            err = f"Runner crashed (exit {proc.returncode})"
        results.append({
            "event": "terminal",
            "payload": {"err": err, "stack": stderr[-2000:]},
        })

    total = meta.get("tests", 0)
    passes = meta.get("passes", 0)
    return {
        "results": results,
        "totalTests": total,
        "passedTests": passes,
        "isPassed": total > 0 and total == passes,
    }
