import ast
import base64
import json
import os
import random
import resource
import secrets
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

# The harness runs inside the sandboxed process together with the untrusted solution. It must not
# be possible for the solution to report tests as passed. Layers:
#   1. Results go to a separate descriptor, one line per test, prefixed with a random nonce the
#      service passes over stdin; the service accepts only lines with that nonce.
#   2. The service decides which tests exist (parsed from the test source); a test without a
#      result is a failure, tests defined by the solution are ignored.
#   3. An audit hook, installed before the solution runs, blocks the ways to reach the harness's
#      frames and closures (sys._getframe, traceback/generator frames, gc, tracing, signal,
#      ctypes, /proc/self/mem, rewriting __code__). Python has no real in-process isolation, so
#      this raises the bar rather than proving anything; the process-level sandbox does the rest.
#   4. Comparisons in `assert` are rewritten so an object with a custom __eq__ (the classic
#      "always equal" trick) never equals a plain value (int, str, list, dict, ...).
RUNNER_TEMPLATE = r"""
def _pasv():
    import ast, binascii, json, os, sys, threading, time
    cfg = json.loads(sys.stdin.buffer.read())
    os.close(0)
    nonce, res_fd, plan = cfg["nonce"], cfg["fd"], cfg["plan"]
    test_file = "<test-" + nonce[:12] + ">"

    # captured before the solution runs: it may replace anything in builtins afterwards
    Str, Type, BaseExc, Len, Bytes = str, type, BaseException, len, bytes
    Callable, Getattr, Enumerate = callable, getattr, enumerate
    ValueErr, AttrErr, RuntimeErr, ImportErr, PermErr = ValueError, AttributeError, RuntimeError, ImportError, PermissionError
    AssertErr = AssertionError
    FunctionType = Type(enc_dummy := lambda: None)
    MethodType = Type(Type("C", (), {"m": lambda self: None})().m)
    cwd_path = os.getcwd()
    b64 = binascii.b2a_base64
    write, clock, get_ident = os.write, time.perf_counter, threading.get_ident
    main_ident = get_ident()

    def enc(text):
        if Type(text) is not Str:
            text = "<unprintable>"
        return b64(text[:8000].encode("utf-8", "replace"), newline=False).decode("ascii")

    def emit(*fields):
        try:
            write(res_fd, (nonce + "\t" + "\t".join(fields) + "\n").encode("ascii"))
        except OSError:
            pass

    def describe(e):
        try:
            msg = Str(e)
        except BaseExc:
            msg = ""
        if Type(msg) is not Str:
            msg = ""
        return msg

    # --- audit hook ------------------------------------------------------------------------
    priv = [False]
    frame_attrs = frozenset(("tb_frame", "gi_frame", "cr_frame", "ag_frame"))
    blocked = frozenset((
        "sys._current_frames", "sys.settrace", "sys.setprofile", "gc.get_objects",
        "gc.get_referrers", "gc.get_referents", "code.__new__", "function.__new__",
        "os.symlink", "os.link", "os.chdir", "os.fchdir", "sys.addaudithook",
    ))
    blocked_imports = frozenset((
        "ctypes", "_ctypes", "signal", "_signal", "faulthandler", "_testcapi", "_testinternalcapi",
        "_xxsubinterpreters", "_xxinterpchannels", "_imp", "pdb", "bdb",
    ))
    allowed_dev = frozenset(("/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"))

    def bad_path(path):
        if Type(path) is Bytes:
            path = path.decode("utf-8", "replace")
        if Type(path) is not Str:
            return False                      # an already open descriptor
        if ".." in path:
            return True
        if not path.startswith("/"):
            return False                      # inside the solution's own directory
        while "//" in path or "/./" in path:
            path = path.replace("//", "/").replace("/./", "/")
        if path in allowed_dev:
            return False
        return path == "/proc" or path == "/sys" or path.startswith(("/proc/", "/sys/", "/dev/"))

    def hook(event, args):
        if priv[0] and get_ident() == main_ident:
            return
        if event == "sys._getframe":
            # ValueError: what namedtuple, enum, logging and warnings already handle
            raise ValueErr("stack inspection is not available in the validator")
        if event == "object.__getattr__" and Len(args) > 1 and args[1] in frame_attrs:
            raise AttrErr("not available in the validator: " + Str(args[1]))
        if event == "object.__getattr__" and Len(args) > 1 and args[1] == "__code__" and Type(args[0]) is FunctionType:
            # reading code objects is fine (namedtuple, enum...), except the tests' own
            priv[0] = True
            try:
                test_owned = args[0].__code__.co_filename == test_file
            finally:
                priv[0] = False
            if test_owned:
                raise AttrErr("not available in the validator: __code__")
        if event == "object.__setattr__" and Len(args) > 1 and args[1] == "__code__":
            raise AttrErr("not available in the validator: __code__")
        if event in blocked:
            raise RuntimeErr("not available in the validator: " + event)
        if event == "import" and Type(args[0]) is Str and args[0].split(".")[0] in blocked_imports:
            raise ImportErr("module is not available in the validator: " + args[0])
        if event in ("open", "os.listdir", "os.scandir") and Len(args) > 0 and bad_path(args[0]):
            raise PermErr("path is not available in the validator")

    def stack_of(e):
        lines = []
        tb = e.__traceback__
        depth = 0
        while tb is not None and depth < 50:
            priv[0] = True
            try:
                frame = tb.tb_frame
                code = frame.f_code
            finally:
                priv[0] = False
            name = code.co_filename
            if name == test_file:
                name = "<test>"
            if name in ("<solution>", "<test>"):
                lines.append('  File "' + name + '", line ' + Str(tb.tb_lineno) + ", in " + code.co_name)
            tb = tb.tb_next
            depth += 1
        return "Traceback (most recent call last):\n" + "\n".join(lines) + "\n" + Type(e).__name__ + ": " + describe(e)

    # --- compile tests before any solution code runs ----------------------------------------
    PLAIN = (
        "(lambda P, v: (lambda t: t is (0).__class__ or t is (0.0).__class__ or t is ''.__class__"
        " or t is True.__class__ or t is None.__class__ or t is b''.__class__ or t is (0j).__class__"
        " or ((t is [].__class__ or t is ().__class__ or t is {0}.__class__)"
        "     and False not in [P(P, x) for x in v])"
        " or (t is {}.__class__ and False not in [P(P, k) and P(P, x) for k, x in v.items()])"
        ")(().__class__.__class__(v)))"
    )
    OPS = {ast.Eq: ("a == b", "False"), ast.NotEq: ("a != b", "True"),
           ast.Lt: ("a < b", "False"), ast.LtE: ("a <= b", "False"),
           ast.Gt: ("a > b", "False"), ast.GtE: ("a >= b", "False")}

    def guard(op_type):
        real, mixed = OPS[op_type]
        # a plain value compared with a non-plain one: the answer is fixed, custom dunders are not called
        return ast.parse("(lambda a, b: (lambda P: " + real + " if P(P, a) == P(P, b) else " + mixed
                         + ")(" + PLAIN + "))", mode="eval").body

    def guard_in(negate):
        real = "a not in b" if negate else "a in b"
        mixed = "True" if negate else "False"
        return ast.parse("(lambda a, b: (lambda P: " + mixed + " if P(P, b) and not P(P, a) else " + real
                         + ")(" + PLAIN + "))", mode="eval").body

    class Harden(ast.NodeTransformer):
        def visit_Assert(self, node):
            self.generic_visit(node)
            test = node.test
            if isinstance(test, ast.Compare) and len(test.ops) == 1:
                op = type(test.ops[0])
                fn = guard(op) if op in OPS else guard_in(op is ast.NotIn) if op in (ast.In, ast.NotIn) else None
                if fn is not None:
                    call = ast.Call(func=fn, args=[test.left, test.comparators[0]], keywords=[])
                    node.test = ast.copy_location(call, test)
                    ast.fix_missing_locations(node)
                    for sub in ast.walk(node.test):
                        if hasattr(sub, "lineno"):
                            sub.lineno = sub.end_lineno = test.lineno
            return node

    try:
        tree = Harden().visit(ast.parse(cfg["test"], "<test>"))
        test_code = compile(tree, test_file, "exec")
        solution_code = compile(cfg["solution"], "<solution>", "exec")
    except BaseExc as e:
        emit("T", enc(Type(e).__name__ + ": " + describe(e)), enc(""))
        emit("E")
        return

    for name in ("signal", "_signal", "faulthandler"):
        sys.modules.pop(name, None)
    sys.addaudithook(hook)

    ns = {"__name__": "__pasv_sandbox__", "__builtins__": __builtins__}
    try:
        exec(solution_code, ns)
        exec(test_code, ns)
    except BaseExc as e:
        emit("T", enc(Type(e).__name__ + ": " + describe(e)), enc(stack_of(e)))
        emit("E")
        return

    def own(fn):
        # the test must come from the test source, not be replaced by the solution. Only exact
        # function/method types are touched, so no solution code can run while priv is set.
        if Type(fn) is MethodType:
            fn = fn.__func__
        if Type(fn) is not FunctionType:
            return False
        priv[0] = True
        try:
            code = fn.__code__
        finally:
            priv[0] = False
        return code.co_filename == test_file

    calls = []
    instances = {}
    for kind, name, method in plan:
        obj = ns.get(name)
        if kind == "func":
            calls.append((obj, None) if own(obj) else (None, "Test was not found or was replaced"))
            continue
        if name not in instances:
            try:
                instances[name] = (obj(), None) if Type(obj) is Type else (None, "Test class was not found")
            except BaseExc as e:
                instances[name] = (None, "Could not instantiate " + name + ": " + describe(e))
        inst, error = instances[name]
        fn = Getattr(inst, method, None) if inst is not None else None
        calls.append((fn, None) if fn is not None and own(fn) else (None, error or "Test was not found or was replaced"))

    for index, (fn, error) in Enumerate(calls):
        if fn is None:
            emit("R", Str(index), "F", "0", enc(error), enc(""))
            continue
        t0 = clock()
        try:
            fn()
            emit("R", Str(index), "P", Str(int((clock() - t0) * 1000)), "", "")
        except BaseExc as e:
            ms = Str(int((clock() - t0) * 1000))
            msg = describe(e) if Type(e) is AssertErr else Type(e).__name__ + ": " + describe(e)
            emit("R", Str(index), "F", ms, enc(msg or "AssertionError"), enc(stack_of(e)))
    emit("E")

_pasv()
del _pasv
"""


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


def plan_tests(test: str) -> list[dict]:
    """Tests the harness must report on, in order, taken from the test source itself."""
    try:
        tree = ast.parse(test)
    except SyntaxError:
        return []
    plan, seen = [], set()

    def add(key, title, full):
        if key not in seen:
            seen.add(key)
            plan.append({"key": key, "title": title, "fullTitle": full})

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            add(("func", node.name, None), node.name, node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name) and t.id.startswith("test_"):
                    add(("func", t.id, None), t.id, t.id)
        elif isinstance(node, ast.ClassDef) and node.name.startswith("TestClass"):
            methods = sorted(
                (m for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name.startswith("test_")),
                key=lambda m: m.name,
            )
            for m in methods:
                title = (ast.get_docstring(m) or m.name).strip()
                add(("method", node.name, m.name), title, node.name + " " + title)
    return plan


def run(solution: str, test: str) -> dict:
    with _run_slots:
        uid = _acquire_uid() if SANDBOXED else None
        try:
            return _run_script(solution, test, uid)
        finally:
            if uid is not None:
                _release_uid(uid)


def _terminal(err: str, stack: str = "") -> dict:
    return {
        "results": [{"event": "terminal", "payload": {"err": err, "stack": stack}}],
        "totalTests": 0,
        "passedTests": 0,
        "isPassed": False,
    }


def _b64(value: str) -> str:
    try:
        return base64.b64decode(value).decode("utf-8", errors="replace")
    except ValueError:
        return ""


def _run_script(solution: str, test: str, uid: int | None) -> dict:
    plan = plan_tests(test)
    nonce = secrets.token_hex(16)
    # stdout/stderr/results go to unlinked temp files owned by the service: the solution reaches them
    # only through the inherited descriptors, and RLIMIT_FSIZE caps them at 1 MB.
    with tempfile.TemporaryDirectory(dir=SANDBOX_ROOT if uid is not None else None) as tmp, \
            tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err, \
            tempfile.TemporaryFile() as res:
        runner_path = Path(tmp) / "runner.py"
        runner_path.write_text(RUNNER_TEMPLATE)
        runner_path.chmod(0o444)
        if uid is not None:
            os.chown(tmp, uid, uid)
        payload = json.dumps({
            "nonce": nonce,
            "fd": res.fileno(),
            "plan": [list(p["key"]) for p in plan],
            "solution": solution,
            "test": test,
        }).encode()

        proc = subprocess.Popen(
            [sys.executable, "-I", "-B", str(runner_path)],
            stdin=subprocess.PIPE,
            stdout=out,
            stderr=err,
            cwd=tmp,
            preexec_fn=_preexec(uid),
            close_fds=True,
            pass_fds=(res.fileno(),),
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": tmp, "TMPDIR": tmp},
        )
        timed_out = False
        try:
            proc.communicate(input=payload, timeout=WALL_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            timed_out = True
        except BrokenPipeError:
            pass
        finally:
            _kill_everything(proc, uid)

        output_overflow = max(os.fstat(f.fileno()).st_size for f in (out, err, res)) >= OUTPUT_LIMIT_BYTES
        stderr = _read_capped(err)
        records = _read_capped(res)

    terminal, outcomes, ended = None, {}, False
    prefix = nonce + "\t"
    for line in records.splitlines():
        if not line.startswith(prefix):
            continue
        fields = line[len(prefix):].split("\t")
        if fields[0] == "E":
            ended = True
        elif fields[0] == "T" and len(fields) == 3:
            terminal = (_b64(fields[1]), _b64(fields[2]))
        elif fields[0] == "R" and len(fields) == 6 and fields[1].isdigit():
            index = int(fields[1])
            if 0 <= index < len(plan) and index not in outcomes:
                outcomes[index] = fields

    if terminal is not None:
        return _terminal(*terminal)

    if timed_out:
        reason = f"Execution timed out after {WALL_TIMEOUT_SEC}s"
    elif output_overflow or proc.returncode == -25:
        reason = "Output limit exceeded (1 MB)"
    elif proc.returncode == -24:
        reason = f"Execution exceeded CPU time limit ({CPU_TIMEOUT_SEC}s) — possible infinite loop"
    elif proc.returncode == -9:
        reason = "Process killed (out of memory or system limit)"
    elif not ended:
        reason = f"The solution ended the run before all tests finished (exit {proc.returncode})"
    else:
        reason = "Test did not report a result"

    if not outcomes and (timed_out or not ended):
        return _terminal(reason, stderr[-2000:])

    results, passes = [], 0
    for index, test_info in enumerate(plan):
        fields = outcomes.get(index)
        payload = {"title": test_info["title"], "fullTitle": test_info["fullTitle"], "currentRetry": 0}
        if fields is None:
            results.append({"event": "fail", "payload": {**payload, "duration": 0, "err": reason, "stack": ""}})
            continue
        _, _, status, ms, err_text, stack = fields
        payload["duration"] = int(ms) if ms.isdigit() else 0
        if status == "P":
            passes += 1
            results.append({"event": "pass", "payload": payload})
        else:
            results.append({"event": "fail", "payload": {**payload, "err": _b64(err_text), "stack": _b64(stack)}})

    return {
        "results": results,
        "totalTests": len(plan),
        "passedTests": passes,
        "isPassed": len(plan) > 0 and passes == len(plan),
    }
