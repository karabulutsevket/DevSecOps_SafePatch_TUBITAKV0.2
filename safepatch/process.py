"""Fixed-command child execution. Never accepts shell command text from jobs/models."""
import os
from pathlib import Path
import subprocess
import time

from safepatch.common import runtime


def child_env(extra=None):
    keep = ("PATH", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "JAVA_HOME", "LANG")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    home = runtime("runner-home")
    env.update({"HOME": str(home), "USERPROFILE": str(home), "TEMP": str(home), "TMP": str(home), "TMPDIR": str(home), "MAVEN_OPTS": "-Xmx512m -Dfile.encoding=UTF-8", "GIT_TERMINAL_PROMPT": "0", "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"})
    env.update(extra or {})
    return env


def limits():
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
    resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024**2, 128 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (512, 512))


def run(argv, cwd: Path, timeout, extra_env=None):
    started = time.monotonic()
    log = cwd / "command-output.log"
    with log.open("wb") as output:
        process = subprocess.Popen(argv, cwd=cwd, env=child_env(extra_env), stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, start_new_session=os.name != "nt", preexec_fn=limits if os.name != "nt" else None, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            terminate(process)
            raise TimeoutError("child_timeout")
    # Raw logs stay in the restricted runner workspace, never in model/system logs.
    tail = log.read_bytes()[-16000:].decode("utf-8", errors="replace")
    return {"exit_code": code, "duration_seconds": round(time.monotonic() - started, 3), "output": tail}


def terminate(process):
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=15)
        if process.poll() is None:
            # The caller owns this Popen handle. Windows restricted tokens may deny
            # taskkill's process enumeration while still permitting direct termination.
            process.kill()
    else:
        import signal
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=15)
