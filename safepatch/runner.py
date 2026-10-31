import base64
from collections import ChainMap
import io
import json
import os
from pathlib import Path
import posixpath
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET

from fastapi import Depends, FastAPI, HTTPException

from safepatch.acceptance import untolerated
from safepatch.common import ROOT, VerifyRequest, digest, known_findings_enabled, safe_path, remaining, require_service, runtime, secret, setting
from safepatch.policy import PolicyError, validate_patch
from safepatch.process import run
from safepatch.repository import allowed_files, baseline, checkout, commit_candidate, git_command, run_git, tracked_changes
from safepatch.scanner import SPOTBUGS_VERSION, SonarAdapter, builtin_scan, parse_semgrep, parse_spotbugs

app = FastAPI(title="SafePatch restricted runner")
lock = threading.Lock()


# Docker sandbox (roadmap weeks 5–6): build and tests run project code, so a real project is
# only ever built in a container with no network, a read-only root, no capabilities, a
# non-root user and resource limits. Dependencies come from a read-only copy of the offline
# Maven cache inside WSL (on /mnt/c a build takes ~8x longer).
SANDBOX_IMAGE = "maven:3.9.16-eclipse-temurin-17@sha256:1a352420f7aba21f5ad08df31bab55f74c013fb491f1ae8ab1dd7ff9ed698584"
# The descriptor's `java` picks the image: old projects (most Vul4J cases) cannot build on JDK 17.
SANDBOX_IMAGES = {"17": SANDBOX_IMAGE, "8": "maven:3.9.16-eclipse-temurin-8@sha256:0f402712b7a469189cfea5ec69cdcadcb32b22aaf1ea62777ab925c3d8470175"}
ARG_LINE = "-Xmx512m -Dfile.encoding=UTF-8"
MAVEN_FLAGS = ["-B", "-ntp", "-Dstyle.color=never", "-DargLine=" + ARG_LINE]
# The test JVM gets its own temp dir. Java's default is /tmp, and a traversal witness aimed at
# /tmp cannot tell a fix apart when the extraction dir is /tmp itself (VUL4J-79). Like /tmp it
# is a noexec tmpfs; Maven's local repository and HOME stay in /tmp.
TEST_TMP = "/jvmtmp"
# Week 8: no single file above 1 GiB (RLIMIT_FSIZE), no core dumps, a bounded descriptor table.
SANDBOX_ULIMITS = ("nofile=8192:8192", "core=0", f"fsize={2**30}")


def sandbox_mode(spec):
    """'docker' or 'native'. Only the owned synthetic labs may still build natively, and only in
    the lab (development) profile (roadmap week 8): the product builds nothing outside the sandbox."""
    mode = setting("RUNNER_SANDBOX", "native")
    if mode not in ("docker", "native"):
        raise PolicyError("unknown_runner_sandbox")
    if mode != "docker" and spec.labels.get("source") != "safepatch-synthetic":
        raise PolicyError("sandbox_required_for_real_projects")
    if mode != "docker" and setting("SAFEPATCH_PROFILE", "product") != "lab":
        raise PolicyError("native_runner_outside_lab_profile")
    return mode


def wsl(*argv):
    return ["wsl", "-d", setting("WSL_DISTRO", "Debian"), "--exec", *argv]


def sandbox_image(java="17"):
    image = setting("SANDBOX_IMAGE_" + java) or (setting("SANDBOX_IMAGE") if java == "17" else None) or SANDBOX_IMAGES.get(java)
    if not image:
        raise PolicyError("no_sandbox_image_for_java_" + java)
    return image


def sandboxed(argv, workspace, name, java="17", mount=None, tools=None):
    """The docker command running argv for this workspace inside the sandbox; `mount` is the
    workspace's copy on the WSL disk (Stage), else the workspace itself over /mnt/c; `tools`
    (SpotBugs) is mounted read-only at TOOLS_IN_SANDBOX."""
    cache = setting("SANDBOX_MAVEN_CACHE")
    if not cache or not cache.startswith("/"):
        raise RuntimeError("sandbox_maven_cache_missing")
    memory = setting("SANDBOX_MEMORY", "2g")
    return wsl("docker", "run", "--rm", "--name", name, "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,size=1g", "--tmpfs", TEST_TMP + ":rw,size=512m",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "1024",
               # Swap equal to memory: no swap on top of the limit (Docker's default doubles it).
               "--memory", memory, "--memory-swap", memory, "--cpus", setting("SANDBOX_CPUS", "2"), "--user", setting("SANDBOX_USER", "1000:1000"),
               *[flag for limit in SANDBOX_ULIMITS for flag in ("--ulimit", limit)],
               "-e", "HOME=/tmp", "-e", "MAVEN_OPTS=-Xmx512m -Dfile.encoding=UTF-8",
               "-v", (mount or wsl_path(workspace)) + ":/workspace", "-w", "/workspace", "-v", cache + ":/m2:ro",
               *(["-v", tools + ":" + TOOLS_IN_SANDBOX + ":ro"] if tools else []),
               # The image's entrypoint script copies settings into a home it cannot write; skip it.
               "--entrypoint", argv[0], sandbox_image(java), *argv[1:])


def sums(output):
    """{file name: digest} from `sha256sum` output; a name holding a backslash or a newline is
    written escaped, with a leading backslash on its line."""
    found = {}
    for line in output.split(b"\n"):
        escaped = line.startswith(b"\\")
        value, name = line[escaped:escaped + 64], line[escaped + 66:]
        if len(value) == 64 and name:
            found[unescape(name) if escaped else name] = value
    return found


def unescape(name):
    """sha256sum's escaping: backslash-n for a newline, two backslashes for one."""
    return re.sub(rb"\\(.)", lambda m: b"\n" if m.group(1) == b"n" else m.group(1), name)


class Stage:
    """A runner workspace copied to the WSL disk for its sandboxed builds and tests.

    A build there takes seconds where over /mnt/c it takes minutes (OWASP Benchmark package: 17 s
    against 48 min). The copy holds the working tree's files, not .git or build output, and file
    modes follow Git, as in a Linux checkout. Only what the runner reads comes back (`pull`);
    `changed` lists files a run altered, as tracked_changes does for a workspace built in place."""

    def __init__(self, workspace):
        cache = setting("SANDBOX_MAVEN_CACHE") or ""
        if not cache.startswith("/"):
            raise RuntimeError("sandbox_maven_cache_missing")
        self.local = Path(workspace)
        self.path = setting("SANDBOX_WORK", posixpath.dirname(cache.rstrip("/")) + "/work") + "/" + self.local.name
        if not re.fullmatch(r"/[A-Za-z0-9._/-]+", self.path):
            raise RuntimeError("sandbox_work_path_invalid")

    def shell(self, script, **kwargs):
        return subprocess.run(wsl("sh", "-c", script), capture_output=True, timeout=600, **kwargs)

    def push(self):
        """Committed files come from Git's object store (`git archive`): reading a fresh checkout
        back from the Windows disk took 145-170 s for Benchmark's 214 MB, the archive 1-4 s. A
        file whose bytes may differ from the archive (modified, untracked, written by SafePatch
        with other line endings, not a regular file) is read from the disk instead.

        The workspace is mounted read-write into the container, so it must sit on its own,
        size-limited filesystem (week 8, scripts/prepare_sandbox.py --bound-work-gb): on the
        WSL root a build could fill the Windows drive behind it."""
        if self.shell(f"mountpoint -q {shlex.quote(posixpath.dirname(self.path))}").returncode:
            raise RuntimeError("sandbox_work_not_bounded")
        modes = {}
        for entry in run_git(self.local, "ls-files", "-s", "-z").split(b"\0"):
            if entry:
                meta, name = entry.split(b"\t", 1)
                modes[name.decode("utf-8")] = 0o755 if meta.startswith(b"100755") else 0o644
        if run_git(self.local, "ls-files", "-z", "--deleted"):
            raise RuntimeError("sandbox_stage_deleted_file")
        disk = {name for name in run_git(self.local, "ls-files", "-z", "--modified", "--others").decode("utf-8").split("\0")
                if name and not self.build_output(name, modes)}
        # The archive must hold every file as checked out: no export-ignore, no export-subst.
        attributes = self.local / run_git(self.local, "rev-parse", "--git-path", "info/attributes").decode().strip()
        attributes.parent.mkdir(parents=True, exist_ok=True)
        attributes.write_text("* -export-ignore -export-subst\n", encoding="utf-8")

        def owned(info, mode):
            info.mode, info.uid, info.gid, info.uname, info.gname = mode, 0, 0, "", ""
            return info

        path = shlex.quote(self.path)
        script = (f"rm -rf {path} && mkdir -p {path} && tar -x -C {path} && cd {path} && "
                  f"find . -type f -print0 | xargs -0 -r sha256sum > {path}.sha256")
        git = subprocess.Popen(git_command(self.local, "archive", "--format=tar", "HEAD"), cwd=self.local, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        process = subprocess.Popen(wsl("sh", "-c", script), stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            # Large blocks: with tarfile's 10 KB default each write is a round trip into WSL.
            with tarfile.open(fileobj=git.stdout, mode="r|", bufsize=1 << 20) as source, \
                    tarfile.open(fileobj=process.stdin, mode="w|", bufsize=1 << 20) as archive:
                for info in source:
                    local = self.local / info.name
                    if info.isdir():
                        archive.addfile(owned(info, 0o755))
                    elif info.isfile() and info.name not in disk and local.is_file() and local.stat().st_size == info.size:
                        archive.addfile(owned(info, modes.get(info.name, 0o644)), source.extractfile(info))
                    elif local.is_file():
                        disk.add(info.name)
                for name in sorted(disk):
                    archive.add(str(self.local / name), arcname=name, recursive=False, filter=lambda info: owned(info, modes.get(info.name, 0o644)))
        except BaseException:
            git.kill()
            process.kill()
            raise
        finally:
            process.stdin.close()
            git.wait(timeout=600)
            process.wait(timeout=600)
        if git.returncode or process.returncode:
            raise RuntimeError("sandbox_stage_failed")

    @staticmethod
    def build_output(name, modes):
        """An untracked file under a `target` directory that holds no tracked file."""
        parts = name.split("/")
        return any(part == "target" and not any(n.startswith("/".join(parts[:i + 1]) + "/") for n in modes)
                   for i, part in enumerate(parts[:-1]))

    def guarded(self, relative, command):
        """Run `command` in the stage only if `relative` resolves inside it with no symbolic link on
        the way (week 8). The runner acts as the WSL user, and a build may leave links pointing to
        anything that user can read or delete."""
        if not safe_path(relative):
            raise RuntimeError("sandbox_stage_path_invalid")
        quoted = shlex.quote(posixpath.normpath(relative))
        result = self.shell(f'cd {shlex.quote(self.path)} && [ "$(realpath -m -- {quoted})" = "$(pwd -P)/"{quoted} ] || exit 3; {command(quoted)}')
        if result.returncode == 3:
            raise RuntimeError("sandbox_stage_link_refused")
        return result

    def clear(self, relative):
        self.guarded(relative, lambda quoted: f"rm -rf -- {quoted}")

    def pull(self, relative):
        """Replace the local `relative` (a directory or file) with the stage's."""
        if not safe_path(relative):
            raise RuntimeError("sandbox_stage_path_invalid")
        local = self.local / relative
        if local.is_dir():
            shutil.rmtree(local)
        elif local.exists():
            local.unlink()
        result = self.guarded(relative, lambda quoted: f"if [ -e {quoted} ]; then tar -c -- {quoted}; fi")
        if result.returncode:
            raise RuntimeError("sandbox_stage_pull_failed")
        if not result.stdout:
            return
        try:
            with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
                wanted = [m for m in archive.getmembers() if m.name == relative or m.name.startswith(relative + "/")]
                archive.extractall(self.local, members=wanted, filter="data")
        except tarfile.TarError as exc:
            raise RuntimeError("sandbox_stage_output_refused") from exc

    def changed(self):
        """Staged files (Git metadata aside) that differ from what was pushed. Only files that are
        still regular files, reached without a symbolic link, are read (`find` follows none); a
        pushed file a run replaced by a link, a pipe or a device counts as changed, unopened."""
        path = shlex.quote(self.path)
        manifest = self.shell(f"cat {path}.sha256").stdout
        regular = set(self.shell(f"cd {path} && find . -type f -print0").stdout.split(b"\0"))
        pushed = sums(manifest)
        present = sorted(name for name in pushed if name in regular)
        current = sums(self.shell(f"cd {path} && xargs -0 -r sha256sum --", input=b"\0".join(present)).stdout) if present else {}
        return sorted(name.decode("utf-8", "replace").removeprefix("./") for name, value in pushed.items() if current.get(name) != value)

    def remove(self):
        path = shlex.quote(self.path)
        self.shell(f"rm -rf {path} {path}.sha256")


def profile(sandbox, java="17"):
    return "docker:" + sandbox_image(java) if sandbox == "docker" else setting("RUNNER_PROFILE", "native-same-user")


def maven(workspace, args, deadline, extra=None, online=False, limit=240, sandbox="native", java="17", stage=None):
    if sandbox == "docker":
        if online or extra:
            raise PolicyError("sandbox_runs_offline_without_secrets")
        name = "safepatch-" + uuid.uuid4().hex[:12]
        flags = [f for f in MAVEN_FLAGS if not f.startswith("-DargLine=")] + [f"-DargLine={ARG_LINE} -Djava.io.tmpdir={TEST_TMP}"]
        argv = ["mvn", *flags, "-o", "-Dmaven.repo.local=/tmp/m2", "-Dmaven.repo.local.tail=/m2", *args]
        try:
            return run(sandboxed(argv, workspace, name, java, stage.path if stage else None), workspace, remaining(deadline, limit))
        except TimeoutError:
            # Stopping the wsl client does not stop the container.
            subprocess.run(wsl("docker", "kill", name), capture_output=True, timeout=30)
            raise
    executable = shutil.which("mvn")
    if not executable:
        raise RuntimeError("maven_missing")
    cache = setting("MAVEN_CACHE", str(ROOT / ".runtime/m2"))
    argv = [executable, *MAVEN_FLAGS, "-Dmaven.repo.local=" + cache]
    if not online:
        argv.append("-o")
    return run(argv + args, workspace, remaining(deadline, limit), extra)


# A project without a security witness never passes (decision 3, 25 Oct 2026).
# SpotBugs + FindSecBugs (week 7): prepared by scripts/prepare_findsecbugs.py, the plugin pinned by digest.
FINDSECBUGS_PLUGIN = ("findsecbugs-plugin-1.14.0.jar", "6fa340344fa433ff46c2985dab1010e8bc739f9395c983594a5240095e92abc8")
DEPENDENCY_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin:3.8.1"
TOOLS_IN_SANDBOX = "/opt/safepatch-tools"
MISSING_WITNESS = {"passed": False, "missing": True, "tests": 0, "failures": 0, "errors": 0, "skipped": 0, "details": []}


def tests(workspace, selection, deadline, limit=240, sandbox="native", java="17", build=None, stage=None):
    """Run one descriptor test selection and read every Surefire report it produced (the
    descriptor's module only, when it names one)."""
    relative = ((build.module + "/") if build and build.module else "") + "target/surefire-reports"
    reports_dir = workspace / relative
    shutil.rmtree(reports_dir, ignore_errors=True)
    if stage:
        stage.clear(relative)
    # A plugin the build skips (animal-sniffer, enforcer...) is skipped in the test run too.
    options = [*build.reactor(), *build.properties()] if build else []
    result = maven(workspace, [*options, "-Dtest=" + ",".join(selection.selectors), "test"], deadline, limit=limit, sandbox=sandbox, java=java, stage=stage)
    if stage:
        stage.pull(relative)
    reports = sorted(reports_dir.glob("TEST-*.xml")) if reports_dir.exists() else []
    if not reports:
        return {"passed": False, "infrastructure_error": True, "reason": "missing_junit_report", "exit_code": result["exit_code"], "duration_seconds": result["duration_seconds"]}
    count = errors = failures = skipped = 0
    details = []
    for report in reports:
        root = ET.parse(report).getroot()
        count += int(root.get("tests", 0))
        errors += int(root.get("errors", 0))
        failures += int(root.get("failures", 0))
        skipped += int(root.get("skipped", 0))
        # Only named assertions from trusted tests are provided back to the model.
        details += [{"name": t.get("name"), "type": f.tag, "assertion": next((m for m in selection.markers if m in f.get("message", "")), "BEHAVIOR_REGRESSION")} for t in root.findall("testcase") for f in list(t) if f.tag in ("failure", "error")]
    return {"passed": result["exit_code"] == 0 and count > 0 and errors + failures + skipped == 0, "tests": count, "failures": failures, "errors": errors, "skipped": skipped, "details": details, "exit_code": result["exit_code"], "duration_seconds": result["duration_seconds"], "junit_sha256": digest(b"".join(r.read_bytes() for r in reports))}


def wsl_path(path):
    path = str(Path(path).resolve())
    if len(path) < 3 or path[1:3] != ":\\":
        raise ValueError("Expected Windows drive path")
    return "/mnt/" + path[0].lower() + "/" + path[3:].replace("\\", "/")


DIAGNOSTIC = re.compile(r"\[ERROR\] (.*?\.java):\[(\d+),(\d+)\]([^\n]*)")
IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")


def symbol_at(workspace, relative, line, column):
    """The identifier at a compiler position; plugins report 0- or 1-based columns."""
    file = Path(workspace) / relative
    if not safe_path(relative) or not file.is_file():
        return None
    lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
    text = lines[line - 1] if 1 <= line <= len(lines) else ""
    for index in (column, column - 1):
        if 0 <= index < len(text) and (index == 0 or not (text[index - 1].isalnum() or text[index - 1] in "_$")):
            match = IDENTIFIER.match(text, index)
            if match:
                return match.group()[:80]
    return None


def diagnostics(output, workspace):
    """Compiler errors with repository-relative paths: the workspace path never reaches a prompt.
    For "cannot find symbol" the name is read from the source, because old compiler plugins
    (zt-zip's 2.3.2) drop javac's "symbol:" line (VUL4J-79, 25 Oct 2026)."""
    base = Path(workspace).resolve().as_posix()
    prefixes = ("/workspace/", "/" + base + "/", base + "/")
    out = []
    for path, line, column, message in DIAGNOSTIC.findall(output):
        relative = next((path[len(p):] for p in prefixes if path.startswith(p)), path.rsplit("/", 1)[-1])
        message = message.strip()
        if "cannot find symbol" in message and (name := symbol_at(workspace, relative, int(line), int(column))):
            message += ": " + name
        entry = f"[ERROR] {relative}:[{line},{column}] {message}"[-400:]
        if entry not in out:
            out.append(entry)
    return out[:4]


def known_findings(spec, commit, patched):
    """Findings from the answer key. Lab and evaluation profiles only; after a patch nothing is
    rescanned, so acceptance rests on the security witness (roadmap week 6)."""
    if not known_findings_enabled():
        raise PolicyError("known_findings_only_in_lab_profile")
    if not spec.scan.known or not spec.tests.security:
        raise PolicyError("known_findings_need_answer_key_and_witness")
    findings = [] if patched else [{"tool": "known-finding", "rule_id": "known:" + k.id, "cwe": k.cwe, "type": "VULNERABILITY", "file": k.file,
                                    "line": k.line, "severity": "HIGH", "source": k.source, "fingerprint": digest("known:" + k.id + k.file)} for k in spec.scan.known]
    return [{"tool": "known-finding", "version": "answer-key", "status": "ok", "commit": commit, "findings": findings,
             "coverage": "answer key; a patched revision is not rescanned, the security witness decides"}]


def imported_findings(spec, files, commit, imported, patched):
    """Findings of the institution's own scanner, imported as SARIF (docs/SARIF_ICERI_ALMA.md). That
    tool cannot run here, so a patched revision is not rescanned with it: the security witness
    decides, and SafePatch's own scanner, run beside it, must leave nothing in the patched file
    (options b and a, the project lead's decision of 31 Oct 2026)."""
    if not spec.tests.security:
        raise PolicyError("imported_findings_need_security_witness")
    if any(f.file not in files for f in imported):
        raise PolicyError("imported_finding_unknown_file")
    return {"tool": "sarif", "version": "2.1.0", "status": "ok", "commit": commit, "findings": [] if patched else [f.model_dump() for f in imported],
            "coverage": "institution's scanner, imported as SARIF; a patched revision is not rescanned with it, the security witness decides"}


def tools_dir():
    return Path(setting("TOOLS_DIR", str(ROOT / ".runtime/tools")))


def analysed_classes(spec, workspace, stage, classes):
    """Class names for -onlyAnalyze: each scan path's class and its inner classes, so scanning one
    file does not analyse its whole package (OWASP Benchmark: 2 740 servlets). None, meaning
    every class, when a scan path is a directory or lies outside src/main/java."""
    names = []
    for path in spec.scan.paths:
        _, marker, tail = path.partition("src/main/java/")
        if not marker or not tail.endswith(".java"):
            return None
        folder, _, name = tail[:-len(".java")].rpartition("/")
        if stage:
            where = shlex.quote(f"{stage.path}/{classes}/{folder}")
            found = stage.shell(f"cd {where} 2>/dev/null && find . -maxdepth 1 -name {shlex.quote(name + '.class')} -o -maxdepth 1 -name {shlex.quote(name + '$*.class')}; true", text=True).stdout.split()
        else:
            base = workspace / classes / folder
            found = [p.name for p in [base / (name + ".class"), *base.glob(name + "$*.class")] if p.is_file()]
        names += [f"{folder}/{Path(f).name[:-len('.class')]}".strip("/").replace("/", ".") for f in found]
    return names


def findsecbugs_scan(workspace, spec, files, commit, deadline, sandbox="native", stage=None):
    """SpotBugs with the FindSecBugs plugin on the compiled classes of the descriptor's module
    (the build has run). The project's classpath comes from maven-dependency-plugin, offline; a
    real project is analysed in the sandbox like its build, the tools mounted read-only."""
    tools = tools_dir()
    plugin = tools / "downloads" / FINDSECBUGS_PLUGIN[0]
    if not plugin.is_file() or digest(plugin.read_bytes()) != FINDSECBUGS_PLUGIN[1]:
        raise RuntimeError("findsecbugs_plugin_missing_or_changed")
    module = (spec.build.module + "/") if spec.build.module else ""
    cp_file, sarif, classes = module + "target/safepatch-classpath.txt", module + "target/safepatch-spotbugs.sarif", module + "target/classes"
    result = maven(workspace, [*spec.build.reactor(), DEPENDENCY_PLUGIN + ":build-classpath", "-Dmdep.outputFile=target/safepatch-classpath.txt"],
                   deadline, limit=300, sandbox=sandbox, java=spec.java, stage=stage)
    if result["exit_code"]:
        raise RuntimeError("findsecbugs_classpath_failed")
    if stage:
        stage.pull(cp_file)
    classpath = (workspace / cp_file).read_text(encoding="utf-8").strip()
    only = analysed_classes(spec, workspace, stage, classes)
    if only == []:
        raise RuntimeError("findsecbugs_classes_missing")
    docker = sandbox == "docker"
    home = TOOLS_IN_SANDBOX if docker else tools.as_posix()
    place = (lambda relative: "/workspace/" + relative) if docker else (lambda relative: str(workspace / relative))
    argv = ["java", "-Xmx" + setting("SPOTBUGS_HEAP", "1g"), "-jar", f"{home}/spotbugs-{SPOTBUGS_VERSION}/lib/spotbugs.jar", "-textui", "-quiet",
            "-effort:max", "-low", "-pluginList", f"{home}/downloads/{FINDSECBUGS_PLUGIN[0]}", *(["-auxclasspath", classpath] if classpath else []),
            *(["-onlyAnalyze", ",".join(only)] if only else []), "-sarif=" + place(sarif), place(classes)]
    if docker:
        name = "safepatch-" + uuid.uuid4().hex[:12]
        try:
            # SpotBugs needs Java 11 or later: the JDK 17 image analyses Java 8 classes too.
            result = run(sandboxed(argv, workspace, name, "17", stage.path if stage else None, wsl_path(tools)), workspace, remaining(deadline, 600))
        except TimeoutError:
            subprocess.run(wsl("docker", "kill", name), capture_output=True, timeout=30)
            raise
        if stage:
            stage.pull(sarif)
    else:
        argv[0] = shutil.which("java") or "java"
        result = run(argv, workspace, remaining(deadline, 600))
    if result["exit_code"] or not (workspace / sarif).is_file():
        raise RuntimeError("findsecbugs_scan_failed")
    return parse_spotbugs(json.loads((workspace / sarif).read_text(encoding="utf-8")), commit, files, spec.scan.paths)


def scan(workspace, spec, files, commit, scanner, job_id, attempt, deadline, patched=False, sandbox="native", stage=None, imported=()):
    paths, kind = spec.scan.paths, spec.labels.get("kind")
    if scanner.startswith("sarif+"):
        own = scan(workspace, spec, files, commit, scanner[len("sarif+"):], job_id, attempt, deadline, patched, sandbox, stage)
        return [imported_findings(spec, files, commit, imported, patched), *own]
    if scanner == "known":
        return known_findings(spec, commit, patched)
    if scanner == "builtin":
        return [builtin_scan(files, paths, kind, commit)]
    if scanner == "findsecbugs":
        return [findsecbugs_scan(workspace, spec, files, commit, deadline, sandbox, stage)]
    output = workspace / "semgrep.json"
    rules = Path(setting("RULES_FILE", str(ROOT / "rules/java.yml")))
    if os.name == "nt":
        executable = setting("SEMGREP_WSL", wsl_path(ROOT / ".runtime/semgrep-venv/bin/semgrep"))
        command = ["wsl", "-d", setting("WSL_DISTRO", "Debian"), "--", "env", "SEMGREP_SEND_METRICS=off", "SEMGREP_ENABLE_VERSION_CHECK=0", executable]
        command += ["scan", "--config", wsl_path(rules), "--json", "--output", wsl_path(output), "--metrics=off", "--disable-version-check", "--no-git-ignore", "--strict", *[wsl_path(workspace / p) for p in paths]]
        prefixes = [wsl_path(workspace)]
    else:
        command = [setting("SEMGREP_BIN", "semgrep"), "scan", "--config", str(rules), "--json", "--output", str(output), "--metrics=off", "--disable-version-check", "--no-git-ignore", "--strict", *[str(workspace / p) for p in paths]]
        prefixes = [str(workspace.resolve()), str(workspace)]
    result = run(command, workspace, remaining(deadline, 90))
    if result["exit_code"] != 0 or not output.exists():
        raise RuntimeError("semgrep_scan_failed")
    data = json.loads(output.read_text(encoding="utf-8"))
    version = data.get("version", "unknown")
    if version != "1.136.0":
        raise RuntimeError("semgrep_version_mismatch")
    reports = [parse_semgrep(data, commit, version, prefixes)]
    if scanner == "semgrep+findsecbugs":
        reports.append(findsecbugs_scan(workspace, spec, files, commit, deadline, sandbox, stage))
    if scanner == "sonarqube+semgrep":
        rule = {"sql": "javasecurity:S3649", "path": "javasecurity:S2083", "command": "javasecurity:S2076"}.get(kind)
        if rule is None:
            raise RuntimeError("sonar_rule_mapping_missing")
        token = secret("SONAR_TOKEN")
        url = setting("SONAR_URL", "http://127.0.0.1:9000")
        adapter = SonarAdapter(url, token)
        coverage = adapter.preflight(setting("SONAR_VERSION", "26.10.0.133078"), rule)
        # Unique key prevents another scan's issues from being mistaken for this scan.
        key = f"bigg-{job_id}-{attempt}-{uuid.uuid4().hex[:8]}"
        result = maven(workspace, ["org.sonarsource.scanner.maven:sonar-maven-plugin:5.1.0.4751:sonar", "-Dsonar.projectKey=" + key, "-Dsonar.scm.revision=" + commit, "-Dsonar.host.url=" + url, "-Dsonar.scanner.skipJreProvisioning=true"], deadline, {"SONAR_TOKEN": token, "SONAR_USER_HOME": str(runtime("sonar-cache"))})
        if result["exit_code"]:
            raise RuntimeError("sonar_scanner_failed")
        report = adapter.collect(workspace / "target/sonar/report-task.txt", key, commit, deadline)
        report["version"] = coverage["server_version"]
        report["coverage_check"] = coverage
        reports.append(report)
    return reports


def execute(req: VerifyRequest):
    started = time.monotonic()
    remaining(req.deadline)
    case, files = baseline(req.case_id, req.base_commit)
    spec = case["spec"]
    sandbox = sandbox_mode(spec)
    if sandbox == "docker" and req.scanner == "sonarqube+semgrep":
        # The Sonar Maven goal needs the Sonar server on the network; refuse before building anything.
        raise PolicyError("sonar_scan_needs_network_not_sandboxed")
    if req.scanner == "known":
        known_findings(spec, req.base_commit, True)   # profile and answer-key checks before anything runs
    if req.scanner.startswith("sarif+"):
        imported_findings(spec, files, req.base_commit, req.imported, True)   # witness and files, likewise
    workspace = runtime("runner-work") / f"{req.job_id}-{req.attempt}-{uuid.uuid4().hex[:8]}"
    try:
        checkout(req.case_id, req.base_commit, workspace)
        patch_meta, view, revision = None, files, req.base_commit
        if req.patch:
            patch_meta = validate_patch(files, req.patch, workspace, allowed_files(spec, files, req.target_file))
            # This source revision is the exact patched content; never label it as base HEAD.
            revision = commit_candidate(workspace, req.base_commit, req.patch.edits, patch_meta["diff"])
            view = ChainMap({edit.path: edit.content for edit in req.patch.edits}, files)
        stage = Stage(workspace) if sandbox == "docker" else None
        try:
            if stage:
                stage.push()
            return outcome(req, spec, workspace, stage, sandbox, patch_meta, view, revision, started)
        finally:
            if stage:
                stage.remove()
    finally:
        # The checkout of a pinned commit is reproducible scratch (0.2+ GB per attempt for a large
        # project) and nothing reads it after the response: the review copy is worker2's own.
        discard(workspace)


def discard(folder):
    """Remove a scratch folder; a file left behind never turns a finished job into an error."""
    def writable(func, path, _):
        try:
            # Git may mark pack files read-only on Windows. Only the write bit is added: on Linux a
            # folder left with just that bit could no longer be read, and a link is never followed.
            if not os.path.islink(path):
                os.chmod(path, stat.S_IMODE(os.stat(path).st_mode) | stat.S_IWRITE)
            func(path)
        except OSError:
            pass
    if Path(folder).exists():
        shutil.rmtree(folder, onexc=writable)


def outcome(req, spec, workspace, stage, sandbox, patch_meta, view, revision, started):
    """Build, behaviour, witness and scan of one checked-out revision; `stage` is its WSL copy."""
    compile_result = maven(workspace, [*spec.build.reactor(), *spec.build.package_goals], req.deadline, limit=spec.limits.build_seconds, sandbox=sandbox, java=spec.java, stage=stage)
    if compile_result["exit_code"]:
        return {"passed": False, "feedback": {"code": "compilation_failed", "diagnostics": diagnostics(compile_result["output"], workspace)}, "patch": patch_meta, "build": {"passed": False, "duration_seconds": compile_result["duration_seconds"]}}
    witness = spec.tests.security
    behavior = tests(workspace, spec.tests.behavior, req.deadline, spec.limits.test_seconds, sandbox, spec.java, spec.build, stage)
    security = tests(workspace, witness, req.deadline, spec.limits.test_seconds, sandbox, spec.java, spec.build, stage) if witness else dict(MISSING_WITNESS)
    reports = scan(workspace, spec, view, revision, req.scanner, req.job_id, req.attempt, req.deadline, patched=bool(req.patch), sandbox=sandbox, stage=stage, imported=req.imported)
    if stage.changed() if stage else tracked_changes(workspace):
        raise PolicyError("tracked_file_changed_during_execution")
    findings = [f for report in reports for f in report["findings"]]
    # Baseline findings in other files may stay (only the target file changed); the rest must be gone.
    remaining_findings = untolerated(findings, req.tolerated)
    gate_ok = all(r.get("quality_gate", "OK") == "OK" for r in reports)
    witness_fails = bool(witness) and security.get("failures", 0) >= 1 and security.get("errors") == 0 and security.get("skipped") == 0 and (not witness.markers or any(d["assertion"] in witness.markers for d in security.get("details", [])))
    baseline_valid = bool(not req.patch and behavior["passed"] and findings and (witness_fails or not witness))
    passed = bool(req.patch and witness and behavior["passed"] and security["passed"] and not remaining_findings and gate_ok)
    code = "verified" if passed else "security_witness_missing" if req.patch and not witness and behavior["passed"] and not remaining_findings and gate_ok else "validation_failed"
    response = {"passed": passed, "baseline_valid": baseline_valid, "base_commit": req.base_commit, "source_revision": revision, "build": {"passed": True, "duration_seconds": compile_result["duration_seconds"]}, "behavior": behavior, "security": security, "scans": reports, "tolerated": req.tolerated, "patch": patch_meta, "feedback": {"code": code, "behavior": behavior, "security": security, "remaining_rules": [f["rule_id"] for f in remaining_findings]}, "duration_seconds": round(time.monotonic() - started, 3), "runner_profile": profile(sandbox, spec.java), "versions": {"java": setting("JAVA_VERSION_LABEL", "17; inspect preparation evidence"), "maven": setting("MAVEN_VERSION_LABEL", "3.9.16")}}
    if passed:
        if not spec.build.artifact:
            raise PolicyError("artifact_not_configured")
        if stage:
            stage.pull(spec.build.artifact)
        artifact = (workspace / spec.build.artifact).read_bytes()
        if len(artifact) > 64 * 1024**2:
            raise PolicyError("artifact_size_budget")
        response["artifact_b64"] = base64.b64encode(artifact).decode()
        response["artifact_sha256"] = digest(artifact)
    return response


@app.get("/health")
def health():
    mode = setting("RUNNER_SANDBOX", "native")
    # Week 8: native builds run only in the lab profile; anywhere else every job would be refused.
    native_allowed = setting("SAFEPATCH_PROFILE", "product") == "lab"
    return {"service": "runner", "status": "ok", "profile": profile(mode), "native_allowed": native_allowed,
            "usable": mode == "docker" or native_allowed}


@app.post("/execute", dependencies=[Depends(require_service("RUNNER_TOKEN"))])
def execute_route(req: VerifyRequest):
    if not lock.acquire(blocking=False):
        raise HTTPException(503, "runner_busy")
    try:
        return execute(req)
    except PolicyError as exc:
        raise HTTPException(422, str(exc)) from exc
    except (RuntimeError, TimeoutError, OSError) as exc:
        raise HTTPException(503, type(exc).__name__ + ":" + str(exc)[:160]) from exc
    finally:
        lock.release()
