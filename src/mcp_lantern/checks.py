"""Config-level checks. Each returns findings; none reads anything but the config.

Secret values are never stored in a finding: only a redacted description.
"""
from __future__ import annotations

import re

SECRET_PATTERNS = [
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
]
SECRET_NAME = re.compile(r"(token|secret|api[_-]?key|passw(or)?d|passwd|credential|private[_-]?key)", re.I)
REFERENCE = re.compile(r"^\s*(\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|\{\{[^}]+\}\}|<[^>]+>)\s*$")
LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]", "::1")
SHELLS = {"sh", "bash", "zsh", "dash", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
RUNNERS = {"npx", "bunx", "uvx", "pipx", "pnpx"}
RUNNER_SUBCMDS = {("pnpm", "dlx"), ("yarn", "dlx"), ("bun", "x"), ("npm", "exec"), ("pipx", "run"), ("uv", "tool")}
BROAD_ROOTS = {"/", "~", "$home", "${home}", "%userprofile%", "/users", "/home", "/root", "c:/", "c:", "d:/"}


def redact(label):
    return f"{label} (value hidden)"


def _finding(rule, severity, confidence, server, title, detail, fix, where):
    return {"rule": rule, "severity": severity, "confidence": confidence, "server": server.ident,
            "title": title, "detail": detail, "fix": fix, "location": f"{server.source} {where}"}


def _secret_label(value):
    for label, pat in SECRET_PATTERNS:
        if pat.search(value):
            return label
    return None


def check_secrets(s):
    out = []
    for key, val in s.env.items():
        label = _secret_label(val)
        if label:
            out.append(_finding("LNT-C001", "high", "high", s, f"{label} written in env.{key}",
                                redact(label) + " is stored in a config file that is often synced, committed or shared.",
                                "Rotate this credential now, then pass it by reference from your secret store or OS environment.",
                                f"{s.pointer}/env/{key}"))
        elif SECRET_NAME.search(key) and len(val.strip()) >= 8 and not REFERENCE.match(val):
            out.append(_finding("LNT-C001", "medium", "medium", s, f"env.{key} looks like a literal secret",
                                "The variable name suggests a credential and the value is not a variable reference (value hidden).",
                                "Use an environment reference instead of the literal value, and rotate it if the file was ever shared.",
                                f"{s.pointer}/env/{key}"))
    for key, val in s.headers.items():
        label = _secret_label(val)
        auth_like = key.lower() in ("authorization", "x-api-key", "api-key", "x-auth-token")
        if (label or (auth_like and len(val) > 12)) and not REFERENCE.match(val.replace("Bearer ", "").strip()):
            out.append(_finding("LNT-C001", "high" if label else "medium", "high" if label else "medium", s,
                                f"Credential written in header {key}", redact(label or "Header value") + " is stored in the config file.",
                                "Use OAuth if the server supports it, or reference the token from the environment.",
                                f"{s.pointer}/headers/{key}"))
    for i, arg in enumerate([*s.args, s.url]):
        label = _secret_label(arg)
        if label:
            out.append(_finding("LNT-C001", "high", "high", s, f"{label} written in arguments or URL",
                                redact(label) + " appears on a command line or URL; command lines are visible to other local users and logs.",
                                "Move it to an environment reference and rotate it.", f"{s.pointer}/args"))
    if re.search(r"[?&](token|key|api[_-]?key|access_token)=[^&\s]{6,}", s.url, re.I):
        out.append(_finding("LNT-C001", "high", "medium", s, "Credential in URL query string",
                            "Query strings are logged by proxies and servers (value hidden).",
                            "Send credentials in a header or use OAuth.", f"{s.pointer}/url"))
    return out


def _package_arg(s):
    cmd = s.command.replace("\\", "/").split("/")[-1].lower().removesuffix(".cmd").removesuffix(".exe")
    args = list(s.args)
    sub = None
    if cmd in RUNNERS:
        sub = cmd
    elif args and (cmd, args[0].lower()) in RUNNER_SUBCMDS:
        sub = f"{cmd} {args[0].lower()}"
        args = args[1:]
    if not sub:
        return None
    for a in args:
        if not a.startswith("-"):
            return sub, a
    return sub, None


def check_pinning(s):
    out = []
    got = _package_arg(s)
    if got and got[1]:
        runner, pkg = got
        name_part = pkg[1:] if pkg.startswith("@") else pkg
        has_version = ("@" in name_part and not name_part.endswith("@")) or "==" in pkg
        latest = pkg.lower().endswith("@latest")
        if latest or not has_version:
            out.append(_finding("LNT-C002", "medium", "high", s, f"{pkg} is not pinned to a version",
                                f"`{runner}` fetches and runs whatever is current each launch, so a compromised release would run on your machine with your server's access.",
                                "Pin an exact version (for example name@1.2.3) and review changes before upgrading.", f"{s.pointer}/args"))
    cmd = s.command.replace("\\", "/").split("/")[-1].lower()
    if cmd == "docker":
        image = None
        i = 0
        args = s.args[1:] if s.args and s.args[0] == "run" else s.args
        skip_next = {"-e", "--env", "-v", "--volume", "--name", "-p", "--publish", "--network", "-w", "--workdir", "--mount", "-u", "--user", "--entrypoint"}
        while i < len(args):
            a = args[i]
            if a in skip_next:
                i += 2
                continue
            if a.startswith("-"):
                i += 1
                continue
            image = a
            break
        if image and "@sha256:" not in image and (":" not in image.split("/")[-1] or image.endswith(":latest")):
            out.append(_finding("LNT-C002", "medium", "medium", s, f"Docker image {image} has no fixed tag or digest",
                                "An untagged or :latest image can change under you.", "Pin a version tag or, better, a digest.", f"{s.pointer}/args"))
        flat = " ".join(s.args)
        if "--privileged" in s.args:
            out.append(_finding("LNT-C006", "high", "high", s, "Container runs with --privileged", "A privileged container has near-host access.", "Remove --privileged and grant only the specific capabilities needed.", f"{s.pointer}/args"))
        if "docker.sock" in flat:
            out.append(_finding("LNT-C006", "high", "high", s, "Docker socket is mounted", "Access to the Docker socket is equivalent to root on the host.", "Do not mount the socket into an MCP server container.", f"{s.pointer}/args"))
        if re.search(r"(-v|--volume)[ =]/:", flat) or re.search(r"(-v|--volume)\s+/:", flat):
            out.append(_finding("LNT-C006", "high", "high", s, "Host root directory is mounted into the container", "The whole host filesystem is visible to the server.", "Mount only the single directory the server needs, read-only if possible.", f"{s.pointer}/args"))
        host_net = any(a in ("--network=host", "--net=host") for a in s.args) or any(
            a in ("--network", "--net") and i + 1 < len(s.args) and s.args[i + 1] == "host" for i, a in enumerate(s.args))
        if host_net:
            out.append(_finding("LNT-C006", "medium", "medium", s, "Container uses the host network", "The container can reach services bound to localhost.", "Use a user-defined network and publish only needed ports.", f"{s.pointer}/args"))
    return out


def check_command_shape(s):
    out = []
    cmd = s.command.replace("\\", "/").split("/")[-1].lower()
    if cmd in SHELLS and any(a in ("-c", "/c", "-command", "-Command", "-EncodedCommand") for a in s.args):
        out.append(_finding("LNT-C003", "medium", "high", s, "Server is launched through a shell string",
                            "A shell wrapper hides what really runs and makes quoting mistakes exploitable.",
                            "Call the program directly with its arguments in `args`.", f"{s.pointer}/command"))
    flat = " ".join([s.command, *s.args]).lower()
    if re.search(r"(curl|wget)[^|]*\|\s*(sudo\s+)?(sh|bash|zsh)", flat):
        out.append(_finding("LNT-C003", "high", "high", s, "Downloads and runs a script in one step",
                            "Piping a download into a shell executes unreviewed remote code every launch.",
                            "Install a reviewed, pinned release instead.", f"{s.pointer}/args"))
    return out


def check_remote(s):
    out = []
    if s.kind != "remote":
        return out
    low = s.url.lower()
    host = re.sub(r"^[a-z+]+://", "", low).split("/")[0].split("@")[-1]
    host_only = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
    if low.startswith("http://") and host_only not in LOCAL_HOSTS:
        out.append(_finding("LNT-C004", "high", "high", s, "Remote server uses unencrypted HTTP",
                            "Tool calls and any credentials cross the network in clear text.",
                            "Use https:// or keep the server on localhost.", f"{s.pointer}/url"))
    if host_only not in LOCAL_HOSTS and not any(k.lower() in ("authorization", "x-api-key", "api-key", "x-auth-token") for k in s.headers):
        out.append(_finding("LNT-C005", "low", "low", s, "No credential header configured for a remote server",
                            "This may be fine if the client performs OAuth, which a config file cannot show. If the server is open, anyone who finds the URL can call its tools.",
                            "Confirm the server requires authentication.", f"{s.pointer}/url"))
    return out


def check_broad_paths(s, caps):
    out = []
    if "private_data" not in caps:
        return out
    for a in s.args:
        norm = a.replace("\\", "/").rstrip("/").lower() or "/"
        if norm in BROAD_ROOTS or norm.endswith("/.ssh") or norm.endswith("/.aws") or "/.ssh/" in norm or "/.aws/" in norm or norm.endswith("/.gnupg"):
            out.append(_finding("LNT-C007", "high", "medium", s, f"Broad or credential directory exposed: {a}",
                                "A file server rooted at a home or system directory, or at a credentials folder, lets the model read keys and tokens.",
                                "Point the server at the single project directory it needs.", f"{s.pointer}/args"))
    return out
