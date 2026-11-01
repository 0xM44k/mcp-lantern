"""Read MCP client configs (JSON or JSONC) into a uniform server list.

Nothing here connects to a server or runs a command. Files are only read.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

MAX_BYTES = 2_000_000
SERVER_KEYS = ("mcpServers", "servers")
MAX_DEPTH = 4


class ConfigError(Exception):
    pass


@dataclass
class Server:
    name: str
    source: str            # file the server came from
    pointer: str           # JSON pointer-ish location inside that file
    kind: str              # "stdio" or "remote"
    command: str = ""
    args: list = field(default_factory=list)
    env: dict = field(default_factory=dict)
    url: str = ""
    headers: dict = field(default_factory=dict)
    raw_keys: list = field(default_factory=list)
    uid: str = ""

    @property
    def ident(self) -> str:
        return self.uid or f"{os.path.basename(self.source)}:{self.name}"

    @property
    def haystack(self) -> str:
        """Lower-cased text that catalog patterns are matched against."""
        parts = [self.command, *[str(a) for a in self.args], self.url]
        return " ".join(parts).lower().replace("\\", "/")


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, respecting strings."""
    out, i, n = [], 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif c == "/" and text[i:i + 2] == "//":
            while i < n and text[i] != "\n":
                i += 1
        elif c == "/" and text[i:i + 2] == "/*":
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        else:
            out.append(c)
            i += 1
    cleaned = "".join(out)
    # trailing commas before } or ]
    res, in_str, i = [], False, 0
    while i < len(cleaned):
        c = cleaned[i]
        if in_str:
            res.append(c)
            if c == "\\" and i + 1 < len(cleaned):
                res.append(cleaned[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            res.append(c)
        elif c == ",":
            j = i + 1
            while j < len(cleaned) and cleaned[j] in " \t\r\n":
                j += 1
            if j < len(cleaned) and cleaned[j] in "}]":
                i += 1
                continue
            res.append(c)
        else:
            res.append(c)
        i += 1
    return "".join(res)


def _looks_like_server(v: Any) -> bool:
    return isinstance(v, dict) and ("command" in v or "url" in v or "serverUrl" in v)


def _find_blocks(node: Any, pointer: str, depth: int):
    if depth > MAX_DEPTH or not isinstance(node, dict):
        return
    for key, val in node.items():
        if key in SERVER_KEYS and isinstance(val, dict) and any(_looks_like_server(s) for s in val.values()):
            yield f"{pointer}/{key}", val
        elif isinstance(val, dict):
            yield from _find_blocks(val, f"{pointer}/{key}", depth + 1)


def _as_str_list(v: Any) -> list:
    return [str(x) for x in v] if isinstance(v, list) else []


def _as_str_map(v: Any) -> dict:
    return {str(k): str(x) for k, x in v.items()} if isinstance(v, dict) else {}


def load_file(path: str) -> list:
    try:
        size = os.path.getsize(path)
    except OSError as e:
        raise ConfigError(f"{path}: {e.strerror}") from e
    if size > MAX_BYTES:
        raise ConfigError(f"{path}: file is larger than {MAX_BYTES} bytes; refusing to parse")
    with open(path, "r", encoding="utf-8-sig") as fh:
        text = fh.read()
    try:
        data = json.loads(strip_jsonc(text))
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: not valid JSON ({e.msg} at line {e.lineno})") from e
    servers = []
    for pointer, block in _find_blocks(data, "", 0):
        for name, spec in block.items():
            if not _looks_like_server(spec):
                continue
            url = str(spec.get("url") or spec.get("serverUrl") or "")
            command = str(spec.get("command") or "")
            kind = "remote" if url and not command else "stdio"
            servers.append(Server(
                name=str(name), source=path, pointer=f"{pointer}/{name}", kind=kind,
                command=command, args=_as_str_list(spec.get("args")),
                env=_as_str_map(spec.get("env")), url=url,
                headers=_as_str_map(spec.get("headers")), raw_keys=sorted(spec.keys()),
            ))
    if not servers:
        raise ConfigError(f"{path}: no MCP server definitions found "
                          f"(looked for {', '.join(SERVER_KEYS)} with command or url)")
    return servers
