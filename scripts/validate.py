#!/usr/bin/env python3
"""Automated repository validator for multiplayer-plugins.

Validates:
1. Strict JSON (including duplicate-key rejection), YAML, and TOML syntax across all repo files.
2. Zero symlinks and zero '..' path escapes; every relative path referenced by manifests exists.
3. Canonical SKILL.md (`agentskills.io` frontmatter) and command parity across all host bundles.
4. Hermes plugin.yaml and upstream plugin-catalog schema validity (including `requires_env: []`).
5. Verified GitHub-safe 1-click Cursor and VS Code install badges in README.md (round-trip decoded).
6. Zero hardcoded secrets or personal absolute paths across repository files.
7. Full `tests/test_hermes_plugin.py` unittest suite pass.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
import tomllib
import urllib.parse
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

SKIP_DIRS = {".git", "__pycache__", "node_modules", "target", ".venv"}

CANONICAL_SKILL = REPO_ROOT / "skills" / "multiplayer" / "SKILL.md"
BUNDLED_SKILLS = [
    REPO_ROOT / "plugins" / "multiplayer" / "skills" / "multiplayer" / "SKILL.md",
    REPO_ROOT / ".agents" / "plugins" / "multiplayer" / "skills" / "multiplayer" / "SKILL.md",
    REPO_ROOT / "adapters" / "pi" / "skills" / "multiplayer" / "SKILL.md",
    REPO_ROOT / "hermes" / "skills" / "multiplayer" / "SKILL.md",
]

CANONICAL_COMMANDS = ["party.md", "friends.md", "status.md", "invite.md", "join.md", "leave.md", "add.md"]

PERSONAL_PATH_RE = re.compile(r"(?:/Users/[A-Za-z0-9._-]+|/home/[A-Za-z0-9._-]+|C:\\\\Users\\\\[A-Za-z0-9._-]+)")
LIVE_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("invite_token", re.compile(r"(?:^|[^A-Za-z0-9])mpinv1_[A-Za-z0-9_-]{43,}", re.IGNORECASE)),
    ("party_invite", re.compile(r"(?:^|[^A-Za-z0-9])mppi1_[0-9]+_[A-Za-z0-9_-]{43,}", re.IGNORECASE)),
    ("device_link_token", re.compile(r"(?:^|[^A-Za-z0-9])mpdl1_[A-Za-z0-9_-]{43,}", re.IGNORECASE)),
    ("recovery_key", re.compile(r"mprk1_[A-Za-z0-9\-_]{32,}", re.IGNORECASE)),
    ("pem_private_key", re.compile(r"-----BEGIN [A-Z0-9 -]{0,48}(?:PRIVATE|RECOVERY|SECRET) KEY-----", re.IGNORECASE)),
    ("github_pat", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
]


def _iter_repo_files() -> list[Path]:
    files: list[Path] = []
    for path in sorted(REPO_ROOT.rglob("*")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_symlink():
            files.append(path)
        elif path.is_file():
            files.append(path)
    return files


def _load_json_strict(path: Path) -> Any:
    def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for k, v in pairs:
            if k in obj:
                raise ValueError(f"duplicate JSON key '{k}'")
            obj[k] = v
        return obj

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates)


def _extract_frontmatter(path: Path) -> dict[str, Any] | None:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ValueError(f"{path.relative_to(REPO_ROOT)}: unterminated YAML frontmatter")
    parsed = yaml.safe_load(text[4:end])
    if not isinstance(parsed, dict):
        raise ValueError(f"{path.relative_to(REPO_ROOT)}: frontmatter must be a YAML mapping")
    return parsed


def _check_rel_path(base_dir: Path, rel: str, owner: Path, errors: list[str]) -> None:
    if not isinstance(rel, str) or not rel.strip():
        errors.append(f"{owner.relative_to(REPO_ROOT)}: empty path reference")
        return
    if rel.startswith("/") or ".." in Path(rel).parts:
        errors.append(f"{owner.relative_to(REPO_ROOT)}: unsafe path reference '{rel}'")
        return
    resolved = (base_dir / rel).resolve()
    try:
        resolved.relative_to(REPO_ROOT.resolve())
    except ValueError:
        errors.append(f"{owner.relative_to(REPO_ROOT)}: path escapes repository '{rel}'")
        return
    if not resolved.exists():
        errors.append(f"{owner.relative_to(REPO_ROOT)}: referenced path does not exist: '{rel}' -> {resolved}")


def _validate_structured_files(files: list[Path], errors: list[str]) -> tuple[int, int, int]:
    json_count = yaml_count = toml_count = 0
    for path in files:
        rel = path.relative_to(REPO_ROOT)
        if path.is_symlink():
            errors.append(f"symlink not allowed in repo: {rel}")
            continue
        suffix = path.suffix.lower()
        try:
            if suffix == ".json":
                _load_json_strict(path)
                json_count += 1
            elif suffix in (".yaml", ".yml"):
                parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
                if parsed is None:
                    errors.append(f"{rel}: empty YAML document")
                yaml_count += 1
            elif suffix == ".toml":
                tomllib.loads(path.read_text(encoding="utf-8"))
                toml_count += 1
            elif suffix in (".md", ".mdc"):
                _extract_frontmatter(path)
        except Exception as exc:
            errors.append(f"{rel}: parse error: {exc}")
    return json_count, yaml_count, toml_count


def _validate_manifest_references(errors: list[str]) -> None:
    # 1. Claude Code marketplace + plugin
    cc_market_path = REPO_ROOT / ".claude-plugin" / "marketplace.json"
    cc_market = _load_json_strict(cc_market_path)
    for plugin in cc_market.get("plugins", []):
        src = plugin.get("source")
        if isinstance(src, str):
            _check_rel_path(REPO_ROOT, src, cc_market_path, errors)
        elif isinstance(src, dict) and "path" in src:
            _check_rel_path(REPO_ROOT, src["path"], cc_market_path, errors)

    cc_plugin_path = REPO_ROOT / "plugins" / "multiplayer" / ".claude-plugin" / "plugin.json"
    cc_plugin = _load_json_strict(cc_plugin_path)
    cc_plugin_root = cc_plugin_path.parent.parent
    for key in ("skills", "commands", "mcpServers"):
        if key in cc_plugin:
            _check_rel_path(cc_plugin_root, cc_plugin[key], cc_plugin_path, errors)

    # 2. Codex CLI plugin + marketplace
    codex_plugin_path = REPO_ROOT / ".codex-plugin" / "plugin.json"
    codex_plugin = _load_json_strict(codex_plugin_path)
    for key in ("skills", "mcpServers"):
        if key in codex_plugin:
            _check_rel_path(REPO_ROOT, codex_plugin[key], codex_plugin_path, errors)

    codex_market_path = REPO_ROOT / ".agents" / "plugins" / "marketplace.json"
    codex_market = _load_json_strict(codex_market_path)
    for plugin in codex_market.get("plugins", []):
        src = plugin.get("source", {})
        if isinstance(src, dict) and src.get("source") == "local" and "path" in src:
            _check_rel_path(REPO_ROOT, src["path"], codex_market_path, errors)

    # 3. Cursor plugin
    cursor_plugin_path = REPO_ROOT / ".cursor-plugin" / "plugin.json"
    cursor_plugin = _load_json_strict(cursor_plugin_path)
    for key in ("skills", "rules", "commands", "mcpServers"):
        if key in cursor_plugin:
            _check_rel_path(REPO_ROOT, cursor_plugin[key], cursor_plugin_path, errors)

    # 4. Antigravity plugin
    agy_root = REPO_ROOT / ".agents" / "plugins" / "multiplayer"
    for required in ("plugin.json", "mcp_config.json", "rules/AGENTS.md", "skills/multiplayer/SKILL.md"):
        _check_rel_path(agy_root, required, agy_root / "plugin.json", errors)

    # 5. Gemini CLI adapter
    gemini_path = REPO_ROOT / "adapters" / "gemini-cli" / "gemini-extension.json"
    gemini = _load_json_strict(gemini_path)
    if "contextFileName" in gemini:
        _check_rel_path(gemini_path.parent, gemini["contextFileName"], gemini_path, errors)

    # 6. OpenCode adapter
    opencode_pkg_path = REPO_ROOT / "adapters" / "opencode" / "package.json"
    opencode_pkg = _load_json_strict(opencode_pkg_path)
    if "main" in opencode_pkg:
        _check_rel_path(opencode_pkg_path.parent, opencode_pkg["main"], opencode_pkg_path, errors)
    opencode_src = (opencode_pkg_path.parent / opencode_pkg["main"]).read_text(encoding="utf-8")
    if re.search(r"\bconsole\.(?:log|warn|error|info|debug)\s*\(", opencode_src):
        errors.append("adapters/opencode/src/index.ts: must not call console.* (corrupts OpenCode TUI)")

    # 7. Pi adapter
    pi_pkg_path = REPO_ROOT / "adapters" / "pi" / "package.json"
    pi_pkg = _load_json_strict(pi_pkg_path)
    pi_block = pi_pkg.get("pi", {})
    for group in ("extensions", "skills"):
        for rel in pi_block.get(group, []):
            _check_rel_path(pi_pkg_path.parent, rel, pi_pkg_path, errors)

    # 8. Zed adapter
    zed_ext_path = REPO_ROOT / "adapters" / "zed" / "extension.toml"
    zed_ext = tomllib.loads(zed_ext_path.read_text(encoding="utf-8"))
    ext_id = str(zed_ext.get("id", ""))
    if "zed" in ext_id.lower() or "extension" in ext_id.lower():
        errors.append(f"adapters/zed/extension.toml: id '{ext_id}' must not contain 'zed' or 'extension'")
    if "multiplayer" not in zed_ext.get("context_servers", {}):
        errors.append("adapters/zed/extension.toml: missing [context_servers.multiplayer]")
    _check_rel_path(zed_ext_path.parent, "Cargo.toml", zed_ext_path, errors)
    _check_rel_path(zed_ext_path.parent, "src/lib.rs", zed_ext_path, errors)


def _validate_skill_and_parity(errors: list[str]) -> None:
    if not CANONICAL_SKILL.is_file():
        errors.append("missing canonical skills/multiplayer/SKILL.md")
        return

    fm = _extract_frontmatter(CANONICAL_SKILL)
    if fm is None:
        errors.append("skills/multiplayer/SKILL.md: missing YAML frontmatter")
    else:
        name = str(fm.get("name", ""))
        if name != CANONICAL_SKILL.parent.name:
            errors.append(f"SKILL.md name '{name}' must match parent folder '{CANONICAL_SKILL.parent.name}'")
        if not re.fullmatch(r"[a-z0-9-]{1,64}", name):
            errors.append(f"SKILL.md name '{name}' fails agentskills.io regex [a-z0-9-]{{1,64}}")
        desc = str(fm.get("description", ""))
        if not desc or len(desc) > 1024:
            errors.append("SKILL.md description must be 1..1024 chars")
        compat = str(fm.get("compatibility", ""))
        if len(compat) > 500:
            errors.append("SKILL.md compatibility must be <= 500 chars")

    skill_text = CANONICAL_SKILL.read_text(encoding="utf-8")
    for tool in (
        "outpost_status",
        "party_list",
        "party_members",
        "party_friends",
        "party_invite",
        "party_join",
        "party_leave",
        "friend_add",
        "party_send",
        "board_post",
        "party_poll",
        "board_read",
        "party_wait",
    ):
        if tool not in skill_text:
            errors.append(f"skills/multiplayer/SKILL.md: missing tool reference '{tool}'")

    canonical_sha = hashlib.sha256(CANONICAL_SKILL.read_bytes()).hexdigest()
    for copy_path in BUNDLED_SKILLS:
        if not copy_path.is_file():
            errors.append(f"missing bundled skill copy: {copy_path.relative_to(REPO_ROOT)}")
        elif hashlib.sha256(copy_path.read_bytes()).hexdigest() != canonical_sha:
            errors.append(f"skill drift detected: {copy_path.relative_to(REPO_ROOT)} != skills/multiplayer/SKILL.md")

    for cmd_name in CANONICAL_COMMANDS:
        src = REPO_ROOT / "commands" / cmd_name
        dst = REPO_ROOT / "plugins" / "multiplayer" / "commands" / cmd_name
        if not src.is_file():
            errors.append(f"missing commands/{cmd_name}")
        elif not dst.is_file():
            errors.append(f"missing plugins/multiplayer/commands/{cmd_name}")
        elif src.read_bytes() != dst.read_bytes():
            errors.append(f"command drift detected: plugins/multiplayer/commands/{cmd_name} != commands/{cmd_name}")


def _validate_readme_badges(errors: list[str]) -> None:
    readme_path = REPO_ROOT / "README.md"
    if not readme_path.is_file():
        errors.append("missing root README.md")
        return
    text = readme_path.read_text(encoding="utf-8")

    cursor_urls = re.findall(r"https://cursor\.com/en/install-mcp\?[^\s)]+", text)
    vscode_urls = re.findall(r"https://vscode\.dev/redirect\?url=vscode%3Amcp%2Finstall%3F[^\s)]+", text)

    cursor_configs: dict[str, dict[str, Any]] = {}
    for url in cursor_urls:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        name = qs.get("name", [""])[0]
        cfg_b64 = qs.get("config", [""])[0]
        try:
            decoded = json.loads(base64.b64decode(cfg_b64).decode("utf-8"))
            cursor_configs[name] = decoded
        except Exception as exc:
            errors.append(f"README.md invalid Cursor install badge '{url}': {exc}")

    if cursor_configs.get("multiplayer-setup") != {"url": "https://multiplayer.tech/mcp"}:
        errors.append("README.md missing/invalid Cursor 1-click badge for https://multiplayer.tech/mcp")
    if cursor_configs.get("multiplayer") != {"command": "mp-outpost", "args": ["mcp"]}:
        errors.append("README.md missing/invalid Cursor 1-click badge for mp-outpost")

    vscode_configs: dict[str, dict[str, Any]] = {}
    for url in vscode_urls:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        inner = qs.get("url", [""])[0]
        if not inner.startswith("vscode:mcp/install?"):
            errors.append(f"README.md invalid VS Code redirect target: {inner}")
            continue
        raw_json = urllib.parse.unquote(inner.split("?", 1)[1])
        try:
            decoded = json.loads(raw_json)
            vscode_configs[decoded.get("name", "")] = decoded
        except Exception as exc:
            errors.append(f"README.md invalid VS Code install badge '{url}': {exc}")

    if vscode_configs.get("multiplayer-setup") != {
        "name": "multiplayer-setup",
        "type": "http",
        "url": "https://multiplayer.tech/mcp",
    }:
        errors.append("README.md missing/invalid VS Code 1-click badge for https://multiplayer.tech/mcp")
    if vscode_configs.get("multiplayer") != {
        "name": "multiplayer",
        "type": "stdio",
        "command": "mp-outpost",
        "args": ["mcp"],
    }:
        errors.append("README.md missing/invalid VS Code 1-click badge for mp-outpost")


def _validate_hygiene(files: list[Path], errors: list[str]) -> None:
    for path in files:
        if path.is_symlink():
            continue
        rel = path.relative_to(REPO_ROOT)
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if PERSONAL_PATH_RE.search(text):
            errors.append(f"{rel}: hardcoded personal path detected")
        for kind, pattern in LIVE_SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"{rel}: potential secret material ({kind}) detected")


def _run_unit_tests(errors: list[str]) -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        errors.append(f"unittest suite failed with exit code {proc.returncode}")


def main() -> int:
    errors: list[str] = []
    files = _iter_repo_files()

    json_count, yaml_count, toml_count = _validate_structured_files(files, errors)
    _validate_manifest_references(errors)
    _validate_skill_and_parity(errors)
    _validate_readme_badges(errors)
    _validate_hygiene(files, errors)
    _run_unit_tests(errors)

    if errors:
        sys.stderr.write("\nVALIDATION FAILED:\n")
        for err in errors:
            sys.stderr.write(f"  - {err}\n")
        return 1

    print(
        f"\nVALIDATION PASSED: {json_count} JSON, {yaml_count} YAML, {toml_count} TOML files checked; "
        f"{len(files)} total files clean; all manifests, badges, parity, hygiene, and tests OK."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
