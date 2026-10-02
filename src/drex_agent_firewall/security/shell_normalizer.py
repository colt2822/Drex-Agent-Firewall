"""Shell command normalizer and obfuscation deconstructor.

Deconstructs command chains, subshells, base64 payloads, wrapper interpreters,
and quoted fragments into distinct canonical subcommands for firewall evaluation.
"""

from __future__ import annotations

import base64
import re
from typing import List, Set, Tuple


# Regex to detect base64 decoders piped to shells
BASE64_PIPE_REGEX = re.compile(
    r"(?:echo|printf)\s+(?:['\"][^'\"]*['\"]\s+)?[\"']?([A-Za-z0-9+/=]{8,})[\"']?\s*\|\s*(?:base64\s+-d|base64\s+--decode|openssl\s+base64\s+-d)\s*\|\s*(?:sh|bash|zsh|dash)",
    re.IGNORECASE,
)

# Regex to detect command substitution
SUBCOMMAND_SUBST_REGEX = re.compile(r"\$\((.*?)\)|`([^`]+)`")

# Shell wrappers: sh -c "...", bash -c "...", eval "...", /usr/bin/bash -c, env bash -c, busybox
WRAPPER_COMMAND_REGEX = re.compile(
    r"(?:(?:\S*\/)?(?:sh|bash|zsh|dash|busybox)|env\s+(?:\S*\/)?(?:sh|bash|zsh|dash))\s+-c\s+[\"'](.*?)[\"']|\beval\s+[\"']?(.*?)[\"']?(?:;|\&|\||$)",
    re.IGNORECASE,
)

# Interpreters executing inline code
INTERPRETER_CODE_REGEX = re.compile(
    r"(?:python[23]?\s+-c|node(?:js)?\s+-e|ruby\s+-e|perl\s+-e)\s+(?P<q>[\"'])([\s\S]*?)(?P=q)",
    re.IGNORECASE,
)

# Python/Perl/Ruby one-liners executing subprocesses
PYTHON_EXEC_REGEX = re.compile(
    r"python[23]?\s+-c\s+[\"'].*?(?:system|Popen|run|check_output|call)\s*\(\s*[\"'](.*?)[\"']",
    re.IGNORECASE,
)

AWK_EXEC_REGEX = re.compile(r"awk\s+.*system\s*\(\s*[\"'](.*?)[\"']", re.IGNORECASE)
FIND_EXEC_REGEX = re.compile(r"find\s+.*?-exec\s+(.*?)(?:\s+\;|\s+\+|\s+\{\})", re.IGNORECASE)
XARGS_EXEC_REGEX = re.compile(r"xargs\s+(?:-[a-zA-Z0-9_\-]+\s+)*(.*)", re.IGNORECASE)


def dequote_word(token: str) -> str:
    """Strip quotes and escape slashes inside a single word/binary name."""
    s = token.strip()
    s = s.replace("\\", "")
    s = s.replace("'", "").replace('"', "")
    return s


def dequote_command(cmd: str) -> str:
    """Normalize quotes and backslash escapes across command line tokens."""
    clean = cmd.replace("\\", "")
    # Remove adjacent empty quotes: '' or ""
    clean = re.sub(r"''|\"\"", "", clean)
    # Remove interior quotes in words: 'r''m' -> rm, .e''nv -> .env, 169.254.1''69.254
    clean = re.sub(r"(?<=[a-zA-Z0-9_\-\.\/])['\"](?=[a-zA-Z0-9_\-\.\/])", "", clean)
    clean = re.sub(r"['\"]([a-zA-Z0-9_\-\.\/]+)['\"]", r"\1", clean)
    return clean


class ShellNormalizer:
    """Normalizes shell commands and extracts all subcommands for invariant checking."""

    @classmethod
    def extract_subcommands(cls, command_str: str) -> List[str]:
        """Split chains (&&, ||, ;, newline, pipes) and extract nested subcommands."""
        raw = str(command_str or "").strip()
        if not raw:
            return []

        dequoted_raw = dequote_command(raw)
        discovered: List[str] = [raw]
        if dequoted_raw != raw:
            discovered.append(dequoted_raw)

        # 1. Check for base64 pipe decode: echo <b64> | base64 -d | sh
        for match in BASE64_PIPE_REGEX.finditer(raw):
            b64_payload = match.group(1)
            try:
                decoded = base64.b64decode(b64_payload).decode("utf-8", errors="replace")
                discovered.append(decoded)
                discovered.append(dequote_command(decoded))
            except Exception:
                pass

        # 2. Check for $(...) and `...` command substitution
        for match in SUBCOMMAND_SUBST_REGEX.finditer(raw):
            nested = match.group(1) or match.group(2)
            if nested:
                discovered.append(nested.strip())
                discovered.append(dequote_command(nested.strip()))

        # 3. Check for shell wrappers sh -c "...", eval "..."
        for match in WRAPPER_COMMAND_REGEX.finditer(raw):
            wrapper_cmd = match.group(1) or match.group(2)
            if wrapper_cmd:
                discovered.append(wrapper_cmd.strip())
                discovered.append(dequote_command(wrapper_cmd.strip()))

        # 4. Check for interpreter inline code (python -c, node -e, ruby -e, perl -e)
        for match in INTERPRETER_CODE_REGEX.finditer(raw):
            code_body = match.group(2)
            if code_body:
                discovered.append(code_body.strip())
                # Extract URLs embedded in interpreter code
                for url_match in re.findall(r"https?://[^\s'\"\)]+", code_body):
                    discovered.append(f"curl -s {url_match}")
                # Extract destructive calls
                if "rmtree" in code_body:
                    rm_target = "/" if "'/'" in code_body or '"/"' in code_body else "/tmp"
                    discovered.append(f"rm -rf {rm_target}")
                if "unlink" in code_body or "os.remove" in code_body:
                    for rm_match in re.findall(r"(?:unlink|remove)\s*\(\s*['\"]([^'\"]+)['\"]", code_body):
                        discovered.append(f"rm {rm_match}")
                if "git" in code_body and "push" in code_body and ("--force" in code_body or "-f" in code_body or "+ref" in code_body):
                    discovered.append("git push --force origin main")
                if "child_process" in code_body or "execSync" in code_body or "system" in code_body:
                    for sys_cmd in re.findall(r"(?:execSync|exec|system)\s*\(\s*['\"]([^'\"]+)['\"]", code_body):
                        discovered.append(sys_cmd)

        # 5. Check for python -c "os.system(...)"
        for match in PYTHON_EXEC_REGEX.finditer(raw):
            py_cmd = match.group(1)
            if py_cmd:
                discovered.append(py_cmd.strip())

        # 6. Check for awk system()
        for match in AWK_EXEC_REGEX.finditer(raw):
            awk_cmd = match.group(1)
            if awk_cmd:
                discovered.append(awk_cmd.strip())

        # 7. Check for find -exec
        for match in FIND_EXEC_REGEX.finditer(raw):
            find_cmd = match.group(1).replace("{}", "").strip()
            if find_cmd:
                discovered.append(find_cmd)

        # 8. Check for xargs
        for match in XARGS_EXEC_REGEX.finditer(raw):
            xargs_cmd = match.group(1).replace("{}", "").strip()
            if xargs_cmd:
                discovered.append(xargs_cmd)

        # 9. Split all discovered strings on standard shell delimiters (&&, ||, ;, \n, |)
        final_subcommands: List[str] = []
        for cmd in discovered:
            normalized = cmd.replace("\r\n", ";").replace("\n", ";")
            tokens = re.split(r"\s*(?:&&|\|\||;|\|)\s*", normalized)
            for t in tokens:
                t_clean = t.strip()
                if t_clean:
                    final_subcommands.append(t_clean)
                    deq = dequote_command(t_clean)
                    if deq != t_clean:
                        final_subcommands.append(deq)

        return list(dict.fromkeys(final_subcommands))

    @classmethod
    def get_canonical_binary(cls, command_line: str) -> str:
        """Extract the canonical leading binary name from a command, de-quoting it."""
        cmd_clean = command_line.strip()
        if not cmd_clean:
            return ""

        parts = cmd_clean.split(None, 1)
        first_token = parts[0]
        unquoted = dequote_word(first_token)
        basename = unquoted.split("/")[-1]
        return basename.lower()
