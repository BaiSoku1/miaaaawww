import discord
from discord.ext import commands
import requests
import os
import io
import sys
import urllib.parse
import subprocess
import uuid
import time
import re
import asyncio
import functools
import ipaddress
import socket
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

load_dotenv()

# ---------------- LOGGING ----------------
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("catmio")

# ---------------- CONFIG ----------------
TOKEN = ""

PREFIX = "."
ALLOWED_GUILDS = {1442884507995869257, 1470477786471858421, 1477780396874924073}  # add more guild IDs here
CATMIO_INVITE  = "https://discord.gg/JzUgsbUFNp"
DUMPER_PATH = "A7kP9xQ2LmZ4bR1c.lua"

MAX_FILE_SIZE = 5 * 1024 * 1024
DUMP_TIMEOUT = 130  # Must exceed catlogger.lua TIMEOUT_SECONDS (120) to allow proper cleanup

LUA_INTERPRETERS = ["lua5.3", "lua5.1", "lua5.4", "luajit", "lua"]

DISCORD_RETRY_ATTEMPTS = 3
DISCORD_RETRY_DELAY = 2.0  # seconds between retries on 503

# ---------------- RATE LIMITING ----------------
# Per-user cooldown in seconds for heavy commands (.l, .bf, .darklua)
_RATE_LIMIT_SECONDS = 5
_user_last_use: dict[int, float] = defaultdict(float)

def _check_rate_limit(user_id: int) -> float:
    """Return remaining cooldown seconds (0 means allowed)."""
    now = time.time()
    elapsed = now - _user_last_use[user_id]
    if elapsed < _RATE_LIMIT_SECONDS:
        return _RATE_LIMIT_SECONDS - elapsed
    _user_last_use[user_id] = now
    return 0.0


async def _send_with_retry(coro_factory):
    """Call a coroutine that sends a Discord message, retrying up to
    DISCORD_RETRY_ATTEMPTS times when a transient 503 DiscordServerError occurs."""
    for attempt in range(DISCORD_RETRY_ATTEMPTS):
        try:
            return await coro_factory()
        except discord.errors.DiscordServerError:
            if attempt < DISCORD_RETRY_ATTEMPTS - 1:
                await asyncio.sleep(DISCORD_RETRY_DELAY * (attempt + 1))
            else:
                raise

class _FailedResponse:
    """Returned by _requests_get when a network error occurs."""
    status_code = 0
    content = b""


_LUA_SCRIPT = '''local url = arg[1] or ""

if url == "" then
    os.exit(1)
end

-- Try using luasocket first
local http_ok, http = pcall(require, "socket.http")

if http_ok then
    local headers = {
        ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        ["Accept-Encoding"] = "gzip, deflate, br",
        ["Accept-Language"] = "en-US,en;q=0.9",
        ["Referer"] = "https://www.google.com/",
        ["Sec-Ch-Ua"] = "\\"Not A(Brand\\";v=\\"99\\", \\"Google Chrome\\";v=\\"124\\"",
        ["Sec-Ch-Ua-Mobile"] = "?0",
        ["Sec-Ch-Ua-Platform"] = "\\"Windows\\"",
        ["Sec-Fetch-Dest"] = "document",
        ["Sec-Fetch-Mode"] = "navigate",
        ["Sec-Fetch-Site"] = "none",
        ["Sec-Fetch-User"] = "?1",
        ["Upgrade-Insecure-Requests"] = "1",
        ["Cache-Control"] = "max-age=0",
        ["Connection"] = "keep-alive",
        ["Cookie"] = ""
    }
    
    local response, status, headers_resp = http.request(url, nil, headers)
    if status == 200 and response then
        io.write(response)
        os.exit(0)
    else
        os.exit(1)
    end
else
    -- Fallback to curl with full headers and browser spoofing
    local user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    local cmd = string.format(
        'curl -s -A "%s" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" -H "Accept-Encoding: gzip, deflate, br" -H "Accept-Language: en-US,en;q=0.9" -H "Referer: https://www.google.com/" -H "Sec-Ch-Ua: \\"Not A(Brand\\";v=\\"99\\", \\"Google Chrome\\";v=\\"124\\"" -H "Sec-Ch-Ua-Mobile: ?0" -H "Sec-Ch-Ua-Platform: \\"Windows\\"" -H "Sec-Fetch-Dest: document" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: none" -H "Cache-Control: max-age=0" -H "Connection: keep-alive" -H "Cookie:" -L "%s"',
        user_agent,
        url:gsub('"', '\\"')
    )
    
    local handle = io.popen(cmd)
    if handle then
        local result = handle:read("*a")
        handle:close()
        if result and #result > 0 then
            io.write(result)
            os.exit(0)
        end
    end
    os.exit(1)
end
'''

def _ensure_lua_script():
    """Create the Lua fetch script if it doesn't exist."""
    script_path = "fetch_http.lua"
    if not os.path.exists(script_path):
        try:
            with open(script_path, "w") as f:
                f.write(_LUA_SCRIPT)
        except:
            pass
    return script_path


# ---------------- SECURITY: URL/SSRF VALIDATION ----------------

# Internal hostname patterns to block
_BLOCKED_HOSTS = re.compile(
    r"^(localhost|.*\.local|.*\.internal|.*\.intranet)$", re.IGNORECASE
)

# Blocked URL schemes
_ALLOWED_SCHEMES = {"http", "https"}

# Strings to redact from dumped output (paths that reveal internal files)
_SENSITIVE_STRINGS = [
    DUMPER_PATH,
    "@" + DUMPER_PATH,
    os.path.splitext(DUMPER_PATH)[0],  # base name without extension
    "path getter",
    "attempting to get path",
    "paths if found",
    "catmio",
    "catlogger",
    "envlogger",
    "sandbox_e",
    "_sandbox_eR",
]


def _is_safe_url(url: str) -> tuple[bool, str]:
    """Validate a URL against SSRF and other injection risks.

    Returns (is_safe, reason). reason is empty string when safe.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "invalid URL"

    # Scheme check
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return False, f"scheme '{parsed.scheme}' not allowed"

    hostname = parsed.hostname or ""
    if not hostname:
        return False, "no hostname"

    # Block by pattern
    if _BLOCKED_HOSTS.match(hostname):
        return False, "internal hostname"

    # Resolve and check IP
    try:
        addrs = socket.getaddrinfo(hostname, None)
        for addr in addrs:
            ip_str = addr[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if (
                    ip.is_loopback
                    or ip.is_private
                    or ip.is_link_local
                    or ip.is_multicast
                    or ip.is_reserved
                    or ip.is_unspecified
                ):
                    return False, f"IP {ip_str} is not public"
            except ValueError:
                pass
    except socket.gaierror:
        # Can't resolve – allow and let the actual request fail naturally
        pass

    return True, ""


def _redact_sensitive_output(code: str) -> str:
    """Remove lines from dumped Lua output that reveal internal bot paths
    or sensitive metadata injected by path-probing scripts.

    Specifically removes print() calls whose string argument contains any
    known sensitive keyword (the dumper filename, path-getter banners, etc.)
    and also strips bare comment lines that reference those strings.
    """
    result: list[str] = []
    for line in code.splitlines():
        stripped = line.strip()

        # Check print("...") lines
        if stripped.startswith("print("):
            # Extract the string argument (handles single/double quotes)
            m = re.match(r'^print\s*\(\s*["\'](.+?)["\']\s*\)', stripped)
            if m:
                inner = m.group(1).lower()
                if any(s.lower() in inner for s in _SENSITIVE_STRINGS):
                    continue  # drop this line

        # Check bare comment lines
        if stripped.startswith("--"):
            inner = stripped[2:].strip().lower()
            if any(s.lower() in inner for s in _SENSITIVE_STRINGS):
                continue

        # Check if the line contains the dumper path as a plain string literal
        if DUMPER_PATH in line:
            continue

        result.append(line)
    return "\n".join(result)


def _requests_get_lua(url, **kwargs):
    """Fetch URL using Lua (luasocket or curl fallback)."""
    try:
        script_path = _ensure_lua_script()
        result = subprocess.run(
            [_lua_interp, script_path, url],
            capture_output=True,
            timeout=kwargs.get("timeout", 8)
        )
        
        if result.returncode == 0 and result.stdout:
            class _LuaResponse:
                status_code = 200
                content = result.stdout
            return _LuaResponse()
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass
    
    return _FailedResponse()

def _requests_get(url, **kwargs):
    """requests.get wrapper with browser-like headers to avoid HTTP 403.
    
    Validates URL safety before fetching (SSRF protection).
    Tries Lua (luasocket/curl) first, falls back to requests library.
    """
    kwargs.setdefault("timeout", 8)

    # SSRF / internal-network protection
    safe, reason = _is_safe_url(url)
    if not safe:
        print(f"[security] blocked request to {url!r}: {reason}")
        return _FailedResponse()

    # Try Lua first (better anti-bot bypass)
    lua_resp = _requests_get_lua(url, **kwargs)
    if lua_resp.status_code == 200:
        return lua_resp
    
    # Fallback to requests
    default_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if "headers" in kwargs:
        merged = dict(default_headers)
        merged.update(kwargs["headers"])
        kwargs["headers"] = merged
    else:
        kwargs["headers"] = default_headers
    try:
        return requests.get(url, **kwargs)
    except requests.exceptions.RequestException as e:
        print(f"Warning: request to {url!r} failed: {e}")
        return _FailedResponse()

# ---------------- BOT ----------------
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=PREFIX, intents=intents, help_command=None)

_executor = ThreadPoolExecutor(max_workers=32)

# ---------------- LUA DETECTION ----------------
def _find_lua() -> str:
    for interp in LUA_INTERPRETERS:
        try:
            r = subprocess.run([interp, "-v"], capture_output=True, timeout=3)
            if r.returncode == 0:
                return interp
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return LUA_INTERPRETERS[0]

def _check_lua_has_E(interp: str) -> bool:
    try:
        r = subprocess.run([interp, "-E", "-v"], capture_output=True, timeout=3)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

_lua_interp = _find_lua()
_lua_has_E = _check_lua_has_E(_lua_interp)


# ---------------- HELPERS ----------------
def extract_links(text):

    url_pattern = r"https?://[^\s\"']+"
    links = re.findall(url_pattern, text)

    seen=set()
    result=[]

    for x in links:
        if x not in seen:
            seen.add(x)
            result.append(x)

    return result

def extract_first_url(text):

    m = re.search(r"https?://[^\s\"')]+", text)
    if not m:
        return None
    url = m.group(0)
    url = url.rstrip("')])")
    if url.endswith(") )()"):
        url = url[:-4]
    return url

def get_filename_from_url(url):

    filename = url.split("/")[-1].split("?")[0]
    filename = urllib.parse.unquote(filename)

    if filename and "." in filename:
        return filename

    return "script.lua"

def _strip_loop_markers(code: str) -> str:
    _LOOP_MARKER_RE = re.compile(r"^\s*--\s*Detected loops\s+\d+\s*$")
    cleaned = [line for line in code.splitlines() if not _LOOP_MARKER_RE.match(line)]
    return "\n".join(cleaned)

_COUNTER_SUFFIX_RE = re.compile(r'\b([a-z][A-Za-z_]*)\d+\b')
_MAX_UNROLLED_REPS = 3


def _normalize_counters(line: str) -> str:
    return _COUNTER_SUFFIX_RE.sub(r'\1', line)


def _collapse_loop_unrolls(code: str, max_reps: int = _MAX_UNROLLED_REPS) -> str:
    lines = code.splitlines()
    n = len(lines)
    if n == 0:
        return code

    norm_lines = [_normalize_counters(ln) for ln in lines]

    result: list[str] = []
    i = 0

    while i < n:
        best_block_size = 0
        best_reps = 0

        for block_size in range(1, min(51, n - i + 1)):
            if i + block_size > n:
                break
            norm_block = norm_lines[i:i + block_size]

            if block_size == 1:
                stripped = norm_block[0].strip()
                if not stripped or stripped in ("end", "do", "then"):
                    continue

            reps = 1
            j = i + block_size
            while j + block_size <= n:
                if norm_lines[j:j + block_size] == norm_block:
                    reps += 1
                    j += block_size
                else:
                    break

            if reps > max_reps and reps > best_reps:
                best_reps = reps
                best_block_size = block_size

        if best_block_size and best_reps > max_reps:
            norm_block = norm_lines[i:i + best_block_size]
            first_nonempty = next(
                (ln for ln in lines[i:i + best_block_size] if ln.strip()), ""
            )
            indent_str = " " * (len(first_nonempty) - len(first_nonempty.lstrip()))
            for rep in range(max_reps):
                result.extend(lines[i + rep * best_block_size:i + (rep + 1) * best_block_size])
            omitted = best_reps - max_reps
            i += best_reps * best_block_size

            partial = 0
            while partial < best_block_size and i + partial < n:
                if norm_lines[i + partial] == norm_block[partial]:
                    partial += 1
                else:
                    break
            if partial > 0:
                omitted += 1
                i += partial

            result.append(
                f"{indent_str}-- [similar block repeated {omitted} more time(s), omitted for clarity]"
            )
        else:
            result.append(lines[i])
            i += 1

    return "\n".join(result)


def _remove_trailing_whitespace(code: str) -> str:
    return "\n".join(line.rstrip() for line in code.splitlines())


def _collapse_blank_lines(code: str) -> str:
    return re.sub(r"\n{3,}", "\n\n", code)


def _normalize_all_counters(code: str) -> str:
    return "\n".join(_normalize_counters(ln) for ln in code.splitlines())


_LOCAL_DECL_RE = re.compile(r"^\s*local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=")
_FUNC_OPEN_RE = re.compile(r"\bfunction\b")
_BLOCK_CLOSE_RE = re.compile(r"^\s*(end|until)\b")
_NONFUNC_OPEN_RE = re.compile(r"\b(then|do)\s*(?:--.*)?$|\brepeat\b")
_SCOPE_LOOKAHEAD = 12


def _scope_group_locals(code: str, max_locals: int = 185) -> str:
    lines = code.splitlines()
    n = len(lines)
    if n == 0:
        return code

    ephemeral: dict[int, int] = {}

    for i, line in enumerate(lines):
        m = _LOCAL_DECL_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        pat = re.compile(r"\b" + re.escape(name) + r"\b")

        last = i
        found_far = False
        for j in range(i + 1, n):
            if pat.search(lines[j]):
                if j <= i + _SCOPE_LOOKAHEAD:
                    last = j
                else:
                    found_far = True
                    break

        if not found_far:
            ephemeral[i] = last

    result: list[str] = []
    i = 0

    while i < n:
        if i in ephemeral:
            group_end = ephemeral[i]
            j = i + 1
            while j <= group_end + 1 and j < n:
                if j in ephemeral:
                    group_end = max(group_end, ephemeral[j])
                j += 1

            indent = " " * (len(lines[i]) - len(lines[i].lstrip()))
            result.append(indent + "do")
            for k in range(i, group_end + 1):
                result.append(lines[k])
            result.append(indent + "end")
            i = group_end + 1
        else:
            result.append(lines[i])
            i += 1

    return "\n".join(result)


_CATMIO_HEADER_RE = re.compile(
    r"^--\s*generated with catmio\b.*$", re.IGNORECASE
)

_INLINE_LONG_COMMENT_RE = re.compile(r"--\[=*\[.*?\]=*\]", re.DOTALL)


def _strip_inline_trailing_comment(line: str) -> str:
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch in ('"', "'"):
            quote = ch
            i += 1
            while i < n:
                c2 = line[i]
                if c2 == '\\':
                    i += 2 if i + 1 < n else 1
                elif c2 == quote:
                    i += 1
                    break
                else:
                    i += 1
        elif ch == '-' and i + 1 < n and line[i + 1] == '-':
            return line[:i].rstrip()
        else:
            i += 1
    return line


def _strip_comments(code: str) -> str:
    result: list[str] = []
    for line in code.splitlines():
        stripped = line.lstrip()
        if _CATMIO_HEADER_RE.match(stripped):
            result.append(line)
            continue
        if stripped.startswith("--"):
            continue
        line = _INLINE_LONG_COMMENT_RE.sub("", line)
        line = _strip_inline_trailing_comment(line)
        result.append(line)
    return "\n".join(result)


_STR_CONCAT_RE = re.compile(r'"((?:[^"\\]|\\.)*)"\s*\.\.\s*"((?:[^"\\]|\\.)*)"')


def _fold_string_concat(code: str) -> str:
    prev = None
    while prev != code:
        prev = code
        code = _STR_CONCAT_RE.sub(lambda m: '"' + m.group(1) + m.group(2) + '"', code)
    return code


_LUA_STR_VAL = r'"(?:[^"\\]|\\.)*"'

_RUNTIME_CONST_RE = re.compile(
    r"^[ \t]*local\s+(_ref_\d+|_url_\d+|_webhook_\d+)\s*=\s*(\"(?:[^\"\\]|\\.)*\")\s*$",
    re.MULTILINE,
)


def _inline_single_use_constants(code: str) -> str:
    constants: dict[str, str] = {}
    for m in _RUNTIME_CONST_RE.finditer(code):
        constants[m.group(1)] = m.group(2)

    if not constants:
        return code

    result = code

    for name, value in constants.items():
        pat = re.compile(r"\b" + re.escape(name) + r"\b")
        total = len(pat.findall(result))
        uses = total - 1

        if uses == 0:
            result = re.sub(
                r"^[ \t]*local\s+" + re.escape(name) + r"\s*=\s*" + _LUA_STR_VAL + r"[ \t]*\n?",
                "",
                result,
                flags=re.MULTILINE,
            )
        elif uses == 1:
            decl_re = re.compile(
                r"^[ \t]*local\s+" + re.escape(name) + r"\s*=\s*(" + _LUA_STR_VAL + r")[ \t]*$",
                re.MULTILINE,
            )
            decl_m = decl_re.search(result)
            if decl_m:
                after = result[decl_m.end():]
                repl = value
                after = pat.sub(lambda _: repl, after, count=1)
                result = result[: decl_m.end()] + after
            result = re.sub(
                r"^[ \t]*local\s+" + re.escape(name) + r"\s*=\s*" + _LUA_STR_VAL + r"[ \t]*\n?",
                "",
                result,
                flags=re.MULTILINE,
            )

    return result


_LUA_KEYWORDS = frozenset({
    "and", "break", "do", "else", "elseif", "end", "false", "for",
    "function", "goto", "if", "in", "local", "nil", "not", "or",
    "repeat", "return", "then", "true", "until", "while",
})

_LUA_STRING_LITERAL_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')


def _sub_identifier_outside_strings(old: str, new: str, code: str) -> str:
    pat = re.compile(
        r"(?<![a-zA-Z0-9_])" + re.escape(old) + r"(?![a-zA-Z0-9_])"
    )
    segments: list[str] = []
    pos = 0
    for m in _LUA_STRING_LITERAL_RE.finditer(code):
        segments.append(pat.sub(new, code[pos:m.start()]))
        segments.append(m.group(0))
        pos = m.end()
    segments.append(pat.sub(new, code[pos:]))
    return "".join(segments)


def _name_to_camel_id(raw: str) -> str:
    parts = [p for p in re.sub(r"[^a-zA-Z0-9]+", " ", raw).split() if p]
    if not parts:
        return ""
    first = parts[0]
    result = first[0].lower() + first[1:] + "".join(p.capitalize() for p in parts[1:])
    if result and result[0].isdigit():
        result = "_" + result
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", result):
        return ""
    if result in _LUA_KEYWORDS:
        return ""
    return result


def _rename_by_name_property(code: str) -> str:
    lines = code.splitlines()
    n = len(lines)

    existing: set[str] = set()
    for line in lines:
        for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", line):
            existing.add(m.group(1))

    renames: dict[str, str] = {}

    _INSTANCE_NEW_RE = re.compile(r'Instance\.new\s*\(\s*"([A-Za-z][A-Za-z0-9]*)"\s*\)')

    for i, line in enumerate(lines):
        m = re.match(r"^\s*local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=", line)
        if not m:
            continue
        var = m.group(1)
        if var in renames:
            continue

        found_name = False
        for j in range(i + 1, n):
            nm = re.match(
                r"^\s*" + re.escape(var) + r"\s*\.\s*Name\s*=\s*\"([^\"]+)\"",
                lines[j],
            )
            if nm:
                new_name = _name_to_camel_id(nm.group(1))
                if (
                    new_name
                    and new_name != var
                    and new_name not in renames.values()
                    and new_name not in existing
                ):
                    renames[var] = new_name
                found_name = True
                break

        if not found_name:
            suffix_m = re.match(r"^([a-zA-Z_][a-zA-Z_]*)(\d+)$", var)
            inst_m = _INSTANCE_NEW_RE.search(line)
            if suffix_m and inst_m:
                type_name = inst_m.group(1)
                suffix = suffix_m.group(2)
                base = _name_to_camel_id(type_name)
                if base:
                    candidate = base + "_" + suffix
                    if (
                        candidate not in renames.values()
                        and candidate not in existing
                    ):
                        renames[var] = candidate
            elif inst_m:
                under_m = re.match(r"^([a-zA-Z][a-zA-Z0-9]*)(_+)$", var)
                if under_m:
                    type_name = inst_m.group(1)
                    underscore_count = len(under_m.group(2))
                    base = _name_to_camel_id(type_name)
                    if base:
                        n_val = underscore_count
                        letters = ""
                        while n_val > 0:
                            n_val -= 1
                            letters = chr(ord("a") + (n_val % 26)) + letters
                            n_val //= 26
                        candidate = base + "_" + letters
                        if (
                            candidate not in renames.values()
                            and candidate not in existing
                        ):
                            renames[var] = candidate

    if not renames:
        return code

    result = "\n".join(lines)
    for old, new in sorted(renames.items(), key=lambda kv: -len(kv[0])):
        result = re.sub(
            r"(?<![a-zA-Z0-9_])" + re.escape(old) + r"(?![a-zA-Z0-9_])",
            new,
            result,
        )

    return result


# ---------------- SMART RENAME ----------------

_INSTANCE_TYPE_PREFIXES: dict[str, str] = {
    "Frame": "frame",
    "TextButton": "button",
    "TextLabel": "label",
    "TextBox": "textBox",
    "ScrollingFrame": "scroll",
    "ScreenGui": "gui",
    "UICorner": "corner",
    "UIListLayout": "listLayout",
    "UIGridLayout": "gridLayout",
    "UIStroke": "stroke",
    "UIAspectRatioConstraint": "aspectRatio",
    "UITableLayout": "tableLayout",
    "UIPageLayout": "pageLayout",
    "UIPadding": "padding",
    "UIScale": "uiScale",
    "UIGradient": "gradient",
    "UISizeConstraint": "sizeConstraint",
    "UITextSizeConstraint": "textConstraint",
    "UIFlexItem": "flexItem",
    "ImageLabel": "imageLabel",
    "ImageButton": "imageButton",
    "ViewportFrame": "viewport",
    "BillboardGui": "billboard",
    "SurfaceGui": "surfaceGui",
    "Part": "part",
    "RemoteEvent": "remote",
    "RemoteFunction": "remoteFunc",
    "BindableEvent": "bindEvent",
    "BindableFunction": "bindFunc",
    "LocalScript": "localScript",
    "Script": "script",
    "ModuleScript": "moduleScript",
    "Folder": "folder",
    "Model": "model",
    "Configuration": "config",
    "StringValue": "strVal",
    "NumberValue": "numVal",
    "BoolValue": "boolVal",
    "IntValue": "intVal",
    "ObjectValue": "objVal",
    "SelectionBox": "selBox",
    "WeldConstraint": "weld",
    "Motor6D": "motor6D",
    "Humanoid": "humanoid",
    "Animator": "animator",
    "Animation": "animation",
    "Sound": "sound",
    "SoundGroup": "soundGroup",
    "Camera": "camera",
}

_TEXT_PROPERTY_TYPES: frozenset[str] = frozenset({"TextButton", "TextLabel", "TextBox"})

_GENERIC_SUFFIX_RE = re.compile(r"^[_a-z\d]*$")


def _is_generic_var_for_type(var: str, type_name: str) -> bool:
    if len(var) <= 2:
        return True
    bases = set()
    prefix = _INSTANCE_TYPE_PREFIXES.get(type_name)
    if prefix:
        bases.add(prefix)
    type_camel = _name_to_camel_id(type_name)
    if type_camel:
        bases.add(type_camel)
    for base in bases:
        if var.startswith(base) and _GENERIC_SUFFIX_RE.fullmatch(var[len(base):]):
            return True
    return False


def _smart_rename_variables(code: str) -> str:
    lines = code.splitlines()

    existing: set[str] = set()
    for line in lines:
        for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", line):
            existing.add(m.group(1))

    _INST_RE = re.compile(
        r'Instance\.new\s*\(\s*"([A-Za-z][A-Za-z0-9]*)"\s*\)'
    )
    var_types: dict[str, str] = {}
    for line in lines:
        m = re.match(r"^\s*local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=", line)
        if not m:
            continue
        var = m.group(1)
        inst_m = _INST_RE.search(line)
        if inst_m and var not in var_types:
            var_types[var] = inst_m.group(1)

    _PROP_RE = re.compile(
        r"(?<![a-zA-Z0-9_])([a-zA-Z_][a-zA-Z0-9_]*)\s*\.\s*(Name|Text)\s*=\s*\"([^\"]+)\""
    )
    var_name_prop: dict[str, str] = {}
    var_text_prop: dict[str, str] = {}
    for line in lines:
        for pm in _PROP_RE.finditer(line):
            var, prop, val = pm.group(1), pm.group(2), pm.group(3)
            if var not in var_types:
                continue
            if prop == "Name" and var not in var_name_prop:
                var_name_prop[var] = val
            elif (
                prop == "Text"
                and var not in var_text_prop
                and var_types.get(var) in _TEXT_PROPERTY_TYPES
            ):
                var_text_prop[var] = val

    _CONN_DECL_RE = re.compile(
        r"^\s*local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"
        r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\.\s*[A-Za-z][A-Za-z0-9]*\s*:\s*Connect\s*\("
    )
    conn_src: dict[str, str] = {}
    _GENERIC_CONN_RE = re.compile(r"^conn\w*$", re.IGNORECASE)
    for line in lines:
        cm = _CONN_DECL_RE.match(line)
        if not cm:
            continue
        conn_var, src_var = cm.group(1), cm.group(2)
        if _GENERIC_CONN_RE.match(conn_var) and conn_var not in conn_src:
            conn_src[conn_var] = src_var

    renameable: set[str] = set(var_types) | set(conn_src)
    used_names: set[str] = existing - renameable

    def _alloc(base: str) -> str:
        if base not in used_names and base not in renames:
            used_names.add(base)
            return base
        c = 2
        while True:
            candidate = f"{base}{c}"
            if candidate not in used_names and candidate not in renames:
                used_names.add(candidate)
                return candidate
            c += 1

    renames: dict[str, str] = {}

    for var, type_name in var_types.items():
        if var in var_name_prop:
            new = _name_to_camel_id(var_name_prop[var])
            if new:
                new = _alloc(new)
                if new != var:
                    renames[var] = new
            else:
                used_names.add(var)
            continue

        if var in var_text_prop and _is_generic_var_for_type(var, type_name):
            new = _name_to_camel_id(var_text_prop[var])
            if new:
                new = _alloc(new)
                if new != var:
                    renames[var] = new
            else:
                used_names.add(var)
            continue

        if _is_generic_var_for_type(var, type_name):
            prefix = _INSTANCE_TYPE_PREFIXES.get(type_name)
            if prefix:
                new = _alloc(prefix)
                if new != var:
                    renames[var] = new
            else:
                used_names.add(var)
        else:
            used_names.add(var)

    for conn_var, src_var in conn_src.items():
        resolved_src = renames.get(src_var, src_var)
        new = _alloc(resolved_src + "Conn")
        if new != conn_var:
            renames[conn_var] = new

    if not renames:
        return code

    result = "\n".join(lines)
    for old, new in sorted(renames.items(), key=lambda kv: -len(kv[0])):
        result = _sub_identifier_outside_strings(old, new, result)
    return result


_LUA_BLOCK_OPEN_RE = re.compile(r"\b(function|do|repeat)\b")
_LUA_COND_OPEN_RE = re.compile(r"\b(if|for|while)\b")
_LUA_COND_CLOSE_RE = re.compile(r"\b(then|do)\s*(?:--.*)?$")
_LUA_BLOCK_CLOSE_RE_FIX = re.compile(r"^\s*(end|until)\b")


def _fix_lua_do_end(code: str) -> str:
    depth = 0
    for raw_line in code.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("--"):
            continue
        m = re.match(r"^(\w+)", line)
        first_kw = m.group(1) if m else ""

        if first_kw in ("end", "until"):
            depth = max(0, depth - 1)

        if first_kw in ("function", "do", "repeat"):
            depth += 1
        elif first_kw in ("if", "for", "while"):
            if _LUA_COND_CLOSE_RE.search(line):
                depth += 1
        elif first_kw == "then":
            depth += 1
        elif re.search(r"\bfunction\b", line) and not re.search(
            r"\bend\b\s*(?:--.*)?$", line
        ):
            depth += 1

    if depth > 0:
        code = code.rstrip() + "\n" + "end\n" * depth
    return code


def _remove_useless_do_blocks(code: str) -> str:
    lines = code.splitlines()
    result: list[str] = []
    i = 0
    n = len(lines)

    _STANDALONE_DO_RE = re.compile(r"^\s*do\s*(?:--.*)?$")

    def _dedent_line(line: str) -> str:
        if line.startswith("\t"):
            return line[1:]
        if line.startswith("    "):
            return line[4:]
        return line

    while i < n:
        line = lines[i]
        if not _STANDALONE_DO_RE.match(line):
            result.append(line)
            i += 1
            continue

        depth = 1
        j = i + 1
        _INNER_OPEN_RE = re.compile(r"\b(function|do|repeat)\b")
        _INNER_COND_RE = re.compile(r"^\s*(if|for|while)\b.*\b(then|do)\s*(?:--.*)?$")
        _INNER_CLOSE_RE = re.compile(r"^\s*(end|until)\b")

        while j < n and depth > 0:
            inner = lines[j].strip()
            if not inner or inner.startswith("--"):
                j += 1
                continue
            if _INNER_CLOSE_RE.match(lines[j]):
                depth -= 1
                if depth == 0:
                    break
            m_cond = _INNER_COND_RE.match(lines[j])
            if m_cond:
                depth += 1
            elif _INNER_OPEN_RE.search(lines[j]):
                depth += 1
            j += 1

        end_idx = j

        body = lines[i + 1:end_idx]

        non_empty_body = [l for l in body if l.strip() and not l.strip().startswith("--")]

        def _is_single_simple_statement(bl: list) -> bool:
            if len(bl) != 1:
                return False
            t = bl[0].strip()
            return not re.match(r"\b(function|do|repeat|if|for|while)\b", t)

        is_useless = (
            not non_empty_body
            or all(l.strip().startswith("local ") for l in non_empty_body)
            or _is_single_simple_statement(non_empty_body)
        )

        if is_useless:
            for bl in body:
                result.append(_dedent_line(bl))
            i = end_idx + 1
        else:
            result.append(line)
            i += 1

    return "\n".join(result)


def _fix_for_missing_do(code: str) -> str:
    _NUM_FOR_NO_DO_RE = re.compile(
        r"(\bfor\s+[a-zA-Z_]\w*\s*=\s*\S+\s*,\s*\S+(?:\s*,\s*\S+)?)"
        r"(\s+)(?!\s*\bdo\b)"
    )
    _GEN_FOR_NO_DO_RE = re.compile(
        r"(\bfor\s+(?:[a-zA-Z_]\w*(?:\s*,\s*[a-zA-Z_]\w*)*)\s+in\s+[^\n]+\))"
        r"(\s+)(?!\s*\bdo\b)"
    )
    code = _NUM_FOR_NO_DO_RE.sub(r"\1 do\2", code)
    code = _GEN_FOR_NO_DO_RE.sub(r"\1 do\2", code)
    return code


def _fix_local_missing_assign(code: str) -> str:
    _LOCAL_MISSING_ASSIGN_RE = re.compile(
        r"\blocal\s+([a-zA-Z_]\w*)\s+(-?\d+(?:\.\d+)?)\b"
    )
    return _LOCAL_MISSING_ASSIGN_RE.sub(r"local \1 = \2", code)


def _fix_extra_ends(code: str) -> str:
    lines = code.splitlines()
    result: list[str] = []
    depth = 0

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("--"):
            result.append(raw_line)
            continue

        m = re.match(r"^(\w+)", line)
        first_kw = m.group(1) if m else ""

        if first_kw in ("end", "until"):
            if depth <= 0:
                continue
            depth -= 1
            result.append(raw_line)
            continue

        if first_kw in ("function", "do", "repeat"):
            depth += 1
        elif first_kw in ("if", "for", "while"):
            if _LUA_COND_CLOSE_RE.search(line):
                depth += 1
        elif first_kw == "then":
            depth += 1
        elif re.search(r"\bfunction\b", line) and not re.search(
            r"\bend\b\s*(?:--.*)?$", line
        ):
            depth += 1

        result.append(raw_line)

    return "\n".join(result)


_CONN_FUNC_OPEN_RE = re.compile(r":Connect\s*\(.*\bfunction\b")


def _fix_connect_end_parens(code: str) -> str:
    lines = code.splitlines()
    result = list(lines)

    connect_stack: list[tuple[int, int, int]] = []
    block_depth = 0

    for idx, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line or line.startswith("--"):
            continue

        m = re.match(r"^(\w+)", line)
        first_kw = m.group(1) if m else ""

        if first_kw in ("end", "until"):
            if connect_stack and block_depth - 1 == connect_stack[-1][1]:
                _, _, missing_parens = connect_stack.pop()
                existing_close = line.count(")")
                needed = missing_parens - existing_close
                if needed > 0:
                    indent = len(raw_line) - len(raw_line.lstrip())
                    result[idx] = raw_line[:indent] + "end" + ")" * needed
            block_depth = max(0, block_depth - 1)
        else:
            if _CONN_FUNC_OPEN_RE.search(line):
                paren_delta = line.count("(") - line.count(")")
                if paren_delta > 0:
                    connect_stack.append((idx, block_depth, paren_delta))

            if first_kw in ("function", "do", "repeat"):
                block_depth += 1
            elif first_kw in ("if", "for", "while"):
                if _LUA_COND_CLOSE_RE.search(line):
                    block_depth += 1
            elif first_kw == "then":
                block_depth += 1
            elif re.search(r"\bfunction\b", line) and not re.search(
                r"\bend\b\s*(?:--.*)?$", line
            ):
                block_depth += 1

    return "\n".join(result)


def _fix_ui_variable_shadowing(code: str) -> str:
    _INST_NEW_DECL_RE = re.compile(
        r"^(\s*local\s+)([a-zA-Z_][a-zA-Z0-9_]*)(\s*=\s*Instance\.new\s*\()"
    )

    lines = code.splitlines()
    seen_count: dict[str, int] = {}

    result: list[str] = []
    renames: list[tuple[str, str, int]] = []

    for idx, raw_line in enumerate(lines):
        m = _INST_NEW_DECL_RE.match(raw_line)
        if m:
            prefix, var_name, suffix = m.group(1), m.group(2), m.group(3)
            count = seen_count.get(var_name, 0)
            seen_count[var_name] = count + 1
            if count > 0:
                new_name = f"{var_name}_{count + 1}"
                rest_of_line = _sub_identifier_outside_strings(
                    var_name, new_name, raw_line[m.end():]
                )
                raw_line = prefix + new_name + suffix + rest_of_line
                renames.append((var_name, new_name, idx))

        active: dict[str, str] = {}
        for orig, new, start in renames:
            if start < idx:
                active[orig] = new

        for orig, new in sorted(active.items(), key=lambda kv: -len(kv[0])):
            raw_line = _sub_identifier_outside_strings(orig, new, raw_line)

        result.append(raw_line)

    return "\n".join(result)


_CONN_OPEN_RE = re.compile(r"^\s*(\w[\w.]*\.\w+):Connect\s*\(")


def _dedup_connections(code: str) -> str:
    lines = code.splitlines()
    seen: set[str] = set()
    result: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _CONN_OPEN_RE.match(line)
        if m:
            conn_key = m.group(1)
            if conn_key in seen:
                depth = line.count("(") - line.count(")")
                i += 1
                while i < len(lines) and depth > 0:
                    depth += lines[i].count("(") - lines[i].count(")")
                    i += 1
                continue
            seen.add(conn_key)
        result.append(line)
        i += 1
    return "\n".join(result)


# ---------------- REFERENCE MESSAGE HELPER ----------------
async def _fetch_reference_content(ctx):
    ref = ctx.message.reference
    if not ref:
        return None, None

    try:
        ref_msg = await ctx.channel.fetch_message(ref.message_id)
    except Exception:
        return None, None

    if ref_msg.attachments:
        att = ref_msg.attachments[0]
        if att.size > MAX_FILE_SIZE:
            return None, None
        loop = asyncio.get_event_loop()
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, att.url))
        if r.status_code == 200 and r.content:
            return r.content, att.filename
        return None, None

    url = extract_first_url(ref_msg.content or "")
    if url:
        filename = get_filename_from_url(url)
        loop = asyncio.get_event_loop()
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, url))
        if r.status_code == 200 and r.content:
            if len(r.content) > MAX_FILE_SIZE:
                return None, None
            return r.content, filename

    return None, None


def _extract_codeblock(text: str):
    if not text:
        return None, None
    
    pattern = r"```(\w*)\n(.*?)\n```"
    match = re.search(pattern, text, re.DOTALL)
    
    if match:
        lang = match.group(1) or "lua"
        code = match.group(2)
        return code, lang
    
    pattern = r"```(.*?)```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        code = match.group(1).strip()
        return code, "lua"
    
    return None, None

def _is_html(content: bytes) -> bool:
    try:
        text = content.decode("utf-8", errors="ignore")[:5000]
        return bool(re.search(r"<!DOCTYPE|<html|<head|<body|<script", text, re.IGNORECASE))
    except:
        return False

def _looks_like_raw_code_snippet(text: str) -> bool:
    if not text or re.search(r'https?://', text, re.IGNORECASE):
        return False
    return bool(re.search(r'\b(local|function|print|repeat|if|for|while|return|end)\b', text))

def _extract_obfuscated_from_html(content: bytes) -> bytes | None:
    try:
        html_text = content.decode("utf-8", errors="ignore")
    except:
        return None
    
    script_pattern = r"<script[^>]*>(.*?)</script>"
    scripts = re.findall(script_pattern, html_text, re.DOTALL | re.IGNORECASE)
    
    if scripts:
        for script in scripts:
            script = script.strip()
            if script and len(script) > 100:
                if not any(x in script.lower() for x in ["google", "analytics", "tracking", "cdn.jsdelivr", "cloudflare"]):
                    return script.encode("utf-8")
    
    data_pattern = r'(?:var|const|let)\s+(\w+)\s*=\s*["\']([a-zA-Z0-9+/=]{500,})["\']'
    matches = re.findall(data_pattern, html_text)
    
    if matches:
        for var_name, code in matches:
            if len(code) > 500:
                return code.encode("utf-8")
    
    obf_pattern = r'["\']([a-zA-Z0-9_$]{1000,})["\']'
    obf_matches = re.findall(obf_pattern, html_text)
    
    if obf_matches:
        largest = max(obf_matches, key=len)
        if len(largest) > 1000:
            return largest.encode("utf-8")
    
    return None

async def _get_content(ctx, link=None):
    loop = asyncio.get_event_loop()

    # 0. Codeblock in the current message
    codeblock, lang = _extract_codeblock(ctx.message.content)
    if codeblock:
        filename = f"codeblock.{lang if lang != 'lua' else 'lua'}"
        return codeblock.encode("utf-8"), filename, None

    # 0.5. Raw code snippet passed directly as argument
    if link:
        stripped_link = link.strip()
        if _looks_like_raw_code_snippet(stripped_link):
            return stripped_link.encode("utf-8"), "snippet.lua", None

    # 1. Attachment in the current message.
    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        if att.size > MAX_FILE_SIZE:
            return None, att.filename, "File too large"
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, att.url))
        if r.status_code == 200 and r.content:
            return r.content, att.filename, None
        return None, att.filename, f"Failed to download attachment (HTTP {r.status_code})"

    # 2. Explicit URL provided in the command argument.
    if link:
        url = extract_first_url(link) or link

        # SSRF check before fetching user-supplied URL
        safe, reason = _is_safe_url(url)
        if not safe:
            return None, "file", f"Blocked URL: {reason}"

        filename = get_filename_from_url(url)
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, url))
        if r.status_code == 200 and r.content:
            if len(r.content) > MAX_FILE_SIZE:
                return None, filename, "File too large"
            return r.content, filename, None
        url_err = f"HTTP {r.status_code}" if r.status_code != 0 else "network error"
        ref_content, ref_filename = await _fetch_reference_content(ctx)
        if ref_content:
            return ref_content, ref_filename or filename, None
        return None, filename, f"Failed to get content ({url_err})"

    # 3. Reply to another message.
    ref_content, ref_filename = await _fetch_reference_content(ctx)
    if ref_content:
        return ref_content, ref_filename or "file", None

    return None, "file", "Provide a codeblock, link, file, or reply to a message that contains one."

# ---------------- PASTEFY ----------------
def upload_to_pastefy(content, title="Dumped Script"):

    payload = {
        "title": title,
        "content": content,
        "visibility": "PUBLIC"
    }

    try:
        resp = requests.post(
            "https://pastefy.app/api/v2/paste",
            json=payload,
            timeout=10
        )
        if resp.status_code in (200, 201):
            data = resp.json()
            pid = (data.get("paste") or {}).get("id") or data.get("id")
            return (
                f"https://pastefy.app/{pid}",
                f"https://pastefy.app/{pid}/raw"
            )
    except Exception as e:
        print(f"[pastefy] upload failed: {e}")

    return None, None

# ---------------- DUMPER ----------------
def _run_dumper_blocking(lua_content):

    uid=str(uuid.uuid4())

    input_file=f"input_{uid}.lua"
    output_file=f"output_{uid}.lua"

    try:

        with open(input_file,"wb") as f:
            f.write(lua_content)

        start=time.time()

        cmd = [_lua_interp]
        if _lua_has_E:
            cmd.append("-E")
        cmd.extend([DUMPER_PATH, input_file, output_file])
        result=subprocess.run(
            cmd,
            capture_output=True,
            timeout=DUMP_TIMEOUT
        )

        exec_ms=(time.time()-start)*1000

        stdout=result.stdout.decode(errors="ignore")

        loops=0
        lines=0

        m=re.search(r"Loops:\s*(\d+)",stdout)
        if m:
            loops=int(m.group(1))

        m=re.search(r"Lines:\s*(\d+)",stdout)
        if m:
            lines=int(m.group(1))

        if os.path.exists(output_file):

            with open(output_file,"rb") as f:
                dumped=f.read()

            return dumped,exec_ms,loops,lines,None

        stderr=result.stderr.decode(errors="ignore").strip()
        lua_err=re.search(r"\[LUA_LOAD_FAIL\][^\n]*",stdout)
        if lua_err:
            detail=lua_err.group(0).replace("[LUA_LOAD_FAIL] ","",1).strip()
        elif stderr:
            detail=stderr.splitlines()[-1].strip()
        else:
            detail=""
        msg="Output not generated"
        if detail:
            msg=f"Output not generated: {detail}"
        return None,0,0,0,msg

    except subprocess.TimeoutExpired:

        return None,0,0,0,"Dump timeout"

    except Exception as e:

        return None,0,0,0,str(e)

    finally:

        for p in (input_file,output_file):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except:
                pass

async def run_dumper(lua_content):

    loop=asyncio.get_event_loop()

    return await loop.run_in_executor(
        _executor,
        functools.partial(_run_dumper_blocking,lua_content)
    )

# ---------------- EVENTS ----------------
@bot.event
async def on_ready():
    print(f"Logged as {bot.user} | Lua {_lua_interp} | -E {'yes' if _lua_has_E else 'no'}")
    log.info("Ready: %s | guilds=%d | lua=%s -E=%s", bot.user, len(bot.guilds), _lua_interp, _lua_has_E)


@bot.check
async def guild_only(ctx):
    """Block all commands outside the allowed guild."""
    if ctx.guild is None or ctx.guild.id not in ALLOWED_GUILDS:
        try:
            await ctx.send(
                f"This bot is only available in the catmio server.\n"
                f"Join here to use it: {CATMIO_INVITE}"
            )
        except discord.errors.Forbidden:
            pass
        return False
    return True


@bot.event
async def on_command_error(ctx, error):
    """Suppress CheckFailure (guild check) — message already sent in the check."""
    if isinstance(error, commands.CheckFailure):
        log.info("Guild check blocked %s guild=%s cmd=%s",
                 ctx.author, ctx.guild.id if ctx.guild else "DM", ctx.command)
        return
    log.error("Unhandled error cmd=%s user=%s: %s", ctx.command, ctx.author, error, exc_info=error)
    raise error

# ---------------- COMMAND .help ----------------
@bot.command(name="help")
async def show_help(ctx):
    """Show available bot commands."""
    lines = [
        f"**Commands** — prefix: `{PREFIX}`",
        "",
        f"`{PREFIX}l [link]` — deobfuscate/dump a Lua script",
        f"`{PREFIX}get [link]` — fetch a file from a URL and send it as attachment",
        f"`{PREFIX}bf [link]` — beautify/reformat a Lua script",
        f"`{PREFIX}darklua [link]` — apply Lua code transformations interactively",
        "",
        "Attach a file, provide a URL, or reply to a message that contains one.",
    ]
    try:
        await _send_with_retry(lambda: ctx.send("\n".join(lines)))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send help message: {e}")


# ---------------- COMMAND .l ----------------
@bot.command(name="l")
async def process_link(ctx, *, link=None):

    log.info(".l user=%s guild=%s", ctx.author, ctx.guild.id if ctx.guild else "DM")
    # Rate limit check
    remaining = _check_rate_limit(ctx.author.id)
    if remaining > 0:
        log.info("Rate limited user=%s cmd=%s remaining=%.1fs", ctx.author, ctx.command, remaining)
        try:
            await ctx.send(f"slow down, wait {remaining:.1f}s")
        except discord.errors.DiscordServerError:
            pass
        return

    try:
        status = await _send_with_retry(lambda: ctx.send("dumping"))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send status message: {e}")
        return

    content, original_filename, err = await _get_content(ctx, link)
    if err:
        await status.edit(content=err)
        return

    # Pre-process: expand Luau operators (+=, //=, etc.) before the dumper loads the script
    try:
        _pre = content.decode('utf-8', errors='ignore')
        _pre_fixed = _fix_lua_compat(_pre)
        if _pre_fixed != _pre:
            content = _pre_fixed.encode('utf-8')
    except Exception:
        pass

    dumped,exec_ms,loops,lines,error=await run_dumper(content)

    if error and content is not None:
        try:
            text_source = content.decode("utf-8", errors="ignore")
            fixed_text = _run_heuristic_fix_pipeline(text_source)
            if fixed_text and fixed_text != text_source:
                fixed_dumped, fixed_exec_ms, fixed_loops, fixed_lines, fixed_error = await run_dumper(fixed_text.encode("utf-8"))
                if not fixed_error and fixed_dumped:
                    dumped,exec_ms,loops,lines,error = fixed_dumped, fixed_exec_ms, fixed_loops, fixed_lines, None
                    content = fixed_text.encode("utf-8")
        except Exception:
            pass

    # Specific retry for 'end expected near elseif' -- remove broken else..end..elseif
    if error and "'end' expected" in error.lower() and "elseif" in error.lower() and content is not None:
        try:
            await status.edit(content="'end' expected near elseif -- fixing broken else..end chains...")
            text_source = content.decode("utf-8", errors="ignore")
            fixed_text = _fix_else_end_elseif(text_source)
            if fixed_text != text_source:
                fixed_dumped, fixed_exec_ms, fixed_loops, fixed_lines, fixed_error = await run_dumper(
                    fixed_text.encode("utf-8")
                )
                if not fixed_error and fixed_dumped:
                    dumped, exec_ms, loops, lines, error = fixed_dumped, fixed_exec_ms, fixed_loops, fixed_lines, None
                    content = fixed_text.encode("utf-8")
        except Exception:
            pass

    # Specific retry for 'control structure too long' -- split giant if/elseif chains
    if error and "control structure too long" in error.lower() and content is not None:
        try:
            await status.edit(content="control structure too long -- splitting chains...")
            text_source = content.decode("utf-8", errors="ignore")
            fixed_text = _fix_control_structure_too_long(text_source)
            if fixed_text != text_source:
                fixed_dumped, fixed_exec_ms, fixed_loops, fixed_lines, fixed_error = await run_dumper(
                    fixed_text.encode("utf-8")
                )
                if not fixed_error and fixed_dumped:
                    dumped, exec_ms, loops, lines, error = fixed_dumped, fixed_exec_ms, fixed_loops, fixed_lines, None
                    content = fixed_text.encode("utf-8")
                elif fixed_error and "control structure too long" in (fixed_error or "").lower():
                    # Still too long -- retry (multiple nested giant chains)
                    fixed_text2 = _fix_control_structure_too_long(fixed_text)
                    if fixed_text2 != fixed_text:
                        fd2, fms2, fl2, fl2b, fe2 = await run_dumper(fixed_text2.encode("utf-8"))
                        if not fe2 and fd2:
                            dumped, exec_ms, loops, lines, error = fd2, fms2, fl2, fl2b, None
                            content = fixed_text2.encode("utf-8")
        except Exception:
            pass

    if error:
        log.warning(".l dump failed user=%s: %s", ctx.author, error)
        await status.edit(content=f"{error}")
        return

    dumped_text=dumped.decode("utf-8",errors="ignore")
    dumped_text=_strip_loop_markers(dumped_text)
    # Redact sensitive paths BEFORE any further processing
    dumped_text=_redact_sensitive_output(dumped_text)
    dumped_text=_collapse_loop_unrolls(dumped_text)
    dumped_text=_fold_string_concat(dumped_text)
    dumped_text=_inline_single_use_constants(dumped_text)
    dumped_text=_rename_by_name_property(dumped_text)
    dumped_text=_dedup_connections(dumped_text)
    dumped_text=_fix_lua_do_end(dumped_text)
    dumped_text=_normalize_all_counters(dumped_text)
    dumped_text=_collapse_loop_unrolls(dumped_text)
    dumped_text=_remove_useless_do_blocks(dumped_text)
    dumped_text=_strip_comments(dumped_text)
    dumped_text=_collapse_blank_lines(dumped_text)
    dumped_text=_remove_trailing_whitespace(dumped_text)
    # Final redaction pass after all transformations
    dumped_text=_redact_sensitive_output(dumped_text)

    loop=asyncio.get_event_loop()
    paste,raw=await loop.run_in_executor(
        _executor,
        functools.partial(upload_to_pastefy,dumped_text,title=original_filename)
    )

    try:
        await status.delete()
    except discord.errors.HTTPException as e:
        print(f"Warning: failed to delete status message: {e}")

    log.info(".l done user=%s file=%s size=%d exec=%.0fms paste=%s",
             ctx.author, original_filename, len(dumped_text), exec_ms, raw or "none")
    msg_content = f"done in {exec_ms:.2f}ms"
    if raw:
        msg_content += f" | {raw}"
    else:
        msg_content += " | paste upload failed"

    try:
        await _send_with_retry(lambda: ctx.send(
            content=msg_content,
            file=discord.File(
                io.BytesIO(dumped_text.encode("utf-8")),
                filename=original_filename+".txt"
            )
        ))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send result: {e}")
        try:
            await status.edit(content=f"Discord error, please retry: {e}")
        except discord.errors.HTTPException:
            pass

# ---------------- BEAUTIFIER ----------------
def _beautify_lua(code: str) -> str:
    for cmd in (["lua-format", "--stdin"], ["luafmt", "-"]):
        try:
            proc = subprocess.run(
                cmd, input=code.encode(),
                capture_output=True, timeout=15
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.decode("utf-8", errors="ignore")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    output = []
    indent = 0

    for raw_line in code.splitlines():
        line = raw_line.strip()

        if not line:
            output.append("")
            continue

        m = re.match(r"^(\w+)", line)
        first_kw = m.group(1) if m else ""

        if first_kw in ("end", "until"):
            indent = max(0, indent - 1)
        elif first_kw in ("else", "elseif"):
            indent = max(0, indent - 1)

        output.append("    " * indent + line)

        if first_kw in ("else", "elseif"):
            indent += 1
        elif first_kw in ("function", "do", "repeat"):
            indent += 1
        elif first_kw in ("if", "for", "while"):
            if re.search(r"\b(then|do)\s*(?:--.*)?$", line):
                indent += 1
        elif first_kw == "then":
            indent += 1
        elif re.search(r"\bfunction\b", line) and not re.search(r"\bend\b\s*(?:--.*)?$", line):
            indent += 1

    return "\n".join(output)

# ---------------- LUA COMPATIBILITY FIXER ----------------
def _fix_lua_compat(code: str) -> str:
    code = re.sub(
        r'^([ \t]*)((?:[a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*)*))[ \t]*//=[ \t]*(.+)$',
        lambda m: f"{m.group(1)}{m.group(2)} = {m.group(2)} // {m.group(3)}",
        code, flags=re.MULTILINE,
    )
    code = re.sub(
        r'^([ \t]*)((?:[a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*)*))[ \t]*\.\.=[ \t]*(.+)$',
        lambda m: f"{m.group(1)}{m.group(2)} = {m.group(2)} .. {m.group(3)}",
        code, flags=re.MULTILINE,
    )
    code = re.sub(
        r'^([ \t]*)((?:[a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*)*))[ \t]*([+\-*/%^])=[ \t]*(.+)$',
        lambda m: f"{m.group(1)}{m.group(2)} = {m.group(2)} {m.group(3)} {m.group(4)}",
        code, flags=re.MULTILINE,
    )

    code = code.replace("!=", "~=")
    code = re.sub(r"\s*&&\s*", " and ", code)
    code = re.sub(r"\s*\|\|\s*", " or ", code)
    code = re.sub(r"(?<!\w)!(?=[a-zA-Z_(])", "not ", code)
    code = re.sub(r"\bnull\b", "nil", code)
    _PROTECT = "\x00CATMIO_ELSEIF\x00"
    code = re.sub(
        r"\bend([ \t]+)else([ \t]+)if\b",
        lambda m: f"end{m.group(1)}else{m.group(2)}{_PROTECT}",
        code,
    )
    code = re.sub(r"\belse[ \t]+if\b", "elseif", code)
    code = code.replace(_PROTECT, "if")
    return code


def _fix_wearedevs_compat(code: str) -> str:
    code = code.replace("end else if", "end\nelse if")
    code = re.sub(r"repeat\s+([^\n]+)\s+until\s+([^\n]+)", r"repeat\n    \1\nuntil \2", code)
    code = code.replace(")\"))()", "\"")
    return code



def _fix_else_end_elseif(code: str) -> str:
    """Fix 'end expected near elseif' caused by obfuscators that emit broken
    ``else BODY end ; elseif`` patterns.

    In Lua, once an if-statement has an ``else`` clause it is closed by the
    subsequent ``end`` — no further ``elseif`` is allowed after that ``end``.
    Several obfuscators (e.g. the rubis/IronBrew family) produce code like:

        if Q <= 1 then
            [body]
            else [else-body]
            end              -- closes the if/else completely
        elseif Q <= 2 then   -- INVALID: if is already closed

    The fix: for each ``else`` whose matching ``end`` is immediately followed by
    ``elseif``, verify that the ``elseif`` has no open ``if`` to continue (i.e.
    scanning backwards from ``elseif`` hits a non-``if`` block opener first).
    If confirmed broken, remove the ``else`` keyword and that ``end`` keyword.

    This check prevents false positives like:
        if outer then if inner then A() else B() end elseif ...
    where the ``else`` belongs to the inner ``if`` (valid Lua).

    Loops until convergence because removing one layer can expose another.
    """
    OPENERS = ("if", "for", "while", "function", "do", "repeat")

    def _tokenize(s: str):
        kws = ["elseif", "else", "end", "until"] + list(OPENERS)
        toks: list[tuple[int, str]] = []
        i = 0
        n = len(s)
        while i < n:
            ch = s[i]
            if ch in ('"', "'"):
                q = ch; i += 1
                while i < n and s[i] != q:
                    if s[i] == "\\": i += 1
                    i += 1
                i += 1
                continue
            if s[i:i+2] == "[[":
                e = s.find("]]", i + 2)
                i = (e + 2) if e != -1 else n
                continue
            if s[i:i+2] == "--":
                if s[i+2:i+4] == "[[":
                    e = s.find("]]", i + 4)
                    i = (e + 2) if e != -1 else n
                else:
                    e = s.find("\n", i)
                    i = (e + 1) if e != -1 else n
                continue
            for kw in kws:
                if s[i:i+len(kw)] == kw:
                    nxt = s[i+len(kw)] if i+len(kw) < n else " "
                    prev = s[i-1] if i > 0 else " "
                    if not (nxt.isalnum() or nxt == "_") and not (prev.isalnum() or prev == "_"):
                        toks.append((i, kw))
                        break
            i += 1
        return toks

    def _elseif_has_open_if(toks: list, ei: int) -> bool:
        """Return True if the elseif at token index ei has an open if to continue.

        Scan backwards from ei. Track block depth (going backwards):
          end/until  → b_depth++
          opener kw  → b_depth--; if -1: found enclosing block
        If the enclosing block is 'if', the elseif is valid (returns True).
        If it's a non-if opener (for/while/function/do/repeat) or nothing, returns False.
        """
        b_depth = 0
        for k in range(ei - 1, -1, -1):
            _, kw = toks[k]
            if kw in ("end", "until"):
                b_depth += 1
            elif kw in OPENERS:
                b_depth -= 1
                if b_depth == -1:
                    return kw == "if"
        return False  # no enclosing block found → broken

    MAX_PASSES = 15
    for _ in range(MAX_PASSES):
        toks = _tokenize(code)
        removals: set[tuple[int, int]] = set()  # (pos, kw_len)

        for ti, (pos, kw) in enumerate(toks):
            if kw != "else":
                continue
            # Scan forward to find the 'end' that closes this else's if-block
            depth = 0
            end_pos: int | None = None
            end_ti: int | None = None
            for j in range(ti + 1, len(toks)):
                jpos, jkw = toks[j]
                if jkw in OPENERS:
                    depth += 1
                elif jkw in ("end", "until"):
                    if depth == 0:
                        end_pos = jpos
                        end_ti = j
                        break
                    depth -= 1
            if end_pos is None:
                continue
            # Check if this end is immediately followed by elseif
            after = code[end_pos + 3:].lstrip("; \t\r\n")
            if not re.match(r"elseif\b", after):
                continue
            # Find the elseif token index that follows end_ti
            elseif_ti: int | None = None
            for j in range(end_ti + 1, len(toks)):
                if toks[j][1] == "elseif":
                    elseif_ti = j
                    break
            if elseif_ti is None:
                continue
            # Verify: scanning backwards from elseif, is there NO open if?
            # If _elseif_has_open_if returns False → truly broken → remove
            if not _elseif_has_open_if(toks, elseif_ti):
                removals.add((pos, 4))       # remove 'else'
                removals.add((end_pos, 3))   # remove 'end'

        if not removals:
            break
        for pos, kw_len in sorted(removals, key=lambda x: -x[0]):
            code = code[:pos] + code[pos + kw_len:]

    return code


def _fix_control_structure_too_long(code: str) -> str:
    """Fix Lua 'control structure too long near end' for large obfuscated scripts.

    Lua's bytecode limits jump offsets to ~131 071 instructions. Large obfuscated
    VM scripts (WeAreDevs, Luraph, IronBrew, etc.) use a giant state-machine
    dispatch loop with hundreds of if/elseif branches that exceed this limit.

    Strategy: find the indent level with the most elseif lines, locate the
    if/end boundaries of that chain, then split it into groups of at most
    SPLIT_SIZE branches. Each group after the first is wrapped in:

        if not <flag> then
            if <cond> then ...
            elseif ...
            end
        end

    A shared boolean flag ensures that once a branch fires the remaining groups
    are skipped, preserving the original semantics exactly.
    The function loops until no chain exceeds SPLIT_SIZE.
    """
    SPLIT_SIZE = 80
    MAX_PASSES = 10

    for _pass in range(MAX_PASSES):
        lines = code.splitlines()
        n = len(lines)

        # ── Find indent level with the most elseif lines ──────────────────
        by_indent: dict[str, list[int]] = {}
        for i, line in enumerate(lines):
            m = re.match(r'^(\s*)elseif\b', line)
            if m:
                by_indent.setdefault(m.group(1), []).append(i)

        if not by_indent:
            break

        ind = max(by_indent, key=lambda k: len(by_indent[k]))
        elseif_idxs = by_indent[ind]

        if len(elseif_idxs) <= SPLIT_SIZE:
            break

        ind_len = len(ind)

        # ── Find the 'if' that opens this chain ───────────────────────────
        if_idx = None
        for i in range(elseif_idxs[0] - 1, -1, -1):
            if re.match(r'^' + re.escape(ind) + r'if\b', lines[i]):
                if_idx = i
                break
        if if_idx is None:
            break

        # ── Find the 'end' that closes this chain ─────────────────────────
        end_idx = None
        depth = 0
        for i in range(if_idx + 1, n):
            raw = lines[i]
            cur_len = len(raw) - len(raw.lstrip())
            stripped = raw.strip()
            if cur_len > ind_len:
                if re.match(r'(?:if\b.*\bthen|for\b.*\bdo|while\b.*\bdo|repeat\b|function\b)\s*(?:--.*)?$', stripped):
                    depth += 1
                elif re.match(r'do\s*(?:--.*)?$', stripped):
                    depth += 1
                elif re.match(r'(?:end|until)\b', stripped):
                    depth = max(0, depth - 1)
            elif cur_len == ind_len and depth == 0:
                if re.match(r'^' + re.escape(ind) + r'end\b', raw):
                    end_idx = i
                    break
        if end_idx is None:
            break

        # ── Build split points (every SPLIT_SIZE-th elseif) ───────────────
        split_set: set[int] = set()
        for k in range(SPLIT_SIZE, len(elseif_idxs), SPLIT_SIZE):
            split_set.add(elseif_idxs[k])
        num_splits = len(split_set)

        flag = f"_c_done_{if_idx}"

        hdr_re = re.compile(
            r'^' + re.escape(ind) + r'(?:if|elseif)\b.*\bthen\b\s*(?:--.*)?$'
        )

        # ── Rebuild with splits ────────────────────────────────────────────
        result: list[str] = []
        i = 0
        while i < n:
            raw = lines[i]

            if i == if_idx:
                result.append(f"{ind}local {flag} = false")
                result.append(raw)
                result.append(f"{ind}    {flag} = true")
                i += 1
                continue

            if i in split_set:
                result.append(f"{ind}end")
                result.append(f"{ind}if not {flag} then")
                new_hdr = re.sub(r'^(\s*)elseif\b', r'\1if', raw)
                result.append(new_hdr)
                result.append(f"{ind}    {flag} = true")
                i += 1
                continue

            if i == end_idx:
                result.append(raw)
                for _ in range(num_splits):
                    result.append(f"{ind}end")
                i += 1
                continue

            # Insert flag=true after every other header in the chain
            if (if_idx < i < end_idx
                    and i not in split_set
                    and hdr_re.match(raw)):
                result.append(raw)
                result.append(f"{ind}    {flag} = true")
                i += 1
                continue

            result.append(raw)
            i += 1

        code = "\n".join(result)

    return code


def _run_heuristic_fix_pipeline(code: str) -> str:
    code = _fix_lua_compat(code)
    code = _fix_wearedevs_compat(code)
    code = _fix_else_end_elseif(code)
    code = _fix_for_missing_do(code)
    code = _fix_local_missing_assign(code)
    code = _fix_connect_end_parens(code)
    code = _fix_extra_ends(code)
    code = _fix_lua_do_end(code)
    code = _remove_useless_do_blocks(code)
    code = _dedup_connections(code)
    code = _fix_ui_variable_shadowing(code)
    code = _smart_rename_variables(code)
    code = _fold_string_concat(code)
    code = _collapse_loop_unrolls(code)
    code = _beautify_lua(code)
    code = _collapse_blank_lines(code)
    code = _remove_trailing_whitespace(code)
    return code


# ---------------- COMMAND .bf ----------------
@bot.command(name="bf")
async def beautify(ctx, *, link=None):

    remaining = _check_rate_limit(ctx.author.id)
    if remaining > 0:
        log.info("Rate limited user=%s cmd=%s remaining=%.1fs", ctx.author, ctx.command, remaining)
        try:
            await ctx.send(f"slow down, wait {remaining:.1f}s")
        except discord.errors.DiscordServerError:
            pass
        return

    try:
        status = await _send_with_retry(lambda: ctx.send("beautifying"))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send status message: {e}")
        return

    content, original_filename, err = await _get_content(ctx, link)
    if err:
        await status.edit(content=err)
        return

    log.info(".bf user=%s guild=%s file=%s", ctx.author, ctx.guild.id if ctx.guild else "DM", original_filename)
    lua_text = content.decode("utf-8", errors="ignore")

    loop = asyncio.get_event_loop()
    beautified = await loop.run_in_executor(
        _executor,
        functools.partial(_beautify_lua, lua_text)
    )

    paste, raw = await loop.run_in_executor(
        _executor,
        functools.partial(upload_to_pastefy, beautified, title=f"[BF] {original_filename}")
    )

    try:
        await status.delete()
    except discord.errors.HTTPException as e:
        print(f"Warning: failed to delete status message: {e}")

    log.info(".bf done user=%s file=%s paste=%s", ctx.author, original_filename, raw or "none")
    msg_content = "beautified"
    if raw:
        msg_content += f" | {raw}"

    try:
        await _send_with_retry(lambda: ctx.send(
            content=msg_content,
            file=discord.File(
                io.BytesIO(beautified.encode("utf-8")),
                filename=os.path.splitext(original_filename)[0] + "_bf.lua"
            )
        ))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send beautified result: {e}")
        try:
            await status.edit(content=f"Discord error, please retry: {e}")
        except discord.errors.HTTPException:
            pass

# ---------------- COMMAND .darklua ----------------

_DARKLUA_TRANSFORM_ORDER = [
    "strip_comments",
    "fix_syntax",
    "rename_vars",
    "fold_strings",
    "inline_constants",
    "beautify",
]

_DARKLUA_OPTIONS = [
    discord.SelectOption(
        label="Remove Comments",
        value="strip_comments",
        description="Remove all Lua comments from the code",
    ),
    discord.SelectOption(
        label="Rename Variables",
        value="rename_vars",
        description="Intelligently rename Instance.new() variables",
    ),
    discord.SelectOption(
        label="Fold String Concatenations",
        value="fold_strings",
        description='Collapse "a" .. "b" into "ab"',
    ),
    discord.SelectOption(
        label="Inline Single-Use Constants",
        value="inline_constants",
        description="Inline constants that are referenced only once",
    ),
    discord.SelectOption(
        label="Beautify / Reformat",
        value="beautify",
        description="Normalize indentation and formatting",
    ),
    discord.SelectOption(
        label="Fix Syntax Errors",
        value="fix_syntax",
        description="Apply heuristic Lua syntax repair pipeline",
    ),
]


class _DarkluaView(discord.ui.View):

    def __init__(self, code: str, filename: str, author_id: int):
        super().__init__(timeout=120)
        self.code = code
        self.filename = filename
        self.author_id = author_id
        self.selected: list[str] = []
        self.message = None

    async def on_timeout(self):
        for child in self.children:
            child.disabled = True
        if self.message:
            try:
                await self.message.edit(view=self)
            except discord.errors.HTTPException:
                pass

    @discord.ui.select(
        placeholder="Choose transformations…",
        min_values=1,
        max_values=len(_DARKLUA_OPTIONS),
        options=_DARKLUA_OPTIONS,
    )
    async def select_transforms(
        self,
        interaction: discord.Interaction,
        select: discord.ui.Select,
    ):
        if interaction.user.id != self.author_id:
            await interaction.response.send_message(
                "Only the command author can use this menu.", ephemeral=True
            )
            return
        self.selected = select.values
        await interaction.response.defer()

    @discord.ui.button(label="Apply", style=discord.ButtonStyle.primary)
    async def apply_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ):
        if interaction.user.id != self.author_id:
            await interaction.response.send_message(
                "Only the command author can use this menu.", ephemeral=True
            )
            return
        if not self.selected:
            await interaction.response.send_message(
                "Please select at least one transformation first.", ephemeral=True
            )
            return

        for child in self.children:
            child.disabled = True
        await interaction.response.edit_message(content="processing…", view=self)
        self.stop()

        code = self.code
        loop = asyncio.get_event_loop()
        selected_set = set(self.selected)

        for key in _DARKLUA_TRANSFORM_ORDER:
            if key not in selected_set:
                continue
            if key == "strip_comments":
                code = _strip_comments(code)
            elif key == "fix_syntax":
                code = await loop.run_in_executor(
                    _executor, functools.partial(_run_heuristic_fix_pipeline, code)
                )
            elif key == "rename_vars":
                code = await loop.run_in_executor(
                    _executor, functools.partial(_smart_rename_variables, code)
                )
            elif key == "fold_strings":
                code = _fold_string_concat(code)
            elif key == "inline_constants":
                code = _inline_single_use_constants(code)
            elif key == "beautify":
                code = await loop.run_in_executor(
                    _executor, functools.partial(_beautify_lua, code)
                )

        paste, raw = await loop.run_in_executor(
            _executor,
            functools.partial(
                upload_to_pastefy, code, title=f"[darklua] {self.filename}"
            ),
        )

        labels = ", ".join(
            o.label for o in _DARKLUA_OPTIONS if o.value in selected_set
        )
        log.info(".darklua applied [%s] user=%s file=%s paste=%s",
                 labels, interaction.user, self.filename, raw or "none")
        out_filename = os.path.splitext(self.filename)[0] + "_darklua.lua"

        embed = discord.Embed(
            title="darklua",
            description=(
                f"Applied: **{labels}**\n"
                + (f"Paste: {raw}" if raw else "Paste upload failed")
            ),
            color=0x5865F2,
        )
        embed.set_footer(text="🐱")

        try:
            await interaction.followup.send(
                embed=embed,
                file=discord.File(
                    io.BytesIO(code.encode("utf-8")),
                    filename=out_filename,
                ),
            )
        except discord.errors.DiscordServerError as e:
            print(f"Warning: failed to send darklua result: {e}")
            try:
                await interaction.followup.send(
                    content=f"Discord error, please retry: {e}"
                )
            except discord.errors.HTTPException:
                pass


@bot.command(name="darklua")
async def darklua_cmd(ctx, *, link=None):

    remaining = _check_rate_limit(ctx.author.id)
    if remaining > 0:
        log.info("Rate limited user=%s cmd=%s remaining=%.1fs", ctx.author, ctx.command, remaining)
        try:
            await ctx.send(f"slow down, wait {remaining:.1f}s")
        except discord.errors.DiscordServerError:
            pass
        return

    try:
        status = await _send_with_retry(lambda: ctx.send("downloading"))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send status message: {e}")
        return

    content, filename, err = await _get_content(ctx, link)
    if err:
        try:
            await status.edit(content=err)
        except discord.errors.HTTPException:
            pass
        return

    lua_text = content.decode("utf-8", errors="ignore")
    log.info(".darklua user=%s guild=%s file=%s size=%d", ctx.author,
             ctx.guild.id if ctx.guild else "DM", filename, len(lua_text))

    view = _DarkluaView(lua_text, filename, ctx.author.id)

    try:
        await status.delete()
    except discord.errors.HTTPException as e:
        print(f"Warning: failed to delete status message: {e}")

    embed = discord.Embed(
        title="darklua",
        description=(
            f"File: **{filename}**  •  {len(lua_text):,} chars\n\n"
            "Select the transformations to apply, then click **Apply**."
        ),
        color=0x5865F2,
    )
    embed.set_footer(text="🐱 • Expires in 2 minutes")

    try:
        msg = await _send_with_retry(lambda: ctx.send(embed=embed, view=view))
        view.message = msg
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send darklua menu: {e}")


# ---------------- COMMAND GET ----------------
@bot.command(name="get")
async def get_link_content(ctx, *, link=None):

    try:
        status = await _send_with_retry(lambda: ctx.send("downloading"))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send status message: {e}")
        return

    try:
        # SSRF check for user-supplied URL
        if link:
            url = extract_first_url(link) or link
            safe, reason = _is_safe_url(url)
            if not safe:
                log.warning(".get SSRF blocked user=%s url=%s reason=%s", ctx.author, url, reason)
                await status.edit(content=f"Blocked URL: {reason}")
                return

        log.info(".get user=%s guild=%s link=%s", ctx.author,
                 ctx.guild.id if ctx.guild else "DM", link or "(attachment/reply)")
        content, filename, err = await _get_content(ctx, link)
        if err:
            await status.edit(content=err)
            return

        if _is_html(content):
            await status.edit(content="HTML detected, extracting obfuscated code...")
            extracted = _extract_obfuscated_from_html(content)
            if extracted:
                content = extracted
                filename = os.path.splitext(filename)[0] + "_extracted.txt"
            else:
                filename = os.path.splitext(filename)[0] + "_raw.html"
        else:
            if not filename.endswith(".txt"):
                filename = os.path.splitext(filename)[0] + ".txt"

        await status.delete()

        source_label = link if link else "from reply"
        await _send_with_retry(lambda: ctx.send(
            content=source_label,
            file=discord.File(io.BytesIO(content), filename=filename)
        ))

    except discord.errors.DiscordServerError as e:
        print(f"Warning: Discord server error in get command: {e}")
        try:
            await status.edit(content=f"Discord error, please retry: {e}")
        except discord.errors.HTTPException:
            pass
    except Exception as e:
        try:
            await status.edit(content=f"{e}")
        except discord.errors.HTTPException:
            pass

# ---------------- START ----------------
_args = sys.argv[1:]

if "-" in _args:
    _lua_input = sys.stdin.read()
    sys.stdout.write(_run_heuristic_fix_pipeline(_lua_input))
    sys.exit(0)

if not TOKEN:
    print("BOT_TOKEN missing")
    exit()

bot.run(TOKEN)
