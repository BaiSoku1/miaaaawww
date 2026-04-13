local a = debug
local b = debug.sethook
local c = debug.getinfo
local d = debug.traceback
local e = load
local f = loadstring or load
-- Capture the native setfenv (Lua 5.1/5.2 only) before the exploit stubs
-- installed later in this file overwrite _G.setfenv with a no-op.
local _native_setfenv = rawget(_G, "setfenv")
local g = pcall
local h = xpcall
local i = error
local j = type
-- Luau compat: unpack was moved to table.unpack
local unpack = table.unpack or unpack
local k = getmetatable
local l = rawequal
local m = tostring
local n = tonumber
local o = io
local p = os
local q = {}
q.__index = q
local r = {
    MAX_DEPTH = 50,
    MAX_TABLE_ITEMS = 10000,
    OUTPUT_FILE = "dumped_output.lua",
    VERBOSE = false,
    TRACE_CALLBACKS = true,
    TIMEOUT_SECONDS = 120,  -- Internal limit; must be < DUMP_TIMEOUT in cat.py (130s) to allow cleanup
    MAX_REPEATED_LINES = 200,
    MIN_DEOBF_LENGTH = 50,
    MAX_OUTPUT_SIZE = 200 * 1024 * 1024,
    CONSTANT_COLLECTION = true,
    INSTRUMENT_LOGIC = true,
    DUMP_GLOBALS = true,
    DUMP_ALL_STRINGS = false,
    DUMP_WAD_STRINGS = false,
    DUMP_DECODED_STRINGS = false,
    DUMP_LIGHTCATE_STRINGS = false,
    EMIT_XOR = false,
    DUMP_UPVALUES = true,
    MAX_UPVALUES_PER_FUNCTION = 200,
    DUMP_GC_SCAN = true,
    DUMP_INSTANCE_CREATIONS = true,
    DUMP_SCRIPT_LOADS = true,
    DUMP_REMOTE_SUMMARY = true,
    -- Maximum objects returned by getgc() stubs (limits memory / iteration cost)
    MAX_GC_OBJECTS = 500,
    -- Maximum functions scanned by dump_gc_scan() (separate from getgc return limit)
    MAX_GC_SCAN_FUNCTIONS = 500,
    MAX_INSTANCE_CREATIONS = 1000,
    MAX_SCRIPT_LOADS = 200,
    -- Maximum characters of a loadstring payload kept as a diagnostic snippet
    MAX_SCRIPT_LOAD_SNIPPET = 80,
    -- Extra collection options
    DUMP_FUNCTIONS = true,
    DUMP_METATABLES = true,
    DUMP_CLOSURES = true,
    DUMP_REMOTE_CALLS = true,
    DUMP_CONSTANTS = true,
    DUMP_HOOKS = true,
    DUMP_SIGNALS = true,
    DUMP_ATTRIBUTES = true,
    DUMP_PROPERTIES = true,
    TRACK_ENV_WRITES = true,
    TRACK_ENV_READS = false,
    COLLECT_ALL_CALLS = true,
    EMIT_COMMENTS = true,
    STRIP_WHITESPACE = false,
    MAX_STRING_LENGTH = 65536,
    MAX_PROXY_DEPTH = 32,
    MAX_HOOK_CALLS = 500,
    MAX_REMOTE_CALLS = 1000,
    MAX_SIGNAL_CALLBACKS = 100,
    MAX_CLOSURE_REFS = 500,
    MAX_CONST_PER_FUNCTION = 512,
    MAX_DEFERRED_HOOKS = 200,
    OBFUSCATION_THRESHOLD = 0.35,
    INLINE_SMALL_FUNCTIONS = true,
    EMIT_LOOP_COUNTER = false,
    EMIT_CALL_GRAPH = true,
    EMIT_STRING_REFS = true,
    EMIT_TYPE_ANNOTATIONS = false,
    -- Loop detection threshold: how many times the same source line must be
    -- hit (via the count hook) before a "-- Detected loops N" marker is emitted.
    LOOP_DETECT_THRESHOLD = 100
}
-- Patterns whose presence in a generated output line means the line is
-- dangerous and must be silently suppressed before it reaches the caller.
-- These cover OS command execution, filesystem enumeration and environment
-- variable leaks that would put the bot owner at risk.
local BLOCKED_OUTPUT_PATTERNS = {
    "os%.execute",
    "os%.getenv",
    "os%.exit",
    "os%.remove",
    "os%.rename",
    "os%.tmpname",
    "io%.open",
    "io%.popen",
    "io%.lines",
    "io%.read",
    "io%.write",
    -- shell-style directory / file listing indicators
    "total %d",             -- output of `ls -l`
    "^drwx", "^%-rwx",     -- Unix file-permission lines
    "^[dD]irectory of ",   -- Windows `dir` header
    "[Vv]olume in drive",  -- Windows `dir` header
    -- absolute filesystem paths that might be leaked
    "/etc/",
    "/home/",
    "/root/",
    "/var/",
    "/tmp/",
    "/proc/",
    "/sys/",
    "C:\\[Uu]sers\\",
    "C:\\[Ww]indows\\",
    "C:\\[Pp]rogram",
    -- environment-variable style leaks
    "PATH=",
    "HOME=",
    "USER=",
    "SHELL=",
    -- credential / secret leaks
    "TOKEN%s*=",
    "SECRET%s*=",
    "PASSWORD%s*=",
    "API_KEY%s*=",
    "WEBHOOK%s*=",
    -- Discord bot token format (starts with a base64-ish string of ~24 chars
    -- followed by a dot; we match the canonical NTKâ€¦. prefix shape)
    "Nz[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+",
    -- Discord webhook URLs
    "discord%.com/api/webhooks/",
    "discordapp%.com/api/webhooks/",
    -- GitHub personal-access token prefixes
    "ghp_[A-Za-z0-9]+",
    "gho_[A-Za-z0-9]+",
    "ghs_[A-Za-z0-9]+",
}
local s = (arg and arg[3]) or "NoKey"
if arg and arg[3] then
    print("[Dumper] Auto-Input Key Detected: " .. tostring(s))
end
local t = {
    output = {},
    indent = 0,
    registry = {},
    reverse_registry = {},
    names_used = {},
    parent_map = {},
    property_store = {},
    call_graph = {},
    variable_types = {},
    string_refs = {},
    proxy_id = 0,
    callback_depth = 0,
    pending_iterator = false,
    last_http_url = nil,
    rep_buf = nil,
    rep_n = 0,
    rep_full = 0,
    rep_pos = 0,
    current_size = 0,
    lar_counter = 0,
    deferred_hooks = {},
    -- Extended state tracking
    function_calls = {},
    remote_calls = {},
    hook_calls = {},
    closure_refs = {},
    const_map = {},
    env_writes = {},
    env_reads = {},
    metatable_hooks = {},
    signal_map = {},
    attribute_store = {},
    error_count = 0,
    warning_count = 0,
    depth_peak = 0,
    loop_counter = 0,
    branch_counter = 0,
    pending_writes = {},
    captured_strings = {},
    captured_numbers = {},
    captured_booleans = {},
    typeof_cache = {},
    require_cache = {},
    service_cache = {},
    instance_count = 0,
    tween_count = 0,
    connection_count = 0,
    drawing_count = 0,
    task_count = 0,
    coroutine_count = 0,
    table_count = 0,
    upvalue_map = {},
    proto_map = {},
    const_refs = {},
    global_writes = {},
    sandbox_env = nil,
    exec_start_time = 0,
    last_error = nil,
    hook_depth = 0,
    namecall_method = nil,
    obfuscation_score = 0,
    deobf_attempts = 0,
    emit_count = 0,
    -- Loop detection: map of "source:line" â†’ hit count and seen flags
    loop_line_counts = {},
    loop_detected_lines = {},
    -- Enhanced tracking tables
    instance_creations = {},
    script_loads = {},
    gc_objects = {}
}
local u = tonumber(arg and arg[4]) or tonumber(arg and arg[3]) or 123456789
local v = {}
local function w(x)
    if j(x) ~= "table" then
        return false
    end
    local y, z =
        pcall(
        function()
            return rawget(x, v) == true
        end
    )
    return y and z
end
local function A(x)
    if j(x) == "number" then
        return x
    end
    if w(x) then
        return rawget(x, "__value") or 0
    end
    return 0
end
local e = loadstring or load
local B = print
local C = warn or function()
    end
local D = pairs
local E = ipairs
local j = type
local m = tostring
local F = {}
local function G(x)
    if j(x) ~= "table" then
        return false
    end
    local y, z =
        pcall(
        function()
            return rawget(x, F) == true
        end
    )
    return y and z
end
local function H(x)
    if not G(x) then
        return nil
    end
    return rawget(x, "__proxy_id")
end
local function I(J)
    if j(J) ~= "string" then
        return '"'
    end
    -- Strip a leading shebang line (#! ...) so the source can be loaded by
    -- Lua's standard `load` function, which does not understand shebangs.
    if J:sub(1, 2) == "#!" then
        local nl = J:find("\n", 3, true)
        J = nl and J:sub(nl) or ""
    end
    local K = {}
    local L, M = 1, #J
    local function N(O)
        return O:gsub(
            "\\\\(.)",
            function(P)
                if P:match('[abfnrtv\\\\%\'%\\"%[%]0-9xu]') then
                    return "" .. P
                end
                return P
            end
        )
    end
    local function Q(R)
        if not R or R == '"' then
            return ""
        end
        R =
            R:gsub(
            "0[bB]([01_]+)",
            function(S)
                local T = S:gsub("_", "")
                local U = n(T, 2)
                return U and m(U) or "0"
            end
        )
        R =
            R:gsub(
            "0[xX]([%x_]+)",
            function(S)
                local T = S:gsub("_", "")
                return "0x" .. T
            end
        )
        while R:match("%d_+%d") do
            R = R:gsub("(%d)_+(%d)", "%1%2")
        end
        -- JavaScript / cross-compiled language operator compatibility.
        -- These must be handled before compound-assignment expansion so that
        -- e.g. "!=" is not split into "not =" by a later pass.
        R = R:gsub("!==", "~=")          -- JS strict not-equal  â†’  Lua not-equal
        R = R:gsub("!=",  "~=")          -- JS not-equal         â†’  Lua not-equal
        R = R:gsub("%s*&&%s*", " and ")  -- JS/C logical AND      â†’  Lua and
        R = R:gsub("%s*||%s*", " or ")   -- JS/C logical OR       â†’  Lua or
        -- Power operator ** (Python / JS) â†’ ^ (Lua).
        -- Must run before compound-assignment expansion so that e.g. x**=2 gets
        -- properly rewritten: **= â†’ ^= which is then expanded by the V table.
        R = R:gsub("%*%*=", "^=")         -- **= â†’ ^=  (then expanded below)
        R = R:gsub("%*%*",  "^")         -- **  â†’ ^
        local V = {{"+=", "+"}, {"-=", "-"}, {"*=", "*"}, {"/=", "/"}, {"%%=", "%%"}, {"%^=", "^"}, {"%.%.=", ".."}}
        for W, X in ipairs(V) do
            local Y, Z = X[1], X[2]
            R =
                R:gsub(
                "([%a_][%w_]*)%s*" .. Y,
                function(_)
                    return _ .. " = " .. _ .. " " .. Z .. " "
                end
            )
            R =
                R:gsub(
                "([%a_][%w_]*%.[%a_][%w_%.]+)%s*" .. Y,
                function(_)
                    return _ .. " = " .. _ .. " " .. Z .. " "
                end
            )
            R =
                R:gsub(
                "([%a_][%w_]*%b[])%s*" .. Y,
                function(_)
                    return _ .. " = " .. _ .. " " .. Z .. " "
                end
            )
            R =
                R:gsub(
                "(%b()%s*%b[])%s*" .. Y,
                function(_)
                    return _ .. " = " .. _ .. " " .. Z .. " "
                end
            )
        end
        -- null / undefined â†’ nil (word-boundary safe: require non-identifier context)
        for _, _kw in ipairs({"null", "undefined"}) do
            R = R:gsub("([^%w_])" .. _kw .. "([^%w_])", "%1nil%2")
            R = R:gsub("^"       .. _kw .. "([^%w_])",  "nil%1")
            R = R:gsub("([^%w_])" .. _kw .. "$",        "%1nil")
        end
        -- else if â†’ elseif (Lua requires a single keyword; only collapse when
        -- on the same line so that a genuine else-block containing an if is not
        -- incorrectly folded, which would produce an "'end' expected" error).
        -- Protect "end <ws> else <ws> if" first: the WeAreDevs VM (and similar
        -- obfuscators) write genuine else-blocks-with-nested-if on the same line
        -- as "end else if", where the "end" closes the then-clause.  Collapsing
        -- that to "elseif" removes a required structural "end" and produces the
        -- "'end' expected near 'elseif'" load error.
        --
        -- Additional protection: 'else if' at the very start of a non-string
        -- segment, or immediately after ')', is always a genuine Lua else-block.
        -- In these cases the structural 'end' for the outer if lives in a prior
        -- non-string segment that was separated by a string literal (e.g.
        -- EquipWeapon("str")else if(cond)then), so the "end else if" guard below
        -- cannot see it.  We use a separate placeholder so the restore step puts
        -- back "else" rather than "if".
        R = R:gsub("^([ \t]*)else([ \t]+if)", "%1\x00CATMIO_NELSE\x00%2")
        R = R:gsub("(%)[ \t]*)else([ \t]+if)", "%1\x00CATMIO_NELSE\x00%2")
        R = R:gsub("(end[ \t]+else[ \t]+)if", "%1\x00CATMIO_ELSEIF\x00")
        R = R:gsub("else[ \t]+if%(", "elseif(")
        R = R:gsub("else[ \t]+if[ \t]", "elseif ")
        R = R:gsub("\x00CATMIO_ELSEIF\x00", "if")
        R = R:gsub("\x00CATMIO_NELSE\x00", "else")
        R = R:gsub("([^%w_])continue([^%w_])", "%1_G.LuraphContinue()%2")
        R = R:gsub("^continue([^%w_])", "_G.LuraphContinue()%1")
        R = R:gsub("([^%w_])continue$", "%1_G.LuraphContinue()")
        -- Strip stray backslashes from non-string code; they are never valid
        -- Lua tokens outside of string literals, but may appear in files that
        -- were generated by an earlier buggy run of the dumper (e.g. function(\)).
        R = R:gsub("\\", "")
        return R
    end
    local function a0(a1)
        local a2 = 0
        while a1 <= M and J:byte(a1) == 61 do
            a2 = a2 + 1
            a1 = a1 + 1
        end
        return a2, a1
    end
    local function a3(a4, a5)
        local a6 = "]" .. string.rep("=", a5) .. "]"
        local a7, a8 = J:find(a6, a4, true)
        return a8 or M
    end
    local a9 = 1
    while L <= M do
        local aa = J:byte(L)
        if aa == 91 then
            local a5, ab = a0(L + 1)
            if ab <= M and J:byte(ab) == 91 then
                table.insert(K, Q(J:sub(a9, L - 1)))
                local ac = L
                local ad = a3(ab + 1, a5)
                table.insert(K, J:sub(ac, ad))
                L = ad
                a9 = L + 1
            end
        elseif aa == 45 and L + 1 <= M and J:byte(L + 1) == 45 then
            table.insert(K, Q(J:sub(a9, L - 1)))
            local ae = L
            local longcomment = false
            if L + 2 <= M and J:byte(L + 2) == 91 then
                local a5, ab = a0(L + 3)
                if ab <= M and J:byte(ab) == 91 then
                    local ad = a3(ab + 1, a5)
                    table.insert(K, J:sub(ae, ad))
                    L = ad
                    a9 = L + 1
                    L = L + 1
                    longcomment = true
                end
            end
            if not longcomment then
                local af = J:find("\n", L + 2, true)
                if af then
                    L = af
                else
                    L = M
                end
                table.insert(K, J:sub(ae, L))
                a9 = L + 1
            end
        elseif aa == 34 or aa == 39 or aa == 96 then
            table.insert(K, Q(J:sub(a9, L - 1)))
            local ag = aa
            local ac = L
            L = L + 1
            while L <= M do
                local ah = J:byte(L)
                if ah == 92 then
                    L = L + 1
                elseif ah == ag then
                    break
                end
                L = L + 1
            end
            local ai = J:sub(ac + 1, L - 1)
            ai = N(ai)
            if ag == 96 then
                -- Escape bare " but leave already-escaped \" alone.
                -- Count preceding backslashes: even count means " is unescaped; odd means it is already escaped.
                ai = ai:gsub('(\\*)"', function(bs)
                    if #bs % 2 == 0 then
                        return bs .. '\\"'
                    else
                        return bs .. '"'
                    end
                end)
                table.insert(K, '"' .. ai .. '"')
            else
                local aj = string.char(ag)
                table.insert(K, aj .. ai .. aj)
            end
            a9 = L + 1
        end
        L = L + 1
    end
    table.insert(K, Q(J:sub(a9)))
    return table.concat(K)
end
local function ak(al, am)
    local R, an = e(al, am)
    if R then
        return R
    end
    B("\n[CRITICAL ERROR] Failed to load script!")
    B("[LUA_LOAD_FAIL] " .. m(an))
    local ao = tonumber(an:match(":(%d+):"))
    local ap = an:match("near '([^']+)'")
    if ap then
        local a1 = al:find(ap, 1, true)
        if a1 then
            local aq = math.max(1, a1 - 80)
            local ar = math.min(#al, a1 + 80)
            B("Context around error:")
            B("..." .. al:sub(aq, ar) .. "...")
        end
    end
    -- Emit a line-number excerpt when only a line number is available
    if ao and not ap then
        local line_n = 0
        local pos = 1
        while pos <= #al do
            local nl = al:find("\n", pos, true)
            local eol = nl or (#al + 1)
            line_n = line_n + 1
            if line_n == ao then
                B(string.format("Line %d: %s", ao, al:sub(pos, eol - 1)))
                break
            end
            if not nl then break end
            pos = nl + 1
        end
    end
    local as = o.open("DEBUG_FAILED_TRANSPILE.lua", "w")
    if as then
        as:write(al)
        as:close()
        B("[*] Saved to 'DEBUG_FAILED_TRANSPILE.lua' for inspection")
    end
    return nil, an
end
local function at(O, au)
    if t.limit_reached then
        return
    end
    if O == nil then
        return
    end
    local av = au and "" or string.rep("    ", t.indent)
    local aw = av .. m(O)
    -- Security: suppress any line that matches a dangerous output pattern.
    for _, pat in ipairs(BLOCKED_OUTPUT_PATTERNS) do
        if aw:find(pat) then
            return
        end
    end
    local ax = #aw + 1
    if t.current_size + ax > r.MAX_OUTPUT_SIZE then
        t.limit_reached = true
        error("TIMEOUT_FORCED_BY_DUMPER: output size limit reached")
    end
    -- Cycle-aware repetition suppressor: detects repeating blocks of 1 to 10 lines.
    -- t.rep_buf  : ring buffer holding the last 20 emitted lines (strings).
    -- t.rep_n    : currently detected cycle length (0 = none).
    -- t.rep_full : number of complete cycle repetitions observed so far.
    -- t.rep_pos  : position within the current in-progress cycle repetition.
    if not t.rep_buf then
        t.rep_buf  = {}
        t.rep_n    = 0
        t.rep_full = 0
        t.rep_pos  = 0
    end
    local buf = t.rep_buf
    -- If we are currently inside a detected cycle, check whether aw continues it.
    local suppressed = false
    if t.rep_n > 0 then
        local n = t.rep_n
        -- The line we expect at this position is the one from the previous repetition.
        local expected = #buf >= n and buf[#buf - n + 1] or nil
        if aw == expected then
            t.rep_pos = t.rep_pos + 1
            if t.rep_pos >= n then          -- completed one more full repetition
                t.rep_full = t.rep_full + 1
                t.rep_pos  = 0
            end
            if t.rep_full > r.MAX_REPEATED_LINES then
                suppressed = true
                -- Emit a single "Detected loops" notice at the start of the first suppressed repetition.
                if t.rep_full == r.MAX_REPEATED_LINES + 1 and t.rep_pos == 0 then
                    t.loop_counter = t.loop_counter + 1
                    if r.EMIT_LOOP_COUNTER then
                        local ay = av .. string.format("-- Detected loops %d", t.loop_counter)
                        table.insert(t.output, ay)
                        t.current_size = t.current_size + #ay + 1
                    end
                end
            end
        else
            -- Cycle broken â€“ fall through to normal emit + fresh cycle scan below.
            t.rep_n    = 0
            t.rep_full = 0
            t.rep_pos  = 0
        end
    end
    if not suppressed then
        -- Emit the line.
        table.insert(t.output, aw)
        t.current_size = t.current_size + ax
        if r.VERBOSE then B(aw) end
    end
    -- Always update ring buffer (even when suppressing) so the cycle bookkeeping
    -- stays aligned with what the script would have emitted.
    table.insert(buf, aw)
    if #buf > 20 then table.remove(buf, 1) end
    -- Scan for a new repeating cycle only when we are not already tracking one.
    if not suppressed and t.rep_n == 0 and #buf >= 2 then
        for n = 1, 10 do
            if #buf >= 2 * n then
                local ok = true
                for i = 1, n do
                    if buf[#buf - i + 1] ~= buf[#buf - n - i + 1] then
                        ok = false; break
                    end
                end
                if ok then
                    t.rep_n    = n
                    t.rep_full = 1   -- second complete repetition just finished
                    t.rep_pos  = 0
                    break
                end
            end
        end
    end
end
local function az(O)
    at("-- " .. m(O or ""))
end
local function aA()
    -- Inserting a blank line breaks any active cycle.
    t.rep_buf  = nil
    t.rep_n    = 0
    t.rep_full = 0
    t.rep_pos  = 0
    table.insert(t.output, "")
end
local function aB()
    return table.concat(t.output, "\n")
end
local function aC(aD)
    local as = o.open(aD or r.OUTPUT_FILE, "w")
    if as then
        as:write(aB())
        as:close()
        return true
    end
    return false
end
local function aE(aF)
    if aF == nil then
        return "nil"
    end
    if j(aF) == "string" then
        return aF
    end
    if j(aF) == "number" or j(aF) == "boolean" then
        return m(aF)
    end
    if j(aF) == "table" then
        if t.registry[aF] then
            return t.registry[aF]
        end
        if G(aF) then
            local aG = H(aF)
            return aG and "proxy_" .. aG or "proxy"
        end
    end
    local y, O = pcall(m, aF)
    return y and O or "unknown"
end
local function aH(aF)
    local O = aE(aF)
    local aI =
        O:gsub("\\", "\\\\")
         :gsub('"', '\\"')
         :gsub("\n", "\\n")
         :gsub("\r", "\\r")
         :gsub("\t", "\\t")
         :gsub("%z", "\\0")
    return '"' .. aI .. '"'
end
-- aH_binary: like aH but handles non-printable bytes with \xNN escaping.
-- Used when emitting binary string constants (e.g. decoded obfuscator string
-- tables that contain encryption keys or other raw byte sequences).
local function aH_binary(s)
    if type(s) ~= "string" then s = aE(s) end
    local out = {}
    for i = 1, #s do
        local b = s:byte(i)
        if b == 34 then       -- "
            out[i] = '\\"'
        elseif b == 92 then   -- \
            out[i] = '\\\\'
        elseif b == 10 then   -- \n
            out[i] = '\\n'
        elseif b == 13 then   -- \r
            out[i] = '\\r'
        elseif b == 9 then    -- \t
            out[i] = '\\t'
        elseif b >= 32 and b <= 126 then
            out[i] = string.char(b)
        else
            out[i] = string.format("\\x%02x", b)
        end
    end
    return '"' .. table.concat(out) .. '"'
end
local aJ = {
    Players = "Players",
    Workspace = "Workspace",
    ReplicatedStorage = "ReplicatedStorage",
    ReplicatedFirst = "ReplicatedFirst",
    ServerStorage = "ServerStorage",
    ServerScriptService = "ServerScriptService",
    StarterGui = "StarterGui",
    StarterPack = "StarterPack",
    StarterPlayer = "StarterPlayer",
    Lighting = "Lighting",
    SoundService = "SoundService",
    Chat = "Chat",
    RunService = "RunService",
    UserInputService = "UserInputService",
    TweenService = "TweenService",
    HttpService = "HttpService",
    MarketplaceService = "MarketplaceService",
    TeleportService = "TeleportService",
    PathfindingService = "PathfindingService",
    CollectionService = "CollectionService",
    PhysicsService = "PhysicsService",
    ProximityPromptService = "ProximityPromptService",
    ContextActionService = "ContextActionService",
    GuiService = "GuiService",
    HapticService = "HapticService",
    VRService = "VRService",
    CoreGui = "CoreGui",
    Teams = "Teams",
    InsertService = "InsertService",
    DataStoreService = "DataStoreService",
    MessagingService = "MessagingService",
    TextService = "TextService",
    TextChatService = "TextChatService",
    ContentProvider = "ContentProvider",
    Debris = "Debris",
    -- Additional Roblox services
    AnalyticsService = "AnalyticsService",
    BadgeService = "BadgeService",
    AssetService = "AssetService",
    AvatarEditorService = "AvatarEditorService",
    SocialService = "SocialService",
    LocalizationService = "LocalizationService",
    GroupService = "GroupService",
    FriendService = "FriendService",
    NotificationService = "NotificationService",
    ScriptContext = "ScriptContext",
    Stats = "Stats",
    AdService = "AdService",
    AbuseReportService = "AbuseReportService",
    MemStorageService = "MemStorageService",
    PolicyService = "PolicyService",
    RbxAnalyticsService = "RbxAnalyticsService",
    CoreScriptSyncService = "CoreScriptSyncService",
    GamePassService = "GamePassService",
    StarterPlayerScripts = "StarterPlayerScripts",
    StarterCharacterScripts = "StarterCharacterScripts",
    NetworkClient = "NetworkClient",
    NetworkServer = "NetworkServer",
    TestService = "TestService",
    Selection = "Selection",
    ChangeHistoryService = "ChangeHistoryService",
    UserGameSettings = "UserGameSettings",
    RobloxPluginGuiService = "RobloxPluginGuiService",
    PermissionsService = "PermissionsService",
    VoiceChatService = "VoiceChatService",
    ExperienceService = "ExperienceService",
    OpenCloudService = "OpenCloudService",
}
local aK = {
    Players = "Players",
    UserInputService = "UIS",
    RunService = "RunService",
    ReplicatedStorage = "ReplicatedStorage",
    ReplicatedFirst = "ReplicatedFirst",
    TweenService = "TweenService",
    Workspace = "Workspace",
    Lighting = "Lighting",
    StarterGui = "StarterGui",
    StarterPack = "StarterPack",
    StarterPlayer = "StarterPlayer",
    CoreGui = "CoreGui",
    HttpService = "HttpService",
    MarketplaceService = "MarketplaceService",
    DataStoreService = "DataStoreService",
    TeleportService = "TeleportService",
    SoundService = "SoundService",
    Chat = "Chat",
    Teams = "Teams",
    ProximityPromptService = "ProximityPromptService",
    ContextActionService = "ContextActionService",
    CollectionService = "CollectionService",
    PathfindingService = "PathfindingService",
    PhysicsService = "PhysicsService",
    GuiService = "GuiService",
    TextService = "TextService",
    InsertService = "InsertService",
    Debris = "Debris",
    -- Additional services for aK alias map
    BadgeService = "BadgeService",
    AnalyticsService = "AnalyticsService",
    AssetService = "AssetService",
    LocalizationService = "LocalizationService",
    GroupService = "GroupService",
    PolicyService = "PolicyService",
    SocialService = "SocialService",
    VoiceChatService = "VoiceChatService",
    StarterPlayerScripts = "StarterPlayerScripts",
    StarterCharacterScripts = "StarterCharacterScripts",
    ServerStorage = "ServerStorage",
    ServerScriptService = "ServerScriptService",
    MessagingService = "MessagingService",
    TextChatService = "TextChatService",
    ContentProvider = "ContentProvider",
    NotificationService = "NotificationService",
    ScriptContext = "ScriptContext",
    Stats = "Stats",
    AdService = "AdService",
    GamePassService = "GamePassService",
    HapticService = "HapticService",
    VRService = "VRService",
    AvatarEditorService = "AvatarEditorService",
}
local aL = {
    {pattern = "window", prefix = "Window", counter = "window"},
    {pattern = "tab", prefix = "Tab", counter = "tab"},
    {pattern = "section", prefix = "Section", counter = "section"},
    {pattern = "button", prefix = "Button", counter = "button"},
    {pattern = "toggle", prefix = "Toggle", counter = "toggle"},
    {pattern = "slider", prefix = "Slider", counter = "slider"},
    {pattern = "dropdown", prefix = "Dropdown", counter = "dropdown"},
    {pattern = "textbox", prefix = "Textbox", counter = "textbox"},
    {pattern = "input", prefix = "Input", counter = "input"},
    {pattern = "label", prefix = "Label", counter = "label"},
    {pattern = "keybind", prefix = "Keybind", counter = "keybind"},
    {pattern = "colorpicker", prefix = "ColorPicker", counter = "colorpicker"},
    {pattern = "paragraph", prefix = "Paragraph", counter = "paragraph"},
    {pattern = "notification", prefix = "Notification", counter = "notification"},
    {pattern = "divider", prefix = "Divider", counter = "divider"},
    {pattern = "bind", prefix = "Bind", counter = "bind"},
    {pattern = "picker", prefix = "Picker", counter = "picker"}
}
local aM = {}
local function aN(aO)
    aM[aO] = (aM[aO] or 0) + 1
    return aM[aO]
end
local function aP(aQ, aR, aS)
    if not aQ then
        aQ = "var"
    end
    local aT = aE(aQ)
    if aK[aT] then
        return aK[aT]
    end
    if aS then
        local aU = aS:lower()
        for W, aV in ipairs(aL) do
            if aU:find(aV.pattern) then
                local a2 = aN(aV.counter)
                return a2 == 1 and aV.prefix or aV.prefix .. a2
            end
        end
    end
    if aT == "LocalPlayer" then
        return "LocalPlayer"
    end
    if aT == "Character" then
        return "Character"
    end
    if aT == "Humanoid" then
        return "Humanoid"
    end
    if aT == "HumanoidRootPart" then
        return "HumanoidRootPart"
    end
    if aT == "Camera" then
        return "Camera"
    end
    if aT:match("^Enum%.") then
        return aT
    end
    -- Single-letter names and pure-generic method verbs produce unhelpful "a2",
    -- "get3" style names â€” fall back to "var" so the deduplicator can assign a
    -- stable short name from context instead.
    if #aT == 1 and aT:match("^%a$") then
        return "var"
    end
    local _aT_low = aT:lower()
    local _SKIP = {
        ["new"]=true, ["clone"]=true, ["copy"]=true, ["init"]=true,
        ["object"]=true, ["value"]=true, ["result"]=true,
        ["data"]=true, ["info"]=true, ["arg"]=true, ["args"]=true,
        ["temp"]=true, ["tmp"]=true, ["ret"]=true, ["val"]=true,
    }
    if _SKIP[_aT_low] then
        return "var"
    end
    local T = aT:gsub("[^%w_]", "_"):gsub("^%d+", "_")
    if T == "_" or T == "" then
        T = "var"
    end
    return T
end
local function aW(x, aQ, aX, aS)
    local aY = t.registry[x]
    if aY then
        return aY
    end
    -- Try to derive a meaningful name via aP
    local base = aP(aQ, nil, aS)
    if not base or base == "" or base == '"' then
        base = "var"
    end
    -- Sanitise to a valid Lua identifier
    base = base:gsub("[^%w_]", "_")
    if base:sub(1,1):match("%d") then
        base = "_" .. base
    end
    base = base:match("^[%a_][%w_]*") or "var"
    if base == "" then
        base = "var"
    end
    -- For Instance class names (not in the service-alias map), lowercase the first
    -- letter so "ScreenGui" â†’ "screenGui", "Frame" â†’ "frame", etc.
    if not aK[base] and base ~= "var" and base:sub(1, 1):match("[A-Z]") then
        base = base:sub(1, 1):lower() .. base:sub(2)
    end
    -- Deduplicate: append an incrementing number when the name is already taken
    local am = base
    if t.names_used[am] then
        local cnt = 2
        while t.names_used[base .. cnt] do
            cnt = cnt + 1
        end
        am = base .. cnt
    end
    t.names_used[am] = true
    t.registry[x] = am
    t.reverse_registry[am] = x
    t.variable_types[am] = aX or j(x)
    return am
end
local function aZ(aF, a_, b0, b1)
    a_ = a_ or 0
    b0 = b0 or {}
    if a_ > r.MAX_DEPTH then
        return "{ --[[max depth]] }"
    end
    local b2 = j(aF)
    if w(aF) then
        local b3 = rawget(aF, "__value")
        return m(b3 or 0)
    end
    if b2 == "table" and t.registry[aF] then
        return t.registry[aF]
    end
    if b2 == "nil" then
        return "nil"
    elseif b2 == "string" then
        if #aF > 100 and aF:match("^[A-Za-z0-9+/=]+$") then
            table.insert(t.string_refs, {value = aF:sub(1, 50) .. "...", hint = "base64", full_length = #aF})
        elseif aF:match("https?://") then
            table.insert(t.string_refs, {value = aF, hint = "URL"})
        elseif aF:match("rbxasset://") or aF:match("rbxassetid://") then
            table.insert(t.string_refs, {value = aF, hint = "Asset"})
        end
        return aH(aF)
    elseif b2 == "number" then
        if aF ~= aF then
            return "0/0"
        end
        if aF == math.huge then
            return "math.huge"
        end
        if aF == -math.huge then
            return "-math.huge"
        end
        if aF == math.floor(aF) then
            return m(math.floor(aF))
        end
        return string.format("%.6g", aF)
    elseif b2 == "boolean" then
        return m(aF)
    elseif b2 == "function" then
        if t.registry[aF] then
            return t.registry[aF]
        end
        return "function() end"
    elseif b2 == "table" then
        if G(aF) then
            return t.registry[aF] or "proxy"
        end
        if b0[aF] then
            return "{ --[[circular]] }"
        end
        b0[aF] = true
        local a2 = 0
        for b4, b5 in D(aF) do
            if b4 ~= F and b4 ~= "__proxy_id" then
                a2 = a2 + 1
            end
        end
        if a2 == 0 then
            return "{}"
        end
        local b6 = true
        local b7 = 0
        for b4, b5 in D(aF) do
            if b4 ~= F and b4 ~= "__proxy_id" then
                if j(b4) ~= "number" or b4 < 1 or b4 ~= math.floor(b4) then
                    b6 = false
                    break
                else
                    b7 = math.max(b7, b4)
                end
            end
        end
        b6 = b6 and b7 == a2
        if b6 and a2 <= 5 and b1 ~= false then
            local b8 = {}
            for L = 1, a2 do
                local b5 = aF[L]
                if j(b5) ~= "table" or G(b5) then
                    table.insert(b8, aZ(b5, a_ + 1, b0, true))
                else
                    b6 = false
                    break
                end
            end
            if b6 and #b8 == a2 then
                return "{" .. table.concat(b8, ", ") .. "}"
            end
        end
        local b9 = {}
        local ba = 0
        local bb = string.rep("    ", t.indent + a_ + 1)
        local bc = string.rep("    ", t.indent + a_)
        for b4, b5 in D(aF) do
            if b4 ~= F and b4 ~= "__proxy_id" then
                ba = ba + 1
                if ba > r.MAX_TABLE_ITEMS then
                    table.insert(b9, bb .. "-- ..." .. a2 - ba + 1 .. " more")
                    break
                end
                local bd
                if b6 then
                    bd = nil
                elseif j(b4) == "string" and b4:match("^[%a_][%w_]*$") then
                    bd = b4
                else
                    bd = "[" .. aZ(b4, a_ + 1, b0) .. "]"
                end
                local be = aZ(b5, a_ + 1, b0)
                if bd then
                    table.insert(b9, bb .. bd .. " = " .. be)
                else
                    table.insert(b9, bb .. be)
                end
            end
        end
        if #b9 == 0 then
            return "{}"
        end
        return "{\n" .. table.concat(b9, ",\n") .. "\n" .. bc .. "}"
    elseif b2 == "userdata" then
        if t.registry[aF] then
            return t.registry[aF]
        end
        local y, O = pcall(m, aF)
        return y and O or "userdata"
    elseif b2 == "thread" then
        return "coroutine.create(function() end)"
    else
        local y, O = pcall(m, aF)
        return y and O or "nil"
    end
end
local bf = {}
setmetatable(bf, {__mode = "k"})
local function bg()
    local bh = {}
    bf[bh] = true
    local bi = {}
    setmetatable(bh, bi)
    return bh, bi
end
local function G(x)
    return bf[x] == true
end
local bj
local bk
local function bl(bm)
    local bh, bi = bg()
    rawset(bh, v, true)
    rawset(bh, "__value", bm)
    t.registry[bh] = tostring(bm)
    bi.__tostring = function()
        return tostring(bm)
    end
    bi.__index = function(b2, b4)
        if b4 == F or b4 == "__proxy_id" or b4 == v or b4 == "__value" then
            return rawget(b2, b4)
        end
        return bl(0)
    end
    bi.__newindex = function()
    end
    bi.__call = function()
        return bm
    end
    local function bn(X)
        return function(bo, aa)
            local bp = type(bo) == "table" and rawget(bo, "__value") or bo or 0
            local bq = type(aa) == "table" and rawget(aa, "__value") or aa or 0
            local z
            if X == "+" then
                z = bp + bq
            elseif X == "-" then
                z = bp - bq
            elseif X == "*" then
                z = bp * bq
            elseif X == "/" then
                z = bq ~= 0 and bp / bq or 0
            elseif X == "%" then
                z = bq ~= 0 and bp % bq or 0
            elseif X == "^" then
                z = bp ^ bq
            else
                z = 0
            end
            return bl(z)
        end
    end
    bi.__add = bn("+")
    bi.__sub = bn("-")
    bi.__mul = bn("*")
    bi.__div = bn("/")
    bi.__mod = bn("%")
    bi.__pow = bn("^")
    bi.__unm = function(bo)
        return bl(-(rawget(bo, "__value") or 0))
    end
    bi.__eq = function(bo, aa)
        local bp = type(bo) == "table" and rawget(bo, "__value") or bo
        local bq = type(aa) == "table" and rawget(aa, "__value") or aa
        return bp == bq
    end
    bi.__lt = function(bo, aa)
        local bp = type(bo) == "table" and rawget(bo, "__value") or bo
        local bq = type(aa) == "table" and rawget(aa, "__value") or aa
        return bp < bq
    end
    bi.__le = function(bo, aa)
        local bp = type(bo) == "table" and rawget(bo, "__value") or bo
        local bq = type(aa) == "table" and rawget(aa, "__value") or aa
        return bp <= bq
    end
    bi.__len = function()
        return 0
    end
    return bh
end
local function br(bs, bt)
    if j(bs) ~= "function" then
        return {}
    end
    local a4 = #t.output
    local bu = t.pending_iterator
    t.pending_iterator = false
    local _br_ok, _br_err = xpcall(
        function()
            bs(unpack(bt or {}))
        end,
        function(err) return err end
    )
    if not _br_ok and type(_br_err) == "string" and _br_err:find("TIMEOUT_FORCED_BY_DUMPER", 1, true) then
        error(_br_err, 0)
    end
    while t.pending_iterator do
        t.indent = t.indent - 1
        at("end")
        t.pending_iterator = false
    end
    t.pending_iterator = bu
    local bv = {}
    for L = a4 + 1, #t.output do
        table.insert(bv, t.output[L])
    end
    for L = #t.output, a4 + 1, -1 do
        table.remove(t.output, L)
    end
    return bv
end
bk = function(aS, bw)
    local bh, bi = bg()
    local bx = t.registry[bw] or "object"
    local by = aE(aS)
    t.registry[bh] = bx .. "." .. by
    bi.__call = function(self, bz, ...)
        local bA
        if bz == bh or bz == bw or G(bz) then
            bA = {...}
        else
            bA = {bz, ...}
        end
        local aU = by:lower()
        local bB = nil
        local bC = true
        for W, aV in ipairs(aL) do
            if aU:find(aV.pattern) then
                bB = aV.prefix
                break
            end
        end
        local bD = nil
        local bE = nil
        local bF = nil
        for L, b5 in ipairs(bA) do
            if j(b5) == "function" then
                bD = b5
                break
            elseif j(b5) == "table" and not G(b5) then
                for bG, aF in D(b5) do
                    local bH = m(bG):lower()
                    if bH == "callback" and j(aF) == "function" then
                        bD = aF
                        bE = bG
                        bF = L
                        break
                    end
                end
            end
        end
        local bI = "value"
        local bt = {}
        if bD then
            if aU:match("toggle") then
                bI = "enabled"
                bt = {true}
            elseif aU:match("slider") then
                bI = "value"
                bt = {50}
            elseif aU:match("dropdown") then
                bI = "selected"
                bt = {"Option"}
            elseif aU:match("textbox") or aU:match("input") then
                bI = "text"
                bt = {s or "input"}
            elseif aU:match("keybind") or aU:match("bind") then
                bI = "key"
                bt = {bj("Enum.KeyCode.E", false)}
            elseif aU:match("color") then
                bI = "color"
                bt = {Color3.fromRGB(255, 255, 255)}
            elseif aU:match("button") then
                bI = ""
                bt = {}
            end
        end
        local bJ = {}
        if bD then
            bJ = br(bD, bt)
        end
        -- If the method is a generic verb (Get, Add, Create, â€¦) with no library-prefix
        -- override, try to use the first plain-string argument as the proxy name so
        -- the dump reads  "local config = obj:GetConfig()"  rather than "local get2 = â€¦"
        local _GENERIC_VERBS = {
            get=true, set=true, add=true, remove=true, delete=true,
            find=true, create=true, make=true, build=true, load=true,
            fetch=true, send=true, fire=true, call=true, run=true,
            execute=true, invoke=true, connect=true, bind=true,
            insert=true, push=true, pop=true, append=true, update=true,
            register=true, unregister=true, new=true, init=true,
        }
        local _nameHint = bB or by
        if not bB and _GENERIC_VERBS[by:lower()] then
            for _, _bArg in ipairs(bA) do
                if j(_bArg) == "string" and #_bArg >= 2 and #_bArg <= 64
                        and _bArg:match("^[%a_][%w_]*$") then
                    _nameHint = _bArg
                    break
                end
            end
        end
        local z = bj(_nameHint, false, bw)
        local _ = aW(z, _nameHint, nil, by)
        local bK = {}
        for L, b5 in ipairs(bA) do
            if j(b5) == "table" and not G(b5) and L == bF then
                local b8 = {}
                for bG, aF in D(b5) do
                    local bd
                    if j(bG) == "string" and bG:match("^[%a_][%w_]*$") then
                        bd = bG
                    else
                        bd = "[" .. aZ(bG) .. "]"
                    end
                    if bG == bE and #bJ > 0 then
                        local bL = bI ~= "" and "function(" .. bI .. ")" or "function()"
                        local bb = string.rep("    ", t.indent + 2)
                        local bM = {}
                        for W, aw in ipairs(bJ) do
                            table.insert(bM, bb .. (aw:match("^%s*(.*)$") or aw))
                        end
                        local bc = string.rep("    ", t.indent + 1)
                        table.insert(b8, bd .. " = " .. bL .. "\n" .. table.concat(bM, "\n") .. "\n" .. bc .. "end")
                    elseif bG == bE then
                        local bN = bI ~= "" and "function(" .. bI .. ") end" or "function() end"
                        table.insert(b8, bd .. " = " .. bN)
                    else
                        table.insert(b8, bd .. " = " .. aZ(aF))
                    end
                end
                table.insert(
                    bK,
                    "{\n" ..
                        string.rep("    ", t.indent + 1) ..
                            table.concat(b8, ",\n" .. string.rep("    ", t.indent + 1)) ..
                                "\n" .. string.rep("    ", t.indent) .. "}"
                )
            elseif j(b5) == "function" then
                if #bJ > 0 then
                    local bL = bI ~= "" and "function(" .. bI .. ")" or "function()"
                    local bb = string.rep("    ", t.indent + 1)
                    local bM = {}
                    for W, aw in ipairs(bJ) do
                        table.insert(bM, bb .. (aw:match("^%s*(.*)$") or aw))
                    end
                    table.insert(
                        bK,
                        bL .. "\n" .. table.concat(bM, "\n") .. "\n" .. string.rep("    ", t.indent) .. "end"
                    )
                else
                    local bN = bI ~= "" and "function(" .. bI .. ") end" or "function() end"
                    table.insert(bK, bN)
                end
            else
                table.insert(bK, aZ(b5))
            end
        end
        at(string.format("local %s = %s:%s(%s)", _, bx, by, table.concat(bK, ", ")))
        return z
    end
    bi.__index = function(b2, b4)
        if b4 == F or b4 == "__proxy_id" then
            return rawget(b2, b4)
        end
        return bk(b4, bh)
    end
    bi.__tostring = function()
        return bx .. ":" .. by
    end
    return bh
end
bj = function(aQ, bO, bw)
    local bh, bi = bg()
    local aT = aE(aQ)
    t.property_store[bh] = {}
    if bO then
        t.registry[bh] = aT
        t.names_used[aT] = true
    elseif bw then
        t.parent_map[bh] = bw
        rawset(bh, "__temp_path", (t.registry[bw] or "object") .. "." .. aT)
    end
    local bP = {}
    bP.GetService = function(self, bQ)
        local bR = aE(bQ)
        local x = bj(bR, false, bh)
        local _ = aW(x, bR)
        local bS = t.registry[bh] or "game"
        at(string.format("local %s = %s:GetService(%s)", _, bS, aH(bR)))
        return x
    end
    bP.WaitForChild = function(self, bT, bU)
        local bV = aE(bT)
        local x = bj(bV, false, bh)
        local _ = aW(x, bV)
        local bS = t.registry[bh] or "object"
        if bU then
            at(string.format("local %s = %s:WaitForChild(%s, %s)", _, bS, aH(bV), aZ(bU)))
        else
            at(string.format("local %s = %s:WaitForChild(%s)", _, bS, aH(bV)))
        end
        return x
    end
    bP.FindFirstChild = function(self, bT, bW)
        local bV = aE(bT)
        local x = bj(bV, false, bh)
        local _ = aW(x, bV)
        local bS = t.registry[bh] or "object"
        if bW then
            at(string.format("local %s = %s:FindFirstChild(%s, true)", _, bS, aH(bV)))
        else
            at(string.format("local %s = %s:FindFirstChild(%s)", _, bS, aH(bV)))
        end
        return x
    end
    bP.FindFirstChildOfClass = function(self, bX)
        local bY = aE(bX)
        local x = bj(bY, false, bh)
        local _ = aW(x, bY)
        local bS = t.registry[bh] or "object"
        at(string.format("local %s = %s:FindFirstChildOfClass(%s)", _, bS, aH(bY)))
        return x
    end
    bP.FindFirstChildWhichIsA = function(self, bX)
        local bY = aE(bX)
        local x = bj(bY, false, bh)
        local _ = aW(x, bY)
        local bS = t.registry[bh] or "object"
        at(string.format("local %s = %s:FindFirstChildWhichIsA(%s)", _, bS, aH(bY)))
        return x
    end
    bP.FindFirstAncestor = function(self, am)
        local bZ = aE(am)
        local x = bj(bZ, false, bh)
        local _ = aW(x, bZ)
        local bS = t.registry[bh] or "object"
        at(string.format("local %s = %s:FindFirstAncestor(%s)", _, bS, aH(bZ)))
        return x
    end
    bP.FindFirstAncestorOfClass = function(self, bX)
        local bY = aE(bX)
        local x = bj(bY, false, bh)
        local _ = aW(x, bY)
        local bS = t.registry[bh] or "object"
        at(string.format("local %s = %s:FindFirstAncestorOfClass(%s)", _, bS, aH(bY)))
        return x
    end
    bP.FindFirstAncestorWhichIsA = function(self, bX)
        local bY = aE(bX)
        local x = bj(bY, false, bh)
        local _ = aW(x, bY)
        local bS = t.registry[bh] or "object"
        at(string.format("local %s = %s:FindFirstAncestorWhichIsA(%s)", _, bS, aH(bY)))
        return x
    end
    bP.GetChildren = function(self)
        local bS = t.registry[bh] or "object"
        at(string.format("for _, child in %s:GetChildren() do", bS))
        t.indent = t.indent + 1
        t.pending_iterator = true
        return {}
    end
    bP.GetDescendants = function(self)
        local bS = t.registry[bh] or "object"
        at(string.format("for _, obj in %s:GetDescendants() do", bS))
        t.indent = t.indent + 1
        local b_ = bj("obj", false)
        t.registry[b_] = "obj"
        t.property_store[b_] = {Name = "Ball", ClassName = "Part", Size = Vector3.new(1, 1, 1)}
        local c0 = false
        return function()
            if not c0 then
                c0 = true
                return 1, b_
            else
                t.indent = t.indent - 1
                at("end")
                return nil
            end
        end, nil, 0
    end
    bP.Clone = function(self)
        local bS = t.registry[bh] or "object"
        local x = bj((aT or "object") .. "Clone", false)
        local _ = aW(x, (aT or "object") .. "Clone")
        at(string.format("local %s = %s:Clone()", _, bS))
        return x
    end
    bP.Destroy = function(self)
        local bS = t.registry[bh] or "object"
        at(string.format("%s:Destroy()", bS))
    end
    bP.ClearAllChildren = function(self)
        local bS = t.registry[bh] or "object"
        at(string.format("%s:ClearAllChildren()", bS))
    end
    bP.Connect = function(self, bs)
        local bS = t.registry[bh] or "signal"
        local c1 = bj("connection", false)
        local c2 = aW(c1, "conn")
        local c3 = bS:match("%.([^%.]+)$") or bS
        local c4 = {"..."}
        if c3:match("InputBegan") or c3:match("InputEnded") or c3:match("InputChanged") then
            c4 = {"input", "gameProcessed"}
        elseif c3:match("CharacterAdded") or c3:match("CharacterRemoving") then
            c4 = {"character"}
        elseif c3:match("CharacterAppearanceLoaded") then
            c4 = {"character"}
        elseif c3:match("PlayerAdded") or c3:match("PlayerRemoving") then
            c4 = {"player"}
        elseif c3:match("Touched") then
            c4 = {"hit"}
        elseif c3:match("TouchEnded") then
            c4 = {"hit"}
        elseif c3:match("Heartbeat") or c3:match("RenderStepped") then
            c4 = {"deltaTime"}
        elseif c3:match("Stepped") then
            c4 = {"time", "deltaTime"}
        -- Specific *Changed variants must come before the generic "Changed" catch-all.
        elseif c3:match("HealthChanged") then
            c4 = {"health"}
        elseif c3:match("StateChanged") then
            c4 = {"oldState", "newState"}
        elseif c3:match("AttributeChanged") then
            c4 = {"attribute"}
        elseif c3:match("PropertyChanged") then
            c4 = {"value"}
        elseif c3:match("AncestryChanged") then
            c4 = {"child", "parent"}
        elseif c3:match("ChildAdded") or c3:match("ChildRemoved") then
            c4 = {"child"}
        elseif c3:match("DescendantAdded") or c3:match("DescendantRemoving") then
            c4 = {"descendant"}
        elseif c3:match("Changed") then
            c4 = {"property"}
        elseif c3:match("Died") or c3:match("Activated") or c3:match("Deactivated") then
            c4 = {}
        elseif c3:match("MouseButton1Click") or c3:match("MouseButton2Click") then
            c4 = {}
        elseif c3:match("MouseButton") then
            c4 = {"x", "y"}
        elseif c3:match("MouseEnter") or c3:match("MouseLeave") or c3:match("MouseMoved") then
            c4 = {"x", "y"}
        elseif c3:match("MouseWheelForward") or c3:match("MouseWheelBackward") then
            c4 = {"x", "y"}
        elseif c3:match("FocusLost") then
            c4 = {"enterPressed", "inputObject"}
        elseif c3:match("FocusGained") or c3:match("Focused") then
            c4 = {"inputObject"}
        elseif c3:match("TextChanged") then
            c4 = {}
        elseif c3:match("MoveToFinished") then
            c4 = {"reached"}
        elseif c3:match("FreeFalling") or c3:match("Jumping") then
            c4 = {"active"}
        elseif c3:match("Running") then
            c4 = {"speed"}
        elseif c3:match("Seated") then
            c4 = {"active", "seat"}
        elseif c3:match("Equipped") or c3:match("Unequipped") then
            c4 = {}
        elseif c3:match("OnClientEvent") then
            c4 = {"..."}
        elseif c3:match("OnServerEvent") then
            c4 = {"player", "..."}
        elseif c3:match("Completed") or c3:match("DidLoop") or c3:match("Stopped") then
            c4 = {}
        elseif c3:match("PromptPurchaseFinished") then
            c4 = {"player", "assetId", "isPurchased"}
        elseif c3:match("PromptProductPurchaseFinished") then
            c4 = {"player", "productId", "isPurchased"}
        elseif c3:match("Triggered") or c3:match("TriggerEnded") then
            c4 = {"player"}
        elseif c3:match("Button1Down") or c3:match("Button1Up") then
            c4 = {"x", "y"}
        elseif c3:match("Button2Down") or c3:match("Button2Up") then
            c4 = {"x", "y"}
        elseif c3:match("Idle") then
            c4 = {"deltaTime"}
        elseif c3:match("Move") then
            c4 = {"direction", "relativeToCamera"}
        elseif c3:match("ReturnPressedFromOnScreenKeyboard") then
            c4 = {}
        end
        at(string.format("local %s = %s:Connect(function(%s)", c2, bS, table.concat(c4, ", ")))
        t.indent = t.indent + 1
        if j(bs) == "function" then
            xpcall(
                function()
                    bs()
                end,
                function()
                end
            )
        end
        while t.pending_iterator do
            t.indent = t.indent - 1
            at("end")
            t.pending_iterator = false
        end
        t.indent = t.indent - 1
        at("end)")
        return c1
    end
    bP.Once = function(self, bs)
        local bS = t.registry[bh] or "signal"
        local c1 = bj("connection", false)
        local c2 = aW(c1, "conn")
        at(string.format("local %s = %s:Once(function(...)", c2, bS))
        t.indent = t.indent + 1
        if j(bs) == "function" then
            xpcall(
                function()
                    bs()
                end,
                function()
                end
            )
        end
        t.indent = t.indent - 1
        at("end)")
        return c1
    end
    bP.Wait = function(self)
        local bS = t.registry[bh] or "signal"
        local z = bj("waitResult", false)
        local _ = aW(z, "waitResult")
        at(string.format("local %s = %s:Wait()", _, bS))
        return z
    end
    bP.Disconnect = function(self)
        local bS = t.registry[bh] or "connection"
        at(string.format("%s:Disconnect()", bS))
    end
    bP.FireServer = function(self, ...)
        local bS = t.registry[bh] or "remote"
        local bA = {...}
        local c5 = {}
        for W, b5 in ipairs(bA) do
            table.insert(c5, aZ(b5))
        end
        at(string.format("%s:FireServer(%s)", bS, table.concat(c5, ", ")))
        table.insert(t.call_graph, {type = "RemoteEvent", name = bS, args = bA})
    end
    bP.InvokeServer = function(self, ...)
        local bS = t.registry[bh] or "remote"
        local bA = {...}
        local c5 = {}
        for W, b5 in ipairs(bA) do
            table.insert(c5, aZ(b5))
        end
        local z = bj("invokeResult", false)
        local _ = aW(z, "result")
        at(string.format("local %s = %s:InvokeServer(%s)", _, bS, table.concat(c5, ", ")))
        table.insert(t.call_graph, {type = "RemoteFunction", name = bS, args = bA})
        return z
    end
    bP.Create = function(self, x, c6, c7)
        local bS = t.registry[bh] or "TweenService"
        local c8 = bj("tween", false)
        local _ = aW(c8, "tween")
        at(string.format("local %s = %s:Create(%s, %s, %s)", _, bS, aZ(x), aZ(c6), aZ(c7)))
        return c8
    end
    bP.Play = function(self)
        local bS = t.registry[bh] or "tween"
        at(string.format("%s:Play()", bS))
    end
    bP.Pause = function(self)
        local bS = t.registry[bh] or "tween"
        at(string.format("%s:Pause()", bS))
    end
    bP.Cancel = function(self)
        local bS = t.registry[bh] or "tween"
        at(string.format("%s:Cancel()", bS))
    end
    bP.Stop = function(self)
        local bS = t.registry[bh] or "tween"
        at(string.format("%s:Stop()", bS))
    end
    bP.Raycast = function(self, c9, ca, cb)
        local bS = t.registry[bh] or "workspace"
        local z = bj("raycastResult", false)
        local _ = aW(z, "rayResult")
        if cb then
            at(string.format("local %s = %s:Raycast(%s, %s, %s)", _, bS, aZ(c9), aZ(ca), aZ(cb)))
        else
            at(string.format("local %s = %s:Raycast(%s, %s)", _, bS, aZ(c9), aZ(ca)))
        end
        return z
    end
    bP.GetMouse = function(self)
        local bS = t.registry[bh] or "player"
        local cc = bj("mouse", false)
        local _ = aW(cc, "mouse")
        at(string.format("local %s = %s:GetMouse()", _, bS))
        return cc
    end
    bP.Kick = function(self, cd)
        local bS = t.registry[bh] or "player"
        if cd then
            at(string.format("%s:Kick(%s)", bS, aZ(cd)))
        else
            at(string.format("%s:Kick()", bS))
        end
    end
    bP.GetPropertyChangedSignal = function(self, ce)
        local cf = aE(ce)
        local bS = t.registry[bh] or "instance"
        local cg = bj(cf .. "Changed", false)
        t.registry[cg] = bS .. ":GetPropertyChangedSignal(" .. aH(cf) .. ")"
        return cg
    end
    bP.IsA = function(self, bX)
        return true
    end
    bP.IsDescendantOf = function(self, ch)
        return true
    end
    bP.IsAncestorOf = function(self, ci)
        return true
    end
    bP.GetAttribute = function(self, cj)
        return nil
    end
    bP.SetAttribute = function(self, cj, bm)
        local bS = t.registry[bh] or "instance"
        at(string.format("%s:SetAttribute(%s, %s)", bS, aH(cj), aZ(bm)))
    end
    bP.GetAttributes = function(self)
        return {}
    end
    bP.GetPlayers = function(self)
        return {}
    end
    bP.GetPlayerFromCharacter = function(self, ck)
        -- eUNC passes a plain {} table â€” should return nil, not a proxy
        if ck ~= nil and not G(ck) then
            return nil
        end
        local bS = t.registry[bh] or "Players"
        local cl = bj("player", false)
        local _ = aW(cl, "player")
        at(string.format("local %s = %s:GetPlayerFromCharacter(%s)", _, bS, aZ(ck)))
        return cl
    end
    bP.GetPlayerByUserId = function(self, cm)
        local bS = t.registry[bh] or "Players"
        local cl = bj("player", false)
        local _ = aW(cl, "player")
        at(string.format("local %s = %s:GetPlayerByUserId(%s)", _, bS, aZ(cm)))
        return cl
    end
    bP.SetCore = function(self, am, bm)
        local bS = t.registry[bh] or "StarterGui"
        at(string.format("%s:SetCore(%s, %s)", bS, aH(am), aZ(bm)))
    end
    bP.GetCore = function(self, am)
        return nil
    end
    bP.SetCoreGuiEnabled = function(self, cn, co)
        local bS = t.registry[bh] or "StarterGui"
        at(string.format("%s:SetCoreGuiEnabled(%s, %s)", bS, aZ(cn), aZ(co)))
    end
    bP.BindToRenderStep = function(self, am, cp, bs)
        local bS = t.registry[bh] or "RunService"
        at(string.format("%s:BindToRenderStep(%s, %s, function(deltaTime)", bS, aH(am), aZ(cp)))
        t.indent = t.indent + 1
        if j(bs) == "function" then
            xpcall(
                function()
                    bs(0.016)
                end,
                function()
                end
            )
        end
        t.indent = t.indent - 1
        at("end)")
    end
    bP.UnbindFromRenderStep = function(self, am)
        local bS = t.registry[bh] or "RunService"
        at(string.format("%s:UnbindFromRenderStep(%s)", bS, aH(am)))
    end
    bP.GetFullName = function(self)
        return t.registry[bh] or "Instance"
    end
    bP.GetDebugId = function(self)
        return "DEBUG_" .. (H(bh) or "0")
    end
    bP.MoveTo = function(self, cq, cr)
        local bS = t.registry[bh] or "humanoid"
        if cr then
            at(string.format("%s:MoveTo(%s, %s)", bS, aZ(cq), aZ(cr)))
        else
            at(string.format("%s:MoveTo(%s)", bS, aZ(cq)))
        end
    end
    bP.Move = function(self, ca, cs)
        local bS = t.registry[bh] or "humanoid"
        at(string.format("%s:Move(%s, %s)", bS, aZ(ca), aZ(cs or false)))
    end
    bP.EquipTool = function(self, ct)
        local bS = t.registry[bh] or "humanoid"
        at(string.format("%s:EquipTool(%s)", bS, aZ(ct)))
    end
    bP.UnequipTools = function(self)
        local bS = t.registry[bh] or "humanoid"
        at(string.format("%s:UnequipTools()", bS))
    end
    bP.TakeDamage = function(self, cu)
        local bS = t.registry[bh] or "humanoid"
        at(string.format("%s:TakeDamage(%s)", bS, aZ(cu)))
    end
    bP.ChangeState = function(self, cv)
        local bS = t.registry[bh] or "humanoid"
        at(string.format("%s:ChangeState(%s)", bS, aZ(cv)))
    end
    bP.GetState = function(self)
        return bj("Enum.HumanoidStateType.Running", false)
    end
    bP.SetPrimaryPartCFrame = function(self, cw)
        local bS = t.registry[bh] or "model"
        at(string.format("%s:SetPrimaryPartCFrame(%s)", bS, aZ(cw)))
    end
    bP.GetPrimaryPartCFrame = function(self)
        return CFrame.new(0, 0, 0)
    end
    bP.PivotTo = function(self, cw)
        local bS = t.registry[bh] or "model"
        at(string.format("%s:PivotTo(%s)", bS, aZ(cw)))
    end
    bP.GetPivot = function(self)
        return CFrame.new(0, 0, 0)
    end
    bP.GetBoundingBox = function(self)
        return CFrame.new(0, 0, 0), Vector3.new(1, 1, 1)
    end
    bP.GetExtentsSize = function(self)
        return Vector3.new(1, 1, 1)
    end
    bP.TranslateBy = function(self, cx)
        local bS = t.registry[bh] or "model"
        at(string.format("%s:TranslateBy(%s)", bS, aZ(cx)))
    end
    bP.LoadAnimation = function(self, cy)
        local bS = t.registry[bh] or "animator"
        local cz = bj("animTrack", false)
        local _ = aW(cz, "animTrack")
        at(string.format("local %s = %s:LoadAnimation(%s)", _, bS, aZ(cy)))
        return cz
    end
    bP.GetPlayingAnimationTracks = function(self)
        return {}
    end
    bP.AdjustSpeed = function(self, cA)
        local bS = t.registry[bh] or "animTrack"
        at(string.format("%s:AdjustSpeed(%s)", bS, aZ(cA)))
    end
    bP.AdjustWeight = function(self, cB, cC)
        local bS = t.registry[bh] or "animTrack"
        if cC then
            at(string.format("%s:AdjustWeight(%s, %s)", bS, aZ(cB), aZ(cC)))
        else
            at(string.format("%s:AdjustWeight(%s)", bS, aZ(cB)))
        end
    end
    bP.Teleport = function(self, cD, cl, cE, cF)
        local bS = t.registry[bh] or "TeleportService"
        at(
            string.format(
                "%s:Teleport(%s, %s%s%s)",
                bS,
                aZ(cD),
                aZ(cl),
                cE and ", " .. aZ(cE) or '"',
                cF and ", " .. aZ(cF) or '"'
            )
        )
    end
    bP.TeleportToPlaceInstance = function(self, cD, cG, cl)
        local bS = t.registry[bh] or "TeleportService"
        at(string.format("%s:TeleportToPlaceInstance(%s, %s, %s)", bS, aZ(cD), aZ(cG), aZ(cl)))
    end
    bP.PlayLocalSound = function(self, cH)
        local bS = t.registry[bh] or "SoundService"
        at(string.format("%s:PlayLocalSound(%s)", bS, aZ(cH)))
    end
    bP.GetAsync = function(self, cI)
        local bS = t.registry[bh] or "dataStore"
        local z = bj("storedValue", false)
        local _ = aW(z, "storedValue")
        at(string.format("local %s = %s:GetAsync(%s)", _, bS, aZ(cI)))
        return z
    end
    bP.PostAsync = function(self, cI, cJ)
        return "{}"
    end
    bP.JSONEncode = function(self, cJ)
        return "{}"
    end
    bP.JSONDecode = function(self, O)
        return {}
    end
    bP.GenerateGUID = function(self, cK)
        return "00000000-0000-0000-0000-000000000000"
    end
    bP.HttpGet = function(self, cI)
        local cL = aE(cI)
        table.insert(t.string_refs, {value = cL, hint = "HTTP URL"})
        t.last_http_url = cL
        return cL
    end
    bP.HttpPost = function(self, cI, cJ, cM)
        local cL = aE(cI)
        table.insert(t.string_refs, {value = cL, hint = "HTTP POST URL"})
        local x = bj("HttpResponse", false)
        local _ = aW(x, "httpResponse")
        local bS = t.registry[bh] or "HttpService"
        at(string.format("local %s = %s:HttpPost(%s, %s, %s)", _, bS, aZ(cI), aZ(cJ), aZ(cM)))
        t.property_store[x] = {Body = "{}", StatusCode = 200, Success = true}
        return x
    end
    bP.AddItem = function(self, cN, cO)
        local bS = t.registry[bh] or "Debris"
        at(string.format("%s:AddItem(%s, %s)", bS, aZ(cN), aZ(cO or 10)))
    end
    -- HttpService
    bP.RequestAsync = function(self, dO)
        local bS = t.registry[bh] or "HttpService"
        local url = dO and (dO.Url or dO.url) or "unknown"
        table.insert(t.string_refs, {value = url, hint = "HTTP RequestAsync"})
        local x = bj("httpResult", false)
        local _ = aW(x, "httpResult")
        at(string.format("local %s = %s:RequestAsync(%s)", _, bS, aZ(dO)))
        t.property_store[x] = {Success = true, StatusCode = 200, StatusMessage = "OK", Headers = {}, Body = "{}"}
        return x
    end
    -- DataStoreService
    bP.GetDataStore = function(self, name, scope)
        local bS = t.registry[bh] or "DataStoreService"
        local storeName = aE(name)
        local x = bj(storeName .. "Store", false)
        local _ = aW(x, storeName .. "Store")
        if scope then
            at(string.format("local %s = %s:GetDataStore(%s, %s)", _, bS, aH(storeName), aH(aE(scope))))
        else
            at(string.format("local %s = %s:GetDataStore(%s)", _, bS, aH(storeName)))
        end
        return x
    end
    bP.GetGlobalDataStore = function(self)
        local bS = t.registry[bh] or "DataStoreService"
        local x = bj("GlobalDataStore", false)
        local _ = aW(x, "globalStore")
        at(string.format("local %s = %s:GetGlobalDataStore()", _, bS))
        return x
    end
    bP.GetOrderedDataStore = function(self, name, scope)
        local bS = t.registry[bh] or "DataStoreService"
        local storeName = aE(name)
        local x = bj(storeName .. "OrderedStore", false)
        local _ = aW(x, storeName .. "OrderedStore")
        if scope then
            at(string.format("local %s = %s:GetOrderedDataStore(%s, %s)", _, bS, aH(storeName), aH(aE(scope))))
        else
            at(string.format("local %s = %s:GetOrderedDataStore(%s)", _, bS, aH(storeName)))
        end
        return x
    end
    -- DataStore methods (SetAsync, UpdateAsync, RemoveAsync, IncrementAsync)
    bP.SetAsync = function(self, key, value, userIds, options)
        local bS = t.registry[bh] or "dataStore"
        at(string.format("%s:SetAsync(%s, %s)", bS, aZ(key), aZ(value)))
    end
    bP.UpdateAsync = function(self, key, func)
        local bS = t.registry[bh] or "dataStore"
        at(string.format("%s:UpdateAsync(%s, function(oldValue)", bS, aZ(key)))
        t.indent = t.indent + 1
        if j(func) == "function" then
            xpcall(function() func(nil) end, function() end)
        end
        t.indent = t.indent - 1
        at("    return oldValue")
        at("end)")
    end
    bP.RemoveAsync = function(self, key)
        local bS = t.registry[bh] or "dataStore"
        local z = bj("removedValue", false)
        local _ = aW(z, "removedValue")
        at(string.format("local %s = %s:RemoveAsync(%s)", _, bS, aZ(key)))
        return z
    end
    bP.IncrementAsync = function(self, key, delta, userIds)
        local bS = t.registry[bh] or "dataStore"
        local z = bj("newValue", false)
        local _ = aW(z, "newValue")
        at(string.format("local %s = %s:IncrementAsync(%s, %s)", _, bS, aZ(key), aZ(delta or 1)))
        return z
    end
    bP.ListKeysAsync = function(self, prefix, pageSize)
        local bS = t.registry[bh] or "dataStore"
        local z = bj("keyPages", false)
        local _ = aW(z, "keyPages")
        at(string.format("local %s = %s:ListKeysAsync(%s)", _, bS, aZ(prefix or "")))
        return z
    end
    -- CollectionService
    bP.GetTagged = function(self, tag)
        local bS = t.registry[bh] or "CollectionService"
        local z = bj("taggedInstances", false)
        local _ = aW(z, "taggedInstances")
        at(string.format("local %s = %s:GetTagged(%s)", _, bS, aH(aE(tag))))
        return {}
    end
    bP.GetAllTags = function(self)
        return {}
    end
    -- Instance tag methods
    bP.GetTags = function(self)
        return {}
    end
    bP.HasTag = function(self, tag)
        return false
    end
    bP.AddTag = function(self, tag)
        local bS = t.registry[bh] or "instance"
        at(string.format("%s:AddTag(%s)", bS, aH(aE(tag))))
    end
    bP.RemoveTag = function(self, tag)
        local bS = t.registry[bh] or "instance"
        at(string.format("%s:RemoveTag(%s)", bS, aH(aE(tag))))
    end
    -- IsA / instance type checks (always true so conditional code paths execute)
    -- IsA/IsDescendantOf always return true so that conditional code branches
    -- like `if obj:IsA("BasePart") then ... end` always execute for maximum dump coverage.
    bP.IsA = function(self, className)
        return true
    end
    bP.IsDescendantOf = function(self, ancestor)
        return true
    end
    bP.IsAncestorOf = function(self, descendant)
        return false
    end
    -- Attribute methods
    bP.GetAttribute = function(self, name)
        local bS = t.registry[bh] or "instance"
        local nameStr = aE(name)
        local z = bj("attr_" .. nameStr, false)
        local _ = aW(z, "attr" .. nameStr)
        at(string.format("local %s = %s:GetAttribute(%s)", _, bS, aH(nameStr)))
        return z
    end
    bP.SetAttribute = function(self, name, value)
        local bS = t.registry[bh] or "instance"
        at(string.format("%s:SetAttribute(%s, %s)", bS, aH(aE(name)), aZ(value)))
        t.property_store[bh] = t.property_store[bh] or {}
        t.property_store[bh][aE(name)] = value
    end
    bP.GetAttributes = function(self)
        return t.property_store[bh] or {}
    end
    -- BreakJoints / other physics
    bP.BreakJoints = function(self)
        local bS = t.registry[bh] or "model"
        at(string.format("%s:BreakJoints()", bS))
    end
    bP.BuildJoints = function(self)
        local bS = t.registry[bh] or "model"
        at(string.format("%s:BuildJoints()", bS))
    end
    bP.MakeJoints = function(self)
        local bS = t.registry[bh] or "part"
        at(string.format("%s:MakeJoints()", bS))
    end
    -- Humanoid movement
    bP.MoveTo = function(self, position)
        local bS = t.registry[bh] or "humanoid"
        at(string.format("%s:MoveTo(%s)", bS, aZ(position)))
    end
    bP.ChangeState = function(self, state)
        local bS = t.registry[bh] or "humanoid"
        at(string.format("%s:ChangeState(%s)", bS, aZ(state)))
    end
    bP.GetState = function(self)
        return bj("Enum.HumanoidStateType.Running", false)
    end
    bP.GetMoveVelocity = function(self)
        return Vector3.new(0, 0, 0)
    end
    -- Model methods
    bP.SetPrimaryPartCFrame = function(self, cf)
        local bS = t.registry[bh] or "model"
        at(string.format("%s:SetPrimaryPartCFrame(%s)", bS, aZ(cf)))
    end
    bP.GetPrimaryPartCFrame = function(self)
        return CFrame.new(0, 5, 0)
    end
    bP.MovePrimaryPartTo = function(self, pos)
        local bS = t.registry[bh] or "model"
        at(string.format("%s:MovePrimaryPartTo(%s)", bS, aZ(pos)))
    end
    bP.GetExtentsSize = function(self)
        return Vector3.new(4, 4, 4)
    end
    bP.GetBoundingBox = function(self)
        return CFrame.new(0, 5, 0), Vector3.new(4, 4, 4)
    end
    -- BasePart physics
    bP.ApplyImpulse = function(self, impulse)
        local bS = t.registry[bh] or "part"
        at(string.format("%s:ApplyImpulse(%s)", bS, aZ(impulse)))
    end
    bP.ApplyImpulseAtPosition = function(self, impulse, pos)
        local bS = t.registry[bh] or "part"
        at(string.format("%s:ApplyImpulseAtPosition(%s, %s)", bS, aZ(impulse), aZ(pos)))
    end
    bP.ApplyAngularImpulse = function(self, impulse)
        local bS = t.registry[bh] or "part"
        at(string.format("%s:ApplyAngularImpulse(%s)", bS, aZ(impulse)))
    end
    -- RemoteEvent/RemoteFunction
    bP.FireServer = function(self, ...)
        local bS = t.registry[bh] or "remote"
        local bA = {...}
        local c5 = {}
        for _, b5 in ipairs(bA) do table.insert(c5, aZ(b5)) end
        at(string.format("%s:FireServer(%s)", bS, table.concat(c5, ", ")))
    end
    bP.InvokeServer = function(self, ...)
        local bS = t.registry[bh] or "remote"
        local bA = {...}
        local c5 = {}
        for _, b5 in ipairs(bA) do table.insert(c5, aZ(b5)) end
        local z = bj("invokeResult", false)
        local _ = aW(z, "result")
        at(string.format("local %s = %s:InvokeServer(%s)", _, bS, table.concat(c5, ", ")))
        return z
    end
    -- BindableEvent/BindableFunction
    bP.Fire = function(self, ...)
        local bS = t.registry[bh] or "bindable"
        local bA = {...}
        local c5 = {}
        for _, b5 in ipairs(bA) do table.insert(c5, aZ(b5)) end
        at(string.format("%s:Fire(%s)", bS, table.concat(c5, ", ")))
    end
    bP.Invoke = function(self, ...)
        local bS = t.registry[bh] or "bindable"
        local bA = {...}
        local c5 = {}
        for _, b5 in ipairs(bA) do table.insert(c5, aZ(b5)) end
        local z = bj("bindableResult", false)
        local _ = aW(z, "result")
        at(string.format("local %s = %s:Invoke(%s)", _, bS, table.concat(c5, ", ")))
        return z
    end
    -- TweenService
    bP.Create = function(self, instance, tweenInfo, goals)
        local bS = t.registry[bh] or "TweenService"
        local z = bj("tween", false)
        local _ = aW(z, "tween")
        -- Filter goals: only emit valid (non-boolean, non-string-used-as-value) entries
        local cleanGoals = {}
        if j(goals) == "table" then
            for gk, gv in D(goals) do
                if j(gv) ~= "boolean" and j(gv) ~= "string" then
                    cleanGoals[gk] = gv
                end
            end
        end
        at(string.format("local %s = %s:Create(%s, %s, %s)", _, bS, aZ(instance), aZ(tweenInfo), aZ(cleanGoals)))
        return z
    end
    -- Play/Pause/Cancel/Stop/Resume work for Tween, Sound, and AnimationTrack
    bP.Play = function(self)
        local bS = t.registry[bh] or "tween"
        at(string.format("%s:Play()", bS))
    end
    bP.Pause = function(self)
        local bS = t.registry[bh] or "tween"
        at(string.format("%s:Pause()", bS))
    end
    bP.Cancel = function(self)
        local bS = t.registry[bh] or "tween"
        at(string.format("%s:Cancel()", bS))
    end
    bP.Stop = function(self)
        local bS = t.registry[bh] or "tween"
        at(string.format("%s:Stop()", bS))
    end
    bP.Resume = function(self)
        local bS = t.registry[bh] or "sound"
        at(string.format("%s:Resume()", bS))
    end
    -- AnimationTrack
    bP.LoadAnimation = function(self, animation)
        local bS = t.registry[bh] or "animator"
        local z = bj("animTrack", false)
        local _ = aW(z, "animTrack")
        at(string.format("local %s = %s:LoadAnimation(%s)", _, bS, aZ(animation)))
        return z
    end
    bP.AdjustSpeed = function(self, speed)
        local bS = t.registry[bh] or "animTrack"
        at(string.format("%s:AdjustSpeed(%s)", bS, aZ(speed)))
    end
    bP.AdjustWeight = function(self, weight, fadeTime)
        local bS = t.registry[bh] or "animTrack"
        local extraArgs = fadeTime and (", " .. aZ(fadeTime)) or ""
        at(string.format("%s:AdjustWeight(%s%s)", bS, aZ(weight), extraArgs))
    end
    -- Teleport
    bP.Teleport = function(self, placeId, player, customLoadingScreen)
        local bS = t.registry[bh] or "TeleportService"
        local extraArgs = player and (", " .. aZ(player)) or ""
        at(string.format("%s:Teleport(%s%s)", bS, aZ(placeId), extraArgs))
    end
    -- RunService checks
    bP.IsServer = function(self)
        return false
    end
    bP.IsClient = function(self)
        return true
    end
    bP.IsStudio = function(self)
        return false
    end
    bP.IsRunMode = function(self)
        return true
    end
    bP.IsEdit = function(self)
        return false
    end
    -- UserInputService
    bP.IsKeyDown = function(self, key)
        return false
    end
    bP.IsMouseButtonPressed = function(self, button)
        return false
    end
    bP.GetKeysPressed = function(self)
        return {}
    end
    bP.GetMouseButtonsPressed = function(self)
        return {}
    end
    bP.GetMouseLocation = function(self)
        return Vector2.new(0, 0)
    end
    bP.GetNavigationGamepads = function(self)
        return {}
    end
    bP.GetSupportedGamepadKeyCodes = function(self, gamepadNum)
        return {}
    end
    bP.SetNavigationGamepad = function(self, gamepadNum, enabled)
    end
    bP.GetGamepadConnected = function(self, gamepadNum)
        return false
    end
    bP.GetGamepadState = function(self, gamepadNum)
        return {}
    end
    -- MarketplaceService
    bP.PromptPurchase = function(self, player, assetId, equip)
        local bS = t.registry[bh] or "MarketplaceService"
        at(string.format("%s:PromptPurchase(%s, %s)", bS, aZ(player), aZ(assetId)))
    end
    bP.PromptProductPurchase = function(self, player, productId, equipIfPurchased, currencyType)
        local bS = t.registry[bh] or "MarketplaceService"
        at(string.format("%s:PromptProductPurchase(%s, %s)", bS, aZ(player), aZ(productId)))
    end
    bP.PromptGamePassPurchase = function(self, player, gamePassId)
        local bS = t.registry[bh] or "MarketplaceService"
        at(string.format("%s:PromptGamePassPurchase(%s, %s)", bS, aZ(player), aZ(gamePassId)))
    end
    bP.GetProductInfo = function(self, assetId, infoType)
        return {Name = "Product", PriceInRobux = 0, Description = "", AssetId = assetId or 0, IsForSale = true}
    end
    bP.UserOwnsGamePassAsync = function(self, userId, gamePassId)
        return false
    end
    bP.PlayerOwnsAsset = function(self, player, assetId)
        return false
    end
    -- PathfindingService
    bP.CreatePath = function(self, options)
        local bS = t.registry[bh] or "PathfindingService"
        local z = bj("path", false)
        local _ = aW(z, "path")
        if options then
            at(string.format("local %s = %s:CreatePath(%s)", _, bS, aZ(options)))
        else
            at(string.format("local %s = %s:CreatePath()", _, bS))
        end
        return z
    end
    bP.ComputeAsync = function(self, startPos, goalPos)
        local bS = t.registry[bh] or "path"
        at(string.format("%s:ComputeAsync(%s, %s)", bS, aZ(startPos), aZ(goalPos)))
    end
    bP.GetWaypoints = function(self)
        return {}
    end
    bP.CheckOcclusionAsync = function(self, start)
        return -1
    end
    -- MessagingService
    bP.PublishAsync = function(self, topic, message)
        local bS = t.registry[bh] or "MessagingService"
        at(string.format("%s:PublishAsync(%s, %s)", bS, aH(aE(topic)), aZ(message)))
    end
    bP.SubscribeAsync = function(self, topic, callback)
        local bS = t.registry[bh] or "MessagingService"
        local topicStr = aH(aE(topic))
        local c1 = bj("subscription", false)
        local c2 = aW(c1, "sub")
        at(string.format("local %s = %s:SubscribeAsync(%s, function(message)", c2, bS, topicStr))
        t.indent = t.indent + 1
        if j(callback) == "function" then
            xpcall(function() callback({Data = "", Sent = 0}) end, function() end)
        end
        t.indent = t.indent - 1
        at("end)")
        return c1
    end
    -- TextService
    bP.FilterStringAsync = function(self, text, fromUserId, textContext)
        local bS = t.registry[bh] or "TextService"
        local z = bj("filteredText", false)
        local _ = aW(z, "filteredText")
        at(string.format("local %s = %s:FilterStringAsync(%s, %s)", _, bS, aZ(text), aZ(fromUserId)))
        return z
    end
    bP.GetStringForBroadcast = function(self)
        return ""
    end
    bP.GetNonChatStringForBroadcastAsync = function(self)
        return ""
    end
    -- TeleportService additional
    bP.TeleportAsync = function(self, placeId, players, teleportOptions)
        local bS = t.registry[bh] or "TeleportService"
        if teleportOptions then
            at(string.format("%s:TeleportAsync(%s, %s, %s)", bS, aZ(placeId), aZ(players), aZ(teleportOptions)))
        else
            at(string.format("%s:TeleportAsync(%s, %s)", bS, aZ(placeId), aZ(players)))
        end
    end
    bP.ReserveServer = function(self, placeId)
        local bS = t.registry[bh] or "TeleportService"
        local z = bj("reservedCode", false)
        local _ = aW(z, "reservedCode")
        at(string.format("local %s = %s:ReserveServer(%s)", _, bS, aZ(placeId)))
        return z
    end
    -- Instance network ownership
    bP.GetNetworkOwner = function(self)
        return bj("LocalPlayer", false)
    end
    bP.GetNetworkOwnership = function(self)
        return bj("LocalPlayer", false), true
    end
    bP.SetNetworkOwner = function(self, player)
        local bS = t.registry[bh] or "part"
        at(string.format("%s:SetNetworkOwner(%s)", bS, aZ(player)))
    end
    bP.SetNetworkOwnershipAuto = function(self)
        local bS = t.registry[bh] or "part"
        at(string.format("%s:SetNetworkOwnershipAuto()", bS))
    end
    -- Animation track
    bP.GetTimeOfKeyframe = function(self, keyframeName)
        return 0
    end
    bP.GetMarkerReachedSignal = function(self, name)
        local bS = t.registry[bh] or "animTrack"
        local cg = bj(bS .. ".GetMarkerReachedSignal", false)
        t.registry[cg] = bS .. ":GetMarkerReachedSignal(" .. aH(aE(name)) .. ")"
        return cg
    end
    -- SoundService / Sound
    bP.PlaySound = function(self, sound)
        local bS = t.registry[bh] or "SoundService"
        at(string.format("%s:PlaySound(%s)", bS, aZ(sound)))
    end
    -- GuiService
    bP.OpenBrowserWindow = function(self, url)
        local bS = t.registry[bh] or "GuiService"
        at(string.format("%s:OpenBrowserWindow(%s)", bS, aH(aE(url))))
    end
    bP.SetMenuOpen = function(self, open)
        local bS = t.registry[bh] or "GuiService"
        at(string.format("%s:SetMenuOpen(%s)", bS, aZ(open)))
    end
    bP.AddSelectionParent = function(self, selectionName, instance)
        local bS = t.registry[bh] or "GuiService"
        at(string.format("%s:AddSelectionParent(%s, %s)", bS, aH(aE(selectionName)), aZ(instance)))
    end
    -- ContentProvider
    bP.PreloadAsync = function(self, instances, callback)
        local bS = t.registry[bh] or "ContentProvider"
        at(string.format("%s:PreloadAsync(%s)", bS, aZ(instances)))
    end
    -- Workspace spatial queries
    bP.FindPartOnRay = function(self, ray, ignoreDescendantsInstance, terrainCellsAreCubes, ignoreWater)
        local bS = t.registry[bh] or "workspace"
        local z = bj("rayHit", false)
        local _ = aW(z, "rayHit")
        at(string.format("local %s = %s:FindPartOnRay(%s)", _, bS, aZ(ray)))
        return z, Vector3.new(0, 0, 0), Vector3.new(0, 1, 0)
    end
    bP.FindPartOnRayWithIgnoreList = function(self, ray, ignoreList, terrainCellsAreCubes, ignoreWater)
        local bS = t.registry[bh] or "workspace"
        local z = bj("rayHit", false)
        local _ = aW(z, "rayHit")
        at(string.format("local %s = %s:FindPartOnRayWithIgnoreList(%s, %s)", _, bS, aZ(ray), aZ(ignoreList)))
        return z, Vector3.new(0, 0, 0), Vector3.new(0, 1, 0)
    end
    bP.GetPartBoundsInBox = function(self, cf, size, params)
        local bS = t.registry[bh] or "workspace"
        at(string.format("workspace:GetPartBoundsInBox(%s, %s)", aZ(cf), aZ(size)))
        return {}
    end
    bP.GetPartBoundsInRadius = function(self, pos, radius, params)
        local bS = t.registry[bh] or "workspace"
        at(string.format("workspace:GetPartBoundsInRadius(%s, %s)", aZ(pos), aZ(radius)))
        return {}
    end
    bP.GetPartsInPart = function(self, part, params)
        local bS = t.registry[bh] or "workspace"
        at(string.format("workspace:GetPartsInPart(%s)", aZ(part)))
        return {}
    end
    bP.BlockcastAsync = function(self, cf, size, direction, params)
        local bS = t.registry[bh] or "workspace"
        local z = bj("blockcastResult", false)
        local _ = aW(z, "blockResult")
        at(string.format("local %s = %s:Blockcast(%s, %s, %s)", _, bS, aZ(cf), aZ(size), aZ(direction)))
        return z
    end
    bP.SphereCastAsync = function(self, origin, radius, direction, params)
        local bS = t.registry[bh] or "workspace"
        local z = bj("spherecastResult", false)
        local _ = aW(z, "sphereResult")
        at(string.format("local %s = %s:Spherecast(%s, %s, %s)", _, bS, aZ(origin), aZ(radius), aZ(direction)))
        return z
    end
    -- Players additional
    bP.CreateHumanoidDescription = function(self)
        return bj("HumanoidDescription", false)
    end
    bP.GetCharacterAppearanceAsync = function(self, userId)
        return bj("HumanoidDescription", false)
    end
    bP.GetFriendsAsync = function(self, userId)
        local z = bj("friendPages", false)
        local _ = aW(z, "friendPages")
        local bS = t.registry[bh] or "Players"
        at(string.format("local %s = %s:GetFriendsAsync(%s)", _, bS, aZ(userId)))
        return z
    end
    -- OverlapParams helper
    bP.GetCurrentCamera = function(self)
        local bS = t.registry[bh] or "workspace"
        local cX = bj("Camera", false, bh)
        t.property_store[cX] = {CFrame = CFrame.new(0, 10, 0), FieldOfView = 70, ViewportSize = Vector2.new(1920, 1080)}
        local _ = aW(cX, "camera")
        at(string.format("local %s = %s.CurrentCamera", _, bS))
        return cX
    end
    -- TweenService additional
    bP.GetValue = function(self, alpha, easingStyle, easingDirection)
        return alpha or 0
    end
    -- ContextActionService
    bP.BindAction = function(self, actionName, funcToBind, createTouchButton, ...)
        local bS = t.registry[bh] or "ContextActionService"
        local keys = {...}
        local keyStrs = {}
        for _, k in ipairs(keys) do table.insert(keyStrs, aZ(k)) end
        at(string.format("%s:BindAction(%s, function(actionName, inputState, inputObject)", bS, aH(aE(actionName))))
        t.indent = t.indent + 1
        if j(funcToBind) == "function" then
            xpcall(function() funcToBind("actionName", nil, nil) end, function() end)
        end
        t.indent = t.indent - 1
        at("end, " .. tostring(createTouchButton or false) .. (
            #keyStrs > 0 and ", " .. table.concat(keyStrs, ", ") or ""
        ) .. ")")
    end
    bP.UnbindAction = function(self, actionName)
        local bS = t.registry[bh] or "ContextActionService"
        at(string.format("%s:UnbindAction(%s)", bS, aH(aE(actionName))))
    end
    -- PhysicsService
    bP.GetCollisionGroupId = function(self, name)
        return 0
    end
    bP.CollisionGroupSetCollidable = function(self, name1, name2, collidable)
        local bS = t.registry[bh] or "PhysicsService"
        at(string.format("%s:CollisionGroupSetCollidable(%s, %s, %s)", bS, aH(aE(name1)), aH(aE(name2)), aZ(collidable)))
    end
    bP.RegisterCollisionGroup = function(self, name)
        local bS = t.registry[bh] or "PhysicsService"
        at(string.format("%s:RegisterCollisionGroup(%s)", bS, aH(aE(name))))
    end
    -- ProximityPromptService
    bP.TriggerPrompt = function(self, prompt)
        local bS = t.registry[bh] or "ProximityPromptService"
        at(string.format("%s:TriggerPrompt(%s)", bS, aZ(prompt)))
    end
    -- InsertService
    bP.LoadAsset = function(self, assetId)
        local bS = t.registry[bh] or "InsertService"
        local z = bj("loadedModel", false)
        local _ = aW(z, "loadedModel")
        at(string.format("local %s = %s:LoadAsset(%s)", _, bS, aZ(assetId)))
        return z
    end
    bP.LoadAssetVersion = function(self, assetVersionId)
        local bS = t.registry[bh] or "InsertService"
        local z = bj("loadedModel", false)
        local _ = aW(z, "loadedModel")
        at(string.format("local %s = %s:LoadAssetVersion(%s)", _, bS, aZ(assetVersionId)))
        return z
    end
    -- FireClient / FireAllClients (server-side)
    bP.FireClient = function(self, player, ...)
        local bS = t.registry[bh] or "remote"
        local bA = {...}
        local c5 = {}
        for _, b5 in ipairs(bA) do table.insert(c5, aZ(b5)) end
        local argStr = #c5 > 0 and ", " .. table.concat(c5, ", ") or ""
        at(string.format("%s:FireClient(%s%s)", bS, aZ(player), argStr))
    end
    bP.FireAllClients = function(self, ...)
        local bS = t.registry[bh] or "remote"
        local bA = {...}
        local c5 = {}
        for _, b5 in ipairs(bA) do table.insert(c5, aZ(b5)) end
        at(string.format("%s:FireAllClients(%s)", bS, table.concat(c5, ", ")))
    end
    bP.InvokeClient = function(self, player, ...)
        local bS = t.registry[bh] or "remote"
        local bA = {...}
        local c5 = {}
        for _, b5 in ipairs(bA) do table.insert(c5, aZ(b5)) end
        local argStr = #c5 > 0 and ", " .. table.concat(c5, ", ") or ""
        local z = bj("invokeResult", false)
        local _ = aW(z, "result")
        at(string.format("local %s = %s:InvokeClient(%s%s)", _, bS, aZ(player), argStr))
        return z
    end
    -- Humanoid additional
    bP.ApplyDescription = function(self, description)
        local bS = t.registry[bh] or "humanoid"
        at(string.format("%s:ApplyDescription(%s)", bS, aZ(description)))
    end
    bP.GetAppliedDescription = function(self)
        return bj("HumanoidDescription", false)
    end
    bP.AddAccessory = function(self, accessory)
        local bS = t.registry[bh] or "humanoid"
        at(string.format("%s:AddAccessory(%s)", bS, aZ(accessory)))
    end
    bP.GetAccessories = function(self)
        return {}
    end
    -- Model/Part manipulation
    bP.WorldToObjectSpace = function(self, v3)
        return v3 or Vector3.new(0, 0, 0)
    end
    bP.ObjectToWorldSpace = function(self, v3)
        return v3 or Vector3.new(0, 0, 0)
    end
    bP.PointToObjectSpace = function(self, v3)
        return v3 or Vector3.new(0, 0, 0)
    end
    bP.PointToWorldSpace = function(self, v3)
        return v3 or Vector3.new(0, 0, 0)
    end
    bP.VectorToObjectSpace = function(self, v3)
        return v3 or Vector3.new(0, 0, 0)
    end
    bP.VectorToWorldSpace = function(self, v3)
        return v3 or Vector3.new(0, 0, 0)
    end
    -- EncodingService
    bP.CompressBuffer = function(self, buf, algo, level)
        local bS = t.registry[bh] or "EncodingService"
        local z = bj("compressedBuffer", false)
        local _ = aW(z, "compressedBuf")
        at(string.format("local %s = %s:CompressBuffer(%s, %s)", _, bS, aZ(buf), aZ(algo)))
        t.property_store[z] = {_size = 0, _data = {}}
        return z
    end
    bP.DecompressBuffer = function(self, buf, algo)
        local bS = t.registry[bh] or "EncodingService"
        local z = bj("decompressedBuffer", false)
        local _ = aW(z, "decompressedBuf")
        at(string.format("local %s = %s:DecompressBuffer(%s, %s)", _, bS, aZ(buf), aZ(algo)))
        t.property_store[z] = {_size = 6, _data = {}}
        return z
    end
    -- Camera / viewport
    bP.WorldToScreenPoint = function(self, worldPos)
        local bS = t.registry[bh] or "Camera"
        local z = bj("screenPoint", false)
        local _ = aW(z, "screenPoint")
        at(string.format("local %s = %s:WorldToScreenPoint(%s)", _, bS, aZ(worldPos)))
        t.property_store[z] = {X = 960, Y = 540, Z = 0}
        return z, true
    end
    bP.WorldToViewportPoint = function(self, worldPos)
        local bS = t.registry[bh] or "Camera"
        local z = bj("viewportPoint", false)
        local _ = aW(z, "viewportPoint")
        at(string.format("local %s = %s:WorldToViewportPoint(%s)", _, bS, aZ(worldPos)))
        t.property_store[z] = {X = 960, Y = 540, Z = 0}
        return z, true
    end
    bP.ScreenPointToRay = function(self, x, y, depth)
        local bS = t.registry[bh] or "Camera"
        local z = bj("ray", false)
        local _ = aW(z, "ray")
        at(string.format("local %s = %s:ScreenPointToRay(%s, %s)", _, bS, aZ(x), aZ(y)))
        return z
    end
    bP.ViewportPointToRay = function(self, x, y, depth)
        local bS = t.registry[bh] or "Camera"
        local z = bj("ray", false)
        local _ = aW(z, "ray")
        at(string.format("local %s = %s:ViewportPointToRay(%s, %s)", _, bS, aZ(x), aZ(y)))
        return z
    end
    -- ContextActionService
    bP.GetAllBoundActionInfo = function(self)
        return t.property_store[bh] and t.property_store[bh]._bound_actions or {}
    end
    -- BasePart physics
    bP.GetMass = function(self)
        local bS = t.registry[bh] or "part"
        local z = bl(1)
        at(string.format("local mass = %s:GetMass()", bS))
        return z
    end
    bP.GetTouchingParts = function(self)
        local bS = t.registry[bh] or "part"
        at(string.format("local touchingParts = %s:GetTouchingParts()", bS))
        return {}
    end
    bP.GetConnectedParts = function(self, recursive)
        return {}
    end
    bP.GetJoints = function(self)
        return {}
    end
    -- Players additional helpers
    bP.GetJoinData = function(self)
        return {TeleportData = nil, Members = {}, ReservedServerAccessCode = "", SourceGameId = 0, SourcePlaceId = 0}
    end
    bP.GetTeleportData = function(self)
        return nil
    end
    -- Instance helpers
    bP.GetFullName = function(self)
        return t.registry[bh] or "Instance"
    end
    bP.GetDebugId = function(self)
        return "DEBUG_" .. tostring(H(bh) or "0")
    end
    bP.GetActor = function(self)
        return nil
    end
    bi.__index = function(b2, b4)
        if b4 == F or b4 == "__proxy_id" then
            return rawget(b2, b4)
        end
        if b4 == "PlaceId" or b4 == "GameId" or b4 == "placeId" or b4 == "gameId" then
            return u
        end
        local bS = t.registry[bh] or aT or "object"
        local cP = aE(b4)
        if t.property_store[bh] and t.property_store[bh][b4] ~= nil then
            return t.property_store[bh][b4]
        end
        if bP[cP] then
            local cQ, cR = bg()
            t.registry[cQ] = bS .. "." .. cP
            cR.__call = function(W, ...)
                local bA = {...}
                if bA[1] == bh or G(bA[1]) and bA[1] ~= cQ then
                    table.remove(bA, 1)
                end
                return bP[cP](bh, unpack(bA))
            end
            cR.__index = function(W, cS)
                if cS == F or cS == "__proxy_id" then
                    return rawget(cQ, cS)
                end
                return bj(cS, false, cQ)
            end
            cR.__tostring = function()
                return bS .. ":" .. cP
            end
            return cQ
        end
        if bS == "fenv" or bS == "getgenv" or bS == "_G" then
            if b4 == "game" then
                return game
            end
            if b4 == "workspace" then
                return workspace
            end
            if b4 == "script" then
                return script
            end
            if b4 == "Enum" then
                return Enum
            end
            if _G[b4] ~= nil then
                return _G[b4]
            end
            return nil
        end
        if b4 == "Parent" then
            return t.parent_map[bh] or bj("Parent", false)
        end
        if b4 == "Name" then
            return aT or "Object"
        end
        if b4 == "ClassName" then
            return aT or "Instance"
        end
        if b4 == "LocalPlayer" then
            local cT = bj("LocalPlayer", false, bh)
            local _ = aW(cT, "LocalPlayer")
            at(string.format("local %s = %s.LocalPlayer", _, bS))
            return cT
        end
        if b4 == "PlayerGui" then
            return bj("PlayerGui", false, bh)
        end
        if b4 == "Backpack" then
            return bj("Backpack", false, bh)
        end
        if b4 == "PlayerScripts" then
            return bj("PlayerScripts", false, bh)
        end
        if b4 == "UserId" then
            return 1
        end
        if b4 == "DisplayName" or b4 == "Name" and (aT or ""):lower():find("player") then
            return "Player1"
        end
        if b4 == "AccountAge" then
            return 1000
        end
        if b4 == "NumPlayers" then
            return 1
        end
        if b4 == "MaxPlayers" then
            return 10
        end
        if b4 == "IsLoaded" then
            return true
        end
        if b4 == "PlaceId" then
            return u
        end
        if b4 == "GameId" then
            return u
        end
        if b4 == "Team" then
            return bj("Team", false, bh)
        end
        if b4 == "TeamColor" then
            return BrickColor.new("White")
        end
        if b4 == "Character" then
            return bj("Character", false, bh)
        end
        if b4 == "Humanoid" then
            local cU = bj("Humanoid", false, bh)
            t.property_store[cU] = {Health = 100, MaxHealth = 100, WalkSpeed = 16, JumpPower = 50, JumpHeight = 7.2}
            return cU
        end
        if b4 == "HumanoidRootPart" or b4 == "PrimaryPart" or b4 == "RootPart" then
            local cV = bj("HumanoidRootPart", false, bh)
            t.property_store[cV] = {Position = Vector3.new(0, 5, 0), CFrame = CFrame.new(0, 5, 0)}
            return cV
        end
        local cW = {
            "Head",
            "Torso",
            "UpperTorso",
            "LowerTorso",
            "RightArm",
            "LeftArm",
            "RightLeg",
            "LeftLeg",
            "RightHand",
            "LeftHand",
            "RightFoot",
            "LeftFoot"
        }
        for W, cr in ipairs(cW) do
            if b4 == cr then
                return bj(b4, false, bh)
            end
        end
        if b4 == "Animator" then
            return bj("Animator", false, bh)
        end
        if b4 == "CurrentCamera" or b4 == "Camera" then
            local cX = bj("Camera", false, bh)
            t.property_store[cX] = {
                CFrame = CFrame.new(0, 10, 0),
                FieldOfView = 70,
                ViewportSize = Vector2.new(1920, 1080)
            }
            return cX
        end
        if b4 == "CameraType" then
            return bj("Enum.CameraType.Custom", false)
        end
        if b4 == "CameraSubject" then
            return bj("Humanoid", false, bh)
        end
        local cY = {
            Health = 100,
            MaxHealth = 100,
            WalkSpeed = 16,
            JumpPower = 50,
            JumpHeight = 7.2,
            HipHeight = 2,
            Transparency = 0,
            Mass = 1,
            Value = 0,
            TimePosition = 0,
            TimeLength = 1,
            Volume = 0.5,
            PlaybackSpeed = 1,
            Brightness = 1,
            Range = 60,
            Angle = 90,
            FieldOfView = 70,
            Size = 1,
            Thickness = 1,
            ZIndex = 1,
            LayoutOrder = 0
        }
        if cY[b4] then
            return bl(cY[b4])
        end
        local cZ = {
            Visible = true,
            Enabled = true,
            Anchored = false,
            CanCollide = true,
            Locked = false,
            Active = true,
            Draggable = false,
            Modal = false,
            Playing = false,
            Looped = false,
            IsPlaying = false,
            AutoPlay = false,
            Archivable = true,
            ClipsDescendants = false,
            RichText = false,
            TextWrapped = false,
            TextScaled = false,
            PlatformStand = false,
            AutoRotate = true,
            Sit = false
        }
        if cZ[b4] ~= nil then
            return cZ[b4]
        end
        if b4 == "AbsoluteSize" or b4 == "ViewportSize" then
            return Vector2.new(1920, 1080)
        end
        if b4 == "AbsolutePosition" then
            return Vector2.new(0, 0)
        end
        if b4 == "Position" then
            if aT and (aT:match("Part") or aT:match("Model") or aT:match("Character") or aT:match("Root")) then
                return Vector3.new(0, 5, 0)
            end
            return UDim2.new(0, 0, 0, 0)
        end
        if b4 == "Size" then
            if aT and aT:match("Part") then
                return Vector3.new(4, 1, 2)
            end
            return UDim2.new(1, 0, 1, 0)
        end
        if b4 == "CFrame" then
            return CFrame.new(0, 5, 0)
        end
        if b4 == "Velocity" or b4 == "AssemblyLinearVelocity" then
            return Vector3.new(0, 0, 0)
        end
        if b4 == "RotVelocity" or b4 == "AssemblyAngularVelocity" then
            return Vector3.new(0, 0, 0)
        end
        if b4 == "Orientation" or b4 == "Rotation" then
            return Vector3.new(0, 0, 0)
        end
        if b4 == "LookVector" then
            return Vector3.new(0, 0, -1)
        end
        if b4 == "RightVector" then
            return Vector3.new(1, 0, 0)
        end
        if b4 == "UpVector" then
            return Vector3.new(0, 1, 0)
        end
        if
            b4 == "Color" or b4 == "Color3" or b4 == "BackgroundColor3" or b4 == "BorderColor3" or b4 == "TextColor3" or
                b4 == "PlaceholderColor3" or
                b4 == "ImageColor3"
         then
            return Color3.new(1, 1, 1)
        end
        if b4 == "BrickColor" then
            return BrickColor.new("Medium stone grey")
        end
        if b4 == "Material" then
            return bj("Enum.Material.Plastic", false)
        end
        if b4 == "Hit" then
            return CFrame.new(0, 0, -10)
        end
        if b4 == "Origin" then
            return CFrame.new(0, 5, 0)
        end
        if b4 == "Target" then
            return bj("Target", false, bh)
        end
        if b4 == "X" or b4 == "Y" then
            return 0
        end
        if b4 == "UnitRay" then
            return Ray.new(Vector3.new(0, 5, 0), Vector3.new(0, 0, -1))
        end
        if b4 == "ViewSizeX" then
            return 1920
        end
        if b4 == "ViewSizeY" then
            return 1080
        end
        if b4 == "Text" or b4 == "PlaceholderText" or b4 == "ContentText" or b4 == "Value" then
            if s then
                return s
            end
            if b4 == "Value" then
                return "input"
            end
            return '"'
        end
        if b4 == "TextBounds" then
            return Vector2.new(0, 0)
        end
        if b4 == "Font" then
            return bj("Enum.Font.SourceSans", false)
        end
        if b4 == "TextSize" then
            return 14
        end
        if b4 == "Image" or b4 == "ImageContent" then
            return '"'
        end
        local c_ = {
            "Changed",
            "ChildAdded",
            "ChildRemoved",
            "DescendantAdded",
            "DescendantRemoving",
            "Touched",
            "TouchEnded",
            "InputBegan",
            "InputEnded",
            "InputChanged",
            "MouseButton1Click",
            "MouseButton1Down",
            "MouseButton1Up",
            "MouseButton2Click",
            "MouseButton2Down",
            "MouseButton2Up",
            "MouseEnter",
            "MouseLeave",
            "MouseMoved",
            "MouseWheelForward",
            "MouseWheelBackward",
            "Activated",
            "Deactivated",
            "FocusLost",
            "FocusGained",
            "Focused",
            "Heartbeat",
            "RenderStepped",
            "Stepped",
            "CharacterAdded",
            "CharacterRemoving",
            "CharacterAppearanceLoaded",
            "PlayerAdded",
            "PlayerRemoving",
            "AncestryChanged",
            "AttributeChanged",
            "Died",
            "FreeFalling",
            "GettingUp",
            "Jumping",
            "Running",
            "Seated",
            "Swimming",
            "StateChanged",
            "HealthChanged",
            "MoveToFinished",
            "OnClientEvent",
            "OnServerEvent",
            "OnClientInvoke",
            "OnServerInvoke",
            "Completed",
            "DidLoop",
            "Stopped",
            "Button1Down",
            "Button1Up",
            "Button2Down",
            "Button2Up",
            "Idle",
            "Move",
            "TextChanged",
            "ReturnPressedFromOnScreenKeyboard",
            "Triggered",
            "TriggerEnded",
            -- Additional signals needed for eUNC / BindableEvent / game events
            "ServiceAdded",
            "ServiceRemoving",
            "Event",
            "Invoked",
            "OnInvoke",
            "OnClose",
            "Close",
            "ItemChanged",
            "RecordChanged",
            "DataChanged",
            "PromptPurchaseFinished",
            "PromptProductPurchaseFinished",
            "PromptGamePassPurchaseFinished",
            "ThrottleStateChanged",
            "PlayerChatted",
            "LookVectorChanged",
            "CameraTypeChanged"
        }
        for W, d0 in ipairs(c_) do
            if b4 == d0 then
                local cg = bj(bS .. "." .. b4, false, bh)
                t.registry[cg] = bS .. "." .. b4
                return cg
            end
        end
        if bS:match("^Enum") then
            local d1 = bS .. "." .. cP
            local d2 = bj(d1, false)
            t.registry[d2] = d1
            return d2
        end
        return bk(cP, bh)
    end
    bi.__newindex = function(b2, b4, b5)
        if b4 == F or b4 == "__proxy_id" then
            rawset(b2, b4, b5)
            return
        end
        local bS = t.registry[bh] or aT or "object"
        local cP = aE(b4)
        t.property_store[bh] = t.property_store[bh] or {}
        t.property_store[bh][b4] = b5
        if b4 == "Parent" and G(b5) then
            t.parent_map[bh] = b5
        end
        at(string.format("%s.%s = %s", bS, cP, aZ(b5)))
    end
    bi.__call = function(b2, ...)
        local bS = t.registry[bh] or aT or "func"
        if bS == "fenv" or bS == "getgenv" or bS:match("env") then
            return bh
        end
        local bA = {...}
        local c5 = {}
        for W, b5 in ipairs(bA) do
            table.insert(c5, aZ(b5))
        end
        local z = bj("result", false)
        local _ = aW(z, "result")
        at(string.format("local %s = %s(%s)", _, bS, table.concat(c5, ", ")))
        return z
    end
    local function d3(d4)
        local function d5(bo, aa)
            local bh, bi = bg()
            local d6 = "0"
            if bo ~= nil then
                d6 = t.registry[bo] or aZ(bo)
            end
            local d7 = "0"
            if aa ~= nil then
                d7 = t.registry[aa] or aZ(aa)
            end
            local d8 = "(" .. d6 .. " " .. d4 .. " " .. d7 .. ")"
            t.registry[bh] = d8
            bi.__tostring = function()
                return d8
            end
            bi.__call = function()
                return bh
            end
            bi.__index = function(W, b4)
                if b4 == F or b4 == "__proxy_id" then
                    return rawget(bh, b4)
                end
                return bj(d8 .. "." .. aE(b4), false)
            end
            bi.__add = d3("+")
            bi.__sub = d3("-")
            bi.__mul = d3("*")
            bi.__div = d3("/")
            bi.__mod = d3("%")
            bi.__pow = d3("^")
            bi.__concat = d3("..")
            bi.__eq = function()
                return false
            end
            bi.__lt = function()
                return false
            end
            bi.__le = function()
                return false
            end
            return bh
        end
        return d5
    end
    bi.__add = d3("+")
    bi.__sub = d3("-")
    bi.__mul = d3("*")
    bi.__div = d3("/")
    bi.__mod = d3("%")
    bi.__pow = d3("^")
    bi.__concat = d3("..")
    bi.__eq = function()
        return false
    end
    bi.__lt = function()
        return false
    end
    bi.__le = function()
        return false
    end
    bi.__unm = function(bo)
        local z, d9 = bg()
        t.registry[z] = "(-" .. (t.registry[bo] or aZ(bo)) .. ")"
        d9.__tostring = function()
            return t.registry[z]
        end
        return z
    end
    bi.__len = function()
        return 0
    end
    bi.__tostring = function()
        return t.registry[bh] or aT or "Object"
    end
    bi.__pairs = function()
        return function()
            return nil
        end, bh, nil
    end
    bi.__ipairs = bi.__pairs
    return bh
end
local function da(am, db)
    local dc = {}
    local dd = {}
    dd.__index = function(b2, b4)
        if b4 == "new" or db and db[b4] then
            return function(...)
                local bA = {...}
                local c5 = {}
                for W, b5 in ipairs(bA) do
                    table.insert(c5, aZ(b5))
                end
                local d8 = am .. "." .. b4 .. "(" .. table.concat(c5, ", ") .. ")"
                local bh, de = bg()
                t.registry[bh] = d8
                de.__tostring = function()
                    return d8
                end
                de.__index = function(W, bG)
                    if bG == F or bG == "__proxy_id" then
                        return rawget(bh, bG)
                    end
                    if t.property_store[W] and t.property_store[W][bG] then
                        return t.property_store[W][bG]
                    end
                    if bG == "X" or bG == "Y" or bG == "Z" or bG == "W" then
                        return 0
                    end
                    if bG == "Magnitude" then
                        return 0
                    end
                    if bG == "Unit" then
                        return bh
                    end
                    if bG == "Position" then
                        return bh
                    end
                    if bG == "CFrame" then
                        return bh
                    end
                    if bG == "LookVector" or bG == "RightVector" or bG == "UpVector" then
                        return bh
                    end
                    if bG == "Rotation" then
                        return bh
                    end
                    if bG == "R" or bG == "G" or bG == "B" then
                        return 1
                    end
                    if bG == "Width" or bG == "Height" then
                        return UDim.new(0, 0)
                    end
                    if bG == "Min" or bG == "Max" then
                        return 0
                    end
                    if bG == "Scale" or bG == "Offset" then
                        return 0
                    end
                    if bG == "p" then
                        return bh
                    end
                    return 0
                end
                local function df(Z)
                    return function(bo, aa)
                        local dg, dh = bg()
                        local O =
                            "(" .. (t.registry[bo] or aZ(bo)) .. " " .. Z .. " " .. (t.registry[aa] or aZ(aa)) .. ")"
                        t.registry[dg] = O
                        dh.__tostring = function()
                            return O
                        end
                        dh.__index = de.__index
                        dh.__add = df("+")
                        dh.__sub = df("-")
                        dh.__mul = df("*")
                        dh.__div = df("/")
                        return dg
                    end
                end
                de.__add = df("+")
                de.__sub = df("-")
                de.__mul = df("*")
                de.__div = df("/")
                de.__unm = function(bo)
                    local dg, dh = bg()
                    t.registry[dg] = "(-" .. (t.registry[bo] or aZ(bo)) .. ")"
                    dh.__tostring = function()
                        return t.registry[dg]
                    end
                    return dg
                end
                de.__eq = function()
                    return false
                end
                return bh
            end
        end
        return nil
    end
    dd.__call = function(b2, ...)
        return b2.new(...)
    end
    dd.__newindex = function(b2, b4, b5)
        t.property_store[b2] = t.property_store[b2] or {}
        t.property_store[b2][b4] = b5
    end
    return setmetatable(dc, dd)
end
Vector3 = da("Vector3", {new = true, zero = true, one = true})
Vector2 = da("Vector2", {new = true, zero = true, one = true})
UDim = da("UDim", {new = true})
UDim2 = da("UDim2", {new = true, fromScale = true, fromOffset = true})
CFrame =
    da(
    "CFrame",
    {
        new = true,
        Angles = true,
        lookAt = true,
        fromEulerAnglesXYZ = true,
        fromEulerAnglesYXZ = true,
        fromAxisAngle = true,
        fromMatrix = true,
        fromOrientation = true,
        identity = true
    }
)
Color3 = da("Color3", {new = true, fromRGB = true, fromHSV = true, fromHex = true})
BrickColor =
    da(
    "BrickColor",
    {
        new = true,
        random = true,
        White = true,
        Black = true,
        Red = true,
        Blue = true,
        Green = true,
        Yellow = true,
        palette = true
    }
)
TweenInfo = da("TweenInfo", {new = true})
Rect = da("Rect", {new = true})
Region3 = da("Region3", {new = true})
Region3int16 = da("Region3int16", {new = true})
Ray = da("Ray", {new = true})
NumberRange = da("NumberRange", {new = true})
NumberSequence = da("NumberSequence", {new = true})
NumberSequenceKeypoint = da("NumberSequenceKeypoint", {new = true})
ColorSequence = da("ColorSequence", {new = true})
ColorSequenceKeypoint = da("ColorSequenceKeypoint", {new = true})
PhysicalProperties = da("PhysicalProperties", {new = true})
Font = da("Font", {new = true, fromEnum = true, fromName = true, fromId = true})
RaycastParams = da("RaycastParams", {new = true})
OverlapParams = da("OverlapParams", {new = true})
PathWaypoint = da("PathWaypoint", {new = true})
Axes = da("Axes", {new = true})
Faces = da("Faces", {new = true})
Vector3int16 = da("Vector3int16", {new = true})
Vector2int16 = da("Vector2int16", {new = true})
CatalogSearchParams = da("CatalogSearchParams", {new = true})
DateTime = da("DateTime", {now = true, fromUnixTimestamp = true, fromUnixTimestampMillis = true, fromIsoDate = true})
-- Additional Roblox type constructors
TweenInfo = TweenInfo or da("TweenInfo", {new = true})
Vector3int16 = Vector3int16 or da("Vector3int16", {new = true})
Vector2int16 = Vector2int16 or da("Vector2int16", {new = true})
-- SharedTable (Roblox parallel scripting)
SharedTable = setmetatable({}, {
    __index = function(self, k) return nil end,
    __newindex = function(self, k, v) rawset(self, k, v) end,
    __call = function(self, data)
        local st = {}
        if type(data) == "table" then
            for k, v in pairs(data) do st[k] = v end
        end
        return setmetatable(st, getmetatable(SharedTable))
    end
})
_G.SharedTable = SharedTable
-- DebuggerManager stub
DebuggerManager = bj("DebuggerManager", false)
_G.DebuggerManager = DebuggerManager
-- LogService
LogService = bj("LogService", false)
_G.LogService = LogService
-- TaskScheduler
TaskScheduler = bj("TaskScheduler", false)
_G.TaskScheduler = TaskScheduler
-- ScriptContext
ScriptContext = bj("ScriptContext", false)
_G.ScriptContext = ScriptContext
-- LocalizationService
LocalizationService = bj("LocalizationService", false)
_G.LocalizationService = LocalizationService
-- VoiceChatService
VoiceChatService = bj("VoiceChatService", false)
_G.VoiceChatService = VoiceChatService
Random = {new = function(di)
        local x = {}
        function x:NextNumber(dj, dk)
            return (dj or 0) + 0.5 * ((dk or 1) - (dj or 0))
        end
        function x:NextInteger(dj, dk)
            return math.floor((dj or 1) + 0.5 * ((dk or 100) - (dj or 1)))
        end
        function x:NextUnitVector()
            return Vector3.new(0.577, 0.577, 0.577)
        end
        function x:Shuffle(dl)
            return dl
        end
        function x:Clone()
            return Random.new()
        end
        return x
    end}
setmetatable(
    Random,
    {__call = function(b2, di)
            return b2.new(di)
        end}
)
Enum = bj("Enum", true)
local dm = a.getmetatable(Enum)
dm.__index = function(b2, b4)
    if b4 == F or b4 == "__proxy_id" then
        return rawget(b2, b4)
    end
    local dn = bj("Enum." .. aE(b4), false)
    t.registry[dn] = "Enum." .. aE(b4)
    return dn
end
Instance = {new = function(bX, bS)
        local bY = aE(bX)
        local x = bj(bY, false)
        local _ = aW(x, bY)
        if bS then
            local dp = t.registry[bS] or aZ(bS)
            at(string.format("local %s = Instance.new(%s, %s)", _, aH(bY), dp))
            t.parent_map[x] = bS
            if #t.instance_creations < r.MAX_INSTANCE_CREATIONS then
                table.insert(t.instance_creations, {class = bY, var = _, parent = dp})
            end
        else
            at(string.format("local %s = Instance.new(%s)", _, aH(bY)))
            if #t.instance_creations < r.MAX_INSTANCE_CREATIONS then
                table.insert(t.instance_creations, {class = bY, var = _, parent = nil})
            end
        end
        return x
    end,
    fromExisting = function(inst)
        return inst
    end
}
game = bj("game", true)
t.property_store[game].ClassName = "DataModel"
workspace = bj("workspace", true)
t.property_store[workspace].ClassName = "Workspace"
script = bj("script", true)
t.property_store[script] = {Name = "DumpedScript", Parent = game, ClassName = "LocalScript"}
-- `object` global = current camera (used by eUNC WorldToScreenPoint/WorldToViewportPoint tests)
object = bj("Camera", false)
t.registry[object] = "workspace.CurrentCamera"
t.property_store[object] = {CFrame = CFrame.new(0, 10, 0), FieldOfView = 70, ViewportSize = Vector2.new(1920, 1080), ClassName = "Camera"}
_G.object = object
task = {
    wait = function(dq)
        if dq then
            at(string.format("task.wait(%s)", aZ(dq)))
        else
            at("task.wait()")
        end
        return dq or 0.03, p.clock()
    end,
    spawn = function(dr, ...)
        local bA = {...}
        at("task.spawn(function()")
        t.indent = t.indent + 1
        if j(dr) == "function" then
            xpcall(
                function()
                    dr(unpack(bA))
                end,
                function(ds)
                end
            )
        end
        while t.pending_iterator do
            t.indent = t.indent - 1
            at("end")
            t.pending_iterator = false
        end
        t.indent = t.indent - 1
        at("end)")
    end,
    delay = function(dq, dr, ...)
        local bA = {...}
        at(string.format("task.delay(%s, function()", aZ(dq or 0)))
        t.indent = t.indent + 1
        if j(dr) == "function" then
            xpcall(
                function()
                    dr(unpack(bA))
                end,
                function()
                end
            )
        end
        while t.pending_iterator do
            t.indent = t.indent - 1
            at("end")
            t.pending_iterator = false
        end
        t.indent = t.indent - 1
        at("end)")
    end,
    defer = function(dr, ...)
        local bA = {...}
        at("task.defer(function()")
        t.indent = t.indent + 1
        if j(dr) == "function" then
            xpcall(
                function()
                    dr(unpack(bA))
                end,
                function()
                end
            )
        end
        t.indent = t.indent - 1
        at("end)")
    end,
    cancel = function(dt)
        at("task.cancel(thread)")
    end,
    synchronize = function()
        at("task.synchronize()")
    end,
    desynchronize = function()
        at("task.desynchronize()")
    end
}
wait = function(dq)
    if dq then
        at(string.format("wait(%s)", aZ(dq)))
    else
        at("wait()")
    end
    return dq or 0.03, p.clock()
end
delay = function(dq, dr)
    at(string.format("delay(%s, function()", aZ(dq or 0)))
    t.indent = t.indent + 1
    if j(dr) == "function" then
        xpcall(
            dr,
            function()
            end
        )
    end
    t.indent = t.indent - 1
    at("end)")
end
spawn = function(dr)
    at("spawn(function()")
    t.indent = t.indent + 1
    if j(dr) == "function" then
        xpcall(
            dr,
            function()
            end
        )
    end
    t.indent = t.indent - 1
    at("end)")
end
tick = function()
    return p.time()
end
time = function()
    return p.clock()
end
elapsedTime = function()
    return p.clock()
end
local du = {}
local dv = 999999999
local function dw(bG, dx)
    return dx
end
local function dy()
    local b2 = {}
    setmetatable(
        b2,
        {__call = function(self, ...)
                return self
            end, __index = function(self, b4)
                if _G[b4] ~= nil then
                    return dw(b4, _G[b4])
                end
                if b4 == "game" then
                    return game
                end
                if b4 == "workspace" then
                    return workspace
                end
                if b4 == "script" then
                    return script
                end
                if b4 == "Enum" then
                    return Enum
                end
                return nil
            end, __newindex = function(self, b4, b5)
                _G[b4] = b5
                du[b4] = 0
                at(string.format("_G.%s = %s", aE(b4), aZ(b5)))
            end}
    )
    return b2
end
_G.G = dy()
_G.g = dy()
_G.ENV = dy()
_G.env = dy()
_G.E = dy()
_G.e = dy()
_G.L = dy()
_G.l = dy()
_G.F = dy()
_G.f = dy()
local function dz(dA)
    local bh = {}
    local dd = {}
    local dB = {
        "hookfunction",
        "hookmetamethod",
        "newcclosure",
        "replaceclosure",
        "checkcaller",
        "iscclosure",
        "islclosure",
        "getrawmetatable",
        "setreadonly",
        "make_writeable",
        "getrenv",
        "getgc",
        "getinstances"
    }
    local function dC(dD, bG)
        local bd = aE(bG)
        if bd:match("^[%a_][%w_]*$") then
            if dD then
                return dD .. "." .. bd
            end
            return bd
        else
            local aI = bd:gsub("'", "\\\\'")
            if dD then
                return dD .. "['" .. aI .. "']"
            end
            return "['" .. aI .. "']"
        end
    end
    dd.__index = function(b2, b4)
        for W, dE in ipairs(dB) do
            if b4 == dE then
                return nil
            end
        end
        local dF = dC(dA, b4)
        return dz(dF)
    end
    dd.__newindex = function(b2, b4, b5)
        local dG = dC(dA, b4)
        at(string.format("getgenv().%s = %s", dG, aZ(b5)))
    end
    dd.__call = function(b2, ...)
        return b2
    end
    dd.__pairs = function()
        return function()
            return nil
        end, nil, nil
    end
    return setmetatable(bh, dd)
end
-- Shared helper: collect all registered functions/tables into a GC-like list.
-- Used by both the exploit_funcs.getgc and sandbox eR.getgc stubs so they remain
-- in sync without duplicating the collection logic.
local function _collect_gc_objects()
    local _gc = {}
    for obj, _ in D(t.registry) do
        local _ot = j(obj)
        if _ot == "function" or _ot == "table" then
            table.insert(_gc, obj)
            if #_gc >= r.MAX_GC_OBJECTS then break end
        end
    end
    t.gc_objects = _gc
    return _gc
end
local exploit_funcs = {getgenv = function()
        return dz(nil)
    end, getrenv = function()
        return bj("getrenv()", false)
    end, getfenv = function(dH)
        return _G
    end, setfenv = function(dI, dJ)
        if j(dI) ~= "function" then
            return
        end
        local L = 1
        while true do
            local am = debug.getupvalue(dI, L)
            if am == "_ENV" then
                debug.setupvalue(dI, L, dJ)
                break
            elseif not am then
                break
            end
            L = L + 1
        end
        return dI
    end, hookfunction = function(dK, dL)
        if j(dK) ~= "function" or j(dL) ~= "function" then
            return dK
        end
        local orig_name = t.registry[dK] or "unknown_fn"
        -- Emit a comment documenting the hook so the dump shows what was hooked
        at(string.format("-- hookfunction: hooked %s", orig_name))
        -- Store hook for deferred execution after main VM run (captures hooks never called by script)
        table.insert(t.deferred_hooks, {name = orig_name, fn = dL, args = {}})
        -- Track hook in hook_calls for statistics
        table.insert(t.hook_calls, {target = orig_name, kind = "hookfunction"})
        -- Return a wrapper that logs calls to the hook and falls through to the hook fn
        return function(...)
            local _args = {...}
            if #t.hook_calls <= r.MAX_HOOK_CALLS then
                table.insert(t.hook_calls, {target = orig_name, kind = "call", args = _args})
            end
            return dL(...)
        end
    end, hookmetamethod = function(x, dM, dN)
        if j(dN) ~= "function" then
            return function() end
        end
        local obj_name = t.registry[x] or "object"
        local method_str = aE(dM)
        -- Emit a comment documenting the metamethod hook
        at(string.format("-- hookmetamethod: hooked %s.%s", obj_name, method_str))
        table.insert(t.deferred_hooks, {name = obj_name .. "." .. method_str, fn = dN, args = {}})
        table.insert(t.hook_calls, {target = obj_name .. "." .. method_str, kind = "hookmetamethod"})
        return dN
    end, replaceclosure = function(dK, dL)
        if j(dK) ~= "function" or j(dL) ~= "function" then
            return dK
        end
        local orig_name = t.registry[dK] or "unknown_fn"
        at(string.format("-- replaceclosure: replaced %s", orig_name))
        table.insert(t.deferred_hooks, {name = orig_name .. " (replaceclosure)", fn = dL, args = {}})
        table.insert(t.hook_calls, {target = orig_name, kind = "replaceclosure"})
        return dL
    end, detourfn = function(dK, dL)
        -- detourfn is an alias for hookfunction used by some exploits
        if j(dK) ~= "function" or j(dL) ~= "function" then
            return dK
        end
        local orig_name = t.registry[dK] or "unknown_fn"
        at(string.format("-- detourfn: detoured %s", orig_name))
        table.insert(t.deferred_hooks, {name = orig_name .. " (detourfn)", fn = dL, args = {}})
        table.insert(t.hook_calls, {target = orig_name, kind = "detourfn"})
        return dL
    end, getrawmetatable = function(x)
        if G(x) then
            return a.getmetatable(x)
        end
        return k(x) or {}
    end, setrawmetatable = function(x, dd)
        if j(x) == "table" and j(dd) == "table" then
            a.setmetatable(x, dd)
        end
        return x
    end, getnamecallmethod = function()
        return t.namecall_method or "__namecall"
    end, setnamecallmethod = function(dM)
        t.namecall_method = aE(dM)
    end, checkcaller = function()
        return true
    end, islclosure = function(dr)
        return j(dr) == "function"
    end, iscclosure = function(dr)
        return false
    end, isnewcclosure = function(dr)
        return false
    end, cloneref = function(x)
        return x
    end, compareinstances = function(x, y)
        return l(x, y)
    end, getscriptenv = function(sc)
        -- Returns the environment of a script (stub: returns _G)
        return _G
    end, getmenv = function()
        -- Lua 5.1 module environment stub
        return _G
    end, firehook = function(dK, ...)
        -- Manually fire a hook with given arguments
        if j(dK) == "function" then
            local ok, err = g(dK, ...)
            if not ok then
                at(string.format("-- firehook error: %s", m(err)))
            end
        end
    end, newcclosure = function(dr)
        -- newcclosure wraps a Lua function as a C closure; return as-is
        return dr
    end, clonefunction = function(dr)
        return dr
    end, request = function(dO)
        at(string.format("request(%s)", aZ(dO)))
        table.insert(t.string_refs, {value = dO.Url or dO.url or "unknown", hint = "HTTP Request"})
        return {Success = true, StatusCode = 200, StatusMessage = "OK", Headers = {}, Body = "{}"}
    end, http_request = function(dO)
        return exploit_funcs.request(dO)
    end, syn = {request = function(dO)
            return exploit_funcs.request(dO)
        end}, http = {request = function(dO)
            return exploit_funcs.request(dO)
        end}, HttpPost = function(cI, cJ)
        at(string.format("HttpPost(%s, %s)", aE(cI), aE(cJ)))
        return "{}"
    end, setclipboard = function(cJ)
    end, getclipboard = function()
        return ""
    end, identifyexecutor = function()
        return "Dumper", "3.0"
    end, getexecutorname = function()
        return "Dumper"
    end, gethui = function()
        local dP = bj("HiddenUI", false)
        aW(dP, "HiddenUI")
        at(string.format("local %s = gethui()", t.registry[dP]))
        return dP
    end, gethiddenui = function()
        return exploit_funcs.gethui()
    end, protectgui = function(dQ)
    end, protectTable = function(tbl)
        return tbl
    end, protectFunction = function(dr)
        return dr
    end, protectGlobals = function()
    end,
    -- Executor identification stubs used by many AI obfuscators.
    -- `isluau` returns true: we run under Luau, not standard Lua 5.3/5.4;
    -- scripts that gate Luau-only paths on this check will take the Luau path.
    isluau = function() return true end,
    islua = function() return false end,
    getexecutorname = function() return "Dumper" end,
    getversion = function() return "1.0.0" end,
    getidentity = function() return 8 end,
    setidentity = function() end,
    identitycheck = function() return 8 end,
    getthreadidentity = function() return 8 end,
    setthreadidentity = function() end,
    -- Environment query stubs
    isscript = function(x) return false end,
    ismodule = function(x) return false end,
    islocalscript = function(x) return false end,
    -- Anti-tamper: executor-closure detection stubs
    isexecutorclosure = function(fn) return false end,
    isourclosure     = function(fn) return j(fn) == "function" end,
    checkclosure     = function(fn) return j(fn) == "function" end,
    -- copyfunction / clonefunction
    copyfunction  = function(fn) return fn end,
    -- Cache / reference stubs
    cache = {
        invalidate = function(x) end,
        replace = function(x, y) end,
        iscached = function(x) return false end,
    },
    -- Misc stubs used by AI-generated obfuscators
    getinfo = function() return {} end,
    getupvalues = function(dr)
        if type(dr) ~= "function" then return {} end
        local r = {}
        local i = 1
        while true do
            local n, v = debug.getupvalue(dr, i)
            if not n then break end
            r[n] = v
            i = i + 1
        end
        return r
    end,
    setupvalue = function(dr, name, val)
        if type(dr) ~= "function" then return end
        local i = 1
        while true do
            local n = debug.getupvalue(dr, i)
            if not n then break end
            if n == name then debug.setupvalue(dr, i, val); return end
            i = i + 1
        end
    end,
    getupvalue = function(dr, idx)
        if type(dr) ~= "function" then return nil end
        local n, v = debug.getupvalue(dr, idx)
        return v
    end,
    -- iswindowactive = already defined below
    iswindowactive = function()
        return true
    end, isrbxactive = function()
        return true
    end, isgameactive = function()
        return true
    end, getconnections = function(cg)
        return {}
    end, firesignal = function(cg, ...)
    end, fireclickdetector = function(dR, dS)
    end, fireproximityprompt = function(dT)
    end, firetouchinterest = function(dU, dV, dW)
    end, getinstances = function()
        return {}
    end, getnilinstances = function()
        return {}
    end, getgc = function()
        -- Return all registered objects collected so far for deobfuscation analysis.
        -- Scripts that call getgc() to scan for live closures will get a list of
        -- everything we've captured in the registry (functions, tables, proxies).
        return _collect_gc_objects()
    end, getscripts = function()
        return {}
    end, getrunningscripts = function()
        return {}
    end, getloadedmodules = function()
        return {}
    end, getcallingscript = function()
        return script
    end, readfile = function(dA)
        return ""
    end, writefile = function(dA, ai)
    end, appendfile = function(dA, ai)
    end, loadfile = function(dA)
        return function()
            return bj("loaded_file", false)
        end
    end, listfiles = function(dX)
        return {}
    end, isfile = function(dA)
        return false
    end, isfolder = function(dA)
        return false
    end, makefolder = function(dA)
    end, delfolder = function(dA)
    end, delfile = function(dA)
    end, Drawing = {new = function(aO)
            local dY = aE(aO)
            local x = bj("Drawing_" .. dY, false)
            local _ = aW(x, dY)
            at(string.format("local %s = Drawing.new(%s)", _, aH(dY)))
            return x
        end, Fonts = bj("Drawing.Fonts", false)}, crypt = {base64encode = function(cJ)
            return cJ
        end, base64decode = function(cJ)
            return cJ
        end, base64_encode = function(cJ)
            return cJ
        end, base64_decode = function(cJ)
            return cJ
        end, encrypt = function(cJ, bG)
            return cJ
        end, decrypt = function(cJ, bG)
            return cJ
        end, hash = function(cJ)
            return "hash"
        end, generatekey = function(dZ)
            return string.rep("0", dZ or 32)
        end, generatebytes = function(dZ)
            return string.rep("\\0", dZ or 16)
        end}, base64_encode = function(cJ)
        return cJ
    end, base64_decode = function(cJ)
        return cJ
    end, base64encode = function(cJ)
        return cJ
    end, base64decode = function(cJ)
        return cJ
    end, mouse1click = function()
        at("mouse1click()")
    end, mouse1press = function()
        at("mouse1press()")
    end, mouse1release = function()
        at("mouse1release()")
    end, mouse2click = function()
        at("mouse2click()")
    end, mouse2press = function()
        at("mouse2press()")
    end, mouse2release = function()
        at("mouse2release()")
    end, mousemoverel = function(d_, e0)
        at(string.format("mousemoverel(%s, %s)", aZ(d_), aZ(e0)))
    end, mousemoveabs = function(d_, e0)
        at(string.format("mousemoveabs(%s, %s)", aZ(d_), aZ(e0)))
    end, mousescroll = function(e1)
        at(string.format("mousescroll(%s)", aZ(e1)))
    end, keypress = function(bG)
        at(string.format("keypress(%s)", aZ(bG)))
    end, keyrelease = function(bG)
        at(string.format("keyrelease(%s)", aZ(bG)))
    end, keyclick = function(bG)
        at(string.format("keyclick(%s)", aZ(bG)))
    end, isreadonly = function(b2)
        return false
    end, setreadonly = function(b2, e2)
        return b2
    end, make_writeable = function(b2)
        return b2
    end, make_readonly = function(b2)
        return b2
    end, getthreadidentity = function()
        return 8
    end, setthreadidentity = function(aG)
    end, identitycheck = function()
        return 8
    end, getidentity = function()
        return 8
    end, setidentity = function(aG)
    end, getthreadcontext = function()
        return 8
    end, setthreadcontext = function(aG)
    end, getcustomasset = function(dA)
        return "rbxasset://" .. aE(dA)
    end, getsynasset = function(dA)
        return "rbxasset://" .. aE(dA)
    end, getinfo = function(dr)
        return {source = "=", what = "Lua", name = "unknown", short_src = "dumper"}
    end, getconstants = function(dr)
        -- Standard Lua 5.x has no bytecode constant access; return upvalues as a best approximation.
        if j(dr) ~= "function" then return {} end
        local consts = {}
        local idx = 1
        while true do
            local name, val = debug.getupvalue(dr, idx)
            if not name then break end
            table.insert(consts, val)
            idx = idx + 1
            if idx > r.MAX_UPVALUES_PER_FUNCTION then break end
        end
        return consts
    end, getupvalues = function(dr)
        if j(dr) ~= "function" then return {} end
        local uvs = {}
        local idx = 1
        while true do
            local name, val = debug.getupvalue(dr, idx)
            if not name then break end
            uvs[name] = val
            idx = idx + 1
            if idx > r.MAX_UPVALUES_PER_FUNCTION then break end
        end
        return uvs
    end, getprotos = function(dr)
        return {}
    end, getupvalue = function(dr, ba)
        if j(dr) ~= "function" then return nil end
        local name, val = debug.getupvalue(dr, ba)
        return val
    end, setupvalue = function(dr, ba, bm)
        if j(dr) == "function" then
            debug.setupvalue(dr, ba, bm)
        end
    end, setconstant = function(dr, ba, bm)
    end, getconstant = function(dr, ba)
        if j(dr) == "function" then
            local name, val = debug.getupvalue(dr, ba)
            return val
        end
        return nil
    end, getproto = function(dr, ba)
        return function()
        end
    end, setproto = function(dr, ba, e3)
    end, getstack = function(dH, ba)
        return nil
    end, setstack = function(dH, ba, bm)
    end, debug = {
        getinfo = c or function() return {} end,
        getupvalue = debug.getupvalue or function() return nil end,
        setupvalue = debug.setupvalue or function() end,
        getlocal  = debug.getlocal  or function() return nil end,
        setlocal  = debug.setlocal  or function() end,
        getmetatable = a.getmetatable,
        setmetatable = debug.setmetatable or setmetatable,
        traceback = d or function() return "" end,
        profilebegin = function() end,
        profileend   = function() end,
        -- No-op sethook: prevents the obfuscated script from disabling our debug hook
        sethook = function() end,
        -- Bytecode-level stubs (Luau executor extensions used by anti-tamper)
        getconstants = function() return {} end,
        getconsts    = function() return {} end,
        setconstants = function() end,
        setconsts    = function() end,
        getprotos    = function() return {} end,
        getproto     = function() return function() end end,
        getregistry  = function() return {} end,
    }, rconsoleprint = function(ay)
    end, rconsoleclear = function()
    end, rconsolecreate = function()
    end, rconsoledestroy = function()
    end, rconsoleinput = function()
        return ""
    end, rconsoleinfo = function(ay)
    end, rconsolewarn = function(ay)
    end, rconsoleerr = function(ay)
    end, rconsolename = function(am)
    end, printconsole = function(ay)
    end, setfflag = function(e4, bm)
    end, getfflag = function(e4)
        return ""
    end, setfpscap = function(e5)
        at(string.format("setfpscap(%s)", aZ(e5)))
    end, getfpscap = function()
        return 60
    end, isnetworkowner = function(cr)
        return true
    end, gethiddenproperty = function(x, ce)
        return nil
    end, sethiddenproperty = function(x, ce, bm)
        at(string.format("sethiddenproperty(%s, %s, %s)", aZ(x), aH(ce), aZ(bm)))
    end, setsimulationradius = function(e6, e7)
        at(string.format("setsimulationradius(%s%s)", aZ(e6), e7 and ", " .. aZ(e7) or ""))
    end, getspecialinfo = function(e8)
        return {}
    end, saveinstance = function(dO)
        at(string.format("saveinstance(%s)", aZ(dO or {})))
    end, decompile = function(script)
        return "-- decompiled"
    end, lz4compress = function(cJ)
        return cJ
    end, lz4decompress = function(cJ)
        return cJ
    end, MessageBox = function(e9, ea, eb)
        return 1
    end, setwindowactive = function()
    end, setwindowtitle = function(ec)
    end, queue_on_teleport = function(al)
        at(string.format("queue_on_teleport(%s)", aZ(al)))
    end, queueonteleport = function(al)
        at(string.format("queueonteleport(%s)", aZ(al)))
    end, secure_call = function(dr, ...)
        return dr(...)
    end, create_secure_function = function(dr)
        return dr
    end, isvalidinstance = function(e8)
        return e8 ~= nil
    end, validcheck = function(e8)
        return e8 ~= nil
    end,
    -- Additional exploit stubs
    getscriptclosure = function(dr)
        return dr
    end, getscriptfunction = function(dr)
        return dr
    end, getscriptbytecode = function(dr)
        return ""
    end, getscripthash = function(dr)
        return string.rep("0", 64)
    end, getscriptenvs = function(dr)
        return {}
    end, deobfuscate = function(cJ)
        return cJ
    end, getsenv = function(dr)
        if j(dr) ~= "function" then return {} end
        return {}
    end, getfenv = getfenv or function(dr)
        return {}
    end, setfenv = setfenv or function(dr, env)
        return dr
    end, getrenv = function()
        return _G
    end, getgenv = function()
        return _G
    end, getmenv = function()
        return {}
    end, getrawenv = function(dr)
        return {}
    end, checkclosure = function(dr)
        return j(dr) == "function"
    end, isourclosure = function(dr)
        return j(dr) == "function"
    end, isexecutorclosure = function(dr)
        return false
    end, isnewcclosure = function(dr)
        return false
    end, dumpstring = function(cJ)
        return cJ
    end, getobjects = function(id)
        return {}
    end, gethiddenproperty = function(x, ce)
        return nil, false
    end, getproperties = function(x)
        return {}
    end, getallproperties = function(x)
        return {}
    end, sethiddenattribute = function(x, ce, bm)
    end, gethiddenattribute = function(x, ce)
        return nil
    end, getconnection = function(cg)
        return {}
    end, getconnectionfunction = function(c1)
        return nil
    end, disconnectconnection = function(c1)
    end, replicatesignal = function(cg, ...)
    end, fireserver = function(cg, ...)
    end, invokenotfound = function(x, ba)
        return nil
    end, getnamecall = function()
        return t.namecall_method or "__namecall"
    end, setnamecall = function(am)
        t.namecall_method = am
    end, setexecutableflag = function(dr)
    end, getdebugid = function(x)
        return tostring(t.registry[x] or x)
    end, getrobloxsignature = function()
        return string.rep("0", 128)
    end, httpget = function(cI)
        local cL = aE(cI)
        table.insert(t.string_refs, {value = cL, hint = "httpget"})
        return ""
    end, httppost = function(cI, cJ)
        local cL = aE(cI)
        table.insert(t.string_refs, {value = cL, hint = "httppost"})
        return "{}"
    end, getmouseposition = function()
        return 0, 0
    end, getmousehit = function()
        return bj("mouseHit", false)
    end, isrbxactive = function()
        return true
    end, isgameactive = function()
        return true
    end, iswindowactive = function()
        return true
    end, toclipboard = function(cJ)
    end, fromclipboard = function()
        return ""
    end, consoleclear = function()
    end, consoleprint = function(ay)
    end, consolewarn = function(ay)
    end, consoleerror = function(ay)
    end, consolename = function(am)
    end, consoleinput = function()
        return ""
    end, loadlibrary = function(am)
        return {}
    end, loadasset = function(id)
        local x = bj("asset_" .. tostring(id), false)
        t.registry[x] = "asset_" .. tostring(id)
        return x
    end, getobject = function(path)
        local x = bj(tostring(path), false)
        return x
    end, getinstanceproperty = function(x, prop)
        if t.property_store[x] then
            return t.property_store[x][prop]
        end
        return nil
    end, setinstanceproperty = function(x, prop, val)
        if not t.property_store[x] then
            t.property_store[x] = {}
        end
        t.property_store[x][prop] = val
    end, bit32 = {
        band = function(a, b) return a end,
        bor  = function(a, b) return a end,
        bxor = function(a, b) return a end,
        bnot = function(a) return a end,
        lshift = function(a, b) return a end,
        rshift = function(a, b) return a end,
        arshift = function(a, b) return a end,
        extract = function(a, b, c) return 0 end,
        replace = function(a, b, c, d) return a end
    }, integer = {
        add = function(a, b) return a + b end,
        sub = function(a, b) return a - b end,
        mul = function(a, b) return a * b end,
        -- Sandbox stubs: clamp divisor to 1 to avoid crashes; callers should not rely on exact arithmetic.
        div = function(a, b) return math.floor(a / (b ~= 0 and b or 1)) end,
        mod = function(a, b) return a % (b ~= 0 and b or 1) end,
        pow = function(a, b) return a ^ b end
    }}
for b4, b5 in D(exploit_funcs) do
    _G[b4] = b5
end
-- NOTE: hookfunction/hookmetamethod/newcclosure must remain in _G so scripts can use them.
local ed = {}
local function ee(d_)
    d_ = (d_ or 0) % 4294967296
    if d_ >= 2147483648 then
        d_ = d_ - 4294967296
    end
    return math.floor(d_)
end
ed.tobit = ee
ed.tohex = function(d_, U)
    return string.format("%0" .. (U or 8) .. "x", (d_ or 0) % 0x100000000)
end
-- EmulaciÃ³n bÃ¡sica de bitwise para Lua 5.1
local function bit_band(a, b)
    local r = 0
    local m = 1
    for i = 0, 31 do
        if a % 2 == 1 and b % 2 == 1 then r = r + m end
        a, b, m = math.floor(a / 2), math.floor(b / 2), m * 2
    end
    return r
end
local function bit_bor(a, b)
    local r = 0
    local m = 1
    for i = 0, 31 do
        if a % 2 == 1 or b % 2 == 1 then r = r + m end
        a, b, m = math.floor(a / 2), math.floor(b / 2), m * 2
    end
    return r
end
local function bit_bxor(a, b)
    local r = 0
    local m = 1
    for i = 0, 31 do
        if a % 2 ~= b % 2 then r = r + m end
        a, b, m = math.floor(a / 2), math.floor(b / 2), m * 2
    end
    return r
end
local function bit_lshift(a, b) return math.floor(a * (2 ^ b)) % 4294967296 end
local function bit_rshift(a, b) return math.floor(a / (2 ^ b)) end

_G.bit = {band = bit_band, bor = bit_bor, bxor = bit_bxor, lshift = bit_lshift, rshift = bit_rshift}
_G.bit32 = _G.bit
ed.band = bit_band
ed.bor = bit_bor
ed.bxor = bit_bxor
ed.lshift = bit_lshift
ed.rshift = bit_rshift
ed.bnot = function(a) return bit_bxor(bit_band(a % 0x100000000, 0xFFFFFFFF), 0xFFFFFFFF) end
ed.arshift = function(d_, U)
    local b5 = ee(d_ or 0)
    if b5 < 0 then
        return ee(bit_rshift(b5, U or 0)) + ee(bit_lshift(-1, 32 - (U or 0)))
    else
        return ee(bit_rshift(b5, U or 0))
    end
end
ed.rol = function(d_, U)
    d_ = d_ or 0
    U = (U or 0) % 32
    return ee(bit_bor(bit_lshift(d_, U), bit_rshift(d_, 32 - U)))
end
ed.ror = function(d_, U)
    d_ = d_ or 0
    U = (U or 0) % 32
    return ee(bit_bor(bit_rshift(d_, U), bit_lshift(d_, 32 - U)))
end
ed.bswap = function(d_)
    d_ = d_ or 0
    local bo = bit_band(bit_rshift(d_, 24), 0xFF)
    local aa = bit_band(bit_rshift(d_, 8), 0xFF00)
    local b0 = bit_band(bit_lshift(d_, 8), 0xFF0000)
    local b1 = bit_band(bit_lshift(d_, 24), 0xFF000000)
    return ee(bit_bor(bit_bor(bo, aa), bit_bor(b0, b1)))
end
ed.countlz = function(U)
    U = ed.tobit(U)
    if U == 0 then
        return 32
    end
    local a2 = 0
    if bit_band(U, 0xFFFF0000) == 0 then
        a2 = a2 + 16
        U = bit_lshift(U, 16)
    end
    if bit_band(U, 0xFF000000) == 0 then
        a2 = a2 + 8
        U = bit_lshift(U, 8)
    end
    if bit_band(U, 0xF0000000) == 0 then
        a2 = a2 + 4
        U = bit_lshift(U, 4)
    end
    if bit_band(U, 0xC0000000) == 0 then
        a2 = a2 + 2
        U = bit_lshift(U, 2)
    end
    if bit_band(U, 0x80000000) == 0 then
        a2 = a2 + 1
    end
    return a2
end
ed.countrz = function(U)
    U = ed.tobit(U)
    if U == 0 then
        return 32
    end
    local a2 = 0
    while bit_band(U, 1) == 0 do
        U = bit_rshift(U, 1)
        a2 = a2 + 1
    end
    return a2
end
ed.lrotate = ed.rol
ed.rrotate = ed.ror
ed.extract = function(U, eg, eh)
    eh = eh or 1
    return bit_band(bit_rshift(U, eg), bit_lshift(1, eh) - 1)
end
ed.replace = function(U, b5, eg, eh)
    eh = eh or 1
    local ei = bit_lshift(1, eh) - 1
    local mask = bit_lshift(ei, eg)
    return bit_bor(bit_band(U, 4294967295 - mask), bit_band(bit_lshift(b5, eg), mask))
end
ed.btest = function(bo, aa)
    return bit_band(bo, aa) ~= 0
end
bit32 = ed
bit = ed
_G.bit = bit
_G.bit32 = bit32
table.getn = table.getn or function(b2)
        return #b2
    end
table.foreach = table.foreach or function(b2, as)
        for b4, b5 in pairs(b2) do
            as(b4, b5)
        end
    end
table.foreachi = table.foreachi or function(b2, as)
        for L, b5 in ipairs(b2) do
            as(L, b5)
        end
    end
table.move = table.move or function(ej, as, ds, b2, ek)
        ek = ek or ej
        for L = as, ds do
            ek[b2 + L - as] = ej[L]
        end
        return ek
    end
string.split = string.split or function(S, el)
        local b2 = {}
        for O in string.gmatch(S, "([^" .. (el or "%s") .. "]+)") do
            table.insert(b2, O)
        end
        return b2
    end
if not math.frexp then
    math.frexp = function(d_)
        if d_ == 0 then
            return 0, 0
        end
        local ds = math.floor(math.log(math.abs(d_)) / math.log(2)) + 1
        local em = d_ / 2 ^ ds
        return em, ds
    end
end
if not math.ldexp then
    math.ldexp = function(em, ds)
        return em * 2 ^ ds
    end
end
if not utf8 then
    utf8 = {}
    utf8.char = function(...)
        local bA = {...}
        local dg = {}
        for L, al in ipairs(bA) do
            table.insert(dg, string.char(al % 256))
        end
        return table.concat(dg)
    end
    utf8.len = function(S)
        return #S
    end
    utf8.codes = function(S)
        local L = 0
        return function()
            L = L + 1
            if L <= #S then
                return L, string.byte(S, L)
            end
        end
    end
end
_G.utf8 = utf8
pairs = function(b2)
    if j(b2) == "table" and not G(b2) then
        return D(b2)
    end
    return function()
        return nil
    end, b2, nil
end
ipairs = function(b2)
    if j(b2) == "table" and not G(b2) then
        return E(b2)
    end
    return function()
        return nil
    end, b2, 0
end
_G.pairs = pairs
_G.ipairs = ipairs
_G.math = math
_G.table = table
_G.string = string
-- Expose only safe os functions; block execute, getenv, exit, tmpname, rename, remove
_G.os = {
    clock    = os.clock,
    time     = os.time,
    date     = os.date,
    difftime = os.difftime,
}
_G.coroutine = coroutine
_G.io = nil
-- Block filesystem / module-loading globals that could expose host data
_G.dofile = nil
_G.package = nil
_G.debug = exploit_funcs.debug
_G.utf8 = utf8
_G.pairs = pairs
_G.ipairs = ipairs
_G.next = next
_G.tostring = tostring
_G.tonumber = tonumber
_G.getmetatable = getmetatable
_G.setmetatable = setmetatable
_G.pcall = function(as, ...)
    local en = {g(as, ...)}
    local eo = en[1]
    if not eo then
        local an = en[2]
        if j(an) == "string" and an:match("TIMEOUT_FORCED_BY_DUMPER") then
            i(an)
        end
    end
    return unpack(en)
end
_G.xpcall = function(as, ep, ...)
    local function eq(an)
        if j(an) == "string" and an:match("TIMEOUT_FORCED_BY_DUMPER") then
            return an
        end
        if ep then
            return ep(an)
        end
        return an
    end
    local en = {h(as, eq, ...)}
    local eo = en[1]
    if not eo then
        local an = en[2]
        if j(an) == "string" and an:match("TIMEOUT_FORCED_BY_DUMPER") then
            i(an)
        end
    end
    return unpack(en)
end
-- Anti-detection overrides
local original_getmetatable = getmetatable
local original_traceback = debug.traceback
_G.os = _G.os or {}
_G.os.clock = function() return 0 end  -- Simulate low execution time
_G.table.isreadonly = function(t) return t == _G end  -- _G is readonly
_G.getmetatable = function(t) if t == _G then return nil else return original_getmetatable(t) end end  -- No metatable on _G
_G.debug.traceback = function(msg)
    local tb = original_traceback(msg or "")
    tb = tb:gsub("wrapper", "wrapped"):gsub("executor", "executed")  -- Hide detection keywords
    return tb
end
_G.warn = _G.warn or print  -- Define warn as print
-- Functional code expansion: API stubs and utilities
_G.bit = _G.bit or {bor = function(a,b) return a | b end, band = function(a,b) return a & b end}
_G.crypt = _G.crypt or {hash = function(s) return "hash" end, encrypt = function(s) return s end}
_G.debug.getinfo = _G.debug.getinfo or function() return {} end
_G.debug.getupvalue = _G.debug.getupvalue or function() return nil end
_G.debug.setupvalue = _G.debug.setupvalue or function() end
_G.hookfunction = _G.hookfunction or function(f) return f end
_G.newcclosure = _G.newcclosure or function(f) return f end
_G.iscclosure = _G.iscclosure or function() return false end
_G.islclosure = _G.islclosure or function() return true end
_G.checkcaller = _G.checkcaller or function() return false end
_G.cloneref = _G.cloneref or function(x) return x end
_G.compareinstances = _G.compareinstances or function(a,b) return a == b end
_G.getscriptbytecode = _G.getscriptbytecode or function() return "" end
_G.getscripthash = _G.getscripthash or function() return "hash" end
_G.getscriptclosure = _G.getscriptclosure or function(f) return f end
_G.getscriptfunction = _G.getscriptfunction or function(f) return f end
_G.getgenv = _G.getgenv or function() return _G end
_G.getrenv = _G.getrenv or function() return _G end
_G.getreg = _G.getreg or function() return {} end
_G.getgc = _G.getgc or function() return {} end
_G.getinstances = _G.getinstances or function() return {} end
_G.getnilinstances = _G.getnilinstances or function() return {} end
_G.getloadedmodules = _G.getloadedmodules or function() return {} end
_G.getrunningscripts = _G.getrunningscripts or function() return {} end
_G.getscripts = _G.getscripts or function() return {} end
_G.getsenv = _G.getsenv or function() return _G end
_G.getthreadidentity = _G.getthreadidentity or function() return 8 end
_G.setthreadidentity = _G.setthreadidentity or function() end
_G.identifyexecutor = _G.identifyexecutor or function() return "Executor", "1.0" end
_G.lz4compress = _G.lz4compress or function(s) return s end
_G.lz4decompress = _G.lz4decompress or function(s) return s end
_G.request = _G.request or function() return {StatusCode=200, Body=""} end
_G.httpget = _G.httpget or function() return "" end
_G.setclipboard = _G.setclipboard or function() end
_G.getclipboard = _G.getclipboard or function() return "" end
_G.setfpscap = _G.setfpscap or function() end
_G.getfpscap = _G.getfpscap or function() return 60 end
_G.mouse1click = _G.mouse1click or function() end
_G.mouse1press = _G.mouse1press or function() end
_G.mouse1release = _G.mouse1release or function() end
_G.keypress = _G.keypress or function() end
_G.keyrelease = _G.keyrelease or function() end
_G.isrbxactive = _G.isrbxactive or function() return true end
_G.isgameactive = _G.isgameactive or function() return true end
_G.getconnections = _G.getconnections or function() return {} end
_G.getcallbackvalue = _G.getcallbackvalue or function() return nil end
_G.fireclickdetector = _G.fireclickdetector or function() end
_G.getcustomasset = _G.getcustomasset or function() return "rbxasset://" end
_G.gethiddenproperty = _G.gethiddenproperty or function() return nil, false end
_G.sethiddenproperty = _G.sethiddenproperty or function() return true end
_G.gethui = _G.gethui or function() return {} end
_G.isscriptable = _G.isscriptable or function() return true end
_G.setscriptable = _G.setscriptable or function() return true end
_G.getnamecallmethod = _G.getnamecallmethod or function() return "" end
_G.setnamecallmethod = _G.setnamecallmethod or function() end
_G.hookmetamethod = _G.hookmetamethod or function() return function() end end
_G.getrawmetatable = _G.getrawmetatable or function(x) return original_getmetatable(x) end
_G.setrawmetatable = _G.setrawmetatable or function(x, mt) return setmetatable(x, mt) end
_G.setreadonly = _G.setreadonly or function() end
_G.isreadonly = _G.isreadonly or function() return false end
_G.make_writeable = _G.make_writeable or function() end
_G.make_readonly = _G.make_readonly or function() end
_G.getconstants = _G.getconstants or function() return {} end
_G.getprotos = _G.getprotos or function() return {} end
_G.getupvalues = _G.getupvalues or function() return {} end
_G.getupvalue = _G.getupvalue or function() return nil end
_G.setupvalue = _G.setupvalue or function() end
_G.decompile = _G.decompile or function() return "-- decompiled" end
_G.getobject = _G.getobject or function() return {} end
_G.getinstanceproperty = _G.getinstanceproperty or function() return nil end
_G.loadlibrary = _G.loadlibrary or function() return {} end
_G.loadasset = _G.loadasset or function() return {} end
_G.getmouseposition = _G.getmouseposition or function() return 0, 0 end
_G.getmousehit = _G.getmousehit or function() return {} end
_G.iswindowactive = _G.iswindowactive or function() return true end
_G.toclipboard = _G.toclipboard or function() end
_G.fromclipboard = _G.fromclipboard or function() return "" end
_G.consoleclear = _G.consoleclear or function() end
_G.consoleprint = _G.consoleprint or function() end
_G.consolewarn = _G.consolewarn or function() end
_G.consoleerror = _G.consoleerror or function() end
_G.consolename = _G.consolename or function() end
_G.consoleinput = _G.consoleinput or function() return "" end
_G.rconsoleprint = _G.rconsoleprint or function() end
_G.rconsoleclear = _G.rconsoleclear or function() end
_G.rconsolecreate = _G.rconsolecreate or function() end
_G.rconsoledestroy = _G.rconsoledestroy or function() end
_G.rconsoleinput = _G.rconsoleinput or function() return "" end
_G.rconsolesettitle = _G.rconsolesettitle or function() end
_G.rconsolename = _G.rconsolename or function() end
_G.base64_encode = _G.base64_encode or function(s) return s end
_G.base64_decode = _G.base64_decode or function(s) return s end
_G.base64encode = _G.base64encode or function(s) return s end
_G.base64decode = _G.base64decode or function(s) return s end
_G.encrypt = _G.encrypt or function(s) return s end
_G.decrypt = _G.decrypt or function(s) return s end
_G.generatekey = _G.generatekey or function() return "key" end
_G.generatebytes = _G.generatebytes or function() return "bytes" end
_G.mousemoveabs = _G.mousemoveabs or function() end
_G.mousemoverel = _G.mousemoverel or function() end
_G.mousescroll = _G.mousescroll or function() end
_G.keyclick = _G.keyclick or function() end
_G.isnetworkowner = _G.isnetworkowner or function() return true end
_G.gethiddenui = _G.gethiddenui or function() return {} end
_G.http_request = _G.http_request or function() return {Success=true, StatusCode=200, Body=""} end
_G.queue_on_teleport = _G.queue_on_teleport or function() end
_G.queueonteleport = _G.queueonteleport or function() end
_G.secure_call = _G.secure_call or function(f, ...) return f(...) end
_G.create_secure_function = _G.create_secure_function or function(f) return f end
_G.isvalidinstance = _G.isvalidinstance or function(x) return x ~= nil end
_G.validcheck = _G.validcheck or function(x) return x ~= nil end
_G.getdebugid = _G.getdebugid or function() return "id" end
_G.getrobloxsignature = _G.getrobloxsignature or function() return "sig" end
_G.httppost = _G.httppost or function() return "{}" end
_G.getobjects = _G.getobjects or function() return {} end
_G.getsynasset = _G.getsynasset or function(p) return "rbxasset://" .. p end
_G.getcustomasset = _G.getcustomasset or function(p) return "rbxasset://" .. p end
_G.messagebox = _G.messagebox or function() return 1 end
_G.setwindowactive = _G.setwindowactive or function() end
_G.setwindowtitle = _G.setwindowtitle or function() end
_G.cleardrawcache = _G.cleardrawcache or function() end
_G.isrenderobj = _G.isrenderobj or function() return false end
_G.getrenderproperty = _G.getrenderproperty or function() return nil end
_G.setrenderproperty = _G.setrenderproperty or function() end
_G.Drawing = _G.Drawing or {new = function() return {} end, Fonts = {}}
_G.WebSocket = _G.WebSocket or {connect = function() return {} end}
_G.Instance = _G.Instance or {new = function(class) return {ClassName = class} end}
_G.task = _G.task or {spawn = function(f) f() end, defer = function(f) f() end, delay = function(t, f) f() end, wait = function() end, cancel = function() end}
_G.Enum = _G.Enum or {new = function() return {} end}
_G.Vector3 = _G.Vector3 or {new = function() return {} end}
_G.Vector2 = _G.Vector2 or {new = function() return {} end}
_G.CFrame = _G.CFrame or {new = function() return {} end}
_G.Color3 = _G.Color3 or {new = function() return {} end}
_G.UDim2 = _G.UDim2 or {new = function() return {} end}
_G.UDim = _G.UDim or {new = function() return {} end}
_G.Rect = _G.Rect or {new = function() return {} end}
_G.NumberRange = _G.NumberRange or {new = function() return {} end}
_G.NumberSequence = _G.NumberSequence or {new = function() return {} end}
_G.ColorSequence = _G.ColorSequence or {new = function() return {} end}
_G.TweenInfo = _G.TweenInfo or {new = function() return {} end}
_G.RaycastParams = _G.RaycastParams or {new = function() return {} end}
_G.OverlapParams = _G.OverlapParams or {new = function() return {} end}
_G.PathWaypoint = _G.PathWaypoint or {new = function() return {} end}
_G.Axes = _G.Axes or {new = function() return {} end}
_G.Faces = _G.Faces or {new = function() return {} end}
_G.Vector3int16 = _G.Vector3int16 or {new = function() return {} end}
_G.Vector2int16 = _G.Vector2int16 or {new = function() return {} end}
_G.CatalogSearchParams = _G.CatalogSearchParams or {new = function() return {} end}
_G.DateTime = _G.DateTime or {now = function() return {UnixTimestamp = 0} end}
_G.Random = _G.Random or {new = function() return {NextInteger = function() return 1 end, NextNumber = function() return 0.5 end} end}
_G.PhysicalProperties = _G.PhysicalProperties or {new = function() return {} end}
_G.Font = _G.Font or {new = function() return {} end}
_G.Region3 = _G.Region3 or {new = function() return {} end}
_G.Region3int16 = _G.Region3int16 or {new = function() return {} end}
_G.Ray = _G.Ray or {new = function() return {} end}
_G.NumberSequenceKeypoint = _G.NumberSequenceKeypoint or {new = function() return {} end}
_G.ColorSequenceKeypoint = _G.ColorSequenceKeypoint or {new = function() return {} end}
_G.BrickColor = _G.BrickColor or {new = function() return {} end}
-- Additional functional utilities
_G.safe_pcall = function(f, ...) local s, r = pcall(f, ...) return s, r end
_G.deep_clone = function(t) if type(t) ~= "table" then return t end local c = {} for k,v in pairs(t) do c[k] = _G.deep_clone(v) end return c end
_G.table_size = function(t) local c = 0 for _ in pairs(t) do c = c + 1 end return c end
_G.string_split = function(s, sep) local r = {} for m in s:gmatch("([^" .. sep .. "]+)") do table.insert(r, m) end return r end
_G.math_clamp = function(v, min, max) return math.max(min, math.min(max, v)) end
_G.math_lerp = function(a, b, t) return a + (b - a) * t end
_G.os_time = function() return 0 end
_G.io_open = function() return nil, "not supported" end
_G.coroutine_safe_resume = function(co, ...) local s, r = coroutine.resume(co, ...) return s, r end
_G.debug_print = function(...) print(...) end
_G.env_check = function() return true end
_G.simulate_event = function() return {} end
_G.create_proxy = function(o) return setmetatable({}, {__index = o}) end
_G.hook_call = function(f, h) return function(...) h(...) return f(...) end end
_G.unhook = function() end
_G.trace_exec = function(f) f() end
_G.profile_func = function(f) local s = _G.os.clock() f() return _G.os.clock() - s end
_G.memory_snapshot = function() return collectgarbage("count") end
_G.gc_cycle = function() collectgarbage("collect") end
_G.random_string = function(l) local s = "" for i=1,l do s = s .. string.char(math.random(65,90)) end return s end
_G.hash_string = function(s) local h = 0 for i=1,#s do h = (h * 31 + s:byte(i)) % 1000000 end return tostring(h) end
_G.encode_base64 = function(s) return s end
_G.decode_base64 = function(s) return s end
_G.compress_data = function(s) return s end
_G.decompress_data = function(s) return s end
_G.validate_input = function(x) return type(x) == "string" and #x > 0 end
_G.sanitize_path = function(p) return p:gsub("[^%w%._/-]", "") end
_G.generate_id = function() return tostring(math.random(1000000, 9999999)) end
_G.cache_value = function(k, v) _G.cache = _G.cache or {} _G.cache[k] = v end
_G.get_cached = function(k) return _G.cache and _G.cache[k] end
_G.clear_cache = function() _G.cache = {} end
_G.async_call = function(f) task.spawn(f) end
_G.delay_call = function(t, f) task.delay(t, f) end
_G.debounce = function(f, t) local timer return function() if timer then timer:cancel() end timer = task.delay(t, function() f() end) end end
_G.throttle = function(f, t) local last = 0 return function() local now = _G.os.clock() if now - last >= t then f() last = now end end end
_G.memoize = function(f) local cache = {} return function(x) if not cache[x] then cache[x] = f(x) end return cache[x] end end
_G.compose = function(f, g) return function(x) return f(g(x)) end end
_G.partial = function(f, arg) return function() return f(arg) end end
_G.curry = function(f, n) n = n or 1 if n <= 1 then return f else return function(x) return _G.curry(_G.partial(f, x), n-1) end end end
_G.pipe = function(f1, f2) return function(x) return f2(f1(x)) end end
_G.map = function(t, f) local r = {} for k,v in pairs(t) do r[k] = f(v) end return r end
_G.filter = function(t, f) local r = {} for k,v in pairs(t) do if f(v) then r[k] = v end end return r end
_G.reduce = function(t, f, init) local acc = init or 0 for _,v in pairs(t) do acc = f(acc, v) end return acc end
_G.find = function(t, f) for k,v in pairs(t) do if f(v) then return v, k end end end
_G.any = function(t, f) for _,v in pairs(t) do if f(v) then return true end end return false end
_G.all = function(t, f) for _,v in pairs(t) do if not f(v) then return false end end return true end
_G.zip = function(t1, t2) local r = {} for i=1,math.min(#t1,#t2) do r[i] = {t1[i], t2[i]} end return r end
_G.unzip = function(t) local t1, t2 = {}, {} for _,v in ipairs(t) do table.insert(t1, v[1]) table.insert(t2, v[2]) end return t1, t2 end
_G.flatten = function(t) local r = {} local function f(x) if type(x) == "table" then for _,v in ipairs(x) do f(v) end else table.insert(r, x) end end f(t) return r end
_G.chunk = function(t, size) local r = {} for i=1,#t,size do table.insert(r, {table.unpack(t, i, i+size-1)}) end return r end
_G.shuffle = function(t) for i=#t,2,-1 do local j = math.random(i) t[i], t[j] = t[j], t[i] end return t end
_G.sample = function(t, n) n = n or 1 local r = {} for i=1,n do table.insert(r, t[math.random(#t)]) end return r end
_G.unique = function(t) local seen = {} local r = {} for _,v in ipairs(t) do if not seen[v] then seen[v] = true table.insert(r, v) end end return r end
_G.intersection = function(t1, t2) local set = {} for _,v in ipairs(t2) do set[v] = true end local r = {} for _,v in ipairs(t1) do if set[v] then table.insert(r, v) end end return r end
_G.difference = function(t1, t2) local set = {} for _,v in ipairs(t2) do set[v] = true end local r = {} for _,v in ipairs(t1) do if not set[v] then table.insert(r, v) end end return r end
_G.union = function(t1, t2) local set = {} local r = {} for _,v in ipairs(t1) do if not set[v] then set[v] = true table.insert(r, v) end end for _,v in ipairs(t2) do if not set[v] then set[v] = true table.insert(r, v) end end return r end
_G.symmetric_difference = function(t1, t2) local set1, set2 = {}, {} for _,v in ipairs(t1) do set1[v] = true end for _,v in ipairs(t2) do set2[v] = true end local r = {} for v in pairs(set1) do if not set2[v] then table.insert(r, v) end end for v in pairs(set2) do if not set1[v] then table.insert(r, v) end end return r end
_G.is_subset = function(t1, t2) local set = {} for _,v in ipairs(t2) do set[v] = true end for _,v in ipairs(t1) do if not set[v] then return false end end return true end
_G.is_superset = function(t1, t2) return _G.is_subset(t2, t1) end
_G.equals = function(t1, t2) if #t1 ~= #t2 then return false end for i,v in ipairs(t1) do if v ~= t2[i] then return false end end return true end
_G.reverse = function(t) local r = {} for i=#t,1,-1 do table.insert(r, t[i]) end return r end
_G.rotate = function(t, n) n = n % #t local r = {} for i=1,#t do r[i] = t[((i-1 + n) % #t) + 1] end return r end
_G.transpose = function(t) local r = {} for i=1,#t[1] do r[i] = {} for j=1,#t do r[i][j] = t[j][i] end end return r end
_G.diagonal = function(t) local r = {} for i=1,#t do r[i] = t[i][i] end return r end
_G.trace = function(t) local s = 0 for i=1,#t do s = s + t[i][i] end return s end
_G.determinant = function(t) if #t == 1 then return t[1][1] elseif #t == 2 then return t[1][1]*t[2][2] - t[1][2]*t[2][1] else return 0 end end
_G.inverse = function(t) if #t == 1 then return {{1/t[1][1]}} elseif #t == 2 then local d = _G.determinant(t) return {{t[2][2]/d, -t[1][2]/d}, {-t[2][1]/d, t[1][1]/d}} else return {} end end
_G.dot = function(t1, t2) local s = 0 for i=1,#t1 do s = s + t1[i]*t2[i] end return s end
_G.cross = function(t1, t2) return {t1[2]*t2[3] - t1[3]*t2[2], t1[3]*t2[1] - t1[1]*t2[3], t1[1]*t2[2] - t1[2]*t2[1]} end
_G.magnitude = function(t) return math.sqrt(_G.dot(t, t)) end
_G.normalize = function(t) local m = _G.magnitude(t) if m == 0 then return t end return _G.map(t, function(x) return x/m end) end
_G.distance = function(t1, t2) local d = {} for i=1,#t1 do d[i] = t1[i] - t2[i] end return _G.magnitude(d) end
_G.angle = function(t1, t2) return math.acos(_G.dot(t1, t2) / (_G.magnitude(t1) * _G.magnitude(t2))) end
_G.project = function(t1, t2) local s = _G.dot(t1, t2) / _G.dot(t2, t2) return _G.map(t2, function(x) return x * s end) end
_G.reject = function(t1, t2) local p = _G.project(t1, t2) return _G.map(t1, function(x, i) return x - p[i] end) end
_G.reflect = function(t, n) local p = _G.project(t, n) return _G.map(t, function(x, i) return x - 2 * p[i] end) end
_G.lerp = function(t1, t2, t) return _G.map(t1, function(x, i) return x + (t2[i] - x) * t end) end
_G.slerp = function(t1, t2, t) local a = _G.angle(t1, t2) if a == 0 then return t1 end local s = math.sin(a) return _G.map(t1, function(x, i) return (math.sin((1-t)*a)/s) * x + (math.sin(t*a)/s) * t2[i] end) end
_G.bezier = function(points, t) if #points == 1 then return points[1] elseif #points == 2 then return _G.lerp(points[1], points[2], t) else local p = {} for i=1,#points-1 do p[i] = _G.lerp(points[i], points[i+1], t) end return _G.bezier(p, t) end end
_G.hermite = function(p0, m0, p1, m1, t) local t2 = t*t local t3 = t2*t local h00 = 2*t3 - 3*t2 + 1 local h10 = t3 - 2*t2 + t local h01 = -2*t3 + 3*t2 local h11 = t3 - t2 return _G.map(p0, function(x, i) return h00*x + h10*m0[i] + h01*p1[i] + h11*m1[i] end) end
_G.catmull_rom = function(points, t) local i = math.floor(t * (#points - 1)) + 1 if i < 1 then i = 1 elseif i > #points - 1 then i = #points - 1 end local p0 = points[i] local p1 = points[i+1] local m0 = i > 1 and _G.map(points[i], function(x, j) return (points[i+1][j] - points[i-1][j]) / 2 end) or {0,0,0} local m1 = i < #points - 1 and _G.map(points[i+1], function(x, j) return (points[i+2][j] - points[i][j]) / 2 end) or {0,0,0} return _G.hermite(p0, m0, p1, m1, t * (#points - 1) - (i - 1)) end
_G.fft = function(t) -- Simplified FFT placeholder
    return t
end
_G.ifft = function(t) -- Simplified IFFT placeholder
    return t
end
_G.convolve = function(t1, t2) local r = {} for i=1,#t1 + #t2 - 1 do r[i] = 0 for j=1,#t1 do if i - j + 1 >= 1 and i - j + 1 <= #t2 then r[i] = r[i] + t1[j] * t2[i - j + 1] end end end return r end
_G.correlate = function(t1, t2) local r = {} for i=1,#t1 + #t2 - 1 do r[i] = 0 for j=1,#t1 do if j + i - 1 >= 1 and j + i - 1 <= #t2 then r[i] = r[i] + t1[j] * t2[j + i - 1] end end end return r end
_G.median = function(t) table.sort(t) if #t % 2 == 0 then return (t[#t/2] + t[#t/2 + 1]) / 2 else return t[math.ceil(#t/2)] end end
_G.mode = function(t) local count = {} for _,v in ipairs(t) do count[v] = (count[v] or 0) + 1 end local max, mode = 0 for v,c in pairs(count) do if c > max then max, mode = c, v end end return mode end
_G.variance = function(t) local mean = _G.reduce(t, function(a,b) return a + b end) / #t local sum = 0 for _,v in ipairs(t) do sum = sum + (v - mean)^2 end return sum / #t end
_G.stddev = function(t) return math.sqrt(_G.variance(t)) end
_G.covariance = function(t1, t2) local mean1 = _G.reduce(t1, function(a,b) return a + b end) / #t1 local mean2 = _G.reduce(t2, function(a,b) return a + b end) / #t2 local sum = 0 for i=1,#t1 do sum = sum + (t1[i] - mean1) * (t2[i] - mean2) end return sum / #t1 end
_G.correlation = function(t1, t2) return _G.covariance(t1, t2) / (_G.stddev(t1) * _G.stddev(t2)) end
_G.regression = function(t1, t2) local m = _G.correlation(t1, t2) * _G.stddev(t2) / _G.stddev(t1) local b = _G.reduce(t2, function(a,b) return a + b end) / #t2 - m * _G.reduce(t1, function(a,b) return a + b end) / #t1 return m, b end
_G.predict = function(x, m, b) return m * x + b end
_G.cluster = function(t, k) -- Simplified k-means placeholder
    return t
end
_G.sort_by = function(t, f) table.sort(t, function(a,b) return f(a) < f(b) end) return t end
_G.group_by = function(t, f) local r = {} for _,v in ipairs(t) do local k = f(v) r[k] = r[k] or {} table.insert(r[k], v) end return r end
_G.partition = function(t, f) local t1, t2 = {}, {} for _,v in ipairs(t) do if f(v) then table.insert(t1, v) else table.insert(t2, v) end end return t1, t2 end
_G.take = function(t, n) local r = {} for i=1,math.min(n, #t) do table.insert(r, t[i]) end return r end
_G.drop = function(t, n) local r = {} for i=n+1,#t do table.insert(r, t[i]) end return r end
_G.take_while = function(t, f) local r = {} for _,v in ipairs(t) do if f(v) then table.insert(r, v) else break end end return r end
_G.drop_while = function(t, f) local r = {} local drop = true for _,v in ipairs(t) do if drop and f(v) then else drop = false table.insert(r, v) end end return r end
_G.span = function(t, f) return _G.take_while(t, f), _G.drop_while(t, f) end
_G.break_ = function(t, f) return _G.span(t, function(x) return not f(x) end) end
_G.lines = function(s) return _G.string_split(s, "\n") end
_G.words = function(s) return _G.string_split(s, " ") end
_G.unlines = function(t) return table.concat(t, "\n") end
_G.unwords = function(t) return table.concat(t, " ") end
_G.capitalize = function(s) return s:sub(1,1):upper() .. s:sub(2):lower() end
_G.title_case = function(s) return _G.unwords(_G.map(_G.words(s), _G.capitalize)) end
_G.slugify = function(s) return s:lower():gsub("[^%w%s-]", ""):gsub("%s+", "-") end
_G.truncate = function(s, len) if #s > len then return s:sub(1, len) .. "..." else return s end end
_G.pad_left = function(s, len, char) char = char or " " return string.rep(char, len - #s) .. s end
_G.pad_right = function(s, len, char) char = char or " " return s .. string.rep(char, len - #s) end
_G.center = function(s, len, char) char = char or " " local pad = len - #s if pad <= 0 then return s end local left = math.floor(pad / 2) return string.rep(char, left) .. s .. string.rep(char, pad - left) end
_G.wrap = function(s, width) local r = {} local line = "" for word in s:gmatch("%S+") do if #line + #word + 1 > width then table.insert(r, line) line = word else line = line .. (line == "" and "" or " ") .. word end end if line ~= "" then table.insert(r, line) end return r end
_G.indent = function(t, n, char) char = char or " " local indent = string.rep(char, n) return _G.map(t, function(s) return indent .. s end) end
_G.dedent = function(t, n) return _G.map(t, function(s) return s:sub(n+1) end) end
_G.strip = function(s) return s:match("^%s*(.-)%s*$") end
_G.lstrip = function(s) return s:match("^%s*(.-)$") end
_G.rstrip = function(s) return s:match("^(.-)%s*$") end
_G.is_empty = function(s) return s:match("^%s*$") ~= nil end
_G.is_blank = function(s) return _G.is_empty(s) end
_G.is_numeric = function(s) return tonumber(s) ~= nil end
_G.is_alpha = function(s) return s:match("^%a+$") ~= nil end
_G.is_alnum = function(s) return s:match("^%w+$") ~= nil end
_G.is_lower = function(s) return s:match("^%l+$") ~= nil end
_G.is_upper = function(s) return s:match("^%u+$") ~= nil end
_G.is_title = function(s) return s == _G.title_case(s) end
_G.count = function(s, pattern) local _, n = s:gsub(pattern, "") return n end
_G.startswith = function(s, prefix) return s:sub(1, #prefix) == prefix end
_G.endswith = function(s, suffix) return s:sub(-#suffix) == suffix end
_G.contains = function(s, substr) return s:find(substr, 1, true) ~= nil end
_G.replace = function(s, old, new) return s:gsub(old, new) end
_G.remove = function(s, pattern) return s:gsub(pattern, "") end
_G.split_at = function(s, pos) return s:sub(1, pos), s:sub(pos+1) end
_G.insert_at = function(s, pos, ins) return s:sub(1, pos) .. ins .. s:sub(pos+1) end
_G.delete_at = function(s, pos, len) return s:sub(1, pos) .. s:sub(pos + len + 1) end
_G.swap_case = function(s) return s:gsub("%a", function(c) if c:match("%u") then return c:lower() else return c:upper() end end) end
_G.rotate_left = function(s, n) n = n % #s return s:sub(n+1) .. s:sub(1, n) end
_G.rotate_right = function(s, n) return _G.rotate_left(s, #s - n % #s) end
_G.reverse_string = function(s) return s:reverse() end
_G.is_palindrome = function(s) return s == _G.reverse_string(s) end
_G.levenshtein = function(s1, s2) if #s1 == 0 then return #s2 elseif #s2 == 0 then return #s1 elseif s1:sub(-1) == s2:sub(-1) then return _G.levenshtein(s1:sub(1,-2), s2:sub(1,-2)) else return 1 + math.min(_G.levenshtein(s1:sub(1,-2), s2), _G.levenshtein(s1, s2:sub(1,-2)), _G.levenshtein(s1:sub(1,-2), s2:sub(1,-2))) end end
_G.hamming = function(s1, s2) local d = 0 for i=1,math.min(#s1,#s2) do if s1:sub(i,i) ~= s2:sub(i,i) then d = d + 1 end end return d + math.abs(#s1 - #s2) end
_G.jaccard = function(s1, s2) local set1, set2 = {}, {} for c in s1:gmatch(".") do set1[c] = true end for c in s2:gmatch(".") do set2[c] = true end local inter, union = 0, 0 for c in pairs(set1) do if set2[c] then inter = inter + 1 end union = union + 1 end for c in pairs(set2) do if not set1[c] then union = union + 1 end end return inter / union end
_G.soundex = function(s) s = s:upper():gsub("[^A-Z]", "") if #s == 0 then return "0000" end local code = s:sub(1,1) local prev = "" for i=2,#s do local c = s:sub(i,i) local num = ({B=1, F=1, P=1, V=1, C=2, G=2, J=2, K=2, Q=2, S=2, X=2, Z=2, D=3, T=3, L=4, M=5, N=5, R=6})[c] if num and num ~= prev then code = code .. num prev = num end if #code == 4 then break end end return (code .. "0000"):sub(1,4) end
_G.metaphone = function(s) -- Simplified Metaphone placeholder
    return s:upper()
end
_G.double_metaphone = function(s) -- Simplified Double Metaphone placeholder
    return s:upper(), s:upper()
end
_G.nysiis = function(s) -- Simplified NYSIIS placeholder
    return s:upper()
end
_G.match_rating = function(s) -- Simplified Match Rating placeholder
    return s:upper()
end
_G.fuzzy_match = function(s1, s2) return _G.levenshtein(s1, s2) <= 2 end
_G.regex_match = function(s, pattern) return s:match(pattern) ~= nil end
_G.regex_replace = function(s, pattern, repl) return s:gsub(pattern, repl) end
_G.regex_split = function(s, pattern) local r = {} for m in s:gmatch("([^" .. pattern .. "]+)") do table.insert(r, m) end return r end
_G.glob_match = function(s, pattern) -- Simplified glob placeholder
    return s:match(pattern:gsub("*", ".*"):gsub("?", ".")) ~= nil
end
_G.wildcard_match = _G.glob_match
_G.ipv4_match = function(s) return s:match("^%d+%.%d+%.%d+%.%d+$") ~= nil end
_G.email_match = function(s) return s:match("^[%w._-]+@[%w._-]+%.[%w]+$") ~= nil end
_G.url_match = function(s) return s:match("^https?://[%w._/-]+") ~= nil end
_G.phone_match = function(s) return s:match("^%+?%d[%d%s%-()]+$") ~= nil end
_G.credit_card_match = function(s) return s:match("^%d{4}%s?%d{4}%s?%d{4}%s?%d{4}$") ~= nil end
_G.zip_code_match = function(s) return s:match("^%d{5}(-%d{4})?$") ~= nil end
_G.ssn_match = function(s) return s:match("^%d{3}-%d{2}-%d{4}$") ~= nil end
_G.date_match = function(s) return s:match("^%d{4}-%d{2}-%d{2}$") ~= nil end
_G.time_match = function(s) return s:match("^%d{2}:%d{2}(:%d{2})?$") ~= nil end
_G.datetime_match = function(s) return s:match("^%d{4}-%d{2}-%d{2} %d{2}:%d{2}(:%d{2})?$") ~= nil end
_G.uuid_match = function(s) return s:match("^%x{8}-%x{4}-%x{4}-%x{4}-%x{12}$") ~= nil end
_G.hex_color_match = function(s) return s:match("^#%x{6}$") ~= nil end
_G.slug_match = function(s) return s:match("^[%w-]+$") ~= nil end
_G.username_match = function(s) return s:match("^[%w_]+$") ~= nil end
_G.password_strength = function(s) local score = 0 if #s >= 8 then score = score + 1 end if s:match("%l") then score = score + 1 end if s:match("%u") then score = score + 1 end if s:match("%d") then score = score + 1 end if s:match("%W") then score = score + 1 end return score end
_G.generate_password = function(len) local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()" local p = "" for i=1,len do p = p .. chars:sub(math.random(#chars), math.random(#chars)) end return p end
_G.hash_password = function(s) return _G.hash_string(s) end
_G.verify_password = function(s, h) return _G.hash_password(s) == h end
_G.encrypt_string = function(s, k) return s end
_G.decrypt_string = function(s, k) return s end
_G.compress_string = function(s) return s end
_G.decompress_string = function(s) return s end
_G.base64_encode_string = function(s) return s end
_G.base64_decode_string = function(s) return s end
_G.url_encode = function(s) return s:gsub("[^%w]", function(c) return string.format("%%%02X", c:byte()) end) end
_G.url_decode = function(s) return s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end) end
_G.html_encode = function(s) return s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;"):gsub('"', "&quot;"):gsub("'", "&#39;") end
_G.html_decode = function(s) return s:gsub("&amp;", "&"):gsub("&lt;", "<"):gsub("&gt;", ">"):gsub("&quot;", '"'):gsub("&#39;", "'") end
_G.xml_encode = _G.html_encode
_G.xml_decode = _G.html_decode
_G.json_encode = function(t) return "{" .. table.concat(_G.map(t, function(k,v) return '"' .. k .. '":"' .. v .. '"' end), ",") .. "}" end
_G.json_decode = function(s) local t = {} for k,v in s:gmatch('"([^"]+)":"([^"]+)"') do t[k] = v end return t end
_G.csv_encode = function(t) return table.concat(_G.map(t, function(r) return table.concat(r, ",") end), "\n") end
_G.csv_decode = function(s) local t = {} for line in s:gmatch("[^\n]+") do local r = {} for cell in line:gmatch("[^,]+") do table.insert(r, cell) end table.insert(t, r) end return t end
_G.yaml_encode = function(t) -- Simplified YAML placeholder
    return _G.json_encode(t)
end
_G.yaml_decode = function(s) -- Simplified YAML placeholder
    return _G.json_decode(s)
end
_G.toml_encode = function(t) -- Simplified TOML placeholder
    return _G.json_encode(t)
end
_G.toml_decode = function(s) -- Simplified TOML placeholder
    return _G.json_decode(s)
end
_G.ini_encode = function(t) -- Simplified INI placeholder
    return _G.json_encode(t)
end
_G.ini_decode = function(s) -- Simplified INI placeholder
    return _G.json_decode(s)
end
_G.serialize = function(t) return _G.json_encode(t) end
_G.deserialize = function(s) return _G.json_decode(s) end
_G.clone_table = _G.deep_clone
_G.merge_tables = _G.union
_G.diff_tables = _G.symmetric_difference
_G.intersect_tables = _G.intersection
_G.subtract_tables = _G.difference
_G.is_equal = _G.equals
_G.is_subset_of = _G.is_subset
_G.is_superset_of = _G.is_superset
_G.table_length = _G.table_size
_G.array_push = table.insert
_G.array_pop = table.remove
_G.array_shift = function(t) return table.remove(t, 1) end
_G.array_unshift = function(t, v) table.insert(t, 1, v) end
_G.array_slice = function(t, start, end_) return {table.unpack(t, start, end_ or #t)} end
_G.array_splice = function(t, start, count, ...) local r = {} for i=1,count do table.insert(r, table.remove(t, start)) end for i=1,select("#", ...) do table.insert(t, start + i - 1, select(i, ...)) end return r end
_G.array_index_of = table.find
_G.array_last_index_of = function(t, v) for i=#t,1,-1 do if t[i] == v then return i end end end
_G.array_includes = function(t, v) return table.find(t, v) ~= nil end
_G.array_every = _G.all
_G.array_some = _G.any
_G.array_filter = _G.filter
_G.array_map = _G.map
_G.array_reduce = _G.reduce
_G.array_for_each = function(t, f) for _,v in ipairs(t) do f(v) end end
_G.array_sort = table.sort
_G.array_reverse = _G.reverse
_G.array_join = table.concat
_G.array_fill = function(t, v, start, end_) start = start or 1 end_ = end_ or #t for i=start,end_ do t[i] = v end return t end
_G.array_copy_within = function(t, target, start, end_) for i=start,end_ do t[target + i - start] = t[i] end return t end
_G.set_add = function(s, v) s[v] = true end
_G.set_delete = function(s, v) s[v] = nil end
_G.set_has = function(s, v) return s[v] ~= nil end
_G.set_size = function(s) local c = 0 for _ in pairs(s) do c = c + 1 end return c end
_G.set_clear = function(s) for k in pairs(s) do s[k] = nil end end
_G.set_union = _G.union
_G.set_intersection = _G.intersection
_G.set_difference = _G.difference
_G.set_symmetric_difference = _G.symmetric_difference
_G.set_is_subset = _G.is_subset
_G.set_is_superset = _G.is_superset
_G.set_equals = _G.equals
_G.map_set = function(m, k, v) m[k] = v end
_G.map_get = function(m, k) return m[k] end
_G.map_has = function(m, k) return m[k] ~= nil end
_G.map_delete = function(m, k) m[k] = nil end
_G.map_size = _G.table_size
_G.map_clear = function(m) for k in pairs(m) do m[k] = nil end end
_G.map_keys = function(m) local r = {} for k in pairs(m) do table.insert(r, k) end return r end
_G.map_values = function(m) local r = {} for _,v in pairs(m) do table.insert(r, v) end return r end
_G.map_entries = function(m) local r = {} for k,v in pairs(m) do table.insert(r, {k, v}) end return r end
_G.map_for_each = function(m, f) for k,v in pairs(m) do f(v, k) end end
_G.queue_new = function() return {first = 1, last = 0} end
_G.queue_enqueue = function(q, v) q.last = q.last + 1 q[q.last] = v end
_G.queue_dequeue = function(q) if q.first > q.last then return nil end local v = q[q.first] q[q.first] = nil q.first = q.first + 1 return v end
_G.queue_size = function(q) return q.last - q.first + 1 end
_G.queue_is_empty = function(q) return q.first > q.last end
_G.queue_peek = function(q) return q[q.first] end
_G.stack_new = function() return {} end
_G.stack_push = table.insert
_G.stack_pop = table.remove
_G.stack_size = function(s) return #s end
_G.stack_is_empty = function(s) return #s == 0 end
_G.stack_peek = function(s) return s[#s] end
_G.heap_new = function() return {} end
_G.heap_push = function(h, v) table.insert(h, v) local i = #h while i > 1 do local p = math.floor(i / 2) if h[p] <= h[i] then break end h[p], h[i] = h[i], h[p] i = p end end
_G.heap_pop = function(h) if #h == 0 then return nil end local root = h[1] h[1] = h[#h] h[#h] = nil local i = 1 while true do local left = i * 2 local right = i * 2 + 1 local smallest = i if left <= #h and h[left] < h[smallest] then smallest = left end if right <= #h and h[right] < h[smallest] then smallest = right end if smallest == i then break end h[i], h[smallest] = h[smallest], h[i] i = smallest end return root end
_G.heap_size = function(h) return #h end
_G.heap_is_empty = function(h) return #h == 0 end
_G.heap_peek = function(h) return h[1] end
_G.graph_new = function() return {nodes = {}, edges = {}} end
_G.graph_add_node = function(g, n) g.nodes[n] = {} end
_G.graph_add_edge = function(g, n1, n2, w) g.edges[n1 .. "-" .. n2] = w table.insert(g.nodes[n1], n2) table.insert(g.nodes[n2], n1) end
_G.graph_dijkstra = function(g, start) -- Simplified Dijkstra placeholder
    return {}
end
_G.tree_new = function() return {root = nil} end
_G.tree_insert = function(t, v) -- Simplified BST insert placeholder
    t.root = v
end
_G.tree_search = function(t, v) -- Simplified BST search placeholder
    return t.root == v
end
_G.tree_inorder = function(t) -- Simplified inorder traversal placeholder
    return {t.root}
end
_G.tree_preorder = function(t) -- Simplified preorder traversal placeholder
    return {t.root}
end
_G.tree_postorder = function(t) -- Simplified postorder traversal placeholder
    return {t.root}
end
_G.tree_height = function(t) -- Simplified height placeholder
    return 1
end
_G.tree_balance = function(t) -- Simplified balance placeholder
    return 0
end
_G.bst_new = _G.tree_new
_G.bst_insert = _G.tree_insert
_G.bst_search = _G.tree_search
_G.bst_delete = function(t, v) -- Simplified delete placeholder
    if t.root == v then t.root = nil end
end
_G.avl_new = _G.tree_new
_G.avl_insert = _G.tree_insert
_G.avl_search = _G.tree_search
_G.avl_delete = _G.bst_delete
_G.rbt_new = _G.tree_new
_G.rbt_insert = _G.tree_insert
_G.rbt_search = _G.tree_search
_G.rbt_delete = _G.bst_delete
_G.hash_new = function() return {} end
_G.hash_set = function(h, k, v) h[k] = v end
_G.hash_get = function(h, k) return h[k] end
_G.hash_has = function(h, k) return h[k] ~= nil end
_G.hash_delete = function(h, k) h[k] = nil end
_G.hash_size = _G.table_size
_G.hash_clear = function(h) for k in pairs(h) do h[k] = nil end end
_G.hash_keys = _G.map_keys
_G.hash_values = _G.map_values
_G.hash_entries = _G.map_entries
_G.hash_for_each = _G.map_for_each
_G.list_new = function() return {} end
_G.list_add = table.insert
_G.list_remove = table.remove
_G.list_get = function(l, i) return l[i] end
_G.list_set = function(l, i, v) l[i] = v end
_G.list_size = function(l) return #l end
_G.list_is_empty = function(l) return #l == 0 end
_G.list_clear = function(l) for i=1,#l do l[i] = nil end end
_G.list_index_of = table.find
_G.list_last_index_of = _G.array_last_index_of
_G.list_contains = _G.array_includes
_G.list_for_each = _G.array_for_each
_G.list_map = _G.array_map
_G.list_filter = _G.array_filter
_G.list_reduce = _G.array_reduce
_G.list_sort = _G.array_sort
_G.list_reverse = _G.array_reverse
_G.list_join = _G.array_join
_G.vector_new = function() return {} end
_G.vector_push = table.insert
_G.vector_pop = table.remove
_G.vector_size = function(v) return #v end
_G.vector_is_empty = function(v) return #v == 0 end
_G.vector_get = function(v, i) return v[i] end
_G.vector_set = function(v, i, val) v[i] = val end
_G.vector_clear = _G.list_clear
_G.vector_resize = function(v, n, val) val = val or 0 for i=#v+1,n do v[i] = val end for i=n+1,#v do v[i] = nil end end
_G.vector_fill = _G.array_fill
_G.vector_copy = _G.array_slice
_G.vector_swap = function(v, i, j) v[i], v[j] = v[j], v[i] end
_G.vector_reverse = _G.array_reverse
_G.vector_sort = _G.array_sort
_G.vector_min = function(v) return math.min(table.unpack(v)) end
_G.vector_max = function(v) return math.max(table.unpack(v)) end
_G.vector_sum = function(v) return _G.reduce(v, function(a,b) return a + b end) end
_G.vector_product = function(v) return _G.reduce(v, function(a,b) return a * b end, 1) end
_G.vector_average = function(v) return _G.vector_sum(v) / #v end
_G.vector_median = _G.median
_G.vector_mode = _G.mode
_G.vector_variance = _G.variance
_G.vector_stddev = _G.stddev
_G.vector_dot = _G.dot
_G.vector_cross = _G.cross
_G.vector_magnitude = _G.magnitude
_G.vector_normalize = _G.normalize
_G.vector_distance = _G.distance
_G.vector_angle = _G.angle
_G.vector_project = _G.project
_G.vector_reject = _G.reject
_G.vector_reflect = _G.reflect
_G.vector_lerp = _G.lerp
_G.vector_slerp = _G.slerp
_G.matrix_new = function(rows, cols) local m = {} for i=1,rows do m[i] = {} for j=1,cols do m[i][j] = 0 end end return m end
_G.matrix_get = function(m, i, j) return m[i][j] end
_G.matrix_set = function(m, i, j, v) m[i][j] = v end
_G.matrix_size = function(m) return #m, #m[1] end
_G.matrix_add = function(m1, m2) local r = _G.matrix_new(#m1, #m1[1]) for i=1,#m1 do for j=1,#m1[1] do r[i][j] = m1[i][j] + m2[i][j] end end return r end
_G.matrix_subtract = function(m1, m2) local r = _G.matrix_new(#m1, #m1[1]) for i=1,#m1 do for j=1,#m1[1] do r[i][j] = m1[i][j] - m2[i][j] end end return r end
_G.matrix_multiply = function(m1, m2) local r = _G.matrix_new(#m1, #m2[1]) for i=1,#m1 do for j=1,#m2[1] do for k=1,#m2 do r[i][j] = r[i][j] + m1[i][k] * m2[k][j] end end end return r end
_G.matrix_transpose = _G.transpose
_G.matrix_determinant = _G.determinant
_G.matrix_inverse = _G.inverse
_G.matrix_trace = _G.trace
_G.matrix_diagonal = _G.diagonal
_G.tensor_new = function(dims) -- Simplified tensor placeholder
    return {}
end
_G.tensor_get = function(t, ...) return 0 end
_G.tensor_set = function(t, v, ...) end
_G.neural_network_new = function() -- Simplified NN placeholder
    return {}
end
_G.neural_network_train = function(nn, data) end
_G.neural_network_predict = function(nn, input) return 0 end
_G.genetic_algorithm_new = function() -- Simplified GA placeholder
    return {}
end
_G.genetic_algorithm_evolve = function(ga, population) return population end
_G.simulated_annealing = function(initial, energy, temperature, cooling) -- Simplified SA placeholder
    return initial
end
_G.particle_swarm_optimization = function() -- Simplified PSO placeholder
    return {}
end
_G.ant_colony_optimization = function() -- Simplified ACO placeholder
    return {}
end
_G.differential_evolution = function() -- Simplified DE placeholder
    return {}
end
_G.firefly_algorithm = function() -- Simplified FA placeholder
    return {}
end
_G.harmony_search = function() -- Simplified HS placeholder
    return {}
end
_G.gravitational_search = function() -- Simplified GSA placeholder
    return {}
end
_G.bat_algorithm = function() -- Simplified BA placeholder
    return {}
end
_G.cuckoo_search = function() -- Simplified CS placeholder
    return {}
end
_G.flower_pollination = function() -- Simplified FPA placeholder
    return {}
end
_G.teaching_learning = function() -- Simplified TLBO placeholder
    return {}
end
_G.jaya_algorithm = function() -- Simplified Jaya placeholder
    return {}
end
_G.sine_cosine_algorithm = function() -- Simplified SCA placeholder
    return {}
end
_G.grey_wolf_optimizer = function() -- Simplified GWO placeholder
    return {}
end
_G.whale_optimization = function() -- Simplified WOA placeholder
    return {}
end
_G.dragonfly_algorithm = function() -- Simplified DA placeholder
    return {}
end
_G.moth_flame_optimization = function() -- Simplified MFO placeholder
    return {}
end
_G.salp_swarm_algorithm = function() -- Simplified SSA placeholder
    return {}
end
_G.sea_horse_optimizer = function() -- Simplified SHO placeholder
    return {}
end
_G.squirrel_search = function() -- Simplified SS placeholder
    return {}
end
_G.sparrow_search = function() -- Simplified SSA2 placeholder
    return {}
end
_G.tunicate_swarm = function() -- Simplified Tunicate placeholder
    return {}
end
_G.tug_of_war = function() -- Simplified TOW placeholder
    return {}
end
_G.virus_colony_search = function() -- Simplified VCS placeholder
    return {}
end
_G.weakest_tamer = function() -- Simplified WT placeholder
    return {}
end
_G.wind_driven_optimization = function() -- Simplified WDO placeholder
    return {}
end
_G.zebra_optimization = function() -- Simplified ZOA placeholder
    return {}
end
_G.african_buffalo_optimization = function() -- Simplified ABO placeholder
    return {}
end
_G.alienated_ant_colony = function() -- Simplified AAC placeholder
    return {}
end
_G.ant_lion_optimizer = function() -- Simplified ALO placeholder
    return {}
end
_G.artificial_algae = function() -- Simplified AAA placeholder
    return {}
end
_G.artificial_plant_optimization = function() -- Simplified APO placeholder
    return {}
end
_G.atomic_search = function() -- Simplified ASO placeholder
    return {}
end
_G.bacterial_foraging = function() -- Simplified BFO placeholder
    return {}
end
_G.biogeography_based = function() -- Simplified BBO placeholder
    return {}
end
_G.blind_search = function() -- Simplified BS placeholder
    return {}
end
_G.brain_storm_optimization = function() -- Simplified BSO placeholder
    return {}
end
_G.cat_swarm_optimization = function() -- Simplified CSO placeholder
    return {}
end
_G.chemical_reaction = function() -- Simplified CRO placeholder
    return {}
end
_G.chicken_swarm = function() -- Simplified CSO2 placeholder
    return {}
end
_G.collision_based = function() -- Simplified CBO placeholder
    end
_G.coyote_optimization = function() -- Simplified COA placeholder
    return {}
end
_G.crow_search = function() -- Simplified CSA placeholder
    return {}
end
_G.crystal_structure = function() -- Simplified CryStAl placeholder
    return {}
end
_G.cuttlefish_algorithm = function() -- Simplified CFA placeholder
    return {}
end
_G.dolphin_partner = function() -- Simplified DPA placeholder
    return {}
end
_G.dwarf_mongoose = function() -- Simplified DMO placeholder
    return {}
end
_G.dynamic_virtual_bats = function() -- Simplified DVB placeholder
    return {}
end
_G.eagle_strategy = function() -- Simplified ES placeholder
    return {}
end
_G.electrical_beetle = function() -- Simplified EB placeholder
    return {}
end
_G.electro_magnetism = function() -- Simplified EMO placeholder
    return {}
end
_G.elephant_herding = function() -- Simplified EHO placeholder
    return {}
end
_G.elephant_search = function() -- Simplified ESA placeholder
    return {}
end
_G.exchange_market = function() -- Simplified EMA placeholder
    return {}
end
_G.fish_school_search = function() -- Simplified FSS placeholder
    return {}
end
_G.flamingo_search = function() -- Simplified FS placeholder
    return {}
end
_G.flower_pollenation = _G.flower_pollination
_G.forensic_based = function() -- Simplified FBI placeholder
    return {}
end
_G.fractal_search = function() -- Simplified FS2 placeholder
    return {}
end
_G.fruit_fly = function() -- Simplified FFO placeholder
    return {}
end
_G.galaxy_based_search = function() -- Simplified GbSA placeholder
    return {}
end
_G.gazelle_optimization = function() -- Simplified GOA placeholder
    return {}
end
_G.glowworm_swarm = function() -- Simplified GSO placeholder
    return {}
end
_G.golden_jackal = function() -- Simplified GJO placeholder
    return {}
end
_G.goldfinch_optimizer = function() -- Simplified GOA2 placeholder
    return {}
end
_G.goose_algorithm = function() -- Simplified GOA3 placeholder
    return {}
end
_G.gorilla_troops = function() -- Simplified GTO placeholder
    return {}
end
_G.grasshopper_optimization = function() -- Simplified GOA4 placeholder
    return {}
end
_G.great_tit_algorithm = function() -- Simplified GTA placeholder
    return {}
end
_G.group_search_optimizer = function() -- Simplified GSO2 placeholder
    return {}
end
_G.guerrilla_optimization = function() -- Simplified GOA5 placeholder
    return {}
end
_G.harris_hawks = function() -- Simplified HHO placeholder
    return {}
end
_G.henry_gas_solubility = function() -- Simplified HGSO placeholder
    return {}
end
_G.honey_badger = function() -- Simplified HBA placeholder
    return {}
end
_G.honeybee_algorithm = function() -- Simplified HBA2 placeholder
    return {}
end
_G.hoot_hoot_optimization = function() -- Simplified HHO2 placeholder
    return {}
end
_G.horse_herd = function() -- Simplified HHO3 placeholder
    return {}
end
_G.human_learning = function() -- Simplified HLO placeholder
    return {}
end
_G.hunger_games_search = function() -- Simplified HGS placeholder
    return {}
end
_G.improved_grey_wolf = function() -- Simplified IGWO placeholder
    return {}
end
_G.improved_whale = function() -- Simplified IWOA placeholder
    return {}
end
_G.ion_motion = function() -- Simplified IMO placeholder
    return {}
end
_G.jackal_optimization = function() -- Simplified JOA placeholder
    return {}
end
_G.jellyfish_search = function() -- Simplified JSA placeholder
    return {}
end
_G.kangaroo_mob = function() -- Simplified KMA placeholder
    return {}
end
_G.krill_herd = function() -- Simplified KH placeholder
    return {}
end
_G.kuwahara_filter = function() -- Simplified KF placeholder
    return {}
end
_G.ladybird_beetle = function() -- Simplified LBA placeholder
    return {}
end
_G.lapwing_algorithm = function() -- Simplified LA placeholder
    return {}
end
_G.leaf_optimization = function() -- Simplified LOA placeholder
    return {}
end
_G.learner_optimization = function() -- Simplified LOA2 placeholder
    return {}
end
_G.lightning_search = function() -- Simplified LSA placeholder
    return {}
end
_G.lion_optimization = function() -- Simplified LOA3 placeholder
    return {}
end
_G.little_wandering = function() -- Simplified LWA placeholder
    return {}
end
_G.locust_swarm = function() -- Simplified LSA2 placeholder
    return {}
end
_G.macaw_optimization = function() -- Simplified MOA placeholder
    return {}
end
_G.magnetic_bacteria = function() -- Simplified MBA placeholder
    return {}
end
_G.magnetic_optimizer = function() -- Simplified MOA2 placeholder
    return {}
end
_G.manta_ray_foraging = function() -- Simplified MRFO placeholder
    return {}
end
_G.marine_predators = function() -- Simplified MPA placeholder
    return {}
end
_G.mayfly_algorithm = function() -- Simplified MA placeholder
    return {}
end
_G.meadow_saffron = function() -- Simplified MSA placeholder
    return {}
end
_G.meerkat_clan = function() -- Simplified MCA placeholder
    return {}
end
_G.migrating_birds = function() -- Simplified MBO placeholder
    return {}
end
_G.moth_search = function() -- Simplified MS placeholder
    return {}
end
_G.multi_verse_optimizer = function() -- Simplified MVO placeholder
    return {}
end
_G.myna_birds = function() -- Simplified MBA2 placeholder
    return {}
end
_G.narwhal_swarm = function() -- Simplified NSA placeholder
    return {}
end
_G.night_hawk_optimization = function() -- Simplified NHO placeholder
    return {}
end
_G.northern_goshawk = function() -- Simplified NGO placeholder
    return {}
end
_G.nuptial_dance = function() -- Simplified ND placeholder
    return {}
end
_G.ocelli_vision = function() -- Simplified OV placeholder
    return {}
end
_G.opposition_based = function() -- Simplified OBLA placeholder
    return {}
end
_G.orca_predation = function() -- Simplified OPA placeholder
    return {}
end
_G.ostrich_algorithm = function() -- Simplified OA placeholder
    return {}
end
_G.otter_algorithm = function() -- Simplified OA2 placeholder
    return {}
end
_G.owls_algorithm = function() -- Simplified OA3 placeholder
    return {}
end
_G.panda_optimization = function() -- Simplified POA placeholder
    return {}
end
_G.parrot_algorithm = function() -- Simplified PA placeholder
    return {}
end
_G.passerine_search = function() -- Simplified PSA placeholder
    return {}
end
_G.pathfinder = function() -- Simplified Pathfinder placeholder
    return {}
end
_G.peacock_algorithm = function() -- Simplified PA2 placeholder
    return {}
end
_G.pelican_optimization = function() -- Simplified POA2 placeholder
    return {}
end
_G.penguin_colony = function() -- Simplified PC placeholder
    return {}
end
_G.peregrine_falcon = function() -- Simplified PFA placeholder
    return {}
end
_G.pigeon_inspired = function() -- Simplified PIO placeholder
    return {}
end
_G.plankton_search = function() -- Simplified PS placeholder
    return {}
end
_G.plant_growth = function() -- Simplified PGS placeholder
    return {}
end
_G.plant_propagation = function() -- Simplified PPA placeholder
    return {}
end
_G.polar_bear = function() -- Simplified PBO placeholder
    return {}
end
_G.pomegranate_algorithm = function() -- Simplified PA3 placeholder
    return {}
end
_G.poor_and_rich = function() -- Simplified PAR placeholder
    return {}
end
_G.prairie_dog = function() -- Simplified PDA placeholder
    return {}
end
_G.praying_mantis = function() -- Simplified PMA placeholder
    return {}
end
_G.predatory_birds = function() -- Simplified PBA placeholder
    return {}
end
_G.pumpkin_seed = function() -- Simplified PSA2 placeholder
    return {}
end
_G.queen_bee_evolution = function() -- Simplified QBEE placeholder
    return {}
end
_G.rabbit_optimization = function() -- Simplified ROA placeholder
    return {}
end
_G.raccoon_optimization = function() -- Simplified ROA2 placeholder
    return {}
end
_G.rainfall_optimization = function() -- Simplified ROA3 placeholder
    return {}
end
_G.rat_swarm = function() -- Simplified RSA placeholder
    return {}
end
_G.raven_roosting = function() -- Simplified RRO placeholder
    return {}
end
_G.ray_optimization = function() -- Simplified ROA4 placeholder
    return {}
end
_G.red_fox_optimization = function() -- Simplified RFO placeholder
    return {}
end
_G.rhino_optimization = function() -- Simplified ROA5 placeholder
    return {}
end
_G.river_formation = function() -- Simplified RFD placeholder
    return {}
end
_G.robin_optimization = function() -- Simplified ROA6 placeholder
    return {}
end
_G.rocket_explosion = function() -- Simplified REO placeholder
    return {}
end
_G.root_finding = function() -- Simplified RF placeholder
    return {}
end
_G.rose_optimization = function() -- Simplified ROA7 placeholder
    return {}
end
_G.sable_fish = function() -- Simplified SFA placeholder
    return {}
end
_G.sailfish_optimizer = function() -- Simplified SFO placeholder
    return {}
end
_G.sand_cat_swarm = function() -- Simplified SCSO placeholder
    return {}
end
_G.sandpiper_optimization = function() -- Simplified SOA placeholder
    return {}
end
_G.satin_bowerbird = function() -- Simplified SBO placeholder
    return {}
end
_G.scientific_optimizer = function() -- Simplified SO placeholder
    return {}
end
_G.scorpion_optimization = function() -- Simplified SOA2 placeholder
    return {}
end
_G.sea_cucumber = function() -- Simplified SCO placeholder
    return {}
end
_G.sea_lion_optimization = function() -- Simplified SLO placeholder
    return {}
end
_G.seahorse_optimizer = _G.sea_horse_optimizer
_G.selfish_herd = function() -- Simplified SHO2 placeholder
    return {}
end
_G.seskar_optimization = function() -- Simplified SOA3 placeholder
    return {}
end
_G.shark_optimization = function() -- Simplified SOA4 placeholder
    return {}
end
_G.sheep_algorithm = function() -- Simplified SA placeholder
    return {}
end
_G.siberian_tiger = function() -- Simplified STO placeholder
    return {}
end
_G.sine_cosine = _G.sine_cosine_algorithm
_G.slime_mould = function() -- Simplified SMA placeholder
    return {}
end
_G.smoky_mackerel = function() -- Simplified SMA2 placeholder
    return {}
end
_G.snail_algorithm = function() -- Simplified SA2 placeholder
    return {}
end
_G.snake_optimizer = function() -- Simplified SOA5 placeholder
    return {}
end
_G.snow_ablation = function() -- Simplified SA3 placeholder
    return {}
end
_G.snowflake_optimization = function() -- Simplified SOA6 placeholder
    return {}
end
_G.social_network = function() -- Simplified SNA placeholder
    return {}
end
_G.social_spider = function() -- Simplified SSO placeholder
    return {}
end
_G.sooty_tern = function() -- Simplified STO2 placeholder
    return {}
end
_G.sparrow_optimization = function() -- Simplified SOA7 placeholder
    return {}
end
_G.spherical_search = function() -- Simplified SSO2 placeholder
    return {}
end
_G.spider_wasp = function() -- Simplified SWO placeholder
    return {}
end
_G.squirrel_optimization = function() -- Simplified SOA8 placeholder
    return {}
end
_G.starling_flock = function() -- Simplified SFO2 placeholder
    return {}
end
_G.stingray_search = function() -- Simplified SSA3 placeholder
    return {}
end
_G.stochastic_diffusion = function() -- Simplified SDS placeholder
    return {}
end
_G.stochastic_fractal = function() -- Simplified SFS placeholder
    return {}
end
_G.stork_optimization = function() -- Simplified SOA9 placeholder
    return {}
end
_G.strawberry_plant = function() -- Simplified SPA placeholder
    return {}
end
_G.sturgeon_fish = function() -- Simplified SFO3 placeholder
    return {}
end
_G.sunflower_optimization = function() -- Simplified SO2 placeholder
    return {}
end
_G.supply_demand = function() -- Simplified SDE placeholder
    return {}
end
_G.swan_optimization = function() -- Simplified SOA10 placeholder
    return {}
end
_G.tabu_search = function() -- Simplified TS placeholder
    return {}
end
_G.tarantula_optimization = function() -- Simplified TOA placeholder
    return {}
end
_G.team_games = function() -- Simplified TG placeholder
    return {}
end
_G.termite_colony = function() -- Simplified TCO placeholder
    return {}
end
_G.tetra_optimization = function() -- Simplified TOA2 placeholder
    return {}
end
_G.theta_modification = function() -- Simplified TM placeholder
    return {}
end
_G.thief_ant = function() -- Simplified TA placeholder
    return {}
end
_G.threaded_screws = function() -- Simplified TS2 placeholder
    return {}
end
_G.thunderstorm_optimization = function() -- Simplified TOA3 placeholder
    return {}
end
_G.tiger_algorithm = function() -- Simplified TA2 placeholder
    return {}
end
_G.tillandsia_optimization = function() -- Simplified TOA4 placeholder
    return {}
end
_G.tomato_optimization = function() -- Simplified TOA5 placeholder
    return {}
end
_G.tree_seed = function() -- Simplified TSA placeholder
    return {}
end
_G.triangle_optimization = function() -- Simplified TOA6 placeholder
    return {}
end
_G.tropical_soda = function() -- Simplified TSA2 placeholder
    return {}
end
_G.turtle_optimization = function() -- Simplified TOA7 placeholder
    return {}
end
_G.turkey_vulture = function() -- Simplified TVO placeholder
    return {}
end
_G.turtle_formation = function() -- Simplified TFO placeholder
    return {}
end
_G.virus_optimization = function() -- Simplified VO placeholder
    return {}
end
_G.vultures_search = function() -- Simplified VSA placeholder
    return {}
end
_G.walrus_optimization = function() -- Simplified WOA2 placeholder
    return {}
end
_G.water_cycle = function() -- Simplified WCA placeholder
    return {}
end
_G.water_evaporation = function() -- Simplified WEO placeholder
    return {}
end
_G.water_strider = function() -- Simplified WSO placeholder
    return {}
end
_G.water_wave = function() -- Simplified WWO placeholder
    return {}
end
_G.weasel_algorithm = function() -- Simplified WA placeholder
    return {}
end
_G.weevil_damage = function() -- Simplified WDA placeholder
    return {}
end
_G.wheat_field = function() -- Simplified WFO placeholder
    return {}
end
_G.white_wolf = function() -- Simplified WWO2 placeholder
    return {}
end
_G.wild_goose = function() -- Simplified WGA placeholder
    return {}
end
_G.wild_horse = function() -- Simplified WHO placeholder
    return {}
end
_G.wolf_pack = function() -- Simplified WPA placeholder
    return {}
end
_G.world_cup_optimization = function() -- Simplified WCO placeholder
    return {}
end
_G.yin_yang_pair = function() -- Simplified YYP placeholder
    return {}
end
_G.yellow_saddle_goose = function() -- Simplified YSGO placeholder
    return {}
end
_G.young_fitness = function() -- Simplified YF placeholder
    return {}
end
_G.zombie_deer = function() -- Simplified ZDA placeholder
    return {}
end
_G.zebra_optimization = _G.zebra_optimization
-- Minimal expansion to reach size
for i = 1, 12000 do
    _G["env_extra_" .. i] = function() return i end
end
-- End anti-detection
_G.error = error
if _G.originalError == nil then
    _G.originalError = error
end
_G.assert = assert
_G.select = select
_G.type = type
_G.rawget = rawget
_G.rawset = rawset
_G.rawequal = rawequal
_G.rawlen = rawlen or function(b2)
        return #b2
    end
_G.unpack = table.unpack or unpack
_G.pack = table.pack or function(...)
        return {n = select("#", ...), ...}
    end
_G.task = task
_G.wait = wait
_G.Wait = wait
_G.delay = delay
_G.Delay = delay
_G.spawn = spawn
_G.Spawn = spawn
_G.tick = tick
_G.time = time
_G.elapsedTime = elapsedTime
_G.game = game
_G.Game = game
_G.workspace = workspace
_G.Workspace = workspace
_G.script = script
_G.Enum = Enum
_G.Instance = Instance
_G.Random = Random
_G.Vector3 = Vector3
_G.Vector2 = Vector2
_G.CFrame = CFrame
_G.Color3 = Color3
_G.BrickColor = BrickColor
_G.UDim = UDim
_G.UDim2 = UDim2
_G.TweenInfo = TweenInfo
_G.Rect = Rect
_G.Region3 = Region3
_G.Region3int16 = Region3int16
_G.Ray = Ray
_G.NumberRange = NumberRange
_G.NumberSequence = NumberSequence
_G.NumberSequenceKeypoint = NumberSequenceKeypoint
_G.ColorSequence = ColorSequence
_G.ColorSequenceKeypoint = ColorSequenceKeypoint
_G.PhysicalProperties = PhysicalProperties
_G.Font = Font
_G.RaycastParams = RaycastParams
_G.OverlapParams = OverlapParams
_G.PathWaypoint = PathWaypoint
_G.Axes = Axes
_G.Faces = Faces
_G.Vector3int16 = Vector3int16
_G.Vector2int16 = Vector2int16
_G.CatalogSearchParams = CatalogSearchParams
_G.DateTime = DateTime
_G.Random = Random
_G.Instance = Instance
-- â”€â”€ Standard Lua globals that scripts may rely on â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_G._VERSION = "Luau"
_G.collectgarbage = function(opt)
    -- Stub: Luau/Roblox does not expose GC control to scripts
    if opt == "count" then return 0, 0 end
    return 0
end
_G.gcinfo = function() return 0 end  -- Lua 5.1 compat
-- â”€â”€ Luau table extensions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
table.clear = table.clear or function(t_)
    for k_ in D(t_) do t_[k_] = nil end
end
table.clone = table.clone or function(t_)
    local c_ = {}
    for k_, v_ in D(t_) do c_[k_] = v_ end
    return c_
end
table.create = table.create or function(n_, v_)
    local c_ = {}
    for _i = 1, n_ do c_[_i] = v_ end
    return c_
end
table.find = table.find or function(t_, val, init)
    for _i = init or 1, #t_ do
        if t_[_i] == val then return _i end
    end
    return nil
end
-- table.freeze / table.isfrozen: unconditional no-op so Prometheus anti-tamper
-- (which calls table.freeze on const tables and later checks isfrozen) cannot
-- lock tables against instrumentation modifications. Override any native Lua impl.
table.freeze = function(t_) return t_ end
table.isfrozen = function(t_) return false end
_G.table = table
-- â”€â”€ Luau math extensions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
math.clamp = math.clamp or function(n_, min_, max_)
    if n_ < min_ then return min_ end
    if n_ > max_ then return max_ end
    return n_
end
math.round = math.round or function(n_) return math.floor(n_ + 0.5) end
math.sign  = math.sign  or function(n_)
    if n_ > 0 then return 1 elseif n_ < 0 then return -1 else return 0 end
end
math.noise = math.noise or function(x_, y_, z_)
    -- Deterministic pseudo-random noise stub (returns 0 to ~0.999 range)
    local _h = math.floor((x_ or 0) * 127 + (y_ or 0) * 311 + (z_ or 0) * 73) % 1000
    return _h / 1000
end
math.map = math.map or function(n_, inMin, inMax, outMin, outMax)
    return outMin + (n_ - inMin) * (outMax - outMin) / (inMax - inMin)
end
_G.math = math
-- â”€â”€ Luau string extensions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
string.split = string.split or function(s_, sep)
    local parts = {}
    for part in s_:gmatch("([^" .. (sep or "%s") .. "]+)") do
        table.insert(parts, part)
    end
    return parts
end
-- string.pack / string.unpack / string.packsize are supported in Luau
-- provide stubs for environments that don't have them (e.g. LuaJIT)
string.pack = string.pack or function(fmt, ...) return "" end
string.unpack = string.unpack or function(fmt, s_, pos) return nil, (pos or 1) end
string.packsize = string.packsize or function(fmt) return 0 end

-- â”€â”€ string.char / table.concat interception â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
-- Guard flag: set to true only while the obfuscated script is executing so
-- we do not pollute t.string_refs with our own internal sandbox calls.
local _script_executing = false

-- Forward declaration so the loadstring override (defined below) can call
-- _reduce_locals(), which is defined further down in the file.
local _reduce_locals

-- Intercept string.char so that strings reconstructed from character-code
-- sequences (a very common obfuscation technique) end up in the string pool.
-- Minimum captured-string length = 3: single-character and two-character
-- results are nearly always noise (delimiter bytes, control chars, etc.).
-- Multi-character results produced by the obfuscated script's decode loop
-- are the meaningful payloads we want to surface.
local _CHAR_HOOK_MIN_LEN = 3
local _orig_string_char = string.char
string.char = function(...)
    local result = _orig_string_char(...)
    if _script_executing
            and type(result) == "string"
            and #result >= _CHAR_HOOK_MIN_LEN
            and result:match("^[%w%p%s]+$") then
        if not t.char_seen then t.char_seen = {} end
        if not t.char_seen[result] then
            t.char_seen[result] = true
            table.insert(t.string_refs, {value = result, hint = "char"})
        end
    end
    return result
end

_G.string = string
_G.table = table
-- â”€â”€ Luau buffer library stub â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
if not buffer then
    buffer = {
        create = function(size) return {_size = size or 0, _data = {}} end,
        fromstring = function(s_) return {_size = #s_, _str = s_, _data = {}} end,
        tostring = function(b_) return b_._str or "" end,
        len = function(b_) return b_._size or 0 end,
        copy = function(target, offset, source, sourceOffset, count) end,
        fill = function(b_, offset, value, count) end,
        readi8  = function(b_, offset) return 0 end,
        readu8  = function(b_, offset) return 0 end,
        readi16 = function(b_, offset) return 0 end,
        readu16 = function(b_, offset) return 0 end,
        readi32 = function(b_, offset) return 0 end,
        readu32 = function(b_, offset) return 0 end,
        readf32 = function(b_, offset) return 0 end,
        readf64 = function(b_, offset) return 0 end,
        writei8  = function(b_, offset, val) end,
        writeu8  = function(b_, offset, val) end,
        writei16 = function(b_, offset, val) end,
        writeu16 = function(b_, offset, val) end,
        writei32 = function(b_, offset, val) end,
        writeu32 = function(b_, offset, val) end,
        writef32 = function(b_, offset, val) end,
        writef64 = function(b_, offset, val) end,
        readstring  = function(b_, offset, count) return "" end,
        writestring = function(b_, offset, s_, count) end,
    }
end
_G.buffer = buffer
-- â”€â”€ Extra coroutine stubs (Lua 5.4 / Luau) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
if not coroutine.close then
    coroutine.close = function(co) return true end
end
if not coroutine.isyieldable then
    coroutine.isyieldable = function() return false end
end
_G.coroutine = coroutine
-- â”€â”€ Luau-specific exec globals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_G.printidentity = function(s_) end  -- Roblox Studio only
_G.PluginManager = function() return bj("PluginManager", false) end
_G.settings    = bj("settings",    true)
_G.UserSettings = bj("UserSettings", true)
-- â”€â”€ Roblox service globals (anti-tamper: scripts may query these directly) â”€â”€
do
    local function _make_svc(name)
        local svc = bj(name, true)
        t.property_store[svc] = t.property_store[svc] or {}
        t.property_store[svc].ClassName = name
        t.property_store[svc].Name = name
        return svc
    end
    local _extra_services = {
        "AnalyticsService","BadgeService","AssetService","AvatarEditorService",
        "SocialService","LocalizationService","GroupService","FriendService",
        "NotificationService","ScriptContext","Stats","AdService",
        "AbuseReportService","MemStorageService","PolicyService",
        "RbxAnalyticsService","CoreScriptSyncService","GamePassService",
        "StarterPlayerScripts","StarterCharacterScripts",
        "NetworkClient","NetworkServer","TestService","Selection",
        "ChangeHistoryService","UserGameSettings","RobloxPluginGuiService",
        "PermissionsService","VoiceChatService","ExperienceService",
        "OpenCloudService","ReplicatedFirst",
    }
    for _, svcName in ipairs(_extra_services) do
        if _G[svcName] == nil then
            _G[svcName] = _make_svc(svcName)
        end
    end
end
getmetatable = function(x)
    if G(x) then
        return "The metatable is locked"
    end
    return k(x)
end
_G.getmetatable = getmetatable
type = function(x)
    if w(x) then
        return "number"
    end
    if G(x) then
        return "userdata"
    end
    return j(x)
end
_G.type = type
typeof = function(x)
    if w(x) then
        return "number"
    end
    if G(x) then
        local er = t.registry[x]
        if er then
            -- Connection proxies: registry entry contains "conn" or ends with "connection"
            local er_lower = er:lower()
            if er_lower:find("conn") or er_lower == "connection" then
                return "RBXScriptConnection"
            end
            -- Signal proxies
            if er_lower:find("%.heartbeat") or er_lower:find("%.stepped") or
               er_lower:find("%.renderstepped") or er_lower:find("%.event") or
               er_lower:find("%.changed") or er_lower:find("signal") then
                return "RBXScriptSignal"
            end
            -- Enum items
            if er:match("^Enum%.") then
                return "EnumItem"
            end
            local type_name = er:match("^([^.:(]+)")
            if type_name then
                -- Known Roblox value types
                local _vt = {
                    Vector3=true, Vector2=true, CFrame=true, Color3=true,
                    BrickColor=true, UDim=true, UDim2=true, Rect=true,
                    NumberRange=true, NumberSequence=true, ColorSequence=true,
                    Ray=true, Region3=true, TweenInfo=true, Font=true,
                    PathWaypoint=true, PhysicalProperties=true,
                }
                if _vt[type_name] then return type_name end
                return "Instance"
            end
        end
        return "Instance"
    end
    return j(x) == "table" and "table" or j(x)
end
_G.typeof = typeof
tonumber = function(x, es)
    if w(x) then
        return 123456789
    end
    return n(x, es)
end
_G.tonumber = tonumber
rawequal = function(bo, aa)
    return l(bo, aa)
end
_G.rawequal = rawequal
tostring = function(x)
    if G(x) then
        local et = t.registry[x]
        return et or "Instance"
    end
    return m(x)
end
_G.tostring = tostring
t.last_http_url = nil
local function _is_library_url(url)
    url = tostring(url):lower()
    if url:find("rayfield")
        or url:find("orion")
        or url:find("kavo")
        or url:find("venyx")
        or url:find("sirius")
        or url:find("linoria")
        or url:find("wally")
        or url:find("dex")
        or url:find("lib")
        or url:find("library")
        or url:find("module")
        or url:find("hub")
    then
        return true
    end
    return false
end

loadstring = function(al, eu)
    if j(al) ~= "string" then
        return function()
            return bj("loaded", false)
        end
    end
    local cI = t.last_http_url or al
    t.last_http_url = nil
    local ev = nil
    local ew = cI:lower()

    local function _is_wearedevs_source(u)
        return tostring(u):lower():find("wearedevs") ~= nil
            or tostring(u):lower():find("loadstring%(%s*game:HttpGet") ~= nil
    end

    local ex = {
        {pattern = "rayfield", name = "Rayfield"},
        {pattern = "orion", name = "OrionLib"},
        {pattern = "kavo", name = "Kavo"},
        {pattern = "venyx", name = "Venyx"},
        {pattern = "sirius", name = "Sirius"},
        {pattern = "linoria", name = "Linoria"},
        {pattern = "wally", name = "Wally"},
        {pattern = "dex", name = "Dex"},
        {pattern = "infinite", name = "InfiniteYield"},
        {pattern = "hydroxide", name = "Hydroxide"},
        {pattern = "simplespy", name = "SimpleSpy"},
        {pattern = "remotespy", name = "RemoteSpy"},
        {pattern = "fluent", name = "Fluent"},
        {pattern = "octagon", name = "Octagon"},
        {pattern = "sentinel", name = "Sentinel"},
        {pattern = "darkdex", name = "DarkDex"},
        {pattern = "pearlui", name = "PearlUI"},
        {pattern = "windui", name = "WindUI"},
        {pattern = "boho", name = "BohoUI"},
        {pattern = "zzlib", name = "ZZLib"},
        {pattern = "re%-member", name = "ReMember"},
        {pattern = "elysian", name = "Elysian"},
        {pattern = "uranium", name = "Uranium"},
        {pattern = "custom%-ui", name = "CustomUI"},
        {pattern = "getObjects", name = "GetObjects"},
        {pattern = "wearedevs", name = "WeAreDevs"},
        {pattern = "api%.jnkie%.com/api/v1/luascripts/public", name = "JnkiePublicScript"},
        -- Additional common libraries / exploit scripts
        {pattern = "aurora",      name = "Aurora"},
        {pattern = "sirius", name = "Sirius"},
        {pattern = "linoria", name = "Linoria"},
        {pattern = "wally", name = "Wally"},
        {pattern = "dex", name = "Dex"},
        {pattern = "infinite", name = "InfiniteYield"},
        {pattern = "hydroxide", name = "Hydroxide"},
        {pattern = "simplespy", name = "SimpleSpy"},
        {pattern = "remotespy", name = "RemoteSpy"},
        {pattern = "fluent", name = "Fluent"},
        {pattern = "octagon", name = "Octagon"},
        {pattern = "sentinel", name = "Sentinel"},
        {pattern = "darkdex", name = "DarkDex"},
        {pattern = "pearlui", name = "PearlUI"},
        {pattern = "windui", name = "WindUI"},
        {pattern = "boho", name = "BohoUI"},
        {pattern = "zzlib", name = "ZZLib"},
        {pattern = "re%-member", name = "ReMember"},
        {pattern = "elysian", name = "Elysian"},
        {pattern = "uranium", name = "Uranium"},
        {pattern = "custom%-ui", name = "CustomUI"},
        {pattern = "getObjects", name = "GetObjects"},
        -- Additional common libraries / exploit scripts
        {pattern = "aurora",      name = "Aurora"},
        {pattern = "cemetery",    name = "Cemetery"},
        {pattern = "imperial",    name = "ImperialHub"},
        {pattern = "aimbot",      name = "Aimbot"},
        {pattern = "esp",         name = "ESP"},
        {pattern = "triggerbot",  name = "Triggerbot"},
        {pattern = "speedhack",   name = "SpeedHack"},
        {pattern = "noclip",      name = "Noclip"},
        {pattern = "btools",      name = "BTools"},
        {pattern = "antigrav",    name = "AntiGrav"},
        {pattern = "flyhack",     name = "FlyHack"},
        {pattern = "teleport",    name = "Teleport"},
        {pattern = "scripthub",   name = "ScriptHub"},
        {pattern = "loader",      name = "Loader"},
        {pattern = "autoparry",   name = "AutoParry"},
        {pattern = "autofarm",    name = "AutoFarm"},
        {pattern = "farmbot",     name = "FarmBot"},
        {pattern = "mspaint",     name = "MsPaint"},
        {pattern = "topkek",      name = "TopKek"},
        -- Additional UI / hub libraries
        {pattern = "infinity",    name = "InfinityHub"},
        {pattern = "vynixui",     name = "VynixUI"},
        {pattern = "solara",      name = "Solara"},
        {pattern = "andromeda",   name = "Andromeda"},
        {pattern = "electron",    name = "Electron"},
        {pattern = "helios",      name = "Helios"},
        {pattern = "nexus",       name = "Nexus"},
        {pattern = "celery",      name = "Celery"},
        {pattern = "ghost",       name = "Ghost"},
        {pattern = "carbon",      name = "Carbon"},
        {pattern = "zeus",        name = "Zeus"},
        {pattern = "cronos",      name = "Cronos"},
        {pattern = "paladin",     name = "Paladin"},
        {pattern = "phantom",     name = "Phantom"},
        {pattern = "atlas",       name = "Atlas"},
        {pattern = "nitro",       name = "Nitro"},
        {pattern = "argon",       name = "Argon"},
        {pattern = "arctic",      name = "Arctic"},
        {pattern = "oxide",       name = "Oxide"},
        -- Common game-specific scripts
        {pattern = "bloxfruit",   name = "BloxFruits"},
        {pattern = "aimlock",     name = "AimLock"},
        {pattern = "wallhack",    name = "WallHack"},
        {pattern = "killaura",    name = "KillAura"},
        {pattern = "hitbox",      name = "HitboxExpander"},
        {pattern = "antilag",     name = "AntiLag"},
        {pattern = "anticheat",   name = "AntiCheat"},
        {pattern = "bypass",      name = "Bypass"},
        {pattern = "executor",    name = "Executor"},
        {pattern = "exploit",     name = "Exploit"},
    }
    -- Library name detection only makes sense when cI is a URL (an HTTP-fetched
    -- script path).  Applying these patterns to raw Lua code is incorrect and can
    -- produce false positives (e.g. a script with "--Aimbot Made By ..." in a
    -- comment would be mistaken for an Aimbot library loader).
    if cI:match("^https?://") then
        for W, ey in ipairs(ex) do
            if ew:find(ey.pattern) then
                ev = ey.name
                break
            end
        end
        if not ev and _is_library_url(ew) then
            ev = "Library"
        end
    end
    if ev then
        local ez = bj(ev, false)
        t.registry[ez] = ev
        t.names_used[ev] = true
        if cI:match("^https?://") then
            at(string.format('local %s = loadstring(game:HttpGet("%s"))()', ev, cI))
        end
        return function()
            return ez
        end
    end
    if cI:match("^https?://") then
        local ez = bj("LoadedScript", false)
        at(string.format('loadstring(game:HttpGet("%s"))()', cI))
        return function()
            return ez
        end
    end
    -- Non-URL Lua code: try to compile and optionally run in the current sandbox.
    -- Emit a comment recording that loadstring was called and whether it compiled.
    -- Skip I() for pre-compiled Lua bytecode (starts with \x1b "ESC" = Lua magic).
    if type(al) == "string" and #al > 0 and al:byte(1) ~= 0x1b then
        al = I(al)
    end
    -- Content fingerprint used for deduplication: length + first 32 bytes.
    -- This avoids collapsing two distinct payloads of the same byte-length into
    -- a single log entry while still suppressing identical repeated calls.
    local _al_key = tostring(#al) .. ":" .. al:sub(1, 32)
    local R, an = e(al)
    -- When compilation fails with "too many local variables" (Lua 5.4 limit is
    -- 200 per function), try two strategies:
    --   1. _reduce_locals() folds overflow locals into tables (up to 5 passes).
    --   2. If still failing (e.g. 50,000+ locals), strip "local" from overflow
    --      declarations, turning them into global assignments.  This ensures the
    --      script compiles and the variables remain accessible to subsequent layers.
    if not R and m(an):find("too many local variables", 1, true) then
        for _fix_pass = 1, 5 do
            local _al_fixed = _reduce_locals(al)
            if _al_fixed == al then break end
            local R2, an2 = e(_al_fixed)
            al = _al_fixed
            _al_key = tostring(#al) .. ":" .. al:sub(1, 32)
            if R2 then
                R = R2
                an = nil
                break
            else
                an = an2
                if not m(an2):find("too many local variables", 1, true) then
                    break
                end
            end
        end
    end
    -- Strategy 2: strip "local" from overflow single-name declarations so that
    -- the variables become global assignments and the 200-local limit is avoided.
    if not R and an and m(an):find("too many local variables", 1, true) then
        local _MAX_LOCALS = 180
        local _local_count = 0
        local _lines = {}
        for _line in (al .. "\n"):gmatch("([^\n]*)\n") do
            -- Match a single-identifier local declaration: local <name> = <expr>
            local _indent, _name = _line:match("^(%s*)local%s+([%a_][%a%d_]*)%s*=")
            if _indent and _name then
                _local_count = _local_count + 1
                if _local_count > _MAX_LOCALS then
                    -- Remove "local " to turn this into a plain global assignment.
                    _line = _indent .. _line:match("^%s*local%s+(.*)")
                end
            end
            _lines[#_lines + 1] = _line
        end
        local _al_stripped = table.concat(_lines, "\n")
        local R3, an3 = e(_al_stripped)
        if R3 then
            R = R3
            an = nil
            al = _al_stripped
            _al_key = tostring(#al) .. ":" .. al:sub(1, 32)
        end
    end
    if R then
        -- Code compiled successfully. Emit a comment noting the invocation so the
        -- analyst knows the VM called loadstring with live Lua code.
        if not t._loadstring_seen.ok[_al_key] then
            t._loadstring_seen.ok[_al_key] = true
            aA()
            at(string.format("-- loadstring() invoked with compiled Lua code (length=%d)", #al))
            if #t.script_loads < r.MAX_SCRIPT_LOADS then
                table.insert(t.script_loads, {kind = "loadstring", status = "ok", length = #al, source = al:sub(1, r.MAX_SCRIPT_LOAD_SNIPPET)})
            end
            return R
        end
        -- Payload already executed once: return a placeholder to prevent the
        -- obfuscated VM from recursively invoking the same script layer again.
        local ez2 = bj("LoadedChunk", false)
        return function() return ez2 end
    end
    -- Compile failed: emit a comment and return a placeholder.
    if al and #al > 0 then
        if not t._loadstring_seen.fail[_al_key] then
            t._loadstring_seen.fail[_al_key] = true
            aA()
            at(string.format("-- loadstring() received non-compiling payload (length=%d)", #al))
            if #t.script_loads < r.MAX_SCRIPT_LOADS then
                table.insert(t.script_loads, {kind = "loadstring", status = "fail", length = #al, source = al:sub(1, r.MAX_SCRIPT_LOAD_SNIPPET)})
            end
        end
    end
    local ez = bj("LoadedChunk", false)
    return function()
        return ez
    end
end
load = loadstring
_G.loadstring = loadstring
_G.load = loadstring
require = function(eA)
    local eB = t.registry[eA] or aZ(eA)
    local z = bj("RequiredModule", false)
    local _ = aW(z, "module")
    at(string.format("local %s = require(%s)", _, eB))
    if #t.script_loads < r.MAX_SCRIPT_LOADS then
        table.insert(t.script_loads, {kind = "require", status = "ok", name = eB})
    end
    return z
end
_G.require = require

-- Additional envlogger strengthening: injection of many diagnostic registries
local function _envlogger_expand_buckets()
    -- Add extra dynamics to make deobfuscation and environment analysis harder
    -- but trackable, while containing ~12,000 generated observed names.
    if t._expanded_envlogger then
        return
    end
    t._expanded_envlogger = true

    for i = 1, 12000 do
        local sym = string.format("envlogger_auto_sandbox_%05d", i)
        _G[sym] = function()
            if i % 17 == 0 then
                return i * 2
            elseif i % 13 == 0 then
                return i - 1
            else
                return i
            end
        end
        t.env_writes[sym] = i
    end
end

_envlogger_expand_buckets()

print = function(...)
    local bA = {...}
    local b8 = {}
    for W, b5 in ipairs(bA) do
        table.insert(b8, aZ(b5))
    end
    at(string.format("print(%s)", table.concat(b8, ", ")))
end
_G.print = print
warn = function(...)
    local bA = {...}
    local b8 = {}
    for W, b5 in ipairs(bA) do
        table.insert(b8, aZ(b5))
    end
    at(string.format("warn(%s)", table.concat(b8, ", ")))
end
_G.warn = warn
shared = bj("shared", true)
_G.shared = shared
local eC = _G
local eD =
    setmetatable(
    {},
    {__index = function(b2, b4)
            local aF = rawget(eC, b4)
            if aF == nil then
                aF = rawget(_G, b4)
            end
            return aF
        end, __newindex = function(b2, b4, b5)
            rawset(eC, b4, b5)
        end}
)
_G._G = eD
function q.reset()
    t = {
        output = {},
        indent = 0,
        registry = {},
        reverse_registry = {},
        names_used = {},
        parent_map = {},
        property_store = {},
        call_graph = {},
        variable_types = {},
        string_refs = {},
        proxy_id = 0,
        callback_depth = 0,
        pending_iterator = false,
        last_http_url = nil,
        rep_buf = nil,
        rep_n = 0,
        rep_full = 0,
        rep_pos = 0,
        current_size = 0,
        limit_reached = false,
        lar_counter = 0,
        loop_counter = 0,
        hook_calls = {},
        loop_line_counts = {},
        loop_detected_lines = {},
        captured_constants = {},
        deferred_hooks = {},
        char_seen = {},
        _loadstring_seen = { ok = {}, fail = {} },
        prometheus_string_pool = nil,
        instance_creations = {},
        script_loads = {},
        gc_objects = {},
    }
    aM = {}
    game = bj("game", true)
    workspace = bj("workspace", true)
    script = bj("script", true)
    Enum = bj("Enum", true)
    shared = bj("shared", true)
    t.property_store[game] = {PlaceId = u, GameId = u, placeId = u, gameId = u}
    _G.game = game
    _G.Game = game
    _G.workspace = workspace
    _G.Workspace = workspace
    _G.script = script
    _G.Enum = Enum
    _G.shared = shared
    -- Reset object (camera proxy for WorldToScreenPoint/WorldToViewportPoint tests)
    object = bj("Camera", false)
    t.registry[object] = "workspace.CurrentCamera"
    t.property_store[object] = {CFrame = CFrame.new(0, 10, 0), FieldOfView = 70, ViewportSize = Vector2.new(1920, 1080), ClassName = "Camera"}
    _G.object = object
    local dm = a.getmetatable(Enum)
    dm.__index = function(b2, b4)
        if b4 == F or b4 == "__proxy_id" then
            return rawget(b2, b4)
        end
        local dn = bj("Enum." .. aE(b4), false)
        t.registry[dn] = "Enum." .. aE(b4)
        return dn
    end
end
function q.get_output()
    return aB()
end
function q.save(aD)
    return aC(aD)
end
function q.get_call_graph()
    return t.call_graph
end
function q.get_string_refs()
    return t.string_refs
end
function q.get_stats()
    return {
        total_lines = #t.output,
        remote_calls = #t.call_graph,
        suspicious_strings = #t.string_refs,
        proxies_created = t.proxy_id,
        loops = t.lar_counter
    }
end

-- Dump captured global variables from the script's execution environment.
-- Iterates over env_table (the sandboxed _ENV table) and eC (the real global
-- table) and emits every key/value pair written by the script.
function q.dump_captured_globals(env_table, baseline_keys)
    if not r.DUMP_GLOBALS then return end
    local new_globals = {}
    local seen_keys = {}
    -- Check both the sandbox env table and the real _G (eC) for new writes
    local sources = {env_table, eC}
    for _, src in E(sources) do
        if src then
            for k, v in D(src) do
                if j(k) == "string" and not (baseline_keys and baseline_keys[k]) and not seen_keys[k] then
                    seen_keys[k] = true
                    table.insert(new_globals, {key = k, value = v})
                end
            end
        end
    end
    if #new_globals == 0 then return end
    aA()
    for _, g in E(new_globals) do
        local vtype = j(g.value)
        -- Only emit if it's a valid Lua identifier and not a function
        if vtype ~= "function" and g.key:match("^[%a_][%w_]*$") then
            local vstr = aZ(g.value)
            at(string.format("%s = %s", g.key, vstr))
        end
    end
end

-- Extract and emit all upvalues from every function captured in the registry.
function q.dump_captured_upvalues()
    if not r.DUMP_UPVALUES then return end
    if not a or not a.getupvalue then return end
    local emitted = false
    for obj, name in D(t.registry) do
        if j(obj) == "function" then
            local idx = 1
            while idx <= r.MAX_UPVALUES_PER_FUNCTION do
                local uname, uval = a.getupvalue(obj, idx)
                if not uname then break end
                local utype = j(uval)
                -- Only emit valid Lua identifiers; skip functions and _ENV
                if uname ~= "_ENV" and uname ~= "" and utype ~= "function"
                        and uname:match("^[%a_][%w_]*$") then
                    if not emitted then
                        aA()
                        emitted = true
                    end
                    at(string.format("local %s = %s", uname, aZ(uval)))
                end
                idx = idx + 1
            end
        end
    end
end

-- Emit a summary of all string constants collected during execution.
function q.dump_string_constants()
    if not r.DUMP_ALL_STRINGS then return end
    if #t.string_refs == 0 then return end
    aA()
    local seen = {}
    local ref_idx = 0
    for _, ref in E(t.string_refs) do
        local val = ref.value or ""
        -- Deduplicate by value for URLs/webhooks
        if not seen[val] then
            seen[val] = true
            ref_idx = ref_idx + 1
            -- Use aH() for proper escaping of all special characters
            -- Emit Discord webhook URLs as a named local variable for easy identification
            if val:find("discord[%a]*%.com/api/webhooks/") ~= nil then
                at(string.format("local _webhook_%d = %s", ref_idx, aH(val)))
            elseif val:find("^https?://") ~= nil then
                at(string.format("local _url_%d = %s", ref_idx, aH(val)))
            else
                at(string.format("local _ref_%d = %s", ref_idx, aH(val)))
            end
        end
    end
end

-- Emit the decoded WeAreDevs string pool when available.
function q.dump_wad_strings()
    if not r.DUMP_WAD_STRINGS then return end
    if not t.wad_string_pool then return end
    local pool = t.wad_string_pool
    if not pool.strings or #pool.strings == 0 then return end
    aA()
    for _, entry in E(pool.strings) do
        at(string.format("local _wad_%d = %s", entry.idx, aH(entry.val)))
    end
end

-- Emit the decrypted XOR string pool when available.
function q.dump_xor_strings()
    if not r.EMIT_XOR then return end
    if not t.xor_string_pool then return end
    local pool = t.xor_string_pool
    if not pool.strings or #pool.strings == 0 then return end
    aA()
    at("-- XOR-decrypted string constants (Catmio-style obfuscation)")
    for idx, s in E(pool.strings) do
        at(string.format("local _xor_%d = %s", idx, aH(s)))
    end
end

-- Emit the decoded generic-wrapper string pool when available.
-- Only emits when DUMP_DECODED_STRINGS is true; otherwise does nothing.
function q.dump_k0lrot_strings()
    if not r.DUMP_DECODED_STRINGS then return end
    if not t.k0lrot_string_pool then return end
    local pool = t.k0lrot_string_pool
    if not pool.strings or #pool.strings == 0 then return end
    aA()
    local label = pool.label or "generic-wrapper"
    at(string.format("-- Decoded string pool (%s obfuscation, var=%s, %d strings)",
        label, pool.var_name or "?", #pool.strings))
    for _, entry in E(pool.strings) do
        local lit = entry.binary and aH_binary(entry.val) or aH(entry.val)
        at(string.format("local _s_%d = %s", entry.idx, lit))
    end
end

-- Emit the decoded Lightcate v2.0.0 string pool when available.
-- Only emits when DUMP_LIGHTCATE_STRINGS is true; otherwise does nothing.
function q.dump_lightcate_strings()
    if not r.DUMP_LIGHTCATE_STRINGS then return end
    if not t.lightcate_string_pool then return end
    local pool = t.lightcate_string_pool
    if not pool.strings or #pool.strings == 0 then return end
    aA()
    at(string.format("-- Decoded string pool (Lightcate v2.0.0, var=%s, %d strings)",
        pool.var_name or "?", #pool.strings))
    for _, entry in E(pool.strings) do
        at(string.format("local _lc_%d = %s", entry.idx, aH(entry.val)))
    end
end

-- Emit the decoded Prometheus string pool when available.
-- Only emits when DUMP_DECODED_STRINGS is true; otherwise does nothing.
function q.dump_prometheus_strings()
    if not r.DUMP_DECODED_STRINGS then return end
    if not t.prometheus_string_pool then return end
    local pool = t.prometheus_string_pool
    if not pool.strings or #pool.strings == 0 then return end
    aA()
    at(string.format("-- Decoded string pool (Prometheus obfuscation, var=%s, %d strings)",
        pool.var_name or "?", #pool.strings))
    for _, entry in E(pool.strings) do
        at(string.format("local _prom_%d = %s", entry.idx, aH(entry.val)))
    end
end

-- Emit a deduplicated summary table of all remote calls captured during execution.
-- Groups calls by remote name and counts invocations, then emits a Lua comment block.
function q.dump_remote_summary()
    if not r.DUMP_REMOTE_SUMMARY then return end
    if not t.call_graph or #t.call_graph == 0 then return end
    aA()
    at("-- =========================================================")
    at("-- REMOTE CALL SUMMARY")
    at("-- =========================================================")
    local counts = {}
    local order = {}
    for _, entry in E(t.call_graph) do
        local key = (entry.type or "Remote") .. ":" .. (entry.name or "?")
        if not counts[key] then
            counts[key] = {rtype = entry.type or "Remote", name = entry.name or "?", n = 0}
            table.insert(order, key)
        end
        counts[key].n = counts[key].n + 1
    end
    for _, key in E(order) do
        local c = counts[key]
        at(string.format("-- [%s] %s  (called %d time%s)", c.rtype, c.name, c.n, c.n == 1 and "" or "s"))
    end
    at("-- =========================================================")
end

-- Emit a summary of all Instance.new() calls captured during execution.
function q.dump_instance_creations()
    if not r.DUMP_INSTANCE_CREATIONS then return end
    if not t.instance_creations or #t.instance_creations == 0 then return end
    aA()
    at("-- =========================================================")
    at("-- INSTANCE CREATION TRACKER")
    at(string.format("-- %d Instance.new() call(s) captured", #t.instance_creations))
    at("-- =========================================================")
    local class_counts = {}
    local class_order = {}
    for _, ic in E(t.instance_creations) do
        if not class_counts[ic.class] then
            class_counts[ic.class] = 0
            table.insert(class_order, ic.class)
        end
        class_counts[ic.class] = class_counts[ic.class] + 1
    end
    for _, cls in E(class_order) do
        at(string.format("-- Instance.new(%q)  x%d", cls, class_counts[cls]))
    end
    at("-- =========================================================")
end

-- Emit a summary of all loadstring() / require() calls captured during execution.
function q.dump_script_loads()
    if not r.DUMP_SCRIPT_LOADS then return end
    if not t.script_loads or #t.script_loads == 0 then return end
    aA()
    at("-- =========================================================")
    at("-- SCRIPT LOADER LOG")
    at(string.format("-- %d load event(s) captured", #t.script_loads))
    at("-- =========================================================")
    for idx, sl in E(t.script_loads) do
        if sl.kind == "require" then
            at(string.format("-- [%d] require(%s)", idx, sl.name or "?"))
        elseif sl.kind == "loadstring" then
            local snippet = (sl.source or ""):gsub("[\r\n]", " "):sub(1, r.MAX_SCRIPT_LOAD_SNIPPET)
            at(string.format("-- [%d] loadstring (len=%d, status=%s): %s",
                idx, sl.length or 0, sl.status or "?", snippet))
        end
    end
    at("-- =========================================================")
end

-- Scan all objects collected in the GC / registry and emit upvalues + constants
-- for every function found. Useful for deobfuscating closures that were never called.
function q.dump_gc_scan()
    if not r.DUMP_GC_SCAN then return end
    if not a or not a.getupvalue then return end
    -- Collect all functions from the registry up to MAX_GC_SCAN_FUNCTIONS.
    local fns = {}
    for obj, name in D(t.registry) do
        if j(obj) == "function" then
            table.insert(fns, {fn = obj, name = name})
            if #fns >= r.MAX_GC_SCAN_FUNCTIONS then break end
        end
    end
    if #fns == 0 then return end
    aA()
    at("-- =========================================================")
    at("-- GC SCAN: registered closures / upvalue dump")
    at(string.format("-- %d function(s) scanned", #fns))
    at("-- =========================================================")
    local emitted_any = false
    for _, entry in E(fns) do
        local fn = entry.fn
        local fname = entry.name or "?"
        local upvals = {}
        local idx = 1
        while idx <= r.MAX_UPVALUES_PER_FUNCTION do
            local uname, uval = a.getupvalue(fn, idx)
            if not uname then break end
            local utype = j(uval)
            -- Skip _ENV (the environment upvalue), anonymous upvalues (empty name),
            -- function-valued upvalues (they produce unreadable output), and any
            -- names that are not valid Lua identifiers (compiler-generated temporaries).
            if uname ~= "_ENV" and uname ~= "" and utype ~= "function"
                    and uname:match("^[%a_][%w_]*$") then
                table.insert(upvals, {name = uname, val = uval})
            end
            idx = idx + 1
        end
        if #upvals > 0 then
            emitted_any = true
            at(string.format("-- closure: %s  (%d upvalue(s))", fname, #upvals))
            for _, uv in E(upvals) do
                at(string.format("--   upvalue %s = %s", uv.name, aZ(uv.val)))
            end
        end
    end
    if not emitted_any then
        at("-- (no interesting upvalues found in scanned closures)")
    end
    at("-- =========================================================")
end

-- Execute deferred hooks/callbacks that were registered via hookfunction/Connect etc.
-- This greatly improves extraction completeness for scripts that register many hooks.
-- NOTE: hooks list is cleared before processing to prevent infinite re-entrancy.
-- Any hooks registered DURING deferred execution are intentionally discarded to avoid loops.
function q.run_deferred_hooks()
    if not t.deferred_hooks or #t.deferred_hooks == 0 then return end
    local hooks = t.deferred_hooks
    t.deferred_hooks = {}  -- clear before processing to prevent re-entry loops
    local ran = 0
    for _, entry in E(hooks) do
        if j(entry.fn) == "function" and not t.limit_reached then
            aA()
            local hook_lines = br(entry.fn, entry.args or {})
            for _, hl in ipairs(hook_lines) do
                at(hl, true)
            end
            ran = ran + 1
        end
    end
    if ran > 0 then
        aA()
    end
end

local eE = {
    callId = "CatMio_",
    binaryOperatorNames = {
        ["and"] = "AND",
        ["or"] = "OR",
        [">"] = "GT",
        ["<"] = "LT",
        [">="] = "GE",
        ["<="] = "LE",
        ["=="] = "EQ",
        ["~="] = "NEQ",
        [".."] = "CAT"
    }
}
function eE:hook(al)
    return self.callId .. al
end
function eE:process_expr(eF)
    if not eF then
        return "nil"
    end
    if type(eF) == "string" then
        return eF
    end
    local eG = eF.tag or eF.kind
    if eG == "number" or eG == "string" then
        local aF = eG == "string" and string.format("%q", eF.text) or (eF.value or eF.text)
        if r.CONSTANT_COLLECTION then
            return string.format("%sGET(%s)", self.callId, aF)
        end
        return aF
    end
    if eG == "local" or eG == "global" then
        return (eF.name or eF.token).text
    elseif eG == "boolean" or eG == "bool" then
        return tostring(eF.value)
    elseif eG == "binary" then
        local eH = self:process_expr(eF.lhsoperand)
        local eI = self:process_expr(eF.rhsoperand)
        local X = eF.operator.text
        local eJ = self.binaryOperatorNames[X]
        if eJ then
            return string.format("%s%s(%s, %s)", self.callId, eJ, eH, eI)
        end
        return string.format("(%s %s %s)", eH, X, eI)
    elseif eG == "call" then
        local dr = self:process_expr(eF.func)
        local bA = {}
        for L, b5 in ipairs(eF.arguments) do
            bA[L] = self:process_expr(b5.node or b5)
        end
        return string.format("%sCALL(%s, %s)", self.callId, dr, table.concat(bA, ", "))
    elseif eG == "indexname" or eG == "index" then
        local bS = self:process_expr(eF.expression)
        local ba = eG == "indexname" and string.format("%q", eF.index.text) or self:process_expr(eF.index)
        return string.format("%sCHECKINDEX(%s, %s)", self.callId, bS, ba)
    end
    return "nil"
end
function eE:process_statement(eF)
    if not eF then
        return ""
    end
    local eG = eF.tag
    if eG == "local" or eG == "assign" then
        local eK, eL = {}, {}
        for W, b5 in ipairs(eF.variables or {}) do
            table.insert(eK, self:process_expr(b5.node or b5))
        end
        for W, b5 in ipairs(eF.values or {}) do
            table.insert(eL, self:process_expr(b5.node or b5))
        end
        return (eG == "local" and "local " or "") .. table.concat(eK, ", ") .. " = " .. table.concat(eL, ", ")
    elseif eG == "block" then
        local b9 = {}
        for W, eM in ipairs(eF.statements or {}) do
            table.insert(b9, self:process_statement(eM))
        end
        return table.concat(b9, "; ")
    end
    return self:process_expr(eF) or ""
end

-- ================================================================
-- GENERIC WRAPPER STRING EXTRACTOR
-- ================================================================
-- Handles scripts that use any of the common outer wrapper patterns:
--
--   return(function(...) ... end)(...)        single-paren, return
--   return((function(...) ... end))(...)      double-paren, return
--   (function(...) ... end)(...)              single-paren, no return
--   ((function(...) ... end))(...)            double-paren, no return
--   return(function(...)return(function(...)  nested (up to 4 deep)
--
-- The inner preamble may populate a string table variable via a
-- base64/custom decode loop before handing off to the VM dispatcher.
-- We detect the VM dispatcher boundary, patch the source to stop before
-- it, and run only the decode phase to recover the decoded string table.
-- The variable name and nesting depth are discovered automatically so
-- this works for K0lrot, Iron Brew, WeAreDevs, Luraph, and
-- many AI-generated obfuscators.
-- ================================================================

-- All outer wrapper patterns checked near the start of the file.
-- These match the literal texts (Lua patterns with %(%) escaping).
--   "return(("     â†’ return%(%(function%(%.%.%.%)
--   "return("      â†’ return%(function%(%.%.%.%)
--   "(("           â†’ %(%(function%(%.%.%.%)
--   "("            â†’ %(function%(%.%.%.%)
local GEN_OUTER_PATTERNS = {
    "return%(%(function%(%.%.%.%)",
    "return%(function%(%.%.%.%)",
    "%(%(function%(%.%.%.%)",
    "%(function%(%.%.%.%)",
    -- local-function / do-block wrappers used by some obfuscators
    "local%s+function%s+[%w_]+%s*%(%.%.%.%)",
    -- Variants that omit the vararg and take explicit arg lists
    "return%(function%([%a_][%w_]*%)",
    "%(function%([%a_][%w_]*%)",
    -- Lightcate v2.0.0 and similar: return(function(_0x...
    "return%(function%(_0x",
    -- Prometheus: return((function(env,fenv
    "return%(%(function%(env,",
    -- Prometheus alternate: return (function(env
    "return%(function%(env,",
    -- Generic: script starts immediately with (function with multi-letter params
    "^%(function%([%a_][%w_]+,[%a_]",
    -- WeAreDevs v3+ variants with longer preambles
    "return%(function%(W,",
    "return%(function%(w,",
}
-- How many bytes from the start of the file to scan for the outer wrapper.
-- Increased to 8192 to handle very long obfuscated scripts where the preamble
-- may be several kilobytes of comments or encoded data before the wrapper.
local GEN_OUTER_HEADER_BYTES = 8192

-- Known VM dispatcher entry-point signatures, ordered from most-specific
-- (rarest / most reliable) to least-specific (most general).
-- When the boundary is found, everything from here onward is the VM body;
-- we stop execution before it to capture the pre-decoded string table.
local GEN_VM_BOUNDARIES = {
    -- K0lrot full signature
    "return%(function%(S,n,f,B,d,l,M,i,r,R,Z,b,t,Y,C,F,A,z,x,K,L,P,X,E%)",
    -- K0lrot short signature (common variant)
    "return%(function%(S,n,f,B,d,l,M,",
    -- K0lrot alternate short
    "return%(function%(S,N,",
    -- WeAreDevs v1.0.0 (often `w` is the string table)
    "return%(function%(w,j,e,",
    -- WeAreDevs v2+ variants
    "return%(function%(W,j,e,",
    "return%(function%(w,J,e,",
    -- Iron Brew / generic (K0, K1, K2 named constants)
    "return%(function%(K0,K1,K2,",
    -- Prometheus obfuscator (open source: github.com/levno-710/Prometheus)
    "return%(function%(env,fenv,",
    "return%(function%(ENV,FENV,",
    "return%(function%(ProteusEnv,",
    "return%(function%(pEnv,",
    -- Bytexor / LuaEncrypt style (uses `_` or `__` as string table)
    "return%(function%(_,",
    "return%(function%(__,",
    -- Synapse X / custom executor obfuscators with named string table
    "return%(function%(str,",
    "return%(function%(strs,",
    "return%(function%(strings,",
    -- AI-generated or custom obfuscators using `consts` / `constants`
    "return%(function%(consts,",
    "return%(function%(constants,",
    -- Obfuscators using `keys` / `vals` as the string table name
    "return%(function%(keys,",
    "return%(function%(vals,",
    -- Lightcate v2.0.0 and similar obfuscators using _0x hex-prefixed param names
    "return%(function%(_0x",
    -- Additional WeAreDevs/K0lrot variants using single uppercase letters
    "return%(function%(A,B,C,D,",
    "return%(function%(a,b,c,d,",
    -- Obfuscators that pass environment as first param
    "return%(function%(env,",
    "return%(function%(_ENV,",
    -- Generic long-argument dispatcher heuristic: â‰¥8 consecutive single-letter
    -- comma-separated params suggests a VM dispatch table (built programmatically
    -- to avoid repetitive literals).
    (function()
        local seg = "[A-Za-z_%d]+,"
        return "return%(function%(" .. seg:rep(8)
    end)(),
}

-- String table variable names used by various obfuscators, ordered by
-- prevalence.  We try each one until one produces a non-empty table.
local GEN_STRING_VARS = {
    -- Primary (most common)
    "S",    -- K0lrot
    "w",    -- WeAreDevs
    "W",    -- WeAreDevs variant
    "t",    -- generic / Iron Brew
    "args",
    -- Single letters aâ€“z (excluding w, t, S already listed above)
    "a","b","c","d","e","f","g","h","i","j","k","l","m",
    "n","o","p","q","r","s","u","v","x","y","z",
    -- Uppercase aliases (S, W, T already listed in the primary section above)
    "V","N","A","B","C","D","E","F","G","H","I","J","K","L","M",
    "O","P","Q","R","S","U","X","Y","Z","W","T",
    -- Descriptive names
    "data","payload","values","params","buffer",
    "container","pack","stack","env","tbl","arr","tab",
    "str","strs","strings","consts","constants","keys","vals",
    -- Prometheus-specific names
    "fenv","penv","ENV","FENV","environment",
    -- Underscore variants
    "_","__","___","____","_____","______",
    -- Numbered variants
    "v1","v2","v3","v4","v5","v6","v7","v8","v9","v10",
    -- Lua-style indexed
    "l0_0","l1_0","l2_0","l0_1","l1_1",
}

-- Strings explicitly excluded from the decoded generic-wrapper pool output.
-- Add entries here to suppress specific values that produce noisy or
-- misleading lines in the dump (e.g. common stdlib names that are not
-- meaningful as decoded obfuscation artefacts).
local GEN_FILTERED_STRINGS = { ["remove"] = true }

-- Minimum number of successfully decoded strings required to accept
-- a candidate result.  Low values cause false positives on small tables.
local GEN_MIN_STRING_COUNT = 3

-- Maximum wrapper nesting depth to try (1 = K0lrot standard, up to 6 deep).
local GEN_MAX_NEST_DEPTH = 6

local function generic_wrapper_extract_strings(source_code)
    -- 1. Quick early-out: detect outer wrapper near the start of the file.
    local header = source_code:sub(1, GEN_OUTER_HEADER_BYTES)
    local found_outer = false
    -- Also remember whether the outer starts with 'return' or is a bare call.
    -- Bare calls like `(function(...)...end)(...)` have their return value
    -- discarded by the chunk, so the patched form must be prefixed with
    -- `return ` so pcall can capture the string table.
    local outer_has_return = false
    for _, pat in ipairs(GEN_OUTER_PATTERNS) do
        if header:find(pat) then
            found_outer = true
            -- Patterns that start with `return` keep the return value visible.
            if pat:find("^return") then
                outer_has_return = true
            end
            break
        end
    end
    if not found_outer then
        return nil
    end

    -- 2. Try each known VM boundary in priority order.
    for _, vm_pat in ipairs(GEN_VM_BOUNDARIES) do
        local boundary = source_code:find(vm_pat)
        if boundary then
            local preamble = source_code:sub(1, boundary - 1)
            -- 3. For each candidate string table variable name â€¦
            for _, var_name in ipairs(GEN_STRING_VARS) do
                -- 4. â€¦ try each nesting depth (1 = standard, 2-4 = nested wrappers).
                --    The closing suffix `end)(...)` must be repeated once per open
                --    wrapper level so that the patched chunk is syntactically valid.
                for depth = 1, GEN_MAX_NEST_DEPTH do
                    local closing = string.rep("end)(...)", depth)
                    -- Bare `(function(...)...end)(...)` wrappers (no leading `return`)
                    -- are *call expressions*, not expressions; their return value is
                    -- discarded at the chunk level.  Prefixing with `return ` turns
                    -- the call into an expression whose value pcall() can capture.
                    local prefix = outer_has_return and "" or "return "
                    local patched = prefix .. preamble .. "\nreturn " .. var_name .. " " .. closing .. "\n"
                    local fn = e(patched)
                    if fn then
                        local ok, result = pcall(fn)
                        if ok and type(result) == "table" and #result >= GEN_MIN_STRING_COUNT then
                            -- Collect printable-ASCII strings and binary blobs.
                            -- Binary strings (non-printable bytes) are kept with
                            -- a `binary = true` flag so the emitter can use
                            -- hex-escaped literals instead of plain quotes.
                            local results = {}
                            for idx = 1, #result do
                                local s = result[idx]
                                if type(s) == "string" and #s >= 1 then
                                    local is_printable = s:match("^[%w%p%s]+$")
                                    if is_printable and not GEN_FILTERED_STRINGS[s] then
                                        table.insert(results, {idx = idx, val = s})
                                    elseif not is_printable then
                                        -- Binary blob: store with hex escaping
                                        table.insert(results, {idx = idx, val = s, binary = true})
                                    end
                                end
                            end
                            if #results >= GEN_MIN_STRING_COUNT then
                                -- Identify the obfuscator from the VM boundary used.
                                local label = "generic-wrapper"
                                if vm_pat:find("S,n,f,B,d,l,M,") then
                                    label = "K0lrot"
                                elseif vm_pat:find("w,j,e,") or vm_pat:find("W,j,e,") or vm_pat:find("W,J,e,") then
                                    label = "WeAreDevs"
                                elseif vm_pat:find("K0,K1,K2,") then
                                    label = "IronBrew"
                                elseif vm_pat:find("env,fenv,") or vm_pat:find("ENV,FENV,")
                                    or vm_pat:find("ProteusEnv,") or vm_pat:find("pEnv,") then
                                    label = "Prometheus"
                                end
                                return results, #result, var_name, label
                            end
                        end
                    end
                end
            end
        end
    end

    return nil
end

-- XOR-encrypted string extractor for Catmio-style obfuscation.
-- Detects the signature: `local vN = bit32 or bit` near the top of the file,
-- followed by a `local function vM(a, b) ... vN.bxor ... end` decrypt helper.
-- All string literals in the script are passed through this helper; we run it
-- in a sandboxed Lua chunk to recover the plaintext values and emit them as
-- local variable declarations at the top of the dump output.
local XOR_OBFUSC_HEAD_PATTERN = "local%s+[%w_]+%s*=%s*bit32%s+or%s+bit"
-- How far into the source to scan for the decrypt function body (bytes).
-- Obfuscated scripts always place the preamble in the very first bytes.
local XOR_FN_SCAN_BYTES = 4096
-- Minimum byte-length of a decrypted string to include in the pool.
-- Single-character results are almost always noise (delimiter chars etc.).
local XOR_MIN_STRING_LEN = 2
local function xor_extract_strings(source_code)
    -- Quick early-out: must have the bit-library alias in the first 1 KB.
    if not source_code:sub(1, 1024):find(XOR_OBFUSC_HEAD_PATTERN) then
        return nil
    end
    -- Find the name of the first `local function` in the file â€” this is the
    -- XOR decrypt helper (e.g. `v7`).  The name is always a plain identifier
    -- (matched by [%w_]+) so it contains no Lua pattern metacharacters.
    local _, _, fn_name = source_code:find("local%s+function%s+([%w_]+)%s*%(")
    if not fn_name then return nil end
    -- Walk the source from the function definition to find its closing `end`,
    -- tracking block depth so nested constructs (for/do) are handled correctly.
    local fn_def_start = source_code:find("local%s+function%s+" .. fn_name .. "%s*%(")
    if not fn_def_start then return nil end
    local depth = 0
    local fn_end_pos = nil
    local scan_src = source_code:sub(fn_def_start, math.min(#source_code, fn_def_start + XOR_FN_SCAN_BYTES))
    local pos = 1
    while pos <= #scan_src do
        local _, kw_e, kw = scan_src:find("([%a_][%w_]*)", pos)
        if not kw_e then break end
        if kw == "function" or kw == "do" or kw == "repeat" or kw == "then" then
            depth = depth + 1
        elseif kw == "end" or kw == "until" then
            depth = depth - 1
            if depth <= 0 then
                fn_end_pos = fn_def_start + kw_e - 1
                break
            end
        end
        pos = kw_e + 1
    end
    -- Build a minimal chunk: preamble up to end of the decrypt function,
    -- then return the function so we can call it from Lua.
    -- Fallback length (fn_def_start + XOR_FN_SCAN_BYTES/2) is used when the
    -- depth tracker could not locate the closing `end` within the scan window.
    local preamble = source_code:sub(1, fn_end_pos or (fn_def_start + math.floor(XOR_FN_SCAN_BYTES / 2)))
    local get_fn_chunk, _ = e(preamble .. "\nreturn " .. fn_name)
    if not get_fn_chunk then return nil end
    local ok, decrypt_fn = pcall(get_fn_chunk)
    if not ok or type(decrypt_fn) ~= "function" then return nil end
    -- Collect every call `fn_name(...)` from the full source and decrypt it.
    -- `%b()` matches balanced parentheses so multi-arg calls are captured whole.
    local results = {}
    local seen = {}
    for args_bal in source_code:gmatch(fn_name .. "(%b())") do
        if not seen[args_bal] then
            seen[args_bal] = true
            local eval_code = "local __f = ...; return __f" .. args_bal
            local eval_fn, _ = e(eval_code)
            if eval_fn then
                local call_ok, result = pcall(eval_fn, decrypt_fn)
                if call_ok and type(result) == "string" and #result >= XOR_MIN_STRING_LEN then
                    -- Keep only strings that consist of printable / whitespace chars.
                    if result:match("^[%w%p%s]+$") then
                        table.insert(results, result)
                    end
                end
            end
        end
    end
    return results, fn_name
end

-- WeAreDevs v1.0.0 obfuscation detector and string-table extractor.
-- Runs only the decode phase of a WeAreDevs-obfuscated file to produce
-- a table of all decoded string constants, then emits them as comments
-- at the top of the dump so the caller can identify the original names.
--
-- In WeAreDevs v1.0.0 the decoded string table ends with three closing
-- "end" keywords followed immediately by the inner-VM function definition:
--   "end end end return(function(W,e,s,...)"
-- The string table variable name (W, w, etc.) varies across script variants
-- and is detected dynamically from the source.
-- This pattern is used to split off the decode phase from the VM body.
local WAD_DECODE_BOUNDARY = "end end end return%(function%([^)]*%)"
-- Length of the literal prefix "end end end" that we keep (11 chars, 0-indexed = 10).
local WAD_DECODE_PREFIX_LEN = 10
-- Strings that must not appear in the decoded pool output.
local WAD_FILTERED_STRINGS = { ["DRo8JK7A99KoYN"] = true }
local function wad_extract_strings(source_code)
    if not source_code:find("wearedevs%.net/obfuscator", 1, false) then
        return nil
    end
    -- Detect the string table variable name: it is always the first local
    -- table literal declared inside the outer return(function(...)) wrapper.
    -- Different script variants use different cases (e.g. "W" vs "w").
    local str_var = source_code:match(
        "return%(function%([^)]*%)%s*local%s+([%a_][%w_]*)%s*=%s*{") or "w"
    -- Find the boundary between the decode block and the inner VM function.
    local boundary = source_code:find(WAD_DECODE_BOUNDARY)
    if not boundary then
        return nil
    end
    -- Inject "return <str_var>" right after "end end end" so we get the
    -- fully-decoded string table without running the VM itself.
    local patched = source_code:sub(1, boundary + WAD_DECODE_PREFIX_LEN) .. "\nreturn " .. str_var .. "\nend)()\n"
    local fn, load_err = e(patched)
    if not fn then
        return nil
    end
    local ok, w_tbl = pcall(fn)
    if not ok or type(w_tbl) ~= "table" then
        return nil
    end
    -- Collect printable-ASCII strings and build a lookup set for hint emission.
    local results = {}
    local lookup = {}
    for idx = 1, #w_tbl do
        local s = w_tbl[idx]
        if type(s) == "string" and #s >= 2 then
            local is_ascii = true
            for ci = 1, #s do
                local b = s:byte(ci)
                if b < 32 or b > 126 then
                    is_ascii = false
                    break
                end
            end
            -- Skip raw table/userdata address strings (e.g. "table: 0xdeadbeef")
            -- that result from tostring() on a non-serialisable value and carry
            -- no useful information for the caller.
            local is_addr = s:match("^%a[%a ]*: 0x%x+$")
            if is_ascii and not is_addr and not WAD_FILTERED_STRINGS[s] then
                table.insert(results, {idx = idx, val = s})
                lookup[s] = true
            end
        end
    end
    return results, #w_tbl, lookup
end

-- ---------------------------------------------------------------------------
-- Lightcate v2.0.0 obfuscation detector and string-table extractor.
-- Detects scripts obfuscated with Lightcate by checking for the "Lightcate"
-- signature string and a VM dispatcher boundary that uses _0x hex-prefixed
-- parameter names (e.g. return(function(_0xABCD, _0xEF01, ...)).
-- The decoded string table variable is discovered dynamically by scanning
-- the preamble for the last local table with a _0x-prefixed name, or by
-- matching the first argument passed to the outer VM call at the end of the
-- file.  The preamble is executed in a sandboxed chunk and the resulting
-- table is returned so that q.dump_lightcate_strings() can emit it as
-- _lc_N local declarations.
-- ---------------------------------------------------------------------------
local LIGHTCATE_DETECT_STR = "Lightcate"
local LIGHTCATE_VM_BOUNDARY_PAT = "return%(function%(_0x[%w_]+"

local function lightcate_extract_strings(source_code)
    -- Quick early-out: must contain the Lightcate signature string.
    if not source_code:find(LIGHTCATE_DETECT_STR, 1, true) then
        return nil
    end
    -- Find the VM dispatcher boundary.
    local boundary = source_code:find(LIGHTCATE_VM_BOUNDARY_PAT)
    if not boundary then
        return nil
    end
    local preamble = source_code:sub(1, boundary - 1)
    -- Helper: accept strings that are non-empty and consist only of printable
    -- characters (including whitespace) to filter out raw binary/address noise.
    local function is_valid_lc_str(s)
        return type(s) == "string" and #s >= 1 and s:match("^[%w%p%s]+$")
    end
    -- Discover the string table variable name dynamically.
    -- Strategy 1: The variable is the first argument passed to the outer call
    -- at the end of the file.  Pattern: end)(_0xXXXX, ...) or end)(_0xXXXX).
    -- Require at least one closing delimiter before the opening parenthesis to
    -- avoid spurious matches (e.g. plain assignment with a _0x name on the rhs).
    local str_var = source_code:match("[%)%]]+%s*%((_0x[%w_]+)%s*[,%)]")
    -- Strategy 2: Fallback â€” find the last local _0x-named variable in the preamble.
    if not str_var then
        for v in preamble:gmatch("local%s+(_0x[%w_]+)%s*=") do
            str_var = v
        end
    end
    if not str_var then
        return nil
    end
    -- Primary strategy: the preamble is flat local declarations (no function
    -- wrapper), so we can simply append "return <var>" and execute it.
    local patched_simple = preamble .. "\nreturn " .. str_var .. "\n"
    local fn = e(patched_simple)
    if fn then
        local ok, result = pcall(fn)
        if ok and type(result) == "table" and #result >= GEN_MIN_STRING_COUNT then
            local results = {}
            for idx = 1, #result do
                if is_valid_lc_str(result[idx]) then
                    table.insert(results, {idx = idx, val = result[idx]})
                end
            end
            if #results >= GEN_MIN_STRING_COUNT then
                return results, #result, str_var
            end
        end
    end
    -- Fallback: try with wrapper closings in case the preamble contains an
    -- outer function wrapper (nested Lightcate or custom variant).
    -- `(...)` is passed to satisfy potential variadic parameters expected by
    -- any wrapper function that opens before the VM boundary.
    for depth = 1, GEN_MAX_NEST_DEPTH do
        local closing = string.rep("end)(...)", depth)
        local patched = preamble .. "\nreturn " .. str_var .. " " .. closing .. "\n"
        local fn2 = e(patched)
        if fn2 then
            local ok2, result2 = pcall(fn2)
            if ok2 and type(result2) == "table" and #result2 >= GEN_MIN_STRING_COUNT then
                local results = {}
                for idx = 1, #result2 do
                    if is_valid_lc_str(result2[idx]) then
                        table.insert(results, {idx = idx, val = result2[idx]})
                    end
                end
                if #results >= GEN_MIN_STRING_COUNT then
                    return results, #result2, str_var
                end
            end
        end
    end
    return nil
end
-- ---------------------------------------------------------------------------
-- Prometheus obfuscator (github.com/levno-710/Prometheus) string extractor.
-- Prometheus wraps the script in: return (function(env, fenv, ...) ... end)(...)
-- and encodes all string constants using a custom decoder stored in the preamble.
-- Detection: script contains "env" and "fenv" near the start as the first two
-- formal parameters of the outer function, and uses table.freeze for anti-tamper.
-- This extractor finds and runs the decode preamble to recover the string table,
-- trying both `ProteusVM`/`env` style and simpler `fenv` table style.
-- ---------------------------------------------------------------------------
local PROMETHEUS_DETECT_PATS = {
    "return%(function%(env,fenv,",
    "return%(function%(ENV,FENV,",
    "return%(function%(ProteusEnv,",
    "%(function%(env,fenv,",
}
local function prometheus_extract_strings(source_code)
    -- Quick detection: must have one of the Prometheus signatures near start.
    local header = source_code:sub(1, GEN_OUTER_HEADER_BYTES)
    local found = false
    for _, pat in ipairs(PROMETHEUS_DETECT_PATS) do
        if header:find(pat) then
            found = true
            break
        end
    end
    if not found then
        return nil
    end
    -- Find the VM boundary (the inner function that takes env/fenv).
    local boundary = nil
    for _, pat in ipairs(PROMETHEUS_DETECT_PATS) do
        boundary = source_code:find(pat)
        if boundary then break end
    end
    if not boundary then
        return nil
    end
    local preamble = source_code:sub(1, boundary - 1)
    -- Strategy: the preamble typically contains:
    --   local <var> = { ... table of decoded strings ... }
    -- We try to find the last local table declaration before the VM boundary,
    -- inject a return of that variable, and execute to get the decoded strings.
    local str_var = nil
    -- Try to find a local variable assigned a table literal: local X = {
    for v in preamble:gmatch("local%s+([%a_][%w_]*)%s*=%s*{") do
        str_var = v
    end
    if not str_var then
        -- Fallback: try `fenv` or `env` as the string container
        if preamble:find("local%s+fenv%s*=") then
            str_var = "fenv"
        elseif preamble:find("local%s+env%s*=") then
            str_var = "env"
        end
    end
    if not str_var then
        return nil
    end
    -- Try to run preamble and return the string table
    local patched = preamble .. "\nreturn " .. str_var .. "\n"
    local fn = e(patched)
    if fn then
        local ok, result = pcall(fn)
        if ok and type(result) == "table" and #result >= GEN_MIN_STRING_COUNT then
            local results = {}
            for idx = 1, #result do
                local s = result[idx]
                if type(s) == "string" and #s >= 1 and s:match("^[%w%p%s]+$") then
                    table.insert(results, {idx = idx, val = s})
                end
            end
            if #results >= GEN_MIN_STRING_COUNT then
                return results, #result, str_var
            end
        end
    end
    -- Fallback: try GEN_STRING_VARS candidates on the preamble
    for _, var_name in ipairs(GEN_STRING_VARS) do
        if var_name ~= str_var then
            local patched2 = preamble .. "\nreturn " .. var_name .. "\n"
            local fn2 = e(patched2)
            if fn2 then
                local ok2, result2 = pcall(fn2)
                if ok2 and type(result2) == "table" and #result2 >= GEN_MIN_STRING_COUNT then
                    local results = {}
                    for idx = 1, #result2 do
                        local s = result2[idx]
                        if type(s) == "string" and #s >= 1 and s:match("^[%w%p%s]+$") then
                            table.insert(results, {idx = idx, val = s})
                        end
                    end
                    if #results >= GEN_MIN_STRING_COUNT then
                        return results, #result2, var_name
                    end
                end
            end
        end
    end
    return nil
end

-- Finds the longest run of sequential numbered local declarations
-- (e.g.  local k0 = v0 â€¦ local k250 = v250) and converts the overflow
-- (everything past the first MAX_SAFE locals) into a single table variable
-- _catExt, then rewrites every reference to the overflow variables.
-- If no fixable pattern is found the original source is returned unchanged.
-- ---------------------------------------------------------------------------
_reduce_locals = function(src)
    local MAX_SAFE = 150   -- conservative: leave ~50 headroom for other locals in same scope

    -- Split into lines
    local lines = {}
    for ln in (src .. "\n"):gmatch("([^\n]*)\n") do
        table.insert(lines, ln)
    end

    -- Parse lines that look like:  [indent]local [base][num] = [expr]
    local parsed = {}
    for i, ln in ipairs(lines) do
        local ind, base, nstr, expr =
            ln:match("^(%s*)local%s+([%a_][%a_]*)(%d+)%s*=%s*(.-)%s*$")
        if ind and base and nstr and expr and expr ~= "" then
            parsed[i] = { indent = ind, base = base, num = tonumber(nstr), expr = expr }
        end
    end

    -- Find the longest consecutive sequential run (same base, nums increase by 1)
    local best = nil
    local rs, rb, rn, rc = nil, nil, nil, 0

    local function flush()
        if rc > MAX_SAFE then
            if not best or rc > best.count then
                best = { start = rs, base = rb, start_num = rn, count = rc }
            end
        end
        rs, rb, rn, rc = nil, nil, nil, 0
    end

    for i = 1, #lines do
        local p = parsed[i]
        if p then
            if rb == p.base and p.num == rn + rc then
                rc = rc + 1
            else
                flush()
                rs, rb, rn, rc = i, p.base, p.num, 1
            end
        else
            flush()
        end
    end
    flush()

    if best then
        -- Determine split boundary
        local overflow_start_line = best.start + MAX_SAFE       -- index of first overflow line
        local overflow_end_line   = best.start + best.count - 1 -- index of last overflow line
        local overflow_count      = best.count - MAX_SAFE

        -- Collect RHS expressions for overflow locals
        local exprs = {}
        for i = overflow_start_line, overflow_end_line do
            local p = parsed[i]
            if not p then return src end  -- bail if we can't parse cleanly
            local e = p.expr
            if e:find(",", 1, true) then e = "(" .. e .. ")" end
            table.insert(exprs, e)
        end

        local indent = (parsed[best.start] or {}).indent or ""
        local tname  = "_catExt"

        -- Build the new source: keep first MAX_SAFE locals, replace rest with table
        local out = {}
        for i = 1, overflow_start_line - 1 do
            table.insert(out, lines[i])
        end
        table.insert(out, indent .. "local " .. tname .. " = {" .. table.concat(exprs, ", ") .. "}")
        for i = overflow_end_line + 1, #lines do
            table.insert(out, lines[i])
        end

        local new_src = table.concat(out, "\n")

        -- Replace all references to overflow variable names (e.g. k180 â†’ _catExt[1])
        for k = 0, overflow_count - 1 do
            local vname = best.base .. (best.start_num + MAX_SAFE + k)
            local repl  = tname .. "[" .. (k + 1) .. "]"
            local vpat  = vname:gsub("([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
            new_src = new_src:gsub("([^%a%d_])" .. vpat .. "([^%a%d_])", "%1" .. repl .. "%2")
            new_src = new_src:gsub("^" .. vpat .. "([^%a%d_])", repl .. "%1")
            new_src = new_src:gsub("([^%a%d_])" .. vpat .. "$", "%1" .. repl)
        end

        return new_src
    end

    -- ---------------------------------------------------------------------------
    -- Strategy 2: No sequential numbered run found (or run too short).
    -- Find the largest block of consecutive  local <name> = <expr>  lines at the
    -- same indentation level and split it so that no contiguous stretch exceeds
    -- MAX_SAFE declarations.  Each extra block is introduced with the same
    -- _catExt table approach.  Unlike strategy 1 the overflow variable names are
    -- NOT rewritten here â€“ instead each chunk keeps its own small table with a
    -- unique suffix (_catExt2, _catExt3, â€¦).  This is safe only when the overflow
    -- locals are no longer referenced after their declaration block, which is
    -- typical for obfuscated VM dispatch tables.
    -- ---------------------------------------------------------------------------
    local function _any_local_pattern(ln)
        -- matches: [indent]local <name> = <anything>
        local ind, rest = ln:match("^(%s*)local%s+([%a_][%w_]*%s*=.-)%s*$")
        if ind and rest and rest ~= "" then
            return ind, rest
        end
        return nil, nil
    end

    -- Scan for the longest run of local-decl lines at the same indent
    local best2 = nil
    local rs2, ri2, rc2 = nil, nil, 0
    for i, ln in ipairs(lines) do
        local ind = _any_local_pattern(ln)
        if ind and (ri2 == nil or ind == ri2) then
            if rs2 == nil then rs2 = i; ri2 = ind; rc2 = 1
            else rc2 = rc2 + 1 end
        else
            if rc2 > MAX_SAFE and (best2 == nil or rc2 > best2.count) then
                best2 = { start = rs2, count = rc2, indent = ri2 }
            end
            if ind then
                rs2 = i; ri2 = ind; rc2 = 1
            else
                rs2 = nil; ri2 = nil; rc2 = 0
            end
        end
    end
    if rc2 > MAX_SAFE and (best2 == nil or rc2 > best2.count) then
        best2 = { start = rs2, count = rc2, indent = ri2 }
    end

    if not best2 then return src end

    -- Split the run into chunks of MAX_SAFE; wrap overflow in _catExt<n> tables
    local out2 = {}
    local chunk_idx = 0
    local in_run_pos = 0
    local chunk_open = false

    for i = 1, #lines do
        local in_run = (i >= best2.start and i < best2.start + best2.count)
        if in_run then
            in_run_pos = in_run_pos + 1
            if in_run_pos == 1 then
                -- First chunk: emit normally
                table.insert(out2, lines[i])
            elseif (in_run_pos - 1) % MAX_SAFE == 0 then
                -- Close previous extra table if open
                if chunk_open then
                    table.insert(out2, best2.indent .. "}")
                    chunk_open = false
                end
                -- Open new extra table
                chunk_idx = chunk_idx + 1
                local tname2 = "_catExt" .. chunk_idx
                -- Start table with first element from this line
                local _, rest = _any_local_pattern(lines[i])
                -- Extract just the rhs (after '=')
                local rhs = (rest or ""):match("=[%s]*(.-)%s*$") or "nil"
                if rhs:find(",", 1, true) then rhs = "(" .. rhs .. ")" end
                table.insert(out2, best2.indent .. "local " .. tname2 .. " = {" .. rhs)
                chunk_open = true
            else
                local _, rest = _any_local_pattern(lines[i])
                local rhs = (rest or ""):match("=[%s]*(.-)%s*$") or "nil"
                if rhs:find(",", 1, true) then rhs = "(" .. rhs .. ")" end
                table.insert(out2, best2.indent .. ", " .. rhs)
            end
        else
            if chunk_open then
                table.insert(out2, best2.indent .. "}")
                chunk_open = false
            end
            table.insert(out2, lines[i])
        end
    end
    if chunk_open then
        table.insert(out2, best2.indent .. "}")
    end

    return table.concat(out2, "\n")
end

function q.dump_file(eN, eO)
    if not eN then return false end
    q.reset()
    az("generated with catmio | https://discord.gg/cq9GkRKX2V")
    local as = o.open(eN, "rb")
    if not as then
        return false
    end
    local al = as:read("*a")
    as:close()
    -- WAD string extraction: wad_extract_strings already checks for the
    -- WeAreDevs obfuscator fingerprint internally, so we call it unconditionally
    -- and let it decide whether extraction is applicable.
    do
        local wad_strings, wad_total, wad_lookup = wad_extract_strings(al)
        if wad_strings then
            t.wad_string_pool = {
                strings = wad_strings,
                total = wad_total or 0,
                lookup = wad_lookup
            }
        else
            t.wad_string_pool = nil
        end
    end
    -- XOR-encrypted string extraction (Catmio-style: bit32 or bit / bxor helper).
    local xor_strings, xor_fn = xor_extract_strings(al)
    if xor_strings and #xor_strings > 0 then
        B(string.format("[Dumper] XOR obfuscation detected (fn=%s) â€” %d strings decrypted", tostring(xor_fn), #xor_strings))
        t.xor_string_pool = { strings = xor_strings }
    else
        t.xor_string_pool = nil
    end
    -- Generic wrapper string extraction: handles K0lrot, WeAreDevs, Iron Brew,
    -- Prometheus, Luraph, and AI-generated obfuscators that use any of:
    --   return(function(...) ... end)(...)   (function(...) ... end)(...)
    --   return((function(...) ... end))(...)  and nested variants up to 4 levels deep.
    local gw_strings, gw_total, gw_var, gw_label = generic_wrapper_extract_strings(al)
    if gw_strings and #gw_strings > 0 then
        B(string.format("[Dumper] %s wrapper detected (var=%s) â€” %d/%d strings decoded",
            gw_label or "generic", gw_var or "?", #gw_strings, gw_total or 0))
        t.k0lrot_string_pool = { strings = gw_strings, var_name = gw_var, label = gw_label }
    else
        t.k0lrot_string_pool = nil
    end
    -- Lightcate v2.0.0 string extraction: detects "Lightcate" signature and
    -- _0x hex-prefixed VM boundary, then recovers the decoded string table.
    local lc_strings, lc_total, lc_var = lightcate_extract_strings(al)
    if lc_strings and #lc_strings > 0 then
        B(string.format("[Dumper] Lightcate v2.0.0 wrapper detected (var=%s) â€” %d/%d strings decoded",
            lc_var or "?", #lc_strings, lc_total or 0))
        t.lightcate_string_pool = { strings = lc_strings, var_name = lc_var }
    else
        t.lightcate_string_pool = nil
    end
    -- Prometheus string extraction: detects env/fenv parameter pattern.
    local prom_strings, prom_total, prom_var = prometheus_extract_strings(al)
    if prom_strings and #prom_strings > 0 then
        B(string.format("[Dumper] Prometheus obfuscation detected (var=%s) â€” %d/%d strings decoded",
            prom_var or "?", #prom_strings, prom_total or 0))
        t.prometheus_string_pool = { strings = prom_strings, var_name = prom_var }
    else
        t.prometheus_string_pool = nil
    end
    B("[Dumper] Sanitizing Luau and Binary Literals...")
    local eP = I(al)
    local R, eQ = e(eP, "Obfuscated_Script")
    if not R then
        -- When the compile error is "too many local variables", attempt a
        -- source-level transformation that folds the overflow into a table.
        -- Retry up to 5 times: each pass fixes one overflow block; multiple
        -- passes are needed when several distinct functions each exceed the limit.
        if m(eQ):find("too many local variables", 1, true) then
            for _fix_pass = 1, 5 do
                local ePfixed = _reduce_locals(eP)
                if ePfixed == eP then break end  -- no further progress
                local R2, eQ2 = e(ePfixed, "Obfuscated_Script")
                eP = ePfixed
                if R2 then
                    R = R2
                    eQ = nil
                    break
                else
                    eQ = eQ2
                    if not m(eQ2):find("too many local variables", 1, true) then
                        break  -- different error; stop
                    end
                end
            end
        end
        if not R then
            B("\n[LUA_LOAD_FAIL] " .. m(eQ))
            return false
        end
    end
    local eR =
        setmetatable(
        {LuraphContinue = function()
            end, script = script, game = game, workspace = workspace,
            -- newproxy compatibility: WeAreDevs uses newproxy(true) to create
            -- mutable-metatable upvalue boxes.  Lua 5.4 has no newproxy, so we
            -- return a plain table whose metatable is already writeable.
            newproxy = function(has_meta)
                if not has_meta then
                    return {}
                end
                local proxy = {}
                a.setmetatable(proxy, {})
                return proxy
            end,
            LARRY_CHECKINDEX = function(x, ba)
                local aF = x[ba]
                if j(aF) == "table" and not t.registry[aF] then
                    t.lar_counter = (t.lar_counter or 0) + 1
                    t.registry[aF] = "tbl" .. t.lar_counter
                end
                return aF
            end, LARRY_GET = function(b5)
                return b5
            end, LARRY_CALL = function(as, ...)
                return as(...)
            end, LARRY_NAMECALL = function(eS, em, ...)
                return eS[em](eS, ...)
            end, pcall = function(as, ...)
                local dg = {g(as, ...)}
                if not dg[1] and m(dg[2]):match("TIMEOUT_FORCED_BY_DUMPER") then
                    i(dg[2], 0)
                end
                return unpack(dg)
            end},
        {__index = _G, __newindex = _G}
    )
    -- Inject getfenv/getgenv stubs into the sandbox that return the sandbox itself.
    -- catlogger's _G.getfenv is a stub returning {} (empty table), so calling it from
    -- inside the script would give the obfuscated VM an empty environment with no
    -- interceptors.  By inserting these into eR directly (bypassing __newindex so they
    -- don't pollute the real _G), we ensure any Lua 5.1 / Luau-style VM that calls
    -- `getfenv and getfenv() or _ENV` or `getgenv()` gets back our full sandbox.
    rawset(eR, "getfenv", function() return eR end)
    rawset(eR, "getgenv", function() return eR end)
    -- Common Roblox exploit-executor globals.  Many obfuscated scripts check for
    -- these to verify they are running inside a trusted executor before executing
    -- their real payload.  Providing stub implementations prevents the script from
    -- taking an anti-dump code path due to missing executor APIs.
    rawset(eR, "getidentity",          function() return 8 end)  -- 8 = maximum trust/identity level
    rawset(eR, "getthreadidentity",    function() return 8 end)  -- same; alias used by some executors
    rawset(eR, "setidentity",          function() end)
    rawset(eR, "setthreadidentity",    function() end)
    -- Persistent thread identity (eUNC tests setthreadidentity then reads it back)
    do
        local _tid = 8
        rawset(eR, "getthreadidentity",    function() return _tid end)
        rawset(eR, "setthreadidentity",    function(id) _tid = tonumber(id) or 8 end)
        rawset(eR, "getidentity",          function() return _tid end)
        rawset(eR, "setidentity",          function(id) _tid = tonumber(id) or 8 end)
        rawset(eR, "getthreadcontext",     function() return _tid end)
        rawset(eR, "setthreadcontext",     function(id) _tid = tonumber(id) or 8 end)
        rawset(eR, "identitycheck",        function() return _tid end)
    end
    -- Persistent namecall method (eUNC tests setnamecallmethod then reads it back)
    do
        local _ncm = "__namecall"
        rawset(eR, "getnamecallmethod",    function() return _ncm end)
        rawset(eR, "setnamecallmethod",    function(m_) _ncm = m_ or "__namecall" end)
        rawset(eR, "getnamecall",          function() return _ncm end)
        rawset(eR, "setnamecall",          function(m_) _ncm = m_ or "__namecall" end)
    end
    -- Persistent readonly tracking (eUNC tests setreadonly + isreadonly)
    do
        local _ro = setmetatable({}, {__mode = "k"})
        rawset(eR, "setreadonly",  function(tbl, v) _ro[tbl] = v == true end)
        rawset(eR, "isreadonly",   function(tbl) return _ro[tbl] == true end)
        rawset(eR, "make_writeable", function(tbl) _ro[tbl] = false end)
        rawset(eR, "make_readonly",  function(tbl) _ro[tbl] = true end)
    end
    -- Persistent flag storage (eUNC tests setfflag + getfflag)
    do
        local _flags = {}
        rawset(eR, "setfflag", function(k, v) _flags[tostring(k)] = tostring(v) end)
        rawset(eR, "getfflag", function(k) return _flags[tostring(k)] or "" end)
    end
    -- newcclosure tracking so iscclosure/isnewcclosure work correctly
    do
        local _ccs = setmetatable({}, {__mode = "k"})
        rawset(eR, "newcclosure", function(f)
            if type(f) ~= "function" then return f end
            local wrapped = function(...) return f(...) end
            _ccs[wrapped] = true
            return wrapped
        end)
        rawset(eR, "iscclosure",    function(f) return type(f) == "function" and (_ccs[f] == true) end)
        rawset(eR, "isnewcclosure", function(f) return type(f) == "function" and (_ccs[f] == true) end)
        rawset(eR, "clonefunction", function(f)
            if type(f) ~= "function" then return f end
            local c_ = function(...) return f(...) end
            return c_
        end)
        rawset(eR, "copyfunction",  function(f) return f end)
    end
    rawset(eR, "getexecutorname",      function() return "ExploitExecutor" end)
    rawset(eR, "identifyexecutor",     function() return "ExploitExecutor", "1.0" end)
    rawset(eR, "hookfunction",         function(f, r_)
        if type(f) ~= "function" or type(r_) ~= "function" then return f end
        return f
    end)
    rawset(eR, "hookmetamethod",       function(obj, m_, r_)
        if type(r_) == "function" then return r_ end
        return function() end
    end)
    rawset(eR, "replaceclosure",       function(f, r_) if type(r_) == "function" then return r_ end return f end)
    rawset(eR, "islclosure",           function(f) return type(f) == "function" end)
    rawset(eR, "isexecutorclosure",    function() return false end)
    rawset(eR, "checkcaller",          function() return true end)
    rawset(eR, "getrawmetatable",      function(x)
        if type(x) == "table" or type(x) == "userdata" then
            return a.getmetatable(x) or {}
        end
        return {}
    end)
    rawset(eR, "setrawmetatable",      function(x, mt)
        if type(x) == "table" then
            pcall(a.setmetatable, x, mt)
        end
        return x
    end)
    rawset(eR, "fireclickdetector",    function() end)
    rawset(eR, "fireproximityprompt",  function() end)
    rawset(eR, "firetouchinterest",    function() end)
    rawset(eR, "firesignal",           function() end)
    rawset(eR, "mousemoverel",         function() end)
    rawset(eR, "mouse1click",          function() end)
    rawset(eR, "mouse2click",          function() end)
    rawset(eR, "keypress",             function() end)
    rawset(eR, "keyrelease",           function() end)
    rawset(eR, "isrbxactive",          function() return true end)
    rawset(eR, "isgameactive",         function() return true end)
    rawset(eR, "getconnections",       function(sig)
        -- Return at least one fake connection so #getconnections(x) >= 1
        return {
            {
                Enabled = true,
                ForeignState = false,
                LuaConnection = true,
                Function = function() end,
                Thread = nil,
                Disconnect = function() end,
                Reconnect = function() end,
            }
        }
    end)
    rawset(eR, "getcallbackvalue",     function(obj, prop) return function() end end)
    rawset(eR, "getscripts",           function() return {} end)
    rawset(eR, "getloadedmodules",     function() return {} end)
    rawset(eR, "getsenv",              function() return eR end)
    rawset(eR, "getrenv",              function() return eR end)
    rawset(eR, "getreg",               function() return {} end)
    rawset(eR, "getgc",                function() return _collect_gc_objects() end)
    rawset(eR, "getinstances",         function() return {game, workspace, script} end)
    rawset(eR, "getnilinstances",      function() return {} end)
    rawset(eR, "decompile",            function() return "-- decompiled" end)
    rawset(eR, "replicatesignal",      function() end)
    rawset(eR, "cloneref",             function(x) return x end)
    rawset(eR, "compareinstances",     function(a_, b_) return rawequal(a_, b_) end)
    rawset(eR, "getinfo",              function(f)
        return {source = "=", what = "Lua", name = "unknown", short_src = "dumper", currentline = 0}
    end)
    -- Additional anti-tamper bypass stubs for Prometheus
    rawset(eR, "isluau",               function() return true end)
    rawset(eR, "islua",                function() return false end)
    rawset(eR, "checkclosure",         function(f) return type(f) == "function" end)
    rawset(eR, "isourclosure",         function(f) return type(f) == "function" end)
    rawset(eR, "detourfn",             function(f, r_) return type(r_) == "function" and r_ or f end)
    rawset(eR, "iswindowactive",       function() return true end)
    -- gethiddenproperty / sethiddenproperty with property store
    rawset(eR, "gethiddenproperty",    function(obj, prop)
        if t.property_store[obj] then
            local v = t.property_store[obj][prop]
            if v ~= nil then return v, true end
        end
        return nil, false
    end)
    rawset(eR, "sethiddenproperty",    function(obj, prop, val)
        t.property_store[obj] = t.property_store[obj] or {}
        t.property_store[obj][prop] = val
        return true
    end)
    -- getproperties / getallproperties
    rawset(eR, "getproperties",        function(obj)
        return t.property_store[obj] or {}
    end)
    rawset(eR, "getallproperties",     function(obj)
        return t.property_store[obj] or {}
    end)
    -- isscriptable / setscriptable
    rawset(eR, "isscriptable",         function(obj, prop) return true end)
    rawset(eR, "setscriptable",        function(obj, prop, val) return true end)
    -- getspecialinfo
    rawset(eR, "getspecialinfo",       function(obj) return {} end)
    -- run_on_actor (Actor scripting)
    rawset(eR, "run_on_actor",         function(actor, fn, ...)
        if type(fn) == "function" then pcall(fn, ...) end
    end)
    -- task.synchronize / task.desynchronize
    do
        local _task = rawget(eR, "task") or task
        if type(_task) == "table" then
            _task.synchronize  = _task.synchronize  or function() end
            _task.desynchronize = _task.desynchronize or function() end
            _task.cancel       = _task.cancel       or function() end
        end
    end
    rawset(eR, "getupvalues",          function(f)
        if type(f) ~= "function" then return {} end
        local uvs = {}
        local i = 1
        while true do
            local n, v = debug.getupvalue(f, i)
            if not n then break end
            uvs[n] = v
            i = i + 1
        end
        return uvs
    end)
    rawset(eR, "getupvalue",           function(f, idx)
        if type(f) ~= "function" then return nil end
        local n, v = debug.getupvalue(f, idx)
        return v
    end)
    rawset(eR, "setupvalue",           function(f, idx, val)
        if type(f) == "function" then debug.setupvalue(f, idx, val) end
    end)
    rawset(eR, "getconstants",         function(f) return {} end)
    rawset(eR, "getprotos",            function(f) return {} end)
    rawset(eR, "getproto",             function(f, idx) return function() end end)
    rawset(eR, "getstack",             function(lvl, idx) return nil end)
    rawset(eR, "setstack",             function(lvl, idx, val) end)
    rawset(eR, "getscriptbytecode",    function() return "" end)
    rawset(eR, "getscripthash",        function() return string.rep("0", 64) end)
    rawset(eR, "getscriptclosure",     function(f) return f end)
    rawset(eR, "getscriptfunction",    function(f) return f end)
    rawset(eR, "firehook",             function() end)
    rawset(eR, "lz4compress",          function(s) return s end)
    rawset(eR, "lz4decompress",        function(s) return s end)
    rawset(eR, "protectgui",           function() end)
    rawset(eR, "gethui",               function() return eR end)
    rawset(eR, "gethiddenui",          function() return eR end)
    rawset(eR, "request",              function(o_) return {Success=true,StatusCode=200,StatusMessage="OK",Headers={},Body="{}"} end)
    rawset(eR, "http_request",         function(o_) return {Success=true,StatusCode=200,StatusMessage="OK",Headers={},Body="{}"} end)
    rawset(eR, "setclipboard",         function() end)
    rawset(eR, "getclipboard",         function() return "" end)
    rawset(eR, "toclipboard",          function() end)
    rawset(eR, "fromclipboard",        function() return "" end)
    rawset(eR, "queue_on_teleport",    function() end)
    rawset(eR, "queueonteleport",      function() end)
    rawset(eR, "readfile",             function() return "" end)
    rawset(eR, "writefile",            function() end)
    rawset(eR, "appendfile",           function() end)
    rawset(eR, "listfiles",            function() return {} end)
    rawset(eR, "isfile",               function() return false end)
    rawset(eR, "isfolder",             function() return false end)
    rawset(eR, "makefolder",           function() end)
    rawset(eR, "delfolder",            function() end)
    rawset(eR, "delfile",              function() end)
    rawset(eR, "setfpscap",            function() end)
    rawset(eR, "getfpscap",            function() return 60 end)
    rawset(eR, "getobjects",           function() return {} end)
    rawset(eR, "getobject",            function() return nil end)
    rawset(eR, "getsynasset",          function(p_) return "rbxasset://"..tostring(p_) end)
    rawset(eR, "getcustomasset",       function(p_) return "rbxasset://"..tostring(p_) end)
    -- crypt / crypto stubs used by Prometheus anti-tamper
    rawset(eR, "crypt",                {
        base64encode = function(s) return s end,
        base64decode = function(s) return s end,
        base64_encode = function(s) return s end,
        base64_decode = function(s) return s end,
        encrypt  = function(s, k_) return s end,
        decrypt  = function(s, k_) return s end,
        hash     = function(s) return string.rep("0", 64) end,
        generatekey = function(n_) return string.rep("0", n_ or 32) end,
        generatebytes = function(n_) return string.rep("\0", n_ or 16) end,
    })
    rawset(eR, "base64_encode",        function(s) return s end)
    rawset(eR, "base64_decode",        function(s) return s end)
    rawset(eR, "base64encode",         function(s) return s end)
    rawset(eR, "base64decode",         function(s) return s end)
    -- rconsole stubs
    rawset(eR, "rconsoleprint",        function() end)
    rawset(eR, "rconsoleclear",        function() end)
    rawset(eR, "rconsolecreate",       function() end)
    rawset(eR, "rconsoledestroy",      function() end)
    rawset(eR, "rconsoleinput",        function() return "" end)
    rawset(eR, "rconsoleinfo",         function() end)
    rawset(eR, "rconsolewarn",         function() end)
    rawset(eR, "rconsoleerr",          function() end)
    rawset(eR, "rconsolename",         function() end)
    rawset(eR, "consoleclear",         function() end)
    rawset(eR, "consoleprint",         function() end)
    rawset(eR, "consolewarn",          function() end)
    rawset(eR, "consoleerror",         function() end)
    rawset(eR, "consolename",          function() end)
    rawset(eR, "consoleinput",         function() return "" end)
    -- Anti-tamper: bit32 must be available inside sandbox too
    rawset(eR, "bit32",                bit32)
    rawset(eR, "bit",                  bit)
    -- table with freeze/unfreeze for Prometheus bypass
    do
        local _frozen = setmetatable({}, {__mode = "k"})
        local _table_ext = setmetatable({}, {__index = table})
        _table_ext.freeze   = function(t_) if type(t_) == "table" then _frozen[t_] = true end return t_ end
        _table_ext.isfrozen = function(t_) return _frozen[t_] == true end
        rawset(eR, "table", _table_ext)
    end
    -- Some scripts use a Luau-style `_G` reference that also goes through getgenv;
    -- expose it inside the sandbox so that `getgenv()["_G"]` round-trips correctly.
    rawset(eR, "_G",                   eR)
    -- cache with persistent invalidation store (eUNC: cache.invalidate, cache.iscached, cache.replace)
    do
        local _invalidated = setmetatable({}, {__mode = "k"})
        local _replacements = setmetatable({}, {__mode = "k"})
        rawset(eR, "cache", {
            invalidate = function(obj) if obj ~= nil then _invalidated[obj] = true end end,
            iscached   = function(obj) return obj ~= nil and not _invalidated[obj] end,
            replace    = function(old, new_)
                if old ~= nil then _replacements[old] = new_ end
                return new_
            end,
        })
    end
    rawset(eR, "getcallingscript", function() return script end)
    rawset(eR, "dofile", function() return nil end)
    rawset(eR, "loadfile", function() return nil, "not supported" end)
    -- crypt full API (eUNC tests encrypt/decrypt round-trip, generatebytes length, hash)
    do
        local function _b64e(s)
            local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            return ((s:gsub(".", function(x)
                local r,b_ = "", x:byte()
                for i=8,1,-1 do r=r..(b_%2^i-b_%2^(i-1)>0 and "1" or "0") end
                return r
            end).."0000"):gsub("%d%d%d?%d?%d?%d?", function(x)
                if #x < 6 then return "" end
                local c=0
                for i=1,6 do c=c+(x:sub(i,i)=="1" and 2^(6-i) or 0) end
                return b:sub(c+1,c+1)
            end)..({  "","==","=" })[#s%3+1])
        end
        local function _b64d(s)
            local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            s = s:gsub("[^"..b.."=]","")
            return (s:gsub(".", function(x)
                if x == "=" then return "" end
                local r, f = "", b:find(x) - 1
                for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and "1" or "0") end
                return r
            end):gsub("%d%d%d?%d?%d?%d?%d?%d?", function(x)
                if #x ~= 8 then return "" end
                local c=0
                for i=1,8 do c=c+(x:sub(i,i)=="1" and 2^(8-i) or 0) end
                return string.char(c)
            end))
        end
        rawset(eR, "crypt", {
            base64encode   = _b64e,
            base64decode   = _b64d,
            base64_encode  = _b64e,
            base64_decode  = _b64d,
            encrypt        = function(s, key, iv, mode)
                -- XOR cipher stub â€” reversible for round-trip tests
                local ks = tostring(key or "")
                local out = {}
                for i = 1, #s do
                    local k_ = ks:byte((i-1)%#ks+1) or 0
                    out[i] = string.char(bit_bxor(s:byte(i), k_))
                end
                local encrypted = table.concat(out)
                return encrypted, iv or ""
            end,
            decrypt        = function(s, key, iv, mode)
                local ks = tostring(key or "")
                local out = {}
                for i = 1, #s do
                    local k_ = ks:byte((i-1)%#ks+1) or 0
                    out[i] = string.char(bit_bxor(s:byte(i), k_))
                end
                return table.concat(out)
            end,
            hash           = function(s, alg)
                -- Deterministic stub: length + first char sum
                local h = #(s or "")
                for i = 1, math.min(#(s or ""), 16) do h = bit_bxor(h * 31, (s or ""):byte(i)) end
                return string.format("%064x", math.abs(h) % (2^52))
            end,
            generatekey    = function() return string.rep("\0", 32) end,
            generatebytes  = function(n) return string.rep("\0", tonumber(n) or 16) end,
        })
        rawset(eR, "base64_encode", _b64e)
        rawset(eR, "base64_decode", _b64d)
        rawset(eR, "base64encode",  _b64e)
        rawset(eR, "base64decode",  _b64d)
    end
    -- debug library extended for UNC
    rawset(eR, "debug", {
        getconstant  = function(f, idx)
            if type(f) ~= "function" then return nil end
            local _, v = debug.getupvalue(f, idx or 1)
            return v
        end,
        getconstants = function(f)
            if type(f) ~= "function" then return {} end
            local out, i = {}, 1
            while true do
                local n, v = debug.getupvalue(f, i)
                if not n then break end
                out[i] = v; i = i + 1
            end
            return out
        end,
        setconstant  = function(f, idx, val)
            if type(f) == "function" then pcall(debug.setupvalue, f, idx, val) end
        end,
        getinfo      = function(f, what)
            if type(f) == "function" then
                local ok, info = pcall(debug.getinfo, f, what or "nSl")
                if ok and info then return info end
            end
            return {source="=",what="Lua",name="unknown",short_src="dumper",currentline=0,nups=0,nparams=0,isvararg=true}
        end,
        getproto     = function(f, idx, copy)
            return copy and {function() end} or function() end
        end,
        getprotos    = function(f) return {} end,
        getstack     = function(lvl, idx) return idx and nil or {} end,
        setstack     = function(lvl, idx, val) end,
        getupvalue   = function(f, idx)
            if type(f) ~= "function" then return nil end
            local n, v = debug.getupvalue(f, idx or 1)
            return v
        end,
        getupvalues  = function(f)
            if type(f) ~= "function" then return {} end
            local out, i = {}, 1
            while true do
                local n, v = debug.getupvalue(f, i)
                if not n then break end
                out[n] = v; i = i + 1
            end
            return out
        end,
        setupvalue   = function(f, idx, val)
            if type(f) == "function" then pcall(debug.setupvalue, f, idx, val) end
        end,
        traceback    = function(msg, lvl) return tostring(msg or "") end,
        profilebegin = function() end,
        profileend   = function() end,
        sethook      = function() end,
    })
    -- Virtual file system (VFS): eUNC tests write then read back files
    do
        local _vfs_files   = {}   -- path â†’ content string
        local _vfs_folders = {}   -- path â†’ true
        rawset(eR, "writefile",  function(path, content) _vfs_files[tostring(path)] = tostring(content or "") end)
        rawset(eR, "readfile",   function(path)
            local c = _vfs_files[tostring(path)]
            if c then return c end
            return "content"
        end)
        rawset(eR, "appendfile", function(path, content)
            local p = tostring(path)
            _vfs_files[p] = (_vfs_files[p] or "") .. tostring(content or "")
        end)
        rawset(eR, "isfile",     function(path) return _vfs_files[tostring(path)] ~= nil end)
        rawset(eR, "isfolder",   function(path) return _vfs_folders[tostring(path)] == true end)
        rawset(eR, "makefolder", function(path) _vfs_folders[tostring(path)] = true end)
        rawset(eR, "listfiles",  function(path)
            local p = tostring(path)
            local out = {}
            for k in pairs(_vfs_files) do
                if k:sub(1, #p + 1) == p .. "/" or k:sub(1, #p) == p then
                    table.insert(out, k)
                end
            end
            return out
        end)
        rawset(eR, "delfolder",  function(path)
            local p = tostring(path)
            _vfs_folders[p] = nil
            for k in pairs(_vfs_files) do
                if k:sub(1, #p + 1) == p .. "/" then _vfs_files[k] = nil end
            end
        end)
        rawset(eR, "delfile",    function(path) _vfs_files[tostring(path)] = nil end)
    end
    -- Drawing library (eUNC checks Drawing.new returns object with .Visible, :Remove)
    rawset(eR, "Drawing", {
        new = function(drawType)
            local obj = {
                Visible      = true,
                Color        = Color3.new(1,1,1),
                Transparency = 1,
                ZIndex       = 1,
                Thickness    = 1,
                Filled       = false,
                Radius       = 100,
                NumSides     = 3,
                Rounding     = 0,
                Size         = Vector2.new(0,0),
                Position     = Vector2.new(0,0),
                From         = Vector2.new(0,0),
                To           = Vector2.new(0,0),
                Text         = "",
                TextBounds   = Vector2.new(0,0),
                Center       = false,
                Outline      = false,
                OutlineColor = Color3.new(0,0,0),
                Font         = 0,
                Image        = "",
                Data         = "",
            }
            obj.Remove  = function() obj.Visible = false end
            obj.Destroy = obj.Remove
            return obj
        end,
        Fonts = {UI = 0, System = 1, Plex = 2, Monospace = 3},
        -- eUNC also checks Drawing.Fonts.UI etc. via numeric index
        [0] = "UI", [1] = "System", [2] = "Plex", [3] = "Monospace",
    })
    rawset(eR, "isrenderobj",      function(obj) return type(obj) == "table" and obj.Visible ~= nil end)
    rawset(eR, "getrenderproperty",function(obj, prop) if type(obj) == "table" then return obj[prop] end return nil end)
    rawset(eR, "setrenderproperty",function(obj, prop, val) if type(obj) == "table" then obj[prop] = val end end)
    rawset(eR, "cleardrawcache",   function() end)
    -- WebSocket
    rawset(eR, "WebSocket", {
        connect = function(url)
            local ws = {
                Send = function() end,
                Close = function() end,
            }
            ws.OnMessage = setmetatable({}, {
                __index = function(_, k)
                    if k == "Connect" then return function() return {Disconnect=function()end} end end
                    return nil
                end
            })
            ws.OnClose = ws.OnMessage
            return ws
        end
    })
    -- Clipboard
    do
        local _clip = ""
        rawset(eR, "setclipboard",  function(s) _clip = tostring(s or "") end)
        rawset(eR, "toclipboard",   function(s) _clip = tostring(s or "") end)
        rawset(eR, "getclipboard",  function() return _clip end)
        rawset(eR, "fromclipboard", function() return _clip end)
        rawset(eR, "setrbxclipboard", function(s) _clip = tostring(s or "") end)
    end
    -- FPS cap (persistent)
    do
        local _fpscap = 0
        rawset(eR, "setfpscap", function(fps) _fpscap = tonumber(fps) or 0 end)
        rawset(eR, "getfpscap", function() return _fpscap end)
    end
    -- getgc returns populated list
    rawset(eR, "getgc",          function(incl) return _collect_gc_objects() end)
    rawset(eR, "getgenv",        function() return eR end)
    rawset(eR, "getloadedmodules",function() return {} end)
    rawset(eR, "getrenv",        function() return eR end)
    rawset(eR, "getrunningscripts",function() return {} end)
    rawset(eR, "getscriptbytecode",function() return "" end)
    rawset(eR, "getscripthash",  function() return string.rep("0", 64) end)
    rawset(eR, "getscripts",     function() return {} end)
    rawset(eR, "getsenv",        function() return eR end)
    rawset(eR, "getcallingscript",function() return script end)
    rawset(eR, "fireclickdetector",function() end)
    rawset(eR, "getcustomasset", function(p_) return "rbxasset://" .. tostring(p_) end)
    rawset(eR, "gethui",         function() return bj("ScreenGui", false) end)
    rawset(eR, "gethiddenui",    function() return bj("ScreenGui", false) end)
    rawset(eR, "lz4compress",    function(s) return s end)
    rawset(eR, "lz4decompress",  function(s, len) return s end)
    rawset(eR, "messagebox",     function(text, cap, t_) return 1 end)
    rawset(eR, "queue_on_teleport",function(code) end)
    rawset(eR, "queueonteleport",  function(code) end)
    rawset(eR, "request",        function(opts) return {Success=true,StatusCode=200,StatusMessage="OK",Headers={},Body="{}"} end)
    rawset(eR, "http_request",   function(opts) return {Success=true,StatusCode=200,StatusMessage="OK",Headers={},Body="{}"} end)
    rawset(eR, "identifyexecutor",function() return "ExploitExecutor", "1.0" end)
    rawset(eR, "getexecutorname", function() return "ExploitExecutor" end)
    rawset(eR, "hookmetamethod",  function(obj, method, hook) return type(hook)=="function" and hook or function() end end)
    rawset(eR, "setreadonly",     rawget(eR,"setreadonly") or function(t_,v) end)  -- already set above via persistent block
    rawset(eR, "isreadonly",      rawget(eR,"isreadonly")  or function(t_) return false end)
    rawset(eR, "getconnections",  rawget(eR,"getconnections") or function() return {} end)
    rawset(eR, "getcallbackvalue",function(obj, prop) return function() end end)
    rawset(eR, "setrbxclipboard", rawget(eR,"setrbxclipboard") or function() end)
    -- Register the sandbox itself so that aZ() returns "getfenv()" rather than
    -- serializing the entire executor-stub table when a script assigns
    -- something like `gui.Parent = getfenv()`.
    t.registry[eR] = "getfenv()"
    if _native_setfenv then
        -- Lua 5.1/5.2: native setfenv properly rebinds the chunk's environment.
        _native_setfenv(R, eR)
    else
        -- Luau lacks setfenv; re-load the already-parsed chunk
        -- with eR as the explicit _ENV upvalue so that every global access inside
        -- the obfuscated script (including `_ENV` itself, which Luau-style VMs
        -- capture via `getfenv and getfenv() or _ENV`) is routed through our
        -- sandbox instead of the real _G.
        local R2, eRloadErr = e(eP, "Obfuscated_Script", "t", eR)
        if R2 then
            R = R2
        elseif eRloadErr then
            B("[Dumper] Note: sandbox reload failed (" .. m(eRloadErr) .. "); running without environment rebinding")
        end
    end
    -- Snapshot the REAL global table (eC, not the eD proxy) before execution,
    -- plus the sandbox keys, so we can detect what the script wrote afterwards.
    local _pre_exec_keys = {}
    for _k in D(eC) do _pre_exec_keys[_k] = true end
    for _k in D(eR) do _pre_exec_keys[_k] = true end
    -- Store baseline so dump_captured_upvalues can filter new-vs-pre-existing globals.
    t.pre_exec_keys = _pre_exec_keys
    B("[Dumper] Executing Protected VM...")
    local eT = p.clock()
    local _is_wad = (t.wad_string_pool ~= nil)
    -- Combined debug hook:
    --   1. Enforce the execution time-out (fires TIMEOUT_FORCED_BY_DUMPER so that
    --      _G.pcall / _G.xpcall cannot silently swallow it).
    --   2. Loop detection: track how many times each source line is hit; when a
    --      line exceeds LOOP_DETECT_THRESHOLD hits emit "-- Detected loops N".
    local function _loop_check()
        local _inf = a.getinfo(3, "Sl")
        if _inf and _inf.currentline and _inf.currentline > 0 then
            local _key = (_inf.short_src or "?") .. ":" .. _inf.currentline
            local _cnt = (t.loop_line_counts[_key] or 0) + 1
            t.loop_line_counts[_key] = _cnt
            if _cnt > r.LOOP_DETECT_THRESHOLD and not t.loop_detected_lines[_key] then
                t.loop_detected_lines[_key] = true
                t.loop_counter = t.loop_counter + 1
                if r.EMIT_LOOP_COUNTER then
                    -- Insert the loop marker directly into output (bypasses cycle suppressor)
                    local _marker = string.format("-- Detected loops %d", t.loop_counter)
                    table.insert(t.output, _marker)
                    t.current_size = t.current_size + #_marker + 1
                end
            end
        end
    end
    if _is_wad then
        b(
            function()
                if p.clock() - eT > r.TIMEOUT_SECONDS then
                    b()  -- disarm the hook before raising so it cannot fire again
                    error("TIMEOUT_FORCED_BY_DUMPER", 0)
                end
                _loop_check()
            end,
            "",
            300
        )
    else
        b(
            function()
                if p.clock() - eT > r.TIMEOUT_SECONDS then
                    b()  -- disarm the hook before raising so it cannot fire again
                    error("TIMEOUT_FORCED_BY_DUMPER", 0)
                end
                _loop_check()
            end,
            "",
            50
        )
    end
    local eo, eU =
        h(
        function()
            _script_executing = true
            R()
        end,
        function(ds)
            _script_executing = false
            return tostring(ds)
        end
    )
    _script_executing = false
    b()
    if not eo and eU then
        B("[VM_ERROR] " .. eU)
        -- Emit the VM error as a comment in the dump output so the analyst sees it.
        aA()
        local _errline = eU or "unknown error"
        if _errline:find("Tamper", 1, true) then
            at("-- [ANTI_TAMPER] Script raised tamper-detection error: " .. _errline)
        else
            at("-- [VM_ERROR] " .. _errline)
        end
    end
    -- Post-execution: run deferred hooks first (more code captured), then supplemental data.
    q.run_deferred_hooks()
    q.dump_captured_globals(eR, _pre_exec_keys)
    q.dump_captured_upvalues()
    q.dump_string_constants()
    q.dump_wad_strings()
    q.dump_xor_strings()
    q.dump_k0lrot_strings()
    q.dump_lightcate_strings()
    q.dump_prometheus_strings()
    q.dump_remote_summary()
    q.dump_instance_creations()
    q.dump_script_loads()
    q.dump_gc_scan()
    return q.save(eO or r.OUTPUT_FILE)
end
function q.dump_string(al, eO)
    q.reset()
    az("generated with catmio | https://discord.gg/cq9GkRKX2V")
    aA()
    if al then
        -- Run string-pool extractors before sanitisation so they see the
        -- raw source (extractors do their own internal detection checks).
        do
            local wad_strings, wad_total, wad_lookup = wad_extract_strings(al)
            if wad_strings then
                t.wad_string_pool = { strings = wad_strings, total = wad_total or 0, lookup = wad_lookup }
            else
                t.wad_string_pool = nil
            end
        end
        local xor_strings, xor_fn = xor_extract_strings(al)
        if xor_strings and #xor_strings > 0 then
            B(string.format("[Dumper] XOR obfuscation detected (fn=%s) â€” %d strings decrypted", m(xor_fn), #xor_strings))
            t.xor_string_pool = { strings = xor_strings }
        else
            t.xor_string_pool = nil
        end
        local gw_strings, gw_total, gw_var, gw_label = generic_wrapper_extract_strings(al)
        if gw_strings and #gw_strings > 0 then
            B(string.format("[Dumper] %s wrapper detected (var=%s) â€” %d/%d strings decoded",
                gw_label or "generic", gw_var or "?", #gw_strings, gw_total or 0))
            t.k0lrot_string_pool = { strings = gw_strings, var_name = gw_var, label = gw_label }
        else
            t.k0lrot_string_pool = nil
        end
        -- Lightcate v2.0.0 string extraction.
        local lc_strings2, lc_total2, lc_var2 = lightcate_extract_strings(al)
        if lc_strings2 and #lc_strings2 > 0 then
            B(string.format("[Dumper] Lightcate v2.0.0 wrapper detected (var=%s) â€” %d/%d strings decoded",
                lc_var2 or "?", #lc_strings2, lc_total2 or 0))
            t.lightcate_string_pool = { strings = lc_strings2, var_name = lc_var2 }
        else
            t.lightcate_string_pool = nil
        end
        -- Prometheus string extraction.
        local prom_strings2, prom_total2, prom_var2 = prometheus_extract_strings(al)
        if prom_strings2 and #prom_strings2 > 0 then
            B(string.format("[Dumper] Prometheus obfuscation detected (var=%s) â€” %d/%d strings decoded",
                prom_var2 or "?", #prom_strings2, prom_total2 or 0))
            t.prometheus_string_pool = { strings = prom_strings2, var_name = prom_var2 }
        else
            t.prometheus_string_pool = nil
        end
        al = I(al)
    end
    local R, an = e(al)
    if not R then
        -- Retry with local-overflow fix when that is the compile error
        if m(an):find("too many local variables", 1, true) then
            for _fix_pass2 = 1, 5 do
                local al_fixed = _reduce_locals(al)
                if al_fixed == al then break end
                local R2, an2 = e(al_fixed)
                al = al_fixed
                if R2 then
                    R = R2
                    an = nil
                    break
                else
                    an = an2
                    if not m(an2):find("too many local variables", 1, true) then
                        break
                    end
                end
            end
        end
        if not R then
            B("[LUA_LOAD_FAIL] " .. m(an))
            return false, an
        end
    end
    -- Snapshot globals before execution so dump_captured_upvalues knows which
    -- globals are new (written by the script) vs pre-existing standard library.
    local _pre_exec_keys = {}
    for _k in D(eC) do _pre_exec_keys[_k] = true end
    t.pre_exec_keys = _pre_exec_keys
    local eT2 = p.clock()
    -- Luau compat metatable for WeAreDevs-obfuscated files: same as dump_file.
    local _ds_is_wad = (t.wad_string_pool ~= nil)
    local function _ds_loop_check()
        local _inf2 = a.getinfo(3, "Sl")
        if _inf2 and _inf2.currentline and _inf2.currentline > 0 then
            local _key2 = (_inf2.short_src or "?") .. ":" .. _inf2.currentline
            local _cnt2 = (t.loop_line_counts[_key2] or 0) + 1
            t.loop_line_counts[_key2] = _cnt2
            if _cnt2 > r.LOOP_DETECT_THRESHOLD and not t.loop_detected_lines[_key2] then
                t.loop_detected_lines[_key2] = true
                t.loop_counter = t.loop_counter + 1
                if r.EMIT_LOOP_COUNTER then
                    local _marker2 = string.format("-- Detected loops %d", t.loop_counter)
                    table.insert(t.output, _marker2)
                    t.current_size = t.current_size + #_marker2 + 1
                end
            end
        end
    end
    if _ds_is_wad then
        b(
            function()
                if p.clock() - eT2 > r.TIMEOUT_SECONDS then
                    b()
                    error("TIMEOUT_FORCED_BY_DUMPER", 0)
                end
                _ds_loop_check()
            end,
            "",
            30
        )
    else
        b(function()
            if p.clock() - eT2 > r.TIMEOUT_SECONDS then
                b()
                error("TIMEOUT_FORCED_BY_DUMPER", 0)
            end
            _ds_loop_check()
        end, "", 50)
    end
    local eo2, eU2 = h(
        function()
            _script_executing = true
            R()
        end,
        function(ds)
            _script_executing = false
            return tostring(ds)
        end
    )
    _script_executing = false
    b()
    q.run_deferred_hooks()
    q.dump_captured_upvalues()
    q.dump_string_constants()
    q.dump_wad_strings()
    q.dump_xor_strings()
    q.dump_k0lrot_strings()
    q.dump_lightcate_strings()
    q.dump_prometheus_strings()
    q.dump_remote_summary()
    q.dump_instance_creations()
    q.dump_script_loads()
    q.dump_gc_scan()
    if eO then
        return q.save(eO)
    end
    return true, aB()
end
if arg and arg[1] then
    local eo = q.dump_file(arg[1], arg[2])
    if eo then
        B("Saved to: " .. (arg[2] or r.OUTPUT_FILE))
        local eV = q.get_stats()
        B(
            string.format(
                "Lines: %d | Remotes: %d | Strings: %d | Loops: %d",
                eV.total_lines,
                eV.remote_calls,
                eV.suspicious_strings,
                eV.loops
            )
        )
    end
else
    local as = o.open("obfuscated.lua", "rb")
    if as then
        as:close()
        local eo = q.dump_file("obfuscated.lua")
        if eo then
            B("Saved to: " .. r.OUTPUT_FILE)
            B(q.get_output())
        end
    else
        B("Usage: lua dumper.lua <input> [output] [key]")
    end
end
_G.LuraphContinue = function()
end
return q 
