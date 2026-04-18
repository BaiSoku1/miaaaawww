-- cat_deobf.lua: Static deobfuscator / string-pool extractor functions.
-- Uses native load (pre-sandbox), accessed via _CATMIO.
local e = _CATMIO.native_load   -- native chunk loader (before sandbox override)
local g = _CATMIO.g             -- native pcall
local n = tonumber
local m = tostring
local r = _CATMIO.r             -- config table

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
    -- Larry / Morpa style: do ... end wrapper with local function inside
    "^do%s+local%s+function%s+",
    -- Inline IIFE without parens: function(...)...end)(...)
    "^function%(%.%.%.%).*end%)%(",
    -- Unix-style wrappers: local _={}; return function(...)
    "local%s+[_%a][_%w]*%s*=%s*{};?%s*return%s+function",
    -- Threaded wrappers often seen in unix v1/v2
    "coroutine%.wrap%(function%(%).*end%)%(",
    -- Common morpa-style: (function(self,...) ... end)(script,...)
    "%(function%(self,",
    -- Hex-literal heavy scripts (getfenv-based VMs)
    "local%s+[_%a][_%w]*%s*=%s*0x",
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
    -- Larry/Morpa-style dispatchers with `self` param
    "return%(function%(self,",
    -- Unix-style threaded VM: coroutine.wrap wrapping the entire dispatcher
    "return%s*coroutine%.wrap%(function%(",
    -- Dispatcher tables indexed by opcode number (common in modern VMs)
    "return%(function%(op,",
    "return%(function%(opcode,",
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

-- ================================================================
-- LUNR v1.0.7 STRING TABLE EXTRACTOR
-- ================================================================
-- Lunr v1.0.7 encodes all string constants in a base64-encoded array
-- using a shuffled alphabet whose character->value mapping is stored in
-- a companion lookup table (b) built from arithmetic expressions.
--
-- This extractor:
--   1. Detects the "This file was protected using Lunr" header.
--   2. Locates the main string array declaration (local Y = {...}).
--   3. Locates the self-contained decode do...end block that builds
--      the lookup table and decodes H[i] in-place.
--   4. Constructs a minimal runnable chunk (Y + decode block + return Y),
--      passes it through I() to convert Luau backtick strings, then
--      loads and executes it to recover the decoded string table.
--   5. Returns the decoded strings for annotation in the dump output.
-- ================================================================

local LUNR_DETECT_STR = "This file was protected using Lunr"

-- Lightweight block-end finder used by the Lunr extractor.
-- Returns the index of the last character of the matching end/until.
local function _lunr_find_block_end(src, pos)
    local n = #src
    local depth = 1
    local i = pos
    while i <= n and depth > 0 do
        local c = src:sub(i, i)
        if c == '-' and src:sub(i+1, i+1) == '-' then
            -- Line comment: skip to end of line
            local nl = src:find('\n', i + 2, true)
            i = nl and nl + 1 or n + 1
        elseif c == '"' or c == "'" or c == '`' then
            -- Quoted string: skip to matching close
            local q = c
            i = i + 1
            while i <= n do
                local sc = src:sub(i, i)
                if sc == '\\' then
                    i = i + 2
                elseif sc == q then
                    i = i + 1
                    break
                elseif sc == '\n' and q ~= '`' then
                    break
                else
                    i = i + 1
                end
            end
        elseif c == '[' and (src:sub(i+1,i+1) == '[' or src:sub(i+1,i+1) == '=') then
            -- Long bracket: skip to matching close
            local j = i + 1
            local lvl = 0
            while j <= n and src:sub(j,j) == '=' do lvl = lvl + 1; j = j + 1 end
            if j <= n and src:sub(j,j) == '[' then
                local close = ']' .. string.rep('=', lvl) .. ']'
                local ce = src:find(close, j + 1, true)
                i = ce and ce + #close or n + 1
            else
                i = i + 1
            end
        else
            local kw = src:match('^(%a+)', i)
            -- Note: 'for' and 'while' are intentionally excluded from the opener
            -- set because they delimit their block via the 'do' keyword that follows
            -- them (e.g. "for i=1,n do ... end").  Counting both 'for'/'while' and
            -- 'do' would double-increment depth, causing the finder to run past the
            -- actual closing 'end' of the block we're trying to bound.
            if kw == 'do' or kw == 'function' or kw == 'repeat' or kw == 'if' then
                depth = depth + 1
                i = i + #kw
            elseif kw == 'end' or kw == 'until' then
                depth = depth - 1
                if depth == 0 then return i + #kw - 1 end
                i = i + #kw
            elseif kw then
                -- Advance by the full word length so that embedded keywords inside
                -- longer identifiers (e.g. the 'if' inside 'elseif') are not
                -- mistakenly counted as block openers.
                i = i + #kw
            else
                i = i + 1
            end
        end
    end
    return n
end

local function lunr_extract_strings(source_code)
    -- 1. Quick detection: header must appear in the first 1000 bytes.
    if not source_code:sub(1, 1000):find(LUNR_DETECT_STR, 1, true) then
        return nil
    end

    -- 2. Locate the main string array.
    -- It is a local whose name is a single uppercase letter and whose value is
    -- a table that begins with base64-encoded string literals (backtick or
    -- double-quoted, depending on whether I() has already been applied).
    local y_var, y_start, y_end_pos
    local search_pos = 1
    for _ = 1, 40 do
        local ms, me, mv = source_code:find(
            'local%s+([A-Z])%s*=%s*{%s*["`][A-Za-z0-9+/=]', search_pos)
        if not ms then break end
        -- Walk braces to find the closing }.
        local depth = 0
        local found_end = nil
        for idx = ms, #source_code do
            local c = source_code:sub(idx, idx)
            if c == '{' then
                depth = depth + 1
            elseif c == '}' then
                depth = depth - 1
                if depth == 0 then found_end = idx; break end
            end
        end
        if found_end then
            -- Require at least 5 base64-ish string entries (avoid false positives).
            local content = source_code:sub(ms, found_end)
            local count = 0
            for _ in content:gmatch('[`"][A-Za-z0-9+/=][A-Za-z0-9+/=][A-Za-z0-9+/=]') do
                count = count + 1
            end
            if count >= 5 then
                y_var     = mv
                y_start   = ms
                y_end_pos = found_end
                break
            end
        end
        search_pos = me + 1
    end

    if not y_var then return nil end

    local y_decl = source_code:sub(y_start, y_end_pos)

    -- 3. Locate the decode do...end block.
    -- It begins with do followed shortly by local <x> = string.char.
    local decode_do_start = source_code:find(
        'do%s+local%s+[a-z]%s*=%s*string%.char', y_end_pos, false)
    if not decode_do_start then
        -- Alternate layout: do on its own line, then local x = string.char.
        decode_do_start = source_code:find(
            'do%s*\n%s*local%s+[a-z]%s*=%s*string%.char', y_end_pos, false)
    end
    if not decode_do_start then return nil end

    -- Find the do keyword and advance past it to start depth counting.
    local after_do = decode_do_start + 1  -- skip 'd', now at 'o'
    while after_do <= #source_code
            and source_code:sub(after_do, after_do):match('%a') do
        after_do = after_do + 1
    end

    local decode_end = _lunr_find_block_end(source_code, after_do)
    local decode_block = source_code:sub(decode_do_start, decode_end)

    -- 4. Build the self-contained runnable chunk.
    -- The decode block aliases the string array as:  local H = <Y_var>
    -- Inside the for-loop the loop counter is also named <Y_var>, which
    -- shadows the outer Y.  We rename the outer array to _lunr_arr and
    -- patch the local H = <Y_var> alias so H still points to the right table.
    local y_decl_fixed = y_decl:gsub(
        'local%s+' .. y_var .. '%s*=', 'local _lunr_arr =', 1)
    -- The alias variable may be any letter (e.g. uppercase H), not just lowercase.
    local decode_fixed = decode_block:gsub(
        'local%s+([a-zA-Z])%s*=%s*' .. y_var .. '%f[^%a%d_]',
        function(h) return 'local ' .. h .. ' = _lunr_arr' end, 1)

    local chunk = y_decl_fixed .. '\n' .. decode_fixed .. '\nreturn _lunr_arr\n'

    -- Convert Luau backtick strings to standard Lua double-quoted strings
    -- (the extractor is called on the raw source, before I() is applied).
    chunk = I(chunk)

    -- 5. Load and execute the chunk.
    local fn, load_err = e(chunk)
    if not fn then
        B(string.format('[Dumper] Lunr extractor: chunk load failed: %s', m(load_err)))
        return nil
    end
    local ok, result = pcall(fn)
    if not ok or type(result) ~= 'table' then
        return nil
    end

    -- 6. Collect decoded strings from the result table.
    local strings = {}
    local total = #result
    for idx = 1, total do
        local s = result[idx]
        if type(s) == 'string' and #s >= 1 then
            table.insert(strings, {idx = idx, val = s})
        end
    end
    if #strings == 0 then return nil end

    return strings, total, y_var
end



return {
    eE                              = eE,
    generic_wrapper_extract_strings = generic_wrapper_extract_strings,
    xor_extract_strings             = xor_extract_strings,
    wad_extract_strings             = wad_extract_strings,
    lightcate_extract_strings       = lightcate_extract_strings,
    prometheus_extract_strings      = prometheus_extract_strings,
    lunr_extract_strings            = lunr_extract_strings,
}
