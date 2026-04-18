-- cat_envlogger.lua: Output/logging methods attached to the q dumper object.
-- Requires: _CATMIO global with shared state.
local _C        = _CATMIO
local q         = _C.q
local r         = _C.r
local t         = _C.t
local at        = _C.at
local az        = _C.az
local aA        = _C.aA
local aH        = _C.aH
local aH_binary = _C.aH_binary
local aZ        = _C.aZ
local aE        = _C.aE
local D         = _C.D
local E         = _C.E
local j         = _C.j
local m         = _C.m
local a         = _C.a
local br        = _C.br

function q.dump_captured_globals(env_table, baseline_keys)
    if not r.DUMP_GLOBALS then return end
    local seen_keys = {}
    local emitted = false
    local function _scan(src)
        if not src then return end
        for k, v in D(src) do
            if j(k) == "string" and not (baseline_keys and baseline_keys[k]) and not seen_keys[k] then
                seen_keys[k] = true
                local vtype = j(v)
                -- Only emit if it's a valid Lua identifier and not a function
                if vtype ~= "function" and k:match("^[%a_][%w_]*$") then
                    if not emitted then
                        aA()
                        emitted = true
                    end
                    at(string.format("%s = %s", k, aZ(v)))
                end
            end
        end
    end
    -- Check both the sandbox env table and the real _G (eC) for new writes
    _scan(env_table)
    _scan(eC)
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

-- Emit the decoded Lunr v1.0.7 string pool when available.
-- Only emits when DUMP_DECODED_STRINGS is true; otherwise does nothing.
function q.dump_lunr_strings()
    if not r.DUMP_DECODED_STRINGS then return end
    if not t.lunr_string_pool then return end
    local pool = t.lunr_string_pool
    if not pool.strings or #pool.strings == 0 then return end
    aA()
    at(string.format("-- Decoded string pool (Lunr v1.0.7, var=%s, %d strings)",
        pool.var_name or "?", #pool.strings))
    for _, entry in E(pool.strings) do
        at(string.format("local _lunr_%d = %s", entry.idx, aH(entry.val)))
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
