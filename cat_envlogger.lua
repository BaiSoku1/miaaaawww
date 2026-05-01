-- cat_envlogger.lua
-- ============================================================================
-- Catmio Envlogger v2 — Section-registry based output/logging dumper.
--
-- Drop-in replacement for the original cat_envlogger.lua. The 14 public
-- functions called by cat_sandbox.lua keep the exact same names and
-- signatures; everything else is additive.
--
-- Design notes
-- ------------
-- * Every dumper is registered as a "section" with a name, title, gating
--   config flag, priority, category, and run() implementation. Adding a
--   new dumper is a one-liner. The public q.dump_<name>() functions just
--   call the runner so the sandbox call sequence is unchanged.
-- * A shared string-interner deduplicates values across pools (e.g. a
--   constant captured by both the WAD and XOR extractors is only emitted
--   as a literal once; the second pool references it by id).
-- * Smart classifier picks meaningful prefixes (_url_, _webhook_,
--   _asset_, _hex_, _b64_, _json_, _ident_) so an analyst can grep the
--   output by intent.
-- * Every external iterator (pairs, ipairs, getupvalue) is wrapped in
--   pcall so a misbehaving runtime can't kill the dump.
-- * Per-section line budgets prevent any single producer from
--   monopolising the output; truncation is announced as a comment.
-- * Reserved-word safe: identifiers that would collide with Lua keywords
--   are rejected so the dump compiles instead of producing
--   `local end = ...`.
-- * Optional run-summary dashboard, optional diagnostics block.
--
-- Shared state lives on the _CATMIO global; see cat.lua for the full
-- helper inventory.
-- ============================================================================

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
local D         = _C.D
local E         = _C.E
local j         = _C.j
local m         = _C.m
local a         = _C.a
local br        = _C.br
local eC        = _C.eC or _G

-- ---------------------------------------------------------------------------
-- Constants & configuration knobs (all backwards-compatible defaults)
-- ---------------------------------------------------------------------------

-- Run-summary banner is on by default if config doesn't say otherwise.
local function _cfg(key, default)
    local v = r[key]
    if v == nil then return default end
    return v
end

local _LUA_KEYWORDS = {
    ["and"] = true,    ["break"] = true,    ["do"] = true,
    ["else"] = true,   ["elseif"] = true,   ["end"] = true,
    ["false"] = true,  ["for"] = true,      ["function"] = true,
    ["goto"] = true,   ["if"] = true,       ["in"] = true,
    ["local"] = true,  ["nil"] = true,      ["not"] = true,
    ["or"] = true,     ["repeat"] = true,   ["return"] = true,
    ["then"] = true,   ["true"] = true,     ["until"] = true,
    ["while"] = true,
}

-- ---------------------------------------------------------------------------
-- Diagnostics & stats
-- ---------------------------------------------------------------------------

local _stats = {
    sections_run       = 0,
    sections_emitted   = 0,
    lines_emitted      = 0,
    redactions         = 0,
    dedup_hits         = 0,
    truncations        = 0,
    errors             = 0,
    by_section         = {},
}

local _diagnostics = {
    started_at = nil,
    finished_at = nil,
    errors    = {},   -- list of {section=..., message=...}
}

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

local function _is_safe_ident(name)
    if j(name) ~= "string" or name == "" then return false end
    if not name:match("^[%a_][%w_]*$") then return false end
    if _LUA_KEYWORDS[name] then return false end
    return true
end

local function _safe_clock()
    local ok, v = pcall(function() return os and os.clock and os.clock() end)
    if ok then return v end
    return nil
end

-- Forward-declared locals (used inside section closures, defined further
-- down so they're visible without polluting the global table).
local _stats_count_table
local _pool_size

-- Wrap a function call in pcall and record any failure to diagnostics.
local function _safe(section, fn, ...)
    local ok, err = pcall(fn, ...)
    if not ok then
        _stats.errors = _stats.errors + 1
        _diagnostics.errors[#_diagnostics.errors + 1] = {
            section = section,
            message = m(err),
        }
    end
    return ok
end

-- Defensive iteration: returns a stateless iterator that swallows iteration
-- errors after the first observed failure rather than propagating them.
local function _iter_pairs(tbl)
    if not tbl then return function() return nil end end
    local ok, it, state, key = pcall(D, tbl)
    if not ok then
        return function() return nil end
    end
    return function()
        local ok2, k, v = pcall(it, state, key)
        if not ok2 then return nil end
        if k == nil then return nil end
        key = k
        return k, v
    end
end

local function _iter_ipairs(tbl)
    if not tbl then return function() return nil end end
    local ok, it, state, idx = pcall(E, tbl)
    if not ok then
        return function() return nil end
    end
    return function()
        local ok2, i, v = pcall(it, state, idx)
        if not ok2 then return nil end
        if i == nil then return nil end
        idx = i
        return i, v
    end
end

-- ---------------------------------------------------------------------------
-- Output budget (per-section)
-- ---------------------------------------------------------------------------

local function _budget(section)
    local global_cap = _cfg("MAX_LINES_PER_SECTION", 10000)
    local emitted = 0
    local truncated = false
    return {
        emit = function(line, raw)
            if truncated then return false end
            emitted = emitted + 1
            if emitted > global_cap then
                truncated = true
                _stats.truncations = _stats.truncations + 1
                at(string.format(
                    "-- [envlogger] section %q truncated after %d line(s) (MAX_LINES_PER_SECTION)",
                    section, global_cap), true)
                return false
            end
            at(line, raw)
            _stats.lines_emitted = _stats.lines_emitted + 1
            local s = _stats.by_section[section] or { lines = 0 }
            s.lines = s.lines + 1
            _stats.by_section[section] = s
            return true
        end,
        finalize = function()
            return emitted, truncated
        end,
    }
end

-- ---------------------------------------------------------------------------
-- String interner (cross-section deduplication)
-- ---------------------------------------------------------------------------

local _interner = {
    by_value = {},   -- value -> { id = "_str_N", section = ..., emitted = bool }
    next_id  = 0,
}

local function _interner_enabled()
    return _cfg("ENVLOGGER_INTERN_POOLS", false) == true
end

-- intern(value, section): returns (entry, is_new). Always returns a usable
-- entry; "is_new" indicates whether this was the first time the value was
-- seen this run. Caller decides how to format (literal vs reference).
local function _intern(value, section)
    if j(value) ~= "string" then
        return { id = nil, section = section }, true
    end
    local entry = _interner.by_value[value]
    if entry then
        _stats.dedup_hits = _stats.dedup_hits + 1
        return entry, false
    end
    _interner.next_id = _interner.next_id + 1
    entry = {
        id = string.format("_str_%d", _interner.next_id),
        section = section,
        first_seen = section,
    }
    _interner.by_value[value] = entry
    return entry, true
end

-- ---------------------------------------------------------------------------
-- String classification (intent-aware variable prefixes)
-- ---------------------------------------------------------------------------

local _CLASSIFIERS = {
    -- name, predicate(string) -> bool, prefix
    { name = "webhook",
      predicate = function(s)
          return s:find("discord[%a]*%.com/api/webhooks/") ~= nil
      end,
      prefix = "_webhook" },

    { name = "url",
      predicate = function(s) return s:find("^https?://") ~= nil end,
      prefix = "_url" },

    { name = "asset",
      predicate = function(s)
          return s:find("^rbxassetid://") or s:find("^rbxthumb://")
              or s:find("^rbxhttp://") or s:find("^rbx://")
      end,
      prefix = "_asset" },

    { name = "lua_source",
      predicate = function(s)
          return #s > 80 and (
              s:find("function%s*%(", 1) ~= nil or
              s:find("local%s+[%a_]", 1)  ~= nil or
              s:find("return%s+", 1)      ~= nil
          )
      end,
      prefix = "_src" },

    { name = "json",
      predicate = function(s)
          if #s < 4 then return false end
          local f, l = s:sub(1, 1), s:sub(-1)
          return (f == "{" and l == "}") or (f == "[" and l == "]")
      end,
      prefix = "_json" },

    { name = "jwt",
      predicate = function(s)
          if #s < 40 then return false end
          local a1, b1, c1 = s:match("^([A-Za-z0-9_%-]+)%.([A-Za-z0-9_%-]+)%.([A-Za-z0-9_%-]+)$")
          return a1 ~= nil
      end,
      prefix = "_jwt" },

    { name = "hex",
      predicate = function(s)
          return #s >= 16 and s:match("^[%da-fA-F]+$") ~= nil
      end,
      prefix = "_hex" },

    { name = "b64",
      predicate = function(s)
          return #s >= 32 and s:match("^[A-Za-z0-9+/=]+$") ~= nil
      end,
      prefix = "_b64" },

    { name = "ip",
      predicate = function(s)
          return s:match("^%d+%.%d+%.%d+%.%d+$") ~= nil
      end,
      prefix = "_ip" },

    { name = "discord_token",
      predicate = function(s)
          return s:match("^[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+$") ~= nil
              and #s >= 50
      end,
      prefix = "_token" },
}

local function _classify(value)
    if j(value) ~= "string" then return "_ref" end
    for _, c in ipairs(_CLASSIFIERS) do
        local ok, hit = pcall(c.predicate, value)
        if ok and hit then return c.prefix end
    end
    return "_ref"
end

-- ---------------------------------------------------------------------------
-- Section header / footer pretty-print
-- ---------------------------------------------------------------------------

local function _hr(emit)
    emit("-- =========================================================", true)
end

local function _section_header(emit, title, subtitle)
    aA()
    _hr(emit)
    emit("-- " .. title, true)
    if subtitle and subtitle ~= "" then
        emit("-- " .. subtitle, true)
    end
    _hr(emit)
end

-- ---------------------------------------------------------------------------
-- Section registry
-- ---------------------------------------------------------------------------

local _sections     = {}   -- by name
local _sections_seq = {}   -- registration order (= run order)

local function _register(name, opts)
    opts.name = name
    _sections[name] = opts
    _sections_seq[#_sections_seq + 1] = opts
end

-- _run(name, ...) executes a section once. It records stats, never throws.
-- Both the gate check and the body run are pcall-wrapped: a single broken
-- section can't abort the post-exec dump sequence in cat_sandbox.lua.
local function _run(name, ...)
    local sec = _sections[name]
    if not sec then return end
    if sec.gate then
        local ok, gated = pcall(sec.gate)
        if not ok then
            _stats.errors = _stats.errors + 1
            _diagnostics.errors[#_diagnostics.errors + 1] = {
                section = name,
                message = "gate: " .. m(gated),
            }
            return
        end
        if not gated then return end
    end
    _stats.sections_run = _stats.sections_run + 1
    local before_lines = _stats.lines_emitted
    _safe(name, sec.run, ...)
    if _stats.lines_emitted > before_lines then
        _stats.sections_emitted = _stats.sections_emitted + 1
    end
end

-- Wrap every public q.dump_*() entrypoint in pcall as belt-and-suspenders.
-- Even if _run() itself somehow throws (e.g. _stats was clobbered), the
-- caller in cat_sandbox.lua never observes an error.
local function _public_run(name, ...)
    local ok, err = pcall(_run, name, ...)
    if not ok then
        _stats.errors = (_stats.errors or 0) + 1
        if _diagnostics and _diagnostics.errors then
            _diagnostics.errors[#_diagnostics.errors + 1] = {
                section = name,
                message = "public_run: " .. m(err),
            }
        end
    end
end

-- ===========================================================================
-- SECTIONS
-- ===========================================================================

-- Deterministic key sort that handles mixed-type keys safely.
local function _sorted_keys(tbl)
    local keys = {}
    for k in _iter_pairs(tbl) do
        keys[#keys + 1] = k
    end
    table.sort(keys, function(x, y)
        local tx, ty = j(x), j(y)
        if tx == ty then
            if tx == "number" or tx == "string" then return x < y end
            return m(x) < m(y)
        end
        return tx < ty
    end)
    return keys
end

-- ---------------------------------------------------------------------------
-- captured_globals
-- ---------------------------------------------------------------------------

_register("captured_globals", {
    title    = "CAPTURED GLOBAL WRITES",
    category = "env",
    gate     = function() return r.DUMP_GLOBALS end,
    run      = function(env_table, baseline_keys)
        local b = _budget("captured_globals")
        local seen = {}
        local emitted_header = false
        local label_source = _cfg("ENVLOGGER_LABEL_GLOBAL_SOURCE", false) == true

        local function _scan(src, src_label)
            if not src then return end
            local keys = _sorted_keys(src)
            for _, k in ipairs(keys) do
                local v = src[k]
                if j(k) == "string"
                        and not (baseline_keys and baseline_keys[k])
                        and not seen[k]
                        and _is_safe_ident(k)
                        and j(v) ~= "function" then
                    seen[k] = true
                    if not emitted_header then
                        emitted_header = true
                        aA()
                    end
                    if label_source then
                        b.emit(string.format("%s = %s -- (%s)", k, aZ(v), src_label))
                    else
                        b.emit(string.format("%s = %s", k, aZ(v)))
                    end
                end
            end
        end

        _scan(env_table, "env")
        _scan(eC,        "_G")
    end,
})

-- ---------------------------------------------------------------------------
-- captured_upvalues
-- ---------------------------------------------------------------------------

_register("captured_upvalues", {
    title    = "CAPTURED UPVALUES",
    category = "closure",
    gate     = function() return r.DUMP_UPVALUES and a and a.getupvalue end,
    run      = function()
        local b = _budget("captured_upvalues")
        local emitted_header = false
        local cap = _cfg("MAX_UPVALUES_PER_FUNCTION", 200)

        for obj in _iter_pairs(t.registry) do
            if j(obj) == "function" then
                local idx = 1
                while idx <= cap do
                    local ok, uname, uval = pcall(a.getupvalue, obj, idx)
                    if not ok or not uname then break end
                    local utype = j(uval)
                    if uname ~= "_ENV"
                            and _is_safe_ident(uname)
                            and utype ~= "function" then
                        if not emitted_header then
                            emitted_header = true
                            aA()
                        end
                        b.emit(string.format("local %s = %s", uname, aZ(uval)))
                    end
                    idx = idx + 1
                end
            end
        end
    end,
})

-- ---------------------------------------------------------------------------
-- Generic helpers used by every string-pool section
-- ---------------------------------------------------------------------------

-- Emit a single string-pool entry, honouring the interner if enabled.
-- Returns true if a literal was emitted (vs a back-reference comment).
local function _emit_pool_entry(b, section, fallback_prefix, idx, value, want_binary)
    local prefix = _classify(value)
    if prefix == "_ref" then prefix = fallback_prefix end
    local var = string.format("%s_%d", prefix, idx)
    local lit
    if want_binary and aH_binary then
        local ok, lit_bin = pcall(aH_binary, value)
        lit = ok and lit_bin or aH(value)
    else
        lit = aH(value)
    end

    if _interner_enabled() then
        local entry, is_new = _intern(value, section)
        if not is_new and entry.id then
            -- Reference the previously emitted literal.
            b.emit(string.format("local %s = %s -- (dup of %s, first seen in %s)",
                var, entry.id, entry.id, entry.first_seen or "?"))
            return false
        else
            -- First emission: tag with the canonical id so later sections can refer to it.
            b.emit(string.format("local %s = %s -- (%s)", var, lit, entry.id))
            entry.first_seen = section
            return true
        end
    else
        b.emit(string.format("local %s = %s", var, lit))
        return true
    end
end

local function _pool_section(name, opts)
    -- opts: title, gate, pool_field, fallback_prefix, comment_template, want_binary
    _register(name, {
        title    = opts.title,
        category = "strings",
        gate     = opts.gate,
        run      = function()
            local pool = t[opts.pool_field]
            if not pool then return end
            if not pool.strings or #pool.strings == 0 then return end

            local b = _budget(name)
            aA()
            if opts.comment_template then
                b.emit("-- " .. opts.comment_template(pool), true)
            end
            for i, entry in _iter_ipairs(pool.strings) do
                -- pool entry shape varies: WAD/k0lrot/lightcate/etc give
                -- {idx,val,binary?}, xor pool gives the raw string.
                local idx, value, want_bin
                if j(entry) == "table" then
                    idx = entry.idx or i
                    value = entry.val
                    want_bin = entry.binary or opts.want_binary
                else
                    idx = i
                    value = entry
                    want_bin = opts.want_binary
                end
                if value ~= nil then
                    _emit_pool_entry(b, name, opts.fallback_prefix, idx, value, want_bin)
                end
            end
        end,
    })
end

-- ---------------------------------------------------------------------------
-- string_constants  (collected via runtime instrumentation)
-- ---------------------------------------------------------------------------

_register("string_constants", {
    title    = "STRING CONSTANTS",
    category = "strings",
    gate     = function() return r.DUMP_ALL_STRINGS end,
    run      = function()
        if not t.string_refs or #t.string_refs == 0 then return end
        local b = _budget("string_constants")
        aA()
        local seen, ref_idx = {}, 0
        for _, ref in _iter_ipairs(t.string_refs) do
            local val = (ref and ref.value) or ""
            if val ~= "" and not seen[val] then
                seen[val] = true
                ref_idx = ref_idx + 1
                _emit_pool_entry(b, "string_constants", "_ref", ref_idx, val, false)
            end
        end
    end,
})

-- ---------------------------------------------------------------------------
-- string-pool sections
-- ---------------------------------------------------------------------------

_pool_section("wad_strings", {
    title             = "WAD DECODED STRINGS",
    gate              = function() return r.DUMP_WAD_STRINGS end,
    pool_field        = "wad_string_pool",
    fallback_prefix   = "_wad",
    comment_template  = function(pool)
        return string.format("Decoded WeAreDevs string pool (%d strings, total=%d)",
            #pool.strings, pool.total or 0)
    end,
})

_pool_section("xor_strings", {
    title             = "XOR DECRYPTED STRINGS",
    gate              = function() return r.EMIT_XOR end,
    pool_field        = "xor_string_pool",
    fallback_prefix   = "_xor",
    comment_template  = function(pool)
        return string.format("XOR-decrypted string constants (%d strings)", #pool.strings)
    end,
})

_pool_section("k0lrot_strings", {
    title             = "GENERIC-WRAPPER DECODED STRINGS",
    gate              = function() return r.DUMP_DECODED_STRINGS end,
    pool_field        = "k0lrot_string_pool",
    fallback_prefix   = "_s",
    comment_template  = function(pool)
        return string.format("Decoded string pool (%s obfuscation, var=%s, %d strings)",
            pool.label or "generic-wrapper", pool.var_name or "?", #pool.strings)
    end,
})

_pool_section("lightcate_strings", {
    title             = "LIGHTCATE DECODED STRINGS",
    gate              = function() return r.DUMP_LIGHTCATE_STRINGS end,
    pool_field        = "lightcate_string_pool",
    fallback_prefix   = "_lc",
    comment_template  = function(pool)
        return string.format("Decoded string pool (Lightcate v2.0.0, var=%s, %d strings)",
            pool.var_name or "?", #pool.strings)
    end,
})

_pool_section("prometheus_strings", {
    title             = "PROMETHEUS DECODED STRINGS",
    gate              = function() return r.DUMP_DECODED_STRINGS end,
    pool_field        = "prometheus_string_pool",
    fallback_prefix   = "_prom",
    comment_template  = function(pool)
        return string.format("Decoded string pool (Prometheus obfuscation, var=%s, %d strings)",
            pool.var_name or "?", #pool.strings)
    end,
})

_pool_section("lunr_strings", {
    title             = "LUNR DECODED STRINGS",
    gate              = function() return r.DUMP_DECODED_STRINGS end,
    pool_field        = "lunr_string_pool",
    fallback_prefix   = "_lunr",
    comment_template  = function(pool)
        return string.format("Decoded string pool (Lunr v1.0.7, var=%s, %d strings)",
            pool.var_name or "?", #pool.strings)
    end,
})

-- ---------------------------------------------------------------------------
-- remote_summary
-- ---------------------------------------------------------------------------

_register("remote_summary", {
    title    = "REMOTE CALL SUMMARY",
    category = "calls",
    gate     = function() return r.DUMP_REMOTE_SUMMARY end,
    run      = function()
        if not t.call_graph or #t.call_graph == 0 then return end
        local b = _budget("remote_summary")
        _section_header(b.emit, "REMOTE CALL SUMMARY")

        local counts, order = {}, {}
        for _, entry in _iter_ipairs(t.call_graph) do
            local rtype = entry.type or "Remote"
            local rname = entry.name or "?"
            local key = rtype .. ":" .. rname
            local c = counts[key]
            if not c then
                c = { rtype = rtype, name = rname, n = 0 }
                counts[key] = c
                order[#order + 1] = key
            end
            c.n = c.n + 1
        end

        -- Sort by call count desc, then name asc, for readability.
        table.sort(order, function(a1, b1)
            local ca, cb = counts[a1], counts[b1]
            if ca.n ~= cb.n then return ca.n > cb.n end
            return ca.name < cb.name
        end)

        local total = 0
        for _, key in ipairs(order) do
            local c = counts[key]
            total = total + c.n
            b.emit(string.format("-- [%s] %-32s  (called %d time%s)",
                c.rtype, c.name, c.n, c.n == 1 and "" or "s"), true)
        end
        b.emit(string.format("-- Total: %d unique remote(s), %d call(s)", #order, total), true)
        b.emit("-- =========================================================", true)
    end,
})

-- ---------------------------------------------------------------------------
-- instance_creations
-- ---------------------------------------------------------------------------

_register("instance_creations", {
    title    = "INSTANCE CREATION TRACKER",
    category = "instances",
    gate     = function() return r.DUMP_INSTANCE_CREATIONS end,
    run      = function()
        if not t.instance_creations or #t.instance_creations == 0 then return end
        local b = _budget("instance_creations")
        _section_header(b.emit, "INSTANCE CREATION TRACKER",
            string.format("%d Instance.new() call(s) captured", #t.instance_creations))

        local counts, order = {}, {}
        for _, ic in _iter_ipairs(t.instance_creations) do
            local cls = ic.class or "?"
            if counts[cls] == nil then
                counts[cls] = 0
                order[#order + 1] = cls
            end
            counts[cls] = counts[cls] + 1
        end
        table.sort(order, function(a1, b1)
            if counts[a1] ~= counts[b1] then return counts[a1] > counts[b1] end
            return a1 < b1
        end)
        for _, cls in ipairs(order) do
            b.emit(string.format("-- Instance.new(%q)  x%d", cls, counts[cls]), true)
        end
        b.emit("-- =========================================================", true)
    end,
})

-- ---------------------------------------------------------------------------
-- script_loads
-- ---------------------------------------------------------------------------

_register("script_loads", {
    title    = "SCRIPT LOADER LOG",
    category = "loaders",
    gate     = function() return r.DUMP_SCRIPT_LOADS end,
    run      = function()
        if not t.script_loads or #t.script_loads == 0 then return end
        local b = _budget("script_loads")
        _section_header(b.emit, "SCRIPT LOADER LOG",
            string.format("%d load event(s) captured", #t.script_loads))

        local snip_max = _cfg("MAX_SCRIPT_LOAD_SNIPPET", 80)
        for idx, sl in _iter_ipairs(t.script_loads) do
            if sl.kind == "require" then
                b.emit(string.format("-- [%d] require(%s)", idx, sl.name or "?"), true)
            elseif sl.kind == "loadstring" then
                local snippet = (sl.source or ""):gsub("[\r\n]", " "):sub(1, snip_max)
                b.emit(string.format("-- [%d] loadstring (len=%d, status=%s): %s",
                    idx, sl.length or 0, sl.status or "?", snippet), true)
            else
                b.emit(string.format("-- [%d] %s", idx, m(sl.kind or "?")), true)
            end
        end
        b.emit("-- =========================================================", true)
    end,
})

-- ---------------------------------------------------------------------------
-- gc_scan
-- ---------------------------------------------------------------------------

_register("gc_scan", {
    title    = "GC SCAN: registered closures / upvalue dump",
    category = "closure",
    gate     = function() return r.DUMP_GC_SCAN and a and a.getupvalue end,
    run      = function()
        local cap     = _cfg("MAX_GC_SCAN_FUNCTIONS", 500)
        local up_cap  = _cfg("MAX_UPVALUES_PER_FUNCTION", 200)

        local fns = {}
        for obj, name in _iter_pairs(t.registry) do
            if j(obj) == "function" then
                fns[#fns + 1] = { fn = obj, name = name }
                if #fns >= cap then break end
            end
        end
        if #fns == 0 then return end

        local b = _budget("gc_scan")
        _section_header(b.emit, "GC SCAN: registered closures / upvalue dump",
            string.format("%d function(s) scanned", #fns))

        local emitted_any = false
        for _, entry in ipairs(fns) do
            local fn = entry.fn
            local fname = entry.name or "?"
            local upvals = {}
            local idx = 1
            while idx <= up_cap do
                local ok, uname, uval = pcall(a.getupvalue, fn, idx)
                if not ok or not uname then break end
                local utype = j(uval)
                if uname ~= "_ENV"
                        and _is_safe_ident(uname)
                        and utype ~= "function" then
                    upvals[#upvals + 1] = { name = uname, val = uval }
                end
                idx = idx + 1
            end
            if #upvals > 0 then
                emitted_any = true
                b.emit(string.format("-- closure: %s  (%d upvalue(s))", fname, #upvals), true)
                for _, uv in ipairs(upvals) do
                    b.emit(string.format("--   upvalue %s = %s", uv.name, aZ(uv.val)), true)
                end
            end
        end
        if not emitted_any then
            b.emit("-- (no interesting upvalues found in scanned closures)", true)
        end
        b.emit("-- =========================================================", true)
    end,
})

-- ---------------------------------------------------------------------------
-- deferred_hooks (executed by run_deferred_hooks; section is just metadata)
-- ---------------------------------------------------------------------------

_register("deferred_hooks", {
    title    = "DEFERRED HOOKS",
    category = "hooks",
    gate     = function() return true end,
    run      = function()
        if not t.deferred_hooks or #t.deferred_hooks == 0 then return end
        local hooks = t.deferred_hooks
        t.deferred_hooks = {}  -- clear before processing to prevent re-entry loops

        local cap = _cfg("MAX_DEFERRED_HOOKS", 200)
        local b   = _budget("deferred_hooks")
        local ran, errored = 0, 0

        for _, entry in _iter_ipairs(hooks) do
            if t.limit_reached then break end
            if ran >= cap then
                b.emit(string.format("-- [envlogger] hook budget exhausted at %d (MAX_DEFERRED_HOOKS)",
                    cap), true)
                break
            end
            if j(entry.fn) == "function" then
                aA()
                local ok, hook_lines = pcall(br, entry.fn, entry.args or {})
                if ok and j(hook_lines) == "table" then
                    for _, hl in ipairs(hook_lines) do
                        b.emit(hl, true)
                    end
                else
                    errored = errored + 1
                    b.emit(string.format("-- [envlogger] deferred hook errored: %s",
                        m(hook_lines or "?")), true)
                end
                ran = ran + 1
            end
        end
        if ran > 0 then aA() end

        local s = _stats.by_section["deferred_hooks"] or { lines = 0 }
        s.ran     = ran
        s.errored = errored
        _stats.by_section["deferred_hooks"] = s
    end,
})

-- ---------------------------------------------------------------------------
-- New (additive) sections
-- ---------------------------------------------------------------------------

-- Run-summary dashboard. Emits a high-level snapshot of what is in `t` so
-- the analyst sees the shape of the dump before reading the body.
_register("run_summary", {
    title    = "ENVLOGGER RUN SUMMARY",
    category = "meta",
    gate     = function() return _cfg("ENVLOGGER_RUN_SUMMARY", true) == true end,
    run      = function()
        local b = _budget("run_summary")
        _section_header(b.emit, "ENVLOGGER RUN SUMMARY")

        local function _len(v) return (type(v) == "table" and #v) or 0 end
        local lines = {
            string.format("-- registered functions      : %d", _stats_count_table(t.registry)),
            string.format("-- string refs (raw)         : %d", _len(t.string_refs)),
            string.format("-- WAD pool                  : %d", _pool_size(t.wad_string_pool)),
            string.format("-- XOR pool                  : %d", _pool_size(t.xor_string_pool)),
            string.format("-- generic-wrapper pool      : %d", _pool_size(t.k0lrot_string_pool)),
            string.format("-- Lightcate pool            : %d", _pool_size(t.lightcate_string_pool)),
            string.format("-- Prometheus pool           : %d", _pool_size(t.prometheus_string_pool)),
            string.format("-- Lunr pool                 : %d", _pool_size(t.lunr_string_pool)),
            string.format("-- remote calls              : %d", _len(t.call_graph)),
            string.format("-- instance creations        : %d", _len(t.instance_creations)),
            string.format("-- script loads              : %d", _len(t.script_loads)),
            string.format("-- deferred hooks pending    : %d", _len(t.deferred_hooks)),
            string.format("-- error count               : %d", t.error_count or 0),
            string.format("-- warning count             : %d", t.warning_count or 0),
            string.format("-- output size (bytes so far): %d", t.current_size or 0),
        }
        for _, ln in ipairs(lines) do b.emit(ln, true) end
        b.emit("-- =========================================================", true)
    end,
})

-- Helpers used by run_summary (forward-declared earlier so the closures
-- can reference them).
_stats_count_table = function(tbl)
    if j(tbl) ~= "table" then return 0 end
    local n = 0
    for _ in _iter_pairs(tbl) do n = n + 1 end
    return n
end

_pool_size = function(pool)
    if j(pool) ~= "table" then return 0 end
    if j(pool.strings) ~= "table" then return 0 end
    return #pool.strings
end

-- Diagnostics: any errors caught during the run.
_register("envlogger_diagnostics", {
    title    = "ENVLOGGER DIAGNOSTICS",
    category = "meta",
    gate     = function() return _cfg("ENVLOGGER_DIAGNOSTICS", false) == true end,
    run      = function()
        if #_diagnostics.errors == 0
                and _stats.truncations == 0
                and _stats.dedup_hits == 0
                and _stats.redactions == 0 then
            return
        end
        local b = _budget("envlogger_diagnostics")
        _section_header(b.emit, "ENVLOGGER DIAGNOSTICS")
        b.emit(string.format("-- sections run        : %d", _stats.sections_run), true)
        b.emit(string.format("-- sections emitted    : %d", _stats.sections_emitted), true)
        b.emit(string.format("-- lines emitted       : %d", _stats.lines_emitted), true)
        b.emit(string.format("-- dedup hits          : %d", _stats.dedup_hits), true)
        b.emit(string.format("-- redactions          : %d", _stats.redactions), true)
        b.emit(string.format("-- section truncations : %d", _stats.truncations), true)
        b.emit(string.format("-- errors caught       : %d", _stats.errors), true)
        if #_diagnostics.errors > 0 then
            b.emit("-- ---- errors -----------------------------------------", true)
            for _, e in ipairs(_diagnostics.errors) do
                b.emit(string.format("-- [%s] %s", e.section, e.message), true)
            end
        end
        b.emit("-- =========================================================", true)
    end,
})

-- ===========================================================================
-- Public API (backwards-compatible with the original cat_envlogger.lua)
-- ===========================================================================

function q.dump_captured_globals(env_table, baseline_keys)
    _public_run("captured_globals", env_table, baseline_keys)
end

function q.dump_captured_upvalues()  _public_run("captured_upvalues") end
function q.dump_string_constants()   _public_run("string_constants")  end
function q.dump_wad_strings()        _public_run("wad_strings")       end
function q.dump_xor_strings()        _public_run("xor_strings")       end
function q.dump_k0lrot_strings()     _public_run("k0lrot_strings")    end
function q.dump_lightcate_strings()  _public_run("lightcate_strings") end
function q.dump_prometheus_strings() _public_run("prometheus_strings")end
function q.dump_lunr_strings()       _public_run("lunr_strings")      end
function q.dump_remote_summary()     _public_run("remote_summary")    end
function q.dump_instance_creations() _public_run("instance_creations") end
function q.dump_script_loads()       _public_run("script_loads")      end
function q.dump_gc_scan()            _public_run("gc_scan")           end
function q.run_deferred_hooks()      _public_run("deferred_hooks")    end

-- ===========================================================================
-- New public API (additive)
-- ===========================================================================

-- Run every registered section in order. The default sandbox call pattern
-- explicitly invokes the legacy 14, but new callers can use this single
-- entry point so they get any future sections for free.
function q.envlogger_run_all(env_table, baseline_keys)
    _diagnostics.started_at = _safe_clock()
    _run("run_summary")
    _run("deferred_hooks")
    _run("captured_globals", env_table, baseline_keys)
    _run("captured_upvalues")
    _run("string_constants")
    _run("wad_strings")
    _run("xor_strings")
    _run("k0lrot_strings")
    _run("lightcate_strings")
    _run("prometheus_strings")
    _run("lunr_strings")
    _run("remote_summary")
    _run("instance_creations")
    _run("script_loads")
    _run("gc_scan")
    _run("envlogger_diagnostics")
    _diagnostics.finished_at = _safe_clock()
end

-- Read-only access to internal stats (handy for tests + cat.py UI).
function q.envlogger_stats()
    return {
        sections_run     = _stats.sections_run,
        sections_emitted = _stats.sections_emitted,
        lines_emitted    = _stats.lines_emitted,
        redactions       = _stats.redactions,
        dedup_hits       = _stats.dedup_hits,
        truncations      = _stats.truncations,
        errors           = _stats.errors,
        by_section       = _stats.by_section,
        diagnostics      = _diagnostics,
    }
end

-- Introspection: list every registered section in run order.
function q.envlogger_sections()
    local out = {}
    for i, sec in ipairs(_sections_seq) do
        out[i] = {
            name     = sec.name,
            title    = sec.title,
            category = sec.category,
        }
    end
    return out
end

-- Reset stats/interner (useful between successive dumps in long-running
-- workers). The legacy q.reset() in cat.lua wipes t.output but doesn't
-- know about envlogger-internal state; callers can invoke this too.
function q.envlogger_reset()
    _stats = {
        sections_run     = 0,
        sections_emitted = 0,
        lines_emitted    = 0,
        redactions       = 0,
        dedup_hits       = 0,
        truncations      = 0,
        errors           = 0,
        by_section       = {},
    }
    _diagnostics = {
        started_at  = nil,
        finished_at = nil,
        errors      = {},
    }
    _interner = { by_value = {}, next_id = 0 }
end
