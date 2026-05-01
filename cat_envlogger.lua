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

-- Shannon entropy in bits-per-byte. Useful to flag random/encrypted blobs.
-- Uses pcall for cheap defense; returns 0 on any error.
local function _entropy(s)
    if j(s) ~= "string" or #s == 0 then return 0 end
    local ok, e = pcall(function()
        local counts = {}
        local n = #s
        for i = 1, n do
            local b = s:byte(i)
            counts[b] = (counts[b] or 0) + 1
        end
        local h = 0
        for _, c in pairs(counts) do
            local p = c / n
            h = h - p * (math.log(p) / math.log(2))
        end
        return h
    end)
    return ok and e or 0
end

-- True if s contains any byte outside printable ASCII (32..126) plus \t\n\r.
local function _has_non_printable(s)
    if j(s) ~= "string" then return false end
    for i = 1, #s do
        local b = s:byte(i)
        if not (b == 9 or b == 10 or b == 13 or (b >= 32 and b <= 126)) then
            return true
        end
    end
    return false
end

-- True if s looks like base32 (RFC 4648, A-Z2-7, optional `=` padding).
local function _looks_base32(s)
    return #s >= 16
        and #s % 8 == 0
        and s:match("^[A-Z2-7]+=*$") ~= nil
end

-- Roblox-specific scalar literals: Color3.fromRGB, Vector3.new, CFrame.new,
-- UDim2.new, NumberSequenceKeypoint, Region3, Ray, BrickColor.
local _ROBLOX_LITERAL_PATTERNS = {
    "^Color3%.fromRGB%(",   "^Color3%.new%(",
    "^Vector3%.new%(",      "^Vector2%.new%(",
    "^CFrame%.new%(",       "^CFrame%.Angles%(",
    "^UDim2%.new%(",        "^UDim%.new%(",
    "^NumberRange%.new%(",  "^NumberSequence%.new%(",
    "^ColorSequence%.new%(",
    "^Region3%.new%(",      "^Ray%.new%(",
    "^BrickColor%.",        "^Faces%.",
    "^Axes%.",              "^Enum%.",
}

-- Known suspicious/exfiltration string fragments (lower-cased substring search).
local _THREAT_FRAGMENTS = {
    "/api/webhooks/",          -- Discord
    "discord.com/api",         -- Discord
    "discordapp.com/api",      -- Discord (legacy host)
    "telegram.org/bot",        -- Telegram bots
    "ngrok.io", "trycloudflare.com",
    "pastebin.com/raw",        -- pastebin exfil
    "hastebin.com/raw",
    "transfer.sh",
    ".onion",                  -- tor
    "/c2/", "/cnc/",           -- C2 endpoints
    "rbxstu", "rblx.club",     -- known cheat marketplaces
    "synapse-x.io", "krnlx.com",
    "iy.fm/", "infyield.com",
    "userid=", "x-api-key:", "authorization:",
}

-- IPv6 (very loose: hex groups separated by colons).
local function _looks_ipv6(s)
    if #s < 3 or #s > 45 then return false end
    return s:match("^[%xA-Fa-f0-9:]+$") ~= nil and s:find(":", 1, true) ~= nil
end

-- UUID v4-ish: 8-4-4-4-12 hex.
local function _looks_uuid(s)
    return #s == 36 and s:match("^[%xA-Fa-f0-9]+%-[%xA-Fa-f0-9]+%-[%xA-Fa-f0-9]+%-[%xA-Fa-f0-9]+%-[%xA-Fa-f0-9]+$") ~= nil
end

-- Roblox UserId / PlaceId / JobId (heuristic: pure numeric strings of 7-19 digits).
local function _looks_roblox_id(s)
    return s:match("^%d+$") ~= nil and #s >= 7 and #s <= 19
end

-- Email-ish.
local function _looks_email(s)
    return s:match("^[%w%.%-_%+]+@[%w%.%-_]+%.[%w]+$") ~= nil
end

-- Lua bytecode signature (Luau prelude is "\27\76uau" or 5.1's "\27Lua").
local function _looks_lua_bytecode(s)
    if #s < 12 then return false end
    local h = s:sub(1, 4)
    return h == "\27Lua" or h == "\27Luau" or s:sub(1, 5) == "\27\76uau"
end

-- The classifier table is ordered: the first matching predicate wins. Order
-- specific patterns BEFORE generic ones (e.g., webhook before url, jwt before
-- discord_token).
local _CLASSIFIERS = {
    -- name, predicate(string) -> bool, prefix
    { name = "webhook",
      predicate = function(s)
          return s:find("discord[%a]*%.com/api/webhooks/") ~= nil
      end,
      prefix = "_webhook" },

    { name = "telegram_bot",
      predicate = function(s) return s:find("api%.telegram%.org/bot") ~= nil end,
      prefix = "_tgbot" },

    { name = "lua_bytecode",
      predicate = _looks_lua_bytecode,
      prefix = "_bytecode" },

    { name = "roblox_uri",
      predicate = function(s)
          return s:find("^rbxassetid://") or s:find("^rbxthumb://")
              or s:find("^rbxhttp://")    or s:find("^rbx://")
              or s:find("^rbxasset://")
      end,
      prefix = "_asset" },

    { name = "url_https", predicate = function(s) return s:find("^https://") ~= nil end, prefix = "_url" },
    { name = "url_http",  predicate = function(s) return s:find("^http://")  ~= nil end, prefix = "_url" },
    { name = "url_ftp",   predicate = function(s) return s:find("^ftp[s]?://") ~= nil end, prefix = "_url" },
    { name = "url_ws",    predicate = function(s) return s:find("^wss?://") ~= nil end, prefix = "_ws" },

    { name = "roblox_literal",
      predicate = function(s)
          for _, pat in ipairs(_ROBLOX_LITERAL_PATTERNS) do
              if s:match(pat) then return true end
          end
          return false
      end,
      prefix = "_rbxval" },

    { name = "lua_source",
      predicate = function(s)
          if #s < 60 then return false end
          local hits = 0
          if s:find("function%s*%(") then hits = hits + 1 end
          if s:find("local%s+[%a_]") then hits = hits + 1 end
          if s:find("return%s+")     then hits = hits + 1 end
          if s:find("end[%s\n;]")    then hits = hits + 1 end
          if s:find("then[%s\n]")    then hits = hits + 1 end
          return hits >= 2
      end,
      prefix = "_src" },

    { name = "json",
      predicate = function(s)
          if #s < 4 then return false end
          local f, l = s:sub(1, 1), s:sub(-1)
          if not ((f == "{" and l == "}") or (f == "[" and l == "]")) then
              return false
          end
          -- Cheap JSON sanity: at least one ":" or "," near the start.
          return s:find("[\":,%[%{]", 2) ~= nil
      end,
      prefix = "_json" },

    { name = "jwt",
      predicate = function(s)
          if #s < 40 then return false end
          if s:sub(1, 1) ~= "e" then return false end
          local a1 = s:match("^([A-Za-z0-9_%-]+)%.([A-Za-z0-9_%-]+)%.([A-Za-z0-9_%-]+)$")
          return a1 ~= nil
      end,
      prefix = "_jwt" },

    { name = "uuid",     predicate = _looks_uuid,        prefix = "_uuid" },
    { name = "ipv6",     predicate = _looks_ipv6,        prefix = "_ipv6" },

    { name = "ip",
      predicate = function(s)
          return s:match("^%d+%.%d+%.%d+%.%d+$") ~= nil
      end,
      prefix = "_ip" },

    { name = "email",    predicate = _looks_email,       prefix = "_email" },
    { name = "rbx_id",   predicate = _looks_roblox_id,   prefix = "_rbxid" },

    { name = "hex",
      predicate = function(s)
          return #s >= 16 and #s % 2 == 0 and s:match("^[%da-fA-F]+$") ~= nil
      end,
      prefix = "_hex" },

    { name = "b64",
      predicate = function(s)
          if #s < 32 then return false end
          if not s:match("^[A-Za-z0-9+/=]+$") then return false end
          return _entropy(s) > 4.5
      end,
      prefix = "_b64" },

    { name = "b32",      predicate = _looks_base32,      prefix = "_b32" },

    { name = "discord_token",
      predicate = function(s)
          return s:match("^[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+$") ~= nil
              and #s >= 50
      end,
      prefix = "_token" },

    { name = "binary_blob",
      predicate = function(s)
          return #s >= 16 and _has_non_printable(s) and _entropy(s) > 5.5
      end,
      prefix = "_bin" },

    { name = "ident",
      predicate = function(s)
          return #s <= 64 and s:match("^[%a_][%w_]*$") ~= nil
      end,
      prefix = "_ident" },
}

local function _classify(value)
    if j(value) ~= "string" then return "_ref" end
    for _, c in ipairs(_CLASSIFIERS) do
        local ok, hit = pcall(c.predicate, value)
        if ok and hit then return c.prefix end
    end
    return "_ref"
end

-- Return the friendly classifier name (not just the prefix) for a value.
-- Used by the threat-assessment / cross-references / dashboard sections.
local function _classify_name(value)
    if j(value) ~= "string" then return "ref" end
    for _, c in ipairs(_CLASSIFIERS) do
        local ok, hit = pcall(c.predicate, value)
        if ok and hit then return c.name end
    end
    return "ref"
end

-- Lower-cased substring scan against the threat fragment list. Returns the
-- first matching fragment or nil.
local function _threat_match(value)
    if j(value) ~= "string" or #value < 3 then return nil end
    local lower = value:lower()
    for _, frag in ipairs(_THREAT_FRAGMENTS) do
        if lower:find(frag, 1, true) then return frag end
    end
    return nil
end

-- ---------------------------------------------------------------------------
-- Pretty-printer for tables (with cycle detection and per-call budgets).
-- Used by sections that want to expand structured values rather than just
-- emit aZ()'s one-line representation.
-- ---------------------------------------------------------------------------

local function _pp(value, opts)
    opts = opts or {}
    local max_depth = opts.max_depth or 3
    local max_keys  = opts.max_keys  or 32
    local indent_s  = opts.indent    or "    "
    local seen      = {}

    local function _q(v)
        if j(v) == "string" then return aH(v) end
        return m(v)
    end

    local out = {}
    local function _emit(s) out[#out + 1] = s end

    local function _walk(val, depth, lead)
        if depth > max_depth then
            _emit(_q(val))
            return
        end
        if j(val) ~= "table" then
            _emit(_q(val))
            return
        end
        if seen[val] then
            _emit(string.format("--[[ cycle %s ]]", m(val)))
            return
        end
        seen[val] = true
        _emit("{")
        local count = 0
        local first = true
        for k, v in _iter_pairs(val) do
            count = count + 1
            if count > max_keys then
                _emit(string.format(",\n%s%s--[[ +%d more ]]", lead, indent_s, count - max_keys))
                break
            end
            if not first then _emit(",") end
            first = false
            _emit("\n")
            _emit(lead)
            _emit(indent_s)
            local kt = j(k)
            if kt == "string" and _is_safe_ident(k) then
                _emit(k)
                _emit(" = ")
            elseif kt == "string" then
                _emit("[")
                _emit(aH(k))
                _emit("] = ")
            elseif kt == "number" then
                _emit("[")
                _emit(m(k))
                _emit("] = ")
            else
                _emit("[")
                _emit(_q(k))
                _emit("] = ")
            end
            _walk(v, depth + 1, lead .. indent_s)
        end
        if count > 0 then
            _emit("\n")
            _emit(lead)
        end
        _emit("}")
    end

    _walk(value, 1, "")
    return table.concat(out)
end

-- ---------------------------------------------------------------------------
-- Tiny ASCII table renderer (one-shot, single-line headers).
-- _ascii_table({{"col1","col2"},{"a","1"},...}) returns a newline-joined string.
-- ---------------------------------------------------------------------------

local function _ascii_table(rows, opts)
    opts = opts or {}
    if not rows or #rows == 0 then return "" end
    local widths = {}
    for _, row in ipairs(rows) do
        for i, cell in ipairs(row) do
            local s = m(cell)
            if (#s) > (widths[i] or 0) then widths[i] = #s end
        end
    end
    local function _line(ch)
        local out = {"--"}
        for _, w in ipairs(widths) do
            out[#out + 1] = " " .. string.rep(ch, w + 2)
        end
        return table.concat(out)
    end
    local function _row(row)
        local out = {"--"}
        for i, w in ipairs(widths) do
            local s = m(row[i] or "")
            out[#out + 1] = " | " .. s .. string.rep(" ", w - #s)
        end
        out[#out + 1] = " |"
        return table.concat(out)
    end
    local lines = {}
    lines[#lines + 1] = _line("-")
    lines[#lines + 1] = _row(rows[1])
    lines[#lines + 1] = _line("-")
    for i = 2, #rows do
        lines[#lines + 1] = _row(rows[i])
    end
    lines[#lines + 1] = _line("-")
    return table.concat(lines, "\n")
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

-- The captured-globals dumper stashes a reference to the env table so
-- analytical sections (threat_assessment, cross_references) can walk it
-- after the fact without needing a parameter passed in.
local _last_env_table   = nil
local _last_baseline    = nil

_register("captured_globals", {
    title    = "CAPTURED GLOBAL WRITES",
    category = "env",
    gate     = function() return r.DUMP_GLOBALS end,
    run      = function(env_table, baseline_keys)
        -- Stash for later analytical sections.
        _last_env_table = env_table
        _last_baseline  = baseline_keys

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
-- property_writes
-- Dumps t.property_store: a map of Instance -> { property -> value } populated
-- by the sandbox's gethiddenproperty / sethiddenproperty / setinstanceproperty
-- stubs. Until v3 this rich state was never written out — analysts had no
-- visibility into which fake properties scripts were poking.
-- ---------------------------------------------------------------------------

local function _instance_label(obj)
    -- t.registry maps obj -> human name; fall back to safe tostring.
    if t.registry and t.registry[obj] then
        return t.registry[obj]
    end
    local ok, s = pcall(m, obj)
    return (ok and s) or "<unknown>"
end

-- Collapse a multi-line aZ() rendering into one line so we can safely embed
-- it inside a Lua comment (`-- foo = bar`). Tables become `{...N keys}` if
-- the flattened form is longer than 80 chars.
local function _oneline_value(v)
    local rendered = aZ(v)
    if j(rendered) ~= "string" then return m(v) end
    if rendered:find("\n", 1, true) then
        rendered = rendered:gsub("%s*\n%s*", " ")
    end
    if #rendered > 120 then
        if j(v) == "table" then
            local n = 0
            for _ in _iter_pairs(v) do n = n + 1 end
            return string.format("{ ... %d keys ... }", n)
        end
        return rendered:sub(1, 117) .. "..."
    end
    return rendered
end

_register("property_writes", {
    title    = "INSTANCE PROPERTY STORE",
    category = "instances",
    gate     = function() return _cfg("DUMP_PROPERTY_STORE", true) ~= false end,
    run      = function()
        if not t.property_store then return end
        local b = _budget("property_writes")
        local entries = {}
        for obj, props in _iter_pairs(t.property_store) do
            if j(props) == "table" then
                local count = 0
                for _ in _iter_pairs(props) do count = count + 1 end
                if count > 0 then
                    entries[#entries + 1] = {
                        label = _instance_label(obj),
                        props = props,
                        count = count,
                    }
                end
            end
        end
        if #entries == 0 then return end

        table.sort(entries, function(a1, b1)
            if a1.count ~= b1.count then return a1.count > b1.count end
            return a1.label < b1.label
        end)

        _section_header(b.emit, "INSTANCE PROPERTY STORE",
            string.format("%d instance(s) had property writes captured", #entries))

        for _, e in ipairs(entries) do
            b.emit(string.format("-- %s  (%d propert%s)", e.label, e.count,
                e.count == 1 and "y" or "ies"), true)
            -- Sort props by key for deterministic output.
            local keys = {}
            for k in _iter_pairs(e.props) do keys[#keys + 1] = k end
            table.sort(keys, function(a1, b1) return m(a1) < m(b1) end)
            for _, k in ipairs(keys) do
                local v = e.props[k]
                local key_s = m(k)
                if _is_safe_ident(key_s) then
                    b.emit(string.format("--   .%s = %s", key_s, _oneline_value(v)), true)
                else
                    b.emit(string.format("--   [%s] = %s", aH(key_s), _oneline_value(v)), true)
                end
            end
        end
        b.emit("-- =========================================================", true)
    end,
})

-- ---------------------------------------------------------------------------
-- hook_calls
-- Dumps t.hook_calls populated by hookfunction / hookmetamethod /
-- replaceclosure / detourfn. Groups by target and kind so the analyst can
-- spot e.g. "this script hooked `print` 47 times".
-- ---------------------------------------------------------------------------

_register("hook_calls", {
    title    = "HOOK CALL TRACKER",
    category = "hooks",
    gate     = function() return _cfg("DUMP_HOOK_CALLS", true) ~= false end,
    run      = function()
        if not t.hook_calls or #t.hook_calls == 0 then return end
        local b = _budget("hook_calls")

        -- Aggregate: target -> kind -> count.
        local agg, totals = {}, {}
        for _, h in _iter_ipairs(t.hook_calls) do
            local target = h.target or "?"
            local kind   = h.kind   or "?"
            agg[target] = agg[target] or {}
            agg[target][kind] = (agg[target][kind] or 0) + 1
            totals[target]    = (totals[target]    or 0) + 1
        end

        local ordered = {}
        for tgt in pairs(totals) do ordered[#ordered + 1] = tgt end
        table.sort(ordered, function(a1, b1)
            if totals[a1] ~= totals[b1] then return totals[a1] > totals[b1] end
            return a1 < b1
        end)

        _section_header(b.emit, "HOOK CALL TRACKER",
            string.format("%d hook event(s) across %d target(s)", #t.hook_calls, #ordered))

        for _, tgt in ipairs(ordered) do
            local kinds = {}
            for kind, n in pairs(agg[tgt]) do
                kinds[#kinds + 1] = string.format("%s=%d", kind, n)
            end
            table.sort(kinds)
            b.emit(string.format("-- %s  (%d total)  [%s]",
                tgt, totals[tgt], table.concat(kinds, ", ")), true)
        end
        b.emit("-- =========================================================", true)
    end,
})

-- ---------------------------------------------------------------------------
-- loop_summary
-- Hot-line report from t.loop_line_counts + t.loop_detected_lines. The
-- sandbox already prints "-- LOOP DETECTED" comments inline; this section
-- gives a roll-up so the analyst sees the worst offenders at a glance.
-- ---------------------------------------------------------------------------

_register("loop_summary", {
    title    = "HOT-LINE LOOP SUMMARY",
    category = "meta",
    gate     = function() return _cfg("DUMP_LOOP_SUMMARY", true) ~= false end,
    run      = function()
        if not t.loop_line_counts then return end
        local b = _budget("loop_summary")

        local rows = {}
        for line_key, hits in _iter_pairs(t.loop_line_counts) do
            rows[#rows + 1] = {
                key      = m(line_key),
                hits     = j(hits) == "number" and hits or 0,
                detected = (t.loop_detected_lines or {})[line_key] == true,
            }
        end
        if #rows == 0 then return end

        table.sort(rows, function(a1, b1)
            if a1.hits ~= b1.hits then return a1.hits > b1.hits end
            return a1.key < b1.key
        end)

        local top_n  = _cfg("LOOP_SUMMARY_TOP_N", 25)
        local total_detected = 0
        for _, r1 in ipairs(rows) do if r1.detected then total_detected = total_detected + 1 end end

        _section_header(b.emit, "HOT-LINE LOOP SUMMARY",
            string.format("%d distinct line(s); %d flagged as hot loops; showing top %d by hit count",
                #rows, total_detected, math.min(top_n, #rows)))

        for i = 1, math.min(top_n, #rows) do
            local r1 = rows[i]
            b.emit(string.format("-- %6d hits %s  %s",
                r1.hits, r1.detected and "[HOT]" or "     ", r1.key), true)
        end
        if #rows > top_n then
            b.emit(string.format("-- ... %d more line(s) suppressed (LOOP_SUMMARY_TOP_N)",
                #rows - top_n), true)
        end
        b.emit("-- =========================================================", true)
    end,
})

-- ---------------------------------------------------------------------------
-- counters
-- Dumps the small numeric counters scattered through t (instance_count,
-- tween_count, connection_count, drawing_count, task_count, coroutine_count,
-- table_count, branch_counter, depth_peak, hook_depth, callback_depth,
-- error_count, warning_count, lar_counter, proxy_id, exec_start_time,
-- obfuscation_score, deobf_attempts, emit_count). Tiny but very useful to
-- see at a glance how busy the script was.
-- ---------------------------------------------------------------------------

local _COUNTER_FIELDS = {
    "instance_count",  "tween_count",     "connection_count", "drawing_count",
    "task_count",      "coroutine_count", "table_count",      "branch_counter",
    "depth_peak",      "hook_depth",      "callback_depth",   "error_count",
    "warning_count",   "lar_counter",     "proxy_id",         "obfuscation_score",
    "deobf_attempts",  "emit_count",      "current_size",     "loop_counter",
}

_register("counters", {
    title    = "RUNTIME COUNTERS",
    category = "meta",
    gate     = function() return _cfg("DUMP_COUNTERS", true) ~= false end,
    run      = function()
        local b = _budget("counters")
        local rows = {{ "counter", "value" }}
        local emitted_any = false
        for _, key in ipairs(_COUNTER_FIELDS) do
            local v = t[key]
            if v ~= nil and v ~= 0 and v ~= false then
                rows[#rows + 1] = { key, m(v) }
                emitted_any = true
            end
        end
        if not emitted_any then return end

        _section_header(b.emit, "RUNTIME COUNTERS",
            "non-zero values from t.* (zero/false/nil suppressed)")
        for line in (_ascii_table(rows) .. "\n"):gmatch("([^\n]+)\n") do
            b.emit(line, true)
        end
        b.emit("-- =========================================================", true)
    end,
})

-- ---------------------------------------------------------------------------
-- last_http_url / namecall_method
-- Tiny but high-signal: the last URL the script tried to reach and the most
-- recent namecall method. Often the smoking gun for exfil scripts.
-- ---------------------------------------------------------------------------

_register("runtime_pointers", {
    title    = "RUNTIME POINTERS",
    category = "meta",
    gate     = function() return _cfg("DUMP_RUNTIME_POINTERS", true) ~= false end,
    run      = function()
        local b = _budget("runtime_pointers")
        local has_any = false
        local rows = {{ "pointer", "value" }}
        if t.last_http_url and t.last_http_url ~= "" then
            rows[#rows + 1] = { "last_http_url", m(t.last_http_url) }
            has_any = true
        end
        if t.namecall_method and t.namecall_method ~= "" then
            rows[#rows + 1] = { "namecall_method", m(t.namecall_method) }
            has_any = true
        end
        if t.last_error then
            rows[#rows + 1] = { "last_error", m(t.last_error) }
            has_any = true
        end
        if t.exec_start_time and t.exec_start_time ~= 0 then
            rows[#rows + 1] = { "exec_start_time", m(t.exec_start_time) }
            has_any = true
        end
        if not has_any then return end
        _section_header(b.emit, "RUNTIME POINTERS")
        for line in (_ascii_table(rows) .. "\n"):gmatch("([^\n]+)\n") do
            b.emit(line, true)
        end
        b.emit("-- =========================================================", true)
    end,
})

-- ---------------------------------------------------------------------------
-- obfuscator_fingerprint
-- Heuristic identification of which obfuscator(s) produced the input, based
-- on the size of each known string pool. Multiple pools may light up if the
-- script was double-obfuscated.
-- ---------------------------------------------------------------------------

local _POOL_FINGERPRINTS = {
    { field = "wad_string_pool",        label = "WAD",           weight = 1 },
    { field = "xor_string_pool",        label = "XOR-stream",    weight = 1 },
    { field = "k0lrot_string_pool",     label = "k0lrot/generic",weight = 1 },
    { field = "lightcate_string_pool",  label = "Lightcate",     weight = 1 },
    { field = "prometheus_string_pool", label = "Prometheus",    weight = 1 },
    { field = "lunr_string_pool",       label = "Lunraph",       weight = 1 },
}

_register("obfuscator_fingerprint", {
    title    = "OBFUSCATOR FINGERPRINT",
    category = "meta",
    gate     = function() return _cfg("DUMP_OBFUSCATOR_FINGERPRINT", true) ~= false end,
    run      = function()
        local b = _budget("obfuscator_fingerprint")
        local rows = {{ "obfuscator", "pool entries", "score" }}
        local hits = {}
        local total_score = 0
        for _, fp in ipairs(_POOL_FINGERPRINTS) do
            local n = _pool_size(t[fp.field])
            if n > 0 then
                local score = math.min(10, math.floor(math.log(1 + n) / math.log(2)))
                rows[#rows + 1] = { fp.label, m(n), m(score) }
                hits[#hits + 1] = { label = fp.label, n = n, score = score }
                total_score = total_score + score
            end
        end
        if #hits == 0 then return end

        table.sort(hits, function(a1, b1) return a1.score > b1.score end)
        local primary = hits[1]
        _section_header(b.emit, "OBFUSCATOR FINGERPRINT",
            string.format("primary suspect: %s  (combined score %d)",
                primary.label, total_score))
        for line in (_ascii_table(rows) .. "\n"):gmatch("([^\n]+)\n") do
            b.emit(line, true)
        end
        b.emit("-- =========================================================", true)
    end,
})

-- ---------------------------------------------------------------------------
-- threat_assessment
-- Walks the interner pool (if enabled) AND every known string source,
-- counting matches against _THREAT_FRAGMENTS. Produces a single risk score
-- 0..100 plus a sample of the strongest indicators.
-- ---------------------------------------------------------------------------

local function _walk_string_sources()
    -- Returns a list of {kind, value} tuples covering every string the
    -- envlogger could possibly emit. This deliberately runs BEFORE the
    -- output sanitizer redacts blocked patterns, so threat assessment can
    -- still see exfil URLs / webhooks / tokens that would be stripped from
    -- the final dump.
    local sources = {}

    local function _collect(kind, container)
        if j(container) ~= "table" then return end
        for _, v in _iter_ipairs(container) do
            if j(v) == "string" then
                sources[#sources + 1] = { kind = kind, value = v }
            elseif j(v) == "table" and j(v.val) == "string" then
                sources[#sources + 1] = { kind = kind, value = v.val }
            end
        end
    end

    _collect("string_refs", t.string_refs)
    if t.wad_string_pool        then _collect("wad",        t.wad_string_pool.strings)        end
    if t.xor_string_pool        then _collect("xor",        t.xor_string_pool.strings)        end
    if t.k0lrot_string_pool     then _collect("k0lrot",     t.k0lrot_string_pool.strings)     end
    if t.lightcate_string_pool  then _collect("lightcate",  t.lightcate_string_pool.strings)  end
    if t.prometheus_string_pool then _collect("prometheus", t.prometheus_string_pool.strings) end
    if t.lunr_string_pool       then _collect("lunr",       t.lunr_string_pool.strings)       end

    -- Captured global writes: walk both the sandbox env and _G, but skip
    -- baseline keys and function/table values (we only care about scalars
    -- for threat hunting).
    local function _scan_env(src, src_label)
        if not src then return end
        for k, v in _iter_pairs(src) do
            if j(k) == "string"
                    and not (_last_baseline and _last_baseline[k])
                    and j(v) == "string" then
                sources[#sources + 1] = { kind = "global:" .. src_label .. ":" .. k, value = v }
            end
        end
    end
    _scan_env(_last_env_table, "env")
    -- _G scan can be very large; opt-out via config if needed.
    if _cfg("THREAT_SCAN_GLOBAL_TABLE", true) ~= false then
        _scan_env(eC, "_G")
    end

    -- Property-store values (Instance:SetAttribute / sethiddenproperty).
    if t.property_store then
        for _, props in _iter_pairs(t.property_store) do
            if j(props) == "table" then
                for k, v in _iter_pairs(props) do
                    if j(v) == "string" then
                        sources[#sources + 1] = {
                            kind = "property:" .. m(k),
                            value = v,
                        }
                    end
                end
            end
        end
    end

    -- Hook-call args may contain juicy URLs.
    if t.hook_calls then
        for _, h in _iter_ipairs(t.hook_calls) do
            if j(h.args) == "table" then
                for _, av in _iter_ipairs(h.args) do
                    if j(av) == "string" then
                        sources[#sources + 1] = { kind = "hook_arg", value = av }
                    end
                end
            end
        end
    end

    -- Remote-call args.
    if t.call_graph then
        for _, c in _iter_ipairs(t.call_graph) do
            if j(c.args) == "table" then
                for _, av in _iter_ipairs(c.args) do
                    if j(av) == "string" then
                        sources[#sources + 1] = { kind = "remote_arg:" .. m(c.name or "?"), value = av }
                    end
                end
            end
        end
    end

    -- Single-value sources.
    if t.last_http_url and t.last_http_url ~= "" then
        sources[#sources + 1] = { kind = "last_http_url", value = m(t.last_http_url) }
    end

    return sources
end

_register("threat_assessment", {
    title    = "THREAT ASSESSMENT",
    category = "meta",
    gate     = function() return _cfg("DUMP_THREAT_ASSESSMENT", true) ~= false end,
    run      = function()
        local b = _budget("threat_assessment")
        local sources = _walk_string_sources()
        if #sources == 0 then return end

        local fragment_counts = {}
        local class_counts    = {}
        local samples         = {}
        local sample_cap      = _cfg("THREAT_SAMPLE_CAP", 20)
        local total_strings   = 0

        for _, src in ipairs(sources) do
            total_strings = total_strings + 1
            local cn = _classify_name(src.value)
            class_counts[cn] = (class_counts[cn] or 0) + 1
            local frag = _threat_match(src.value)
            if frag then
                fragment_counts[frag] = (fragment_counts[frag] or 0) + 1
                if #samples < sample_cap then
                    samples[#samples + 1] = {
                        kind  = src.kind,
                        frag  = frag,
                        value = src.value,
                    }
                end
            end
        end

        -- Risk scoring: each unique fragment hit scales risk roughly
        -- log-quadratically. Cap at 100.
        local risk = 0
        for _, n in pairs(fragment_counts) do
            risk = risk + math.min(40, 8 + math.floor(math.log(1 + n) * 6))
        end
        if (class_counts.webhook or 0) > 0 then risk = risk + 30 end
        if (class_counts.telegram_bot or 0) > 0 then risk = risk + 20 end
        if (class_counts.discord_token or 0) > 0 then risk = risk + 15 end
        if (class_counts.lua_bytecode or 0) > 0 then risk = risk + 10 end
        if risk > 100 then risk = 100 end

        local verdict
        if     risk >= 80 then verdict = "CRITICAL"
        elseif risk >= 50 then verdict = "HIGH"
        elseif risk >= 25 then verdict = "ELEVATED"
        elseif risk >= 5  then verdict = "LOW"
        else                   verdict = "CLEAN"
        end

        _section_header(b.emit, "THREAT ASSESSMENT",
            string.format("risk score %d/100 [%s] (scanned %d string(s))",
                risk, verdict, total_strings))

        local frag_rows = {{ "fragment", "hits" }}
        local frag_keys = {}
        for k in pairs(fragment_counts) do frag_keys[#frag_keys + 1] = k end
        table.sort(frag_keys, function(a1, b1)
            if fragment_counts[a1] ~= fragment_counts[b1] then
                return fragment_counts[a1] > fragment_counts[b1]
            end
            return a1 < b1
        end)
        for _, k in ipairs(frag_keys) do
            frag_rows[#frag_rows + 1] = { k, m(fragment_counts[k]) }
        end
        if #frag_rows > 1 then
            for line in (_ascii_table(frag_rows) .. "\n"):gmatch("([^\n]+)\n") do
                b.emit(line, true)
            end
        end

        if #samples > 0 then
            b.emit("-- sample indicators (values redacted; only matched fragment shown):", true)
            for _, sm in ipairs(samples) do
                -- We deliberately do NOT echo the full value — the host
                -- process has BLOCKED_OUTPUT_PATTERNS protecting against
                -- leaking webhooks / tokens, and we don't want this section
                -- to bypass that. Show only the matched fragment + a safe
                -- characterisation (length + entropy).
                b.emit(string.format("--   [%s] hit=%q  len=%d  entropy=%.2f  class=%s",
                    sm.kind, sm.frag, #sm.value, _entropy(sm.value),
                    _classify_name(sm.value)), true)
            end
        end
        b.emit("-- =========================================================", true)
    end,
})

-- ---------------------------------------------------------------------------
-- cross_references
-- When the interner is enabled, this section emits a digest of which string
-- ids appear in which sections — invaluable for tracing how a single
-- decoded constant is reused throughout the deobfuscated script.
-- ---------------------------------------------------------------------------

_register("cross_references", {
    title    = "STRING CROSS-REFERENCES",
    category = "meta",
    gate     = function() return _interner_enabled() end,
    run      = function()
        local b = _budget("cross_references")
        local entries = {}
        for value, entry in pairs(_interner.by_value) do
            if entry.id then
                entries[#entries + 1] = {
                    id = entry.id,
                    first_seen = entry.first_seen or entry.section or "?",
                    value = value,
                }
            end
        end
        if #entries == 0 then return end

        table.sort(entries, function(a1, b1)
            return tonumber(a1.id:match("(%d+)") or "0")
                 < tonumber(b1.id:match("(%d+)") or "0")
            end)

        _section_header(b.emit, "STRING CROSS-REFERENCES",
            string.format("%d unique string(s) interned across all pools", #entries))

        for _, e in ipairs(entries) do
            local snippet = e.value
            if #snippet > 60 then snippet = snippet:sub(1, 57) .. "..." end
            b.emit(string.format("-- %-12s  first=%s  %s",
                e.id, e.first_seen, aH(snippet)), true)
        end
        b.emit("-- =========================================================", true)
    end,
})

-- ---------------------------------------------------------------------------
-- timeline
-- Chronological view of the captured events. We don't have real
-- timestamps, but the order of t.script_loads + t.instance_creations +
-- t.call_graph + t.hook_calls is preserved (insertion order). This section
-- merges them into one ordered list with markers so the analyst can read
-- the script's behaviour as a story.
-- ---------------------------------------------------------------------------

_register("timeline", {
    title    = "EVENT TIMELINE",
    category = "meta",
    gate     = function() return _cfg("DUMP_TIMELINE", true) ~= false end,
    run      = function()
        local b = _budget("timeline")

        local events = {}
        local function _push(kind, label, idx)
            events[#events + 1] = { kind = kind, label = label, ord = idx, src = #events + 1 }
        end

        if t.script_loads then
            for i, s in _iter_ipairs(t.script_loads) do
                local desc = s.kind or "load"
                if s.target then desc = desc .. " " .. m(s.target) end
                _push("LOAD",   desc, i)
            end
        end
        if t.instance_creations then
            for i, ic in _iter_ipairs(t.instance_creations) do
                _push("NEW", string.format("Instance.new(%q)", ic.class or "?"), i)
            end
        end
        if t.call_graph then
            for i, c in _iter_ipairs(t.call_graph) do
                _push("REMOTE", string.format("%s:%s", c.type or "?", c.name or "?"), i)
            end
        end
        if t.hook_calls then
            for i, h in _iter_ipairs(t.hook_calls) do
                _push("HOOK", string.format("%s %s", h.kind or "?", h.target or "?"), i)
            end
        end

        if #events == 0 then return end

        -- Stable order: original insertion (src). Already in that order.
        local cap = _cfg("TIMELINE_CAP", 200)
        _section_header(b.emit, "EVENT TIMELINE",
            string.format("%d event(s) captured (showing first %d)",
                #events, math.min(cap, #events)))
        for i = 1, math.min(cap, #events) do
            local e = events[i]
            b.emit(string.format("-- [%5d] %-7s %s", i, e.kind, e.label), true)
        end
        if #events > cap then
            b.emit(string.format("-- ... %d more event(s) suppressed (TIMELINE_CAP)",
                #events - cap), true)
        end
        b.emit("-- =========================================================", true)
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

-- Public wrappers for the v3 sections. They follow the same pattern: a
-- single _public_run call so they cannot abort the post-exec sequence.
function q.dump_property_writes()        _public_run("property_writes")        end
function q.dump_hook_calls()             _public_run("hook_calls")             end
function q.dump_loop_summary()           _public_run("loop_summary")           end
function q.dump_counters()               _public_run("counters")               end
function q.dump_runtime_pointers()       _public_run("runtime_pointers")       end
function q.dump_obfuscator_fingerprint() _public_run("obfuscator_fingerprint") end
function q.dump_threat_assessment()      _public_run("threat_assessment")      end
function q.dump_cross_references()       _public_run("cross_references")       end
function q.dump_timeline()               _public_run("timeline")               end

-- ===========================================================================
-- New public API (additive)
-- ===========================================================================

-- Run every registered section in order. The default sandbox call pattern
-- explicitly invokes the legacy 14, but new callers can use this single
-- entry point so they get any future sections for free.
function q.envlogger_run_all(env_table, baseline_keys)
    _diagnostics.started_at = _safe_clock()
    _public_run("run_summary")
    _public_run("deferred_hooks")
    _public_run("captured_globals", env_table, baseline_keys)
    _public_run("captured_upvalues")
    _public_run("string_constants")
    _public_run("wad_strings")
    _public_run("xor_strings")
    _public_run("k0lrot_strings")
    _public_run("lightcate_strings")
    _public_run("prometheus_strings")
    _public_run("lunr_strings")
    _public_run("remote_summary")
    _public_run("instance_creations")
    _public_run("script_loads")
    _public_run("gc_scan")
    _public_run("property_writes")
    _public_run("hook_calls")
    _public_run("loop_summary")
    _public_run("runtime_pointers")
    _public_run("counters")
    _public_run("obfuscator_fingerprint")
    _public_run("threat_assessment")
    _public_run("cross_references")
    _public_run("timeline")
    _public_run("envlogger_diagnostics")
    _diagnostics.finished_at = _safe_clock()
end

-- Compute a threat score 0..100 without emitting anything. Useful for
-- cat.py to surface a one-line risk verdict before opening the dump.
function q.envlogger_threat_score()
    local sources = _walk_string_sources()
    local fragment_counts, class_counts = {}, {}
    for _, src in ipairs(sources) do
        local cn = _classify_name(src.value)
        class_counts[cn] = (class_counts[cn] or 0) + 1
        local frag = _threat_match(src.value)
        if frag then
            fragment_counts[frag] = (fragment_counts[frag] or 0) + 1
        end
    end
    local risk = 0
    for _, n in pairs(fragment_counts) do
        risk = risk + math.min(40, 8 + math.floor(math.log(1 + n) * 6))
    end
    if (class_counts.webhook or 0) > 0 then risk = risk + 30 end
    if (class_counts.telegram_bot or 0) > 0 then risk = risk + 20 end
    if (class_counts.discord_token or 0) > 0 then risk = risk + 15 end
    if (class_counts.lua_bytecode or 0) > 0 then risk = risk + 10 end
    if risk > 100 then risk = 100 end
    local verdict
    if     risk >= 80 then verdict = "CRITICAL"
    elseif risk >= 50 then verdict = "HIGH"
    elseif risk >= 25 then verdict = "ELEVATED"
    elseif risk >= 5  then verdict = "LOW"
    else                   verdict = "CLEAN"
    end
    return {
        risk = risk,
        verdict = verdict,
        sources_scanned = #sources,
        fragment_counts = fragment_counts,
        class_counts    = class_counts,
    }
end

-- Identify the obfuscator(s) that produced the input, by string-pool size.
function q.envlogger_fingerprint()
    local hits = {}
    for _, fp in ipairs(_POOL_FINGERPRINTS) do
        local n = _pool_size(t[fp.field])
        if n > 0 then
            hits[#hits + 1] = {
                label = fp.label,
                field = fp.field,
                count = n,
                score = math.min(10, math.floor(math.log(1 + n) / math.log(2))),
            }
        end
    end
    table.sort(hits, function(a1, b1) return a1.score > b1.score end)
    return hits
end

-- Public wrapper around the entropy helper — handy for the Discord bot's
-- "is this string suspicious?" follow-ups.
function q.envlogger_string_entropy(s)
    return _entropy(s)
end

-- Classify a single string the same way the envlogger does internally.
function q.envlogger_classify(s)
    return _classify_name(s), _classify(s)
end

-- Pretty-print an arbitrary Lua value with cycle detection. Exposed so
-- cat.py / sandbox helpers can format captures consistently.
function q.envlogger_pretty_print(value, opts)
    return _pp(value, opts)
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
