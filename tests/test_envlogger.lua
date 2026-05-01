-- tests/test_envlogger.lua
-- ============================================================================
-- Stand-alone self-test for cat_envlogger.lua. Mocks the _CATMIO global so
-- the file can be loaded outside the catmio sandbox, then drives every
-- public q.dump_*() function with synthetic state and asserts the
-- envlogger emits the expected lines.
--
-- Run with any of:
--   lua5.1 tests/test_envlogger.lua
--   lua5.3 tests/test_envlogger.lua
--   luajit tests/test_envlogger.lua
-- ============================================================================

local function _quote(s)
    return string.format("%q", s)
end

local function _build_mock()
    local q = {}
    local r = {
        DUMP_GLOBALS = true,
        DUMP_UPVALUES = true,
        DUMP_ALL_STRINGS = true,
        DUMP_WAD_STRINGS = true,
        EMIT_XOR = true,
        DUMP_DECODED_STRINGS = true,
        DUMP_LIGHTCATE_STRINGS = true,
        DUMP_GC_SCAN = true,
        DUMP_INSTANCE_CREATIONS = true,
        DUMP_SCRIPT_LOADS = true,
        DUMP_REMOTE_SUMMARY = true,
        MAX_UPVALUES_PER_FUNCTION = 200,
        MAX_GC_SCAN_FUNCTIONS = 500,
        MAX_SCRIPT_LOAD_SNIPPET = 80,
        MAX_DEFERRED_HOOKS = 200,
        MAX_LINES_PER_SECTION = 10000,
        ENVLOGGER_RUN_SUMMARY = true,
        ENVLOGGER_INTERN_POOLS = true,
        ENVLOGGER_DIAGNOSTICS = true,
        ENVLOGGER_LABEL_GLOBAL_SOURCE = true,
    }
    local t = {
        output = {},
        indent = 0,
        registry = {},
        string_refs = {},
        wad_string_pool = nil,
        xor_string_pool = nil,
        k0lrot_string_pool = nil,
        lightcate_string_pool = nil,
        prometheus_string_pool = nil,
        lunr_string_pool = nil,
        call_graph = {},
        instance_creations = {},
        script_loads = {},
        deferred_hooks = {},
        limit_reached = false,
        current_size = 0,
        error_count = 0,
        warning_count = 0,
    }

    -- Output emitter — captures every line into t.output.
    local function at(line, _raw)
        if t.limit_reached then return end
        line = tostring(line or "")
        table.insert(t.output, line)
        t.current_size = t.current_size + #line + 1
    end
    local function aA() at("") end
    local function az(s) at(tostring(s or "")) end
    local function aH(s)  return _quote(tostring(s or "")) end
    local function aH_binary(s) return _quote(tostring(s or "")) end
    -- aZ is the value-to-Lua-repr helper. A faithful enough mock for tests.
    local function aZ(v)
        local typ = type(v)
        if typ == "string" then return _quote(v) end
        if typ == "number" or typ == "boolean" then return tostring(v) end
        if typ == "nil" then return "nil" end
        if typ == "table" then return "<table>" end
        if typ == "function" then return "<function>" end
        return "<" .. typ .. ">"
    end
    local function br(fn, args)
        -- run a deferred hook and return the captured output as a list of lines
        local lines = {}
        local unpack_fn = table.unpack or unpack
        local ok, err = pcall(function()
            -- Hooks in the real runtime emit through `at`, but for the
            -- tests we just record whatever the hook returns.
            local ret = fn(unpack_fn(args))
            if type(ret) == "string" then
                table.insert(lines, ret)
            elseif type(ret) == "table" then
                for _, v in ipairs(ret) do
                    table.insert(lines, tostring(v))
                end
            end
        end)
        if not ok then
            table.insert(lines, "-- hook err: " .. tostring(err))
        end
        return lines
    end

    _CATMIO = {
        q = q,
        r = r,
        t = t,
        at = at, az = az, aA = aA, aH = aH, aH_binary = aH_binary, aZ = aZ,
        D = pairs,  E = ipairs,
        j = type,   m = tostring,
        a = debug,  br = br,
        eC = _G,
    }
    return _CATMIO
end

-- ---------------------------------------------------------------------------
-- Test harness
-- ---------------------------------------------------------------------------

local _passed, _failed, _failures = 0, 0, {}

local function _assert(cond, msg)
    if cond then
        _passed = _passed + 1
    else
        _failed = _failed + 1
        table.insert(_failures, msg or "assertion failed")
    end
end

local function _contains(haystack, needle)
    for _, line in ipairs(haystack) do
        if line:find(needle, 1, true) then return true end
    end
    return false
end

local function _count(haystack, needle)
    local n = 0
    for _, line in ipairs(haystack) do
        if line:find(needle, 1, true) then n = n + 1 end
    end
    return n
end

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

local function _load_envlogger()
    local mock = _build_mock()
    -- Load the real envlogger source against the mock.
    local f = assert(loadfile("cat_envlogger.lua"))
    f()
    return mock
end

local function test_smoke_loadfile()
    local m = _load_envlogger()
    _assert(type(m.q.dump_captured_globals) == "function", "dump_captured_globals defined")
    _assert(type(m.q.dump_captured_upvalues) == "function", "dump_captured_upvalues defined")
    _assert(type(m.q.dump_string_constants) == "function", "dump_string_constants defined")
    _assert(type(m.q.dump_wad_strings) == "function", "dump_wad_strings defined")
    _assert(type(m.q.dump_xor_strings) == "function", "dump_xor_strings defined")
    _assert(type(m.q.dump_k0lrot_strings) == "function", "dump_k0lrot_strings defined")
    _assert(type(m.q.dump_lightcate_strings) == "function", "dump_lightcate_strings defined")
    _assert(type(m.q.dump_prometheus_strings) == "function", "dump_prometheus_strings defined")
    _assert(type(m.q.dump_lunr_strings) == "function", "dump_lunr_strings defined")
    _assert(type(m.q.dump_remote_summary) == "function", "dump_remote_summary defined")
    _assert(type(m.q.dump_instance_creations) == "function", "dump_instance_creations defined")
    _assert(type(m.q.dump_script_loads) == "function", "dump_script_loads defined")
    _assert(type(m.q.dump_gc_scan) == "function", "dump_gc_scan defined")
    _assert(type(m.q.run_deferred_hooks) == "function", "run_deferred_hooks defined")
    -- New API
    _assert(type(m.q.envlogger_run_all) == "function", "envlogger_run_all defined")
    _assert(type(m.q.envlogger_stats) == "function", "envlogger_stats defined")
    _assert(type(m.q.envlogger_sections) == "function", "envlogger_sections defined")
    _assert(type(m.q.envlogger_reset) == "function", "envlogger_reset defined")
end

local function test_captured_globals()
    local m = _load_envlogger()
    local env = { foo = "bar", baz = 42, ["end"] = "reserved", ["123bad"] = "x" }
    m.q.dump_captured_globals(env, {})

    _assert(_contains(m.t.output, "foo = "), "captured globals emits foo")
    _assert(_contains(m.t.output, "baz = "), "captured globals emits baz")
    _assert(not _contains(m.t.output, "end ="),
        "captured globals refuses Lua reserved word as identifier")
    _assert(not _contains(m.t.output, "123bad ="),
        "captured globals refuses non-identifier keys")
end

local function test_captured_globals_baseline_filter()
    local m = _load_envlogger()
    local env = { newkey = 1, oldkey = 2 }
    m.q.dump_captured_globals(env, { oldkey = true })

    _assert(_contains(m.t.output, "newkey = "), "emits new key")
    _assert(not _contains(m.t.output, "oldkey = "), "filters baseline key")
end

local function test_string_constants_dedup()
    local m = _load_envlogger()
    table.insert(m.t.string_refs, { value = "https://example.com/a" })
    table.insert(m.t.string_refs, { value = "https://example.com/a" })  -- dup
    table.insert(m.t.string_refs, { value = "https://discord.com/api/webhooks/123/abc" })
    table.insert(m.t.string_refs, { value = "rbxassetid://12345" })
    m.q.dump_string_constants()

    _assert(_count(m.t.output, "https://example.com/a") <= 2,
        "dedup keeps each value at most twice (literal + maybe ref)")
    _assert(_contains(m.t.output, "_webhook_"), "discord webhook gets _webhook_ prefix")
    _assert(_contains(m.t.output, "_url_"),     "plain url gets _url_ prefix")
    _assert(_contains(m.t.output, "_asset_"),   "rbxassetid:// gets _asset_ prefix")
end

local function test_remote_summary_sorted_by_count()
    local m = _load_envlogger()
    for i = 1, 5 do
        table.insert(m.t.call_graph, { type = "Remote", name = "Frequent" })
    end
    table.insert(m.t.call_graph, { type = "Remote", name = "Rare" })
    m.q.dump_remote_summary()

    -- Frequent must appear before Rare in the emitted output.
    local fi, ri
    for i, line in ipairs(m.t.output) do
        if line:find("Frequent", 1, true) then fi = fi or i end
        if line:find("Rare",     1, true) then ri = ri or i end
    end
    _assert(fi and ri and fi < ri, "remote_summary sorts by call count desc")
    _assert(_contains(m.t.output, "Total: 2 unique remote(s), 6 call(s)"),
        "remote_summary emits totals line")
end

local function test_instance_creations_grouping()
    local m = _load_envlogger()
    table.insert(m.t.instance_creations, { class = "Part" })
    table.insert(m.t.instance_creations, { class = "Part" })
    table.insert(m.t.instance_creations, { class = "Part" })
    table.insert(m.t.instance_creations, { class = "Decal" })
    m.q.dump_instance_creations()

    _assert(_contains(m.t.output, 'Instance.new("Part")  x3'), "groups Part x3")
    _assert(_contains(m.t.output, 'Instance.new("Decal")  x1'), "groups Decal x1")
end

local function test_script_loads()
    local m = _load_envlogger()
    table.insert(m.t.script_loads, { kind = "require", name = "mymod" })
    table.insert(m.t.script_loads, {
        kind = "loadstring", source = "return 1+1", length = 10, status = "ok",
    })
    m.q.dump_script_loads()

    _assert(_contains(m.t.output, "require(mymod)"), "emits require entry")
    _assert(_contains(m.t.output, "loadstring (len=10, status=ok): return 1+1"),
        "emits loadstring entry")
end

local function test_deferred_hooks_are_drained()
    local m = _load_envlogger()
    local seen = 0
    table.insert(m.t.deferred_hooks, {
        fn = function() seen = seen + 1; return "-- hook ran" end,
        args = {},
    })
    m.q.run_deferred_hooks()

    _assert(seen == 1, "hook fn was invoked")
    _assert(#m.t.deferred_hooks == 0, "deferred_hooks list cleared after drain")
end

local function test_pool_sections_handle_missing_pools()
    local m = _load_envlogger()
    -- All pools are nil — every dumper must no-op safely.
    m.q.dump_wad_strings()
    m.q.dump_xor_strings()
    m.q.dump_k0lrot_strings()
    m.q.dump_lightcate_strings()
    m.q.dump_prometheus_strings()
    m.q.dump_lunr_strings()
    _assert(#m.t.output == 0, "no output when all pools are nil")
end

local function test_xor_pool_emission()
    local m = _load_envlogger()
    m.t.xor_string_pool = { strings = { "alpha", "beta", "alpha" } }  -- xor pool is raw strings
    m.q.dump_xor_strings()

    _assert(_contains(m.t.output, "alpha"), "xor pool emits 'alpha'")
    _assert(_contains(m.t.output, "beta"),  "xor pool emits 'beta'")
end

local function test_envlogger_stats_and_sections()
    local m = _load_envlogger()
    table.insert(m.t.string_refs, { value = "https://x.test/y" })
    m.q.dump_string_constants()

    local stats = m.q.envlogger_stats()
    _assert(stats.sections_run >= 1, "stats counts sections_run")
    _assert(stats.lines_emitted >= 1, "stats counts emitted lines")

    local secs = m.q.envlogger_sections()
    _assert(#secs >= 14, "envlogger registers >=14 sections")
end

local function test_envlogger_run_all_runs_summary()
    local m = _load_envlogger()
    m.q.envlogger_run_all({}, {})
    _assert(_contains(m.t.output, "ENVLOGGER RUN SUMMARY"),
        "run_all emits the run-summary banner when ENVLOGGER_RUN_SUMMARY=true")
end

local function test_section_budget_truncation()
    local m = _load_envlogger()
    m.r.MAX_LINES_PER_SECTION = 3
    -- Stuff 10 string refs in; only 3 should land plus a truncation comment.
    for i = 1, 10 do
        table.insert(m.t.string_refs, { value = "v" .. i })
    end
    m.q.dump_string_constants()
    _assert(_contains(m.t.output, "truncated after 3 line(s)"),
        "section budget enforced + truncation announcement emitted")
end

-- ---------------------------------------------------------------------------
-- Run
-- ---------------------------------------------------------------------------

local tests = {
    test_smoke_loadfile,
    test_captured_globals,
    test_captured_globals_baseline_filter,
    test_string_constants_dedup,
    test_remote_summary_sorted_by_count,
    test_instance_creations_grouping,
    test_script_loads,
    test_deferred_hooks_are_drained,
    test_pool_sections_handle_missing_pools,
    test_xor_pool_emission,
    test_envlogger_stats_and_sections,
    test_envlogger_run_all_runs_summary,
    test_section_budget_truncation,
}

local _names = {
    "test_smoke_loadfile",
    "test_captured_globals",
    "test_captured_globals_baseline_filter",
    "test_string_constants_dedup",
    "test_remote_summary_sorted_by_count",
    "test_instance_creations_grouping",
    "test_script_loads",
    "test_deferred_hooks_are_drained",
    "test_pool_sections_handle_missing_pools",
    "test_xor_pool_emission",
    "test_envlogger_stats_and_sections",
    "test_envlogger_run_all_runs_summary",
    "test_section_budget_truncation",
}

for i, fn in ipairs(tests) do
    local before_failed = _failed
    local ok, err = pcall(fn)
    if not ok then
        _failed = _failed + 1
        table.insert(_failures, _names[i] .. ": test crashed: " .. tostring(err))
    elseif _failed > before_failed then
        table.insert(_failures, "(in " .. _names[i] .. ")")
    end
end

print(string.format("envlogger tests: %d passed / %d failed", _passed, _failed))
for _, f in ipairs(_failures) do print("  FAIL: " .. f) end
os.exit(_failed == 0 and 0 or 1)
