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
        -- v3 tracking state
        property_store = {},
        hook_calls = {},
        loop_line_counts = {},
        loop_detected_lines = {},
        gc_objects = {},
        last_http_url = nil,
        namecall_method = nil,
        last_error = nil,
        exec_start_time = 0,
        instance_count = 0,
        tween_count = 0,
        connection_count = 0,
        drawing_count = 0,
        task_count = 0,
        coroutine_count = 0,
        table_count = 0,
        branch_counter = 0,
        depth_peak = 0,
        hook_depth = 0,
        callback_depth = 0,
        lar_counter = 0,
        proxy_id = 0,
        obfuscation_score = 0,
        deobf_attempts = 0,
        emit_count = 0,
        loop_counter = 0,
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
-- v3 section tests
-- ---------------------------------------------------------------------------

local function test_property_writes_section()
    local m = _load_envlogger()
    -- Synthetic "Instance" object — just a table the registry can stringify.
    local part = {}
    m.t.registry[part] = "Workspace.Part"
    m.t.property_store[part] = { Anchored = true, Size = "v3" }
    m.q.dump_property_writes()

    _assert(_contains(m.t.output, "INSTANCE PROPERTY STORE"),
        "property_writes emits the section header")
    _assert(_contains(m.t.output, "Workspace.Part"),
        "property_writes uses registry label for instance")
    _assert(_contains(m.t.output, ".Anchored = true"),
        "property_writes emits each captured property")
end

local function test_property_writes_no_op_when_empty()
    local m = _load_envlogger()
    m.q.dump_property_writes()
    _assert(not _contains(m.t.output, "INSTANCE PROPERTY STORE"),
        "property_writes is silent when t.property_store is empty")
end

local function test_hook_calls_section()
    local m = _load_envlogger()
    table.insert(m.t.hook_calls, { target = "print", kind = "hookfunction" })
    table.insert(m.t.hook_calls, { target = "print", kind = "call" })
    table.insert(m.t.hook_calls, { target = "print", kind = "call" })
    table.insert(m.t.hook_calls, { target = "warn",  kind = "hookfunction" })
    m.q.dump_hook_calls()

    _assert(_contains(m.t.output, "HOOK CALL TRACKER"),
        "hook_calls emits section header")
    _assert(_contains(m.t.output, "4 hook event(s)"),
        "hook_calls counts total events")
    _assert(_contains(m.t.output, "print"),
        "hook_calls emits target name")
    _assert(_contains(m.t.output, "hookfunction=1"),
        "hook_calls aggregates kinds per target")
    _assert(_contains(m.t.output, "call=2"),
        "hook_calls aggregates call count per target")
end

local function test_loop_summary_section()
    local m = _load_envlogger()
    m.t.loop_line_counts["script:42"] = 100
    m.t.loop_line_counts["script:43"] = 5
    m.t.loop_detected_lines["script:42"] = true
    m.q.dump_loop_summary()

    _assert(_contains(m.t.output, "HOT-LINE LOOP SUMMARY"),
        "loop_summary emits section header")
    _assert(_contains(m.t.output, "script:42"),
        "loop_summary emits the hottest line")
    _assert(_contains(m.t.output, "[HOT]"),
        "loop_summary marks detected lines as [HOT]")
end

local function test_counters_section_skips_zero()
    local m = _load_envlogger()
    m.t.instance_count = 7
    m.t.tween_count    = 3
    -- Other counters stay at 0; should be suppressed.
    m.q.dump_counters()

    _assert(_contains(m.t.output, "RUNTIME COUNTERS"),
        "counters emits section header")
    _assert(_contains(m.t.output, "instance_count"),
        "counters emits non-zero counter")
    _assert(_contains(m.t.output, "tween_count"),
        "counters emits second non-zero counter")
    _assert(not _contains(m.t.output, "drawing_count"),
        "counters omits zero-valued counters")
end

local function test_runtime_pointers_section()
    local m = _load_envlogger()
    m.t.last_http_url   = "https://example.com/exfil"
    m.t.namecall_method = "FireServer"
    m.q.dump_runtime_pointers()

    _assert(_contains(m.t.output, "RUNTIME POINTERS"),
        "runtime_pointers emits section header")
    _assert(_contains(m.t.output, "last_http_url"),
        "runtime_pointers emits last_http_url")
    _assert(_contains(m.t.output, "namecall_method"),
        "runtime_pointers emits namecall_method")
end

local function test_obfuscator_fingerprint_section()
    local m = _load_envlogger()
    m.t.wad_string_pool = { strings = { "a", "b", "c", "d" }, total = 4, lookup = {} }
    m.t.xor_string_pool = { strings = { "e", "f" } }
    m.q.dump_obfuscator_fingerprint()

    _assert(_contains(m.t.output, "OBFUSCATOR FINGERPRINT"),
        "obfuscator_fingerprint emits section header")
    _assert(_contains(m.t.output, "WAD"),
        "obfuscator_fingerprint emits WAD label")
    _assert(_contains(m.t.output, "XOR-stream"),
        "obfuscator_fingerprint emits XOR label")
end

local function test_threat_assessment_detects_webhook()
    local m = _load_envlogger()
    -- Drive captured_globals first so threat_assessment has env_table reference.
    local env = {
        exfil_url = "https://discord.com/api/webhooks/1234/foobar",
        normal    = "hello",
    }
    m.q.dump_captured_globals(env, {})
    m.q.dump_threat_assessment()

    _assert(_contains(m.t.output, "THREAT ASSESSMENT"),
        "threat_assessment emits section header")
    _assert(_contains(m.t.output, "/api/webhooks/"),
        "threat_assessment lists matched fragment")
    -- Verdict line must NOT be CLEAN when webhook is present.
    _assert(not _contains(m.t.output, "[CLEAN]"),
        "threat_assessment is NOT clean when webhook is present")
end

local function test_threat_assessment_clean_when_no_threats()
    local m = _load_envlogger()
    m.q.dump_captured_globals({ a = "hello", b = "world" }, {})
    m.q.dump_threat_assessment()
    -- Either no section emitted (no sources) OR section reports CLEAN.
    if _contains(m.t.output, "THREAT ASSESSMENT") then
        _assert(_contains(m.t.output, "[CLEAN]"),
            "threat_assessment reports [CLEAN] verdict")
    else
        _assert(true, "threat_assessment skipped (no string sources)")
    end
end

local function test_envlogger_threat_score_api()
    local m = _load_envlogger()
    m.q.dump_captured_globals({
        exfil = "https://discord.com/api/webhooks/abc",
    }, {})
    local res = m.q.envlogger_threat_score()
    _assert(type(res) == "table", "threat_score returns a table")
    _assert(type(res.risk) == "number", "threat_score.risk is a number")
    _assert(res.risk > 0, "threat_score.risk > 0 when webhook present")
    _assert(res.verdict ~= "CLEAN", "threat_score.verdict not CLEAN when webhook present")
end

local function test_envlogger_classify_api()
    local m = _load_envlogger()
    local n1, p1 = m.q.envlogger_classify("https://example.com/abc")
    _assert(n1 == "url_https" or n1 == "url",
        "url is classified as url* (got " .. tostring(n1) .. ")")
    _assert(p1 == "_url", "url prefix is _url")
    local n2, p2 = m.q.envlogger_classify("rbxassetid://12345")
    _assert(n2 == "roblox_uri", "rbxassetid is roblox_uri")
    _assert(p2 == "_asset", "rbxassetid prefix is _asset")
end

local function test_envlogger_pretty_print_api()
    local m = _load_envlogger()
    local s = m.q.envlogger_pretty_print({ a = 1, b = "hi", nested = { 1, 2, 3 } })
    _assert(type(s) == "string", "pretty_print returns a string")
    _assert(s:find("a", 1, true) ~= nil, "pretty_print includes key 'a'")
    -- Cycle detection.
    local cyc = {}
    cyc.self = cyc
    local s2 = m.q.envlogger_pretty_print(cyc)
    _assert(s2:find("cycle", 1, true) ~= nil, "pretty_print marks cycles")
end

local function test_envlogger_string_entropy_api()
    local m = _load_envlogger()
    local low  = m.q.envlogger_string_entropy("aaaaaaaa")
    local high = m.q.envlogger_string_entropy("abcdefghijklmnopqrstuvwxyz0123456789")
    _assert(low < high, "entropy of repeated bytes < entropy of varied bytes")
end

local function test_timeline_section()
    local m = _load_envlogger()
    table.insert(m.t.script_loads, { kind = "loadstring", source = "x", length = 1, status = "ok" })
    table.insert(m.t.instance_creations, { class = "Part" })
    table.insert(m.t.call_graph, { type = "Remote", name = "Fire" })
    table.insert(m.t.hook_calls, { target = "print", kind = "hookfunction" })
    m.q.dump_timeline()

    _assert(_contains(m.t.output, "EVENT TIMELINE"),
        "timeline emits section header")
    _assert(_contains(m.t.output, "LOAD"),
        "timeline emits LOAD events")
    _assert(_contains(m.t.output, "NEW"),
        "timeline emits NEW events")
    _assert(_contains(m.t.output, "REMOTE"),
        "timeline emits REMOTE events")
    _assert(_contains(m.t.output, "HOOK"),
        "timeline emits HOOK events")
end

local function test_envlogger_fingerprint_api()
    local m = _load_envlogger()
    m.t.wad_string_pool = { strings = { "a", "b", "c" }, total = 3, lookup = {} }
    local hits = m.q.envlogger_fingerprint()
    _assert(type(hits) == "table", "fingerprint returns table")
    _assert(#hits >= 1, "fingerprint identifies at least one obfuscator when WAD pool present")
    _assert(hits[1].label == "WAD",
        "fingerprint primary suspect is WAD when only WAD pool populated")
end

local function test_v3_public_api_present()
    local m = _load_envlogger()
    _assert(type(m.q.dump_property_writes)        == "function", "dump_property_writes defined")
    _assert(type(m.q.dump_hook_calls)             == "function", "dump_hook_calls defined")
    _assert(type(m.q.dump_loop_summary)           == "function", "dump_loop_summary defined")
    _assert(type(m.q.dump_counters)               == "function", "dump_counters defined")
    _assert(type(m.q.dump_runtime_pointers)       == "function", "dump_runtime_pointers defined")
    _assert(type(m.q.dump_obfuscator_fingerprint) == "function", "dump_obfuscator_fingerprint defined")
    _assert(type(m.q.dump_threat_assessment)      == "function", "dump_threat_assessment defined")
    _assert(type(m.q.dump_cross_references)       == "function", "dump_cross_references defined")
    _assert(type(m.q.dump_timeline)               == "function", "dump_timeline defined")
    _assert(type(m.q.envlogger_threat_score)      == "function", "envlogger_threat_score defined")
    _assert(type(m.q.envlogger_fingerprint)       == "function", "envlogger_fingerprint defined")
    _assert(type(m.q.envlogger_string_entropy)    == "function", "envlogger_string_entropy defined")
    _assert(type(m.q.envlogger_classify)          == "function", "envlogger_classify defined")
    _assert(type(m.q.envlogger_pretty_print)      == "function", "envlogger_pretty_print defined")
end

local function test_run_does_not_throw_on_corrupted_t()
    -- _public_run must absorb any internal exception. We simulate this by
    -- corrupting t.string_refs to a non-table value before running the
    -- string_constants section.
    local m = _load_envlogger()
    m.t.string_refs = "this is not a table"
    local ok = pcall(m.q.dump_string_constants)
    _assert(ok, "_public_run swallows internal error from string_constants")
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
    -- v3
    test_property_writes_section,
    test_property_writes_no_op_when_empty,
    test_hook_calls_section,
    test_loop_summary_section,
    test_counters_section_skips_zero,
    test_runtime_pointers_section,
    test_obfuscator_fingerprint_section,
    test_threat_assessment_detects_webhook,
    test_threat_assessment_clean_when_no_threats,
    test_envlogger_threat_score_api,
    test_envlogger_classify_api,
    test_envlogger_pretty_print_api,
    test_envlogger_string_entropy_api,
    test_timeline_section,
    test_envlogger_fingerprint_api,
    test_v3_public_api_present,
    test_run_does_not_throw_on_corrupted_t,
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
    "test_property_writes_section",
    "test_property_writes_no_op_when_empty",
    "test_hook_calls_section",
    "test_loop_summary_section",
    "test_counters_section_skips_zero",
    "test_runtime_pointers_section",
    "test_obfuscator_fingerprint_section",
    "test_threat_assessment_detects_webhook",
    "test_threat_assessment_clean_when_no_threats",
    "test_envlogger_threat_score_api",
    "test_envlogger_classify_api",
    "test_envlogger_pretty_print_api",
    "test_envlogger_string_entropy_api",
    "test_timeline_section",
    "test_envlogger_fingerprint_api",
    "test_v3_public_api_present",
    "test_run_does_not_throw_on_corrupted_t",
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
