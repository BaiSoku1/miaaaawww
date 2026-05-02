-- cat_sandbox.lua: Sandbox execution environment and main dump entry points.
-- Requires: _CATMIO global with all shared state including deobf functions.
local _C               = _CATMIO
local q                = _C.q
local r                = _C.r
local t                = _C.t
local at               = _C.at
local az               = _C.az
local aA               = _C.aA
local aB               = _C.aB
local aZ               = _C.aZ
local aE               = _C.aE
local aH               = _C.aH
local B                = _C.B
local e                = _C.native_load
local g                = _C.g
local h                = _C.h
local i                = _C.i
local m                = _C.m
local j                = _C.j
local a                = _C.a
local b                = _C.b
local p                = _C.p
local o                = _C.o
local D                = _C.D
local E                = _C.E
local I                = _C.I
local _reduce_locals   = _C.reduce_locals
local _native_setfenv  = _C._native_setfenv
local bit_bxor         = _C.bit_bxor
local bj               = _C.bj
local G                = _C.G
local _collect_gc_objects = _C.collect_gc_objects
local wad_extract_strings             = _C.wad_extract_strings
local xor_extract_strings             = _C.xor_extract_strings
local generic_wrapper_extract_strings = _C.generic_wrapper_extract_strings
local lightcate_extract_strings       = _C.lightcate_extract_strings
local prometheus_extract_strings      = _C.prometheus_extract_strings
local lunr_extract_strings            = _C.lunr_extract_strings
local eC               = _C.eC

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
    -- Lunr v1.0.7 static string extraction.
    -- Detects the Lunr header, extracts the base64 string table and the
    -- decode block, executes them in isolation to recover all decoded strings.
    local lunr_strs, lunr_total, lunr_var = lunr_extract_strings(al)
    if lunr_strs and #lunr_strs > 0 then
        B(string.format("[Dumper] Lunr v1.0.7 detected (var=%s) -- %d/%d strings decoded",
            lunr_var or "?", #lunr_strs, lunr_total or 0))
        t.lunr_string_pool = { strings = lunr_strs, var_name = lunr_var }
    else
        t.lunr_string_pool = nil
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
    rawset(eR, "getfenv", function(lvl)
        -- getfenv(0) returns global env; getfenv(function) returns eR; numeric levels
        -- above the real call-stack depth must raise an error (checked by anti-cheat).
        if lvl == nil or lvl == 0 then return eR end
        if type(lvl) == "function" then return eR end
        local n = tonumber(lvl) or 1
        if n > 100 then
            error("bad argument #1 to 'getfenv' (invalid level)", 2)
        end
        return eR
    end)
    rawset(eR, "getgenv", function() return eR end)
    -- setfenv: allow rebinding Lua closures; refuse to rebind C functions (e.g. print)
    rawset(eR, "setfenv", function(f, env)
        if type(f) == "number" then
            -- level-based setfenv (Lua 5.1 style) – just return f
            return f
        end
        if type(f) ~= "function" then
            error("bad argument #1 to 'setfenv' (number or function expected)", 2)
        end
        -- Detect C functions: debug.getinfo returns what=="C" for them
        local ok, info = pcall(debug.getinfo, f, "S")
        if ok and info and info.what == "C" then
            error("cannot set environment of a C function", 2)
        end
        -- Attempt upvalue rebind (_ENV)
        if _native_setfenv then
            pcall(_native_setfenv, f, env)
        else
            local i = 1
            while true do
                local n = debug.getupvalue(f, i)
                if not n then break end
                if n == "_ENV" then
                    pcall(debug.setupvalue, f, i, env)
                    break
                end
                i = i + 1
            end
        end
        return f
    end)
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
    -- table with freeze/unfreeze; freeze installs a __newindex guard so writes error
    do
        local _frozen = setmetatable({}, {__mode = "k"})
        local _table_ext = setmetatable({}, {__index = table})
        _table_ext.freeze = function(t_)
            if type(t_) == "table" then
                _frozen[t_] = true
                local mt = getmetatable(t_)
                if not mt then
                    mt = {}
                    pcall(setmetatable, t_, mt)
                end
                if mt then
                    mt.__newindex = mt.__newindex or function()
                        error("attempt to modify a frozen table", 2)
                    end
                end
            end
            return t_
        end
        _table_ext.isfrozen = function(t_) return _frozen[t_] == true end
        rawset(eR, "table", _table_ext)
    end
    -- math override: expose all standard functions plus make tostring() on any math
    -- function return a "native" string so checks like
    --   `not tostring(getfenv().math.floor):find("native")` pass.
    do
        local _math_ext = setmetatable({}, {__index = math})
        -- Wrap each math function with a proxy that tostrings as "function: [native code]"
        for _k, _v in pairs(math) do
            if type(_v) == "function" then
                local _wrapped = _v  -- keep original behavior
                _math_ext[_k] = setmetatable({}, {
                    __call = function(_, ...) return _wrapped(...) end,
                    __tostring = function() return "function: [native code]" end,
                    __newindex = function(t__, k__, v__) _wrapped = v__ end,
                })
            end
        end
        rawset(eR, "math", _math_ext)
    end
    -- os with advancing clock for timing checks
    do
        local _os_ext = setmetatable({}, {__index = _G.os})
        _os_ext.clock = _G.os.clock  -- inherits the advancing stub defined globally
        rawset(eR, "os", _os_ext)
    end
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
            _C.set_executing(true)
            R()
        end,
        function(ds)
            _C.set_executing(false)
            return tostring(ds)
        end
    )
    _C.set_executing(false)
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
    q.dump_lunr_strings()
    q.dump_remote_summary()
    q.dump_instance_creations()
    q.dump_script_loads()
    q.dump_gc_scan()
    -- Envlogger v3 supplemental sections (each guarded by its own config flag
    -- so deployments that prefer the legacy output can disable them).
    if q.dump_property_writes        then q.dump_property_writes()        end
    if q.dump_hook_calls             then q.dump_hook_calls()             end
    if q.dump_loop_summary           then q.dump_loop_summary()           end
    if q.dump_runtime_pointers       then q.dump_runtime_pointers()       end
    if q.dump_counters               then q.dump_counters()               end
    if q.dump_obfuscator_fingerprint then q.dump_obfuscator_fingerprint() end
    if q.dump_threat_assessment      then q.dump_threat_assessment()      end
    if q.dump_cross_references       then q.dump_cross_references()       end
    if q.dump_timeline               then q.dump_timeline()               end
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
            _C.set_executing(true)
            R()
        end,
        function(ds)
            _C.set_executing(false)
            return tostring(ds)
        end
    )
    _C.set_executing(false)
    b()
    q.run_deferred_hooks()
    q.dump_captured_upvalues()
    q.dump_string_constants()
    q.dump_wad_strings()
    q.dump_xor_strings()
    q.dump_k0lrot_strings()
    q.dump_lightcate_strings()
    q.dump_prometheus_strings()
    q.dump_lunr_strings()
    q.dump_remote_summary()
    q.dump_instance_creations()
    q.dump_script_loads()
    q.dump_gc_scan()
    -- Envlogger v3 supplemental sections (see q.dump_file for rationale).
    if q.dump_property_writes        then q.dump_property_writes()        end
    if q.dump_hook_calls             then q.dump_hook_calls()             end
    if q.dump_loop_summary           then q.dump_loop_summary()           end
    if q.dump_runtime_pointers       then q.dump_runtime_pointers()       end
    if q.dump_counters               then q.dump_counters()               end
    if q.dump_obfuscator_fingerprint then q.dump_obfuscator_fingerprint() end
    if q.dump_threat_assessment      then q.dump_threat_assessment()      end
    if q.dump_cross_references       then q.dump_cross_references()       end
    if q.dump_timeline               then q.dump_timeline()               end
    if eO then
        return q.save(eO)
    end
    return true, aB()
end
if arg and arg[1] == "--server" then
    -- Persistent worker mode. Reads line-based commands from stdin and
    -- processes one dump per command without re-parsing the (large) bundle
    -- between jobs. This is the fast path used by cat.py's worker pool.
    --
    -- Protocol (one command per line, fields separated by tabs):
    --   request:  DUMP\t<input_path>\t<output_path>\n
    --   response: OK\t<lines>\t<remotes>\t<loops>\n
    --             ERR\t<single-line message>\n
    --   request:  PING\n  -> response: PONG\n
    --   request:  QUIT\n  -> exit cleanly
    --
    -- Protocol responses are written to stdout with a fixed prefix
    -- ("READY", "PONG", "OK\t...", "ERR\t...") so the parent process can
    -- safely filter out the dumper's own status banners ("[Dumper] ...",
    -- "[LUA_LOAD_FAIL] ...") that share the same stream. Note: we
    -- deliberately do NOT redirect _G.print here because the dumper's
    -- sandbox installs its own print interceptor to capture script output
    -- into the dump, and replacing _G.print would break that capture.
    local _stdin  = o.stdin
    local _stdout = o.stdout
    _stdout:write("READY\n")
    _stdout:flush()
    while true do
        local line = _stdin:read("*l")
        if not line then break end
        if line == "QUIT" then
            break
        elseif line == "PING" then
            _stdout:write("PONG\n")
            _stdout:flush()
        elseif line:sub(1, 5) == "DUMP\t" then
            local rest = line:sub(6)
            local sep  = rest:find("\t", 1, true)
            local in_p, out_p
            if sep then
                in_p  = rest:sub(1, sep - 1)
                out_p = rest:sub(sep + 1)
            else
                in_p, out_p = rest, nil
            end
            -- Use xpcall so a crash in the deobfuscator does not kill the
            -- worker; we catch the error, surface it, and stay alive for
            -- the next request.
            local ok, ev_or_err = h(function()
                if not q.dump_file(in_p, out_p) then
                    error("dump_file returned false")
                end
                return q.get_stats()
            end, d)
            if ok and type(ev_or_err) == "table" then
                _stdout:write(string.format(
                    "OK\t%d\t%d\t%d\n",
                    ev_or_err.total_lines or 0,
                    ev_or_err.remote_calls or 0,
                    ev_or_err.loops or 0
                ))
            else
                local em = m(ev_or_err or "unknown error")
                em = em:gsub("[\r\n]+", " ")
                _stdout:write("ERR\t" .. em .. "\n")
            end
            _stdout:flush()
            -- Free per-job allocations promptly so long-lived workers don't
            -- accumulate arena fragmentation across hundreds of dumps.
            collectgarbage("collect")
        else
            _stdout:write("ERR\tunknown command\n")
            _stdout:flush()
        end
    end
elseif arg and arg[1] then
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
