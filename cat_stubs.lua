-- cat_stubs.lua: Exploit-executor function stubs (sandbox shim).
-- Requires: _CATMIO global with shared state.
local _C   = _CATMIO
local r    = _C.r
local t    = _C.t
local at   = _C.at
local aZ   = _C.aZ
local aE   = _C.aE
local aH   = _C.aH
local bj   = _C.bj
local aW   = _C.aW
local G    = _C.G
local w    = _C.w
local dz   = _C.dz
local j    = _C.j
local m    = _C.m
local g    = _C.g
local k    = _C.k
local l    = _C.l
local D    = _C.D
local E    = _C.E
local a    = _C.a
local B    = _C.B
local v    = _C.v
local F    = _C.F

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

return exploit_funcs, _collect_gc_objects
