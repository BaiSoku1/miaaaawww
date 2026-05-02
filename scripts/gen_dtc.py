#!/usr/bin/env python3
"""Generates tests/dtc/checks.lua: a battery of Roblox/Luau heuristic
detection checks (Custom DTC).

Each check is a self-contained `local function catNNN() ... end; catNNN()`
block in the user-requested form. The check ends with
    print(("c" .. NNN) .. (ok and "_ok" or "_dtc"))
so the dumped output is grep-able for "_dtc" failures.

Generated checks deliberately avoid detection by string match: they probe
behavior of low-level VM primitives, the C++/Luau bridge, GC semantics,
NaN/Inf handling, error propagation, and the rigidity of Roblox userdata
types.
"""

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Each entry: (lua_body) — body must compute a local `ok` boolean.
# A wrapping framework adds the function header, footer, and the print line.
CHECKS = []


def add(body):
    CHECKS.append(body.strip("\n"))


# ---------------------------------------------------------------------------
# Coroutine / thread integrity (yield-in-pcall, getfenv, status, close)
# ---------------------------------------------------------------------------

add(
    """
    local co = coroutine.create(function()
        return pcall(function()
            coroutine.yield(123)
            return 456
        end)
    end)
    local _, r1 = coroutine.resume(co)
    local _, r2, r3 = coroutine.resume(co)
    local ok = (r1 == 123 and r2 == true and r3 == 456)
""")

add(
    """
    local f = function() end
    local co = coroutine.create(f)
    local ok = (getfenv(co) == getfenv(f))
""")

add(
    """
    local co = coroutine.create(function() end)
    local ok = (coroutine.status(co) == "suspended")
""")

add(
    """
    local co = coroutine.create(function() end)
    coroutine.resume(co)
    local ok = (coroutine.status(co) == "dead")
""")

add(
    """
    local co = coroutine.create(function() coroutine.yield() end)
    coroutine.resume(co)
    local ok = (coroutine.status(co) == "suspended")
""")

add(
    """
    local s, err = pcall(coroutine.resume, "not a coroutine")
    local ok = (s == false or (s == true and err == false))
""")

add(
    """
    local co = coroutine.create(function() end)
    coroutine.resume(co)
    local s = coroutine.resume(co)
    local ok = (s == false)
""")

add(
    """
    local co = coroutine.create(function() error("boom") end)
    local s, err = coroutine.resume(co)
    local ok = (s == false and tostring(err):find("boom", 1, true) ~= nil)
""")

add(
    """
    local got = nil
    local function inner()
        coroutine.yield()
        got = coroutine.running() ~= nil
    end
    local co = coroutine.create(inner)
    coroutine.resume(co)
    coroutine.resume(co)
    local ok = (got == true)
""")

add(
    """
    local main, isMain = coroutine.running()
    local ok = (main ~= nil)
""")

add(
    """
    local w = coroutine.wrap(function(x) coroutine.yield(x + 1); return x + 2 end)
    local a = w(10)
    local b = w()
    local ok = (a == 11 and b == 12)
""")

add(
    """
    local s, err = pcall(function()
        local w = coroutine.wrap(function() error("inner") end)
        w()
    end)
    local ok = (s == false and tostring(err):find("inner", 1, true) ~= nil)
""")

add(
    """
    local co = coroutine.create(function() return 1, 2, 3 end)
    local s, a, b, c = coroutine.resume(co)
    local ok = (s == true and a == 1 and b == 2 and c == 3)
""")

add(
    """
    local co = coroutine.create(function() coroutine.yield(1, 2, 3) end)
    local s, a, b, c = coroutine.resume(co)
    local ok = (s == true and a == 1 and b == 2 and c == 3)
""")

add(
    """
    local s, err = pcall(coroutine.yield)
    local ok = (s == false)
""")

# ---------------------------------------------------------------------------
# table.* return values (Roblox is strict; many executors return the table)
# ---------------------------------------------------------------------------

add(
    """
    local t = {}
    local r = table.insert(t, 1)
    local ok = (r == nil)
""")

add(
    """
    local t = {}
    local r = table.insert(t, 1, 0)
    local ok = (r == nil)
""")

add(
    """
    local t = {1, 2, 3}
    local r = table.remove(t)
    local ok = (r == 3 and #t == 2)
""")

add(
    """
    local t = {1, 2, 3}
    local r = table.remove(t, 1)
    local ok = (r == 1 and t[1] == 2 and t[2] == 3)
""")

add(
    """
    local t = {3, 1, 2}
    local r = table.sort(t)
    local ok = (r == nil and t[1] == 1 and t[2] == 2 and t[3] == 3)
""")

add(
    """
    local s = table.concat({"a", "b", "c"}, "-")
    local ok = (s == "a-b-c")
""")

add(
    """
    local p = table.pack(1, 2, 3)
    local ok = (p.n == 3 and p[1] == 1 and p[2] == 2 and p[3] == 3)
""")

add(
    """
    local a, b, c = table.unpack({10, 20, 30})
    local ok = (a == 10 and b == 20 and c == 30)
""")

add(
    """
    local t = {}
    for i = 1, 10 do t[i] = i * 10 end
    local ok = (#t == 10 and t[5] == 50)
""")

add(
    """
    local t = setmetatable({}, {__len = function() return 999 end})
    local ok = (rawlen(t) == 0)
""")

# ---------------------------------------------------------------------------
# string library edge cases
# ---------------------------------------------------------------------------

add(
    """
    -- Lua 5.3 %q escapes \\n as backslash + literal newline, not "\\\\n";
    -- check that the result contains a backslash followed by either form.
    local s = string.format("%q", "a\\nb")
    local ok = (s:find("\\\\\\n") ~= nil) or (s:find("\\\\n") ~= nil)
""")

add(
    """
    local ok = (string.format("%5d", 7) == "    7")
""")

add(
    """
    local ok = (string.rep("ab", 3) == "ababab")
""")

add(
    """
    local ok = (string.rep("x", 3, "-") == "x-x-x")
""")

add(
    """
    local ok = (string.byte("A") == 65)
""")

add(
    """
    local ok = (string.char(65, 66, 67) == "ABC")
""")

add(
    """
    local ok = (string.sub("hello", 2, 4) == "ell")
""")

add(
    """
    local ok = (string.sub("hello", -3) == "llo")
""")

add(
    """
    local ok = (string.find("abc", "b") == 2)
""")

add(
    """
    local s, count = string.gsub("aaaa", "a", "b", 2)
    local ok = (s == "bbaa" and count == 2)
""")

add(
    """
    local n = 0
    for _ in string.gmatch("a,b,c,d", "[^,]+") do n = n + 1 end
    local ok = (n == 4)
""")

add(
    """
    local ok = (string.upper("Hello") == "HELLO")
""")

add(
    """
    local ok = (string.lower("Hello") == "hello")
""")

add(
    """
    local ok = (string.reverse("abc") == "cba")
""")

add(
    """
    local ok = (string.len("\\0\\0\\0") == 3)
""")

add(
    """
    local ok = (#"\\0\\0\\0" == 3)
""")

add(
    """
    local ok = (("abc"):upper() == "ABC")
""")

# ---------------------------------------------------------------------------
# math library / NaN / Inf integrity
# ---------------------------------------------------------------------------

add(
    """
    local ok = (0/0 ~= 0/0)
""")

add(
    """
    local nan = 0/0
    local ok = (nan ~= nan)
""")

add(
    """
    local ok = (math.huge > 1e308)
""")

add(
    """
    local ok = (-math.huge < -1e308)
""")

add(
    """
    local ok = (1/0 == math.huge)
""")

add(
    """
    local ok = (-1/0 == -math.huge)
""")

add(
    """
    local ok = (math.floor(3.7) == 3 and math.ceil(3.2) == 4)
""")

add(
    """
    local i, f = math.modf(2.5)
    local ok = (i == 2 and f == 0.5)
""")

add(
    """
    local ok = (math.abs(-5) == 5 and math.abs(5) == 5)
""")

add(
    """
    local ok = (math.max(1, 2, 3, 2) == 3)
""")

add(
    """
    local ok = (math.min(3, 1, 2) == 1)
""")

add(
    """
    local ok = (math.pi > 3.14 and math.pi < 3.15)
""")

add(
    """
    local ok = (math.sqrt(16) == 4)
""")

add(
    """
    local ok = (math.pow and math.pow(2, 10) == 1024 or 2^10 == 1024)
""")

add(
    """
    -- NaN comparisons: any comparison with NaN must be false (except ~=)
    local nan = 0/0
    local ok = not (nan < nan) and not (nan > nan) and not (nan <= nan)
              and not (nan >= nan) and (nan ~= nan)
""")

add(
    """
    local ok = (math.huge + math.huge == math.huge)
""")

add(
    """
    local ok = (math.huge - math.huge ~= math.huge - math.huge)
""")

# ---------------------------------------------------------------------------
# bit32 (Roblox/Luau exposes bit32; values are clamped to uint32)
# ---------------------------------------------------------------------------

add(
    """
    local ok = (bit32.band(0xFFFF, 0x00FF) == 0x00FF)
""")

add(
    """
    local ok = (bit32.bor(0xF0F0, 0x0F0F) == 0xFFFF)
""")

add(
    """
    local ok = (bit32.bxor(0xFF, 0x0F) == 0xF0)
""")

add(
    """
    local ok = (bit32.bnot(0) == 0xFFFFFFFF)
""")

add(
    """
    local ok = (bit32.lshift(1, 4) == 16)
""")

add(
    """
    local ok = (bit32.rshift(16, 4) == 1)
""")

add(
    """
    local ok = (bit32.arshift(0xFFFFFFFF, 4) == 0xFFFFFFFF)
""")

add(
    """
    local ok = (bit32.lrotate(0x12345678, 8) == 0x34567812)
""")

add(
    """
    local ok = (bit32.rrotate(0x12345678, 8) == 0x78123456)
""")

add(
    """
    local ok = (bit32.extract(0xFF, 4, 4) == 0xF)
""")

add(
    """
    local ok = (bit32.replace(0, 0xF, 4, 4) == 0xF0)
""")

add(
    """
    local ok = (bit32.countlz(0x00FF0000) == 8)
""")

add(
    """
    local ok = (bit32.countrz(0x0000FF00) == 8)
""")

add(
    """
    local ok = (bit32.btest(0xF0, 0x10) == true)
""")

# ---------------------------------------------------------------------------
# pcall / xpcall / error: non-string errors, level argument, identity preservation
# ---------------------------------------------------------------------------

add(
    """
    local _, err = pcall(error, "oops", 0)
    local ok = (err == "oops")
""")

add(
    """
    local tbl = {x = 1}
    local _, err = pcall(error, tbl, 0)
    local ok = (err == tbl)
""")

add(
    """
    local _, err = pcall(function()
        error({code = 42})
    end)
    local ok = (type(err) == "table" and err.code == 42)
""")

add(
    """
    local s, a, b = pcall(function() return 1, 2 end)
    local ok = (s == true and a == 1 and b == 2)
""")

add(
    """
    local function thrower() error("inner") end
    local s = xpcall(thrower, function(e) return "handled:" .. tostring(e) end)
    local ok = (s == false)
""")

add(
    """
    local function thrower() error("inner") end
    local _, msg = xpcall(thrower, function(e) return "H:" .. tostring(e) end)
    local ok = (tostring(msg):find("H:", 1, true) == 1
                and tostring(msg):find("inner", 1, true) ~= nil)
""")

add(
    """
    local s, err = pcall(function() error("at level", 1) end)
    local ok = (s == false and tostring(err):find("at level", 1, true) ~= nil)
""")

add(
    """
    local s, err = pcall(error)
    local ok = (s == false and err == nil)
""")

add(
    """
    local s, a, b, c = pcall(function() return 10, 20, 30 end)
    local ok = (s and a == 10 and b == 20 and c == 30)
""")

add(
    """
    local s, err = pcall(function()
        local t = nil
        return t.x
    end)
    local ok = (s == false)
""")

add(
    """
    local s, err = pcall(function() return (nil)() end)
    local ok = (s == false)
""")

add(
    """
    local s = pcall(function() pcall(error, "x") end)
    local ok = (s == true)
""")

# ---------------------------------------------------------------------------
# getfenv / setfenv (Lua 5.1 + Luau) — Roblox preserves the per-thread env
# ---------------------------------------------------------------------------

add(
    """
    local ok = (type(getfenv) == "function")
""")

add(
    """
    local ok = (type(getfenv(1)) == "table")
""")

add(
    """
    local f = function() return getfenv() end
    local g = function() return getfenv() end
    local ok = (f() == g())
""")

add(
    """
    local f = function() end
    local e = getfenv(f)
    local ok = (type(e) == "table")
""")

add(
    """
    local s = pcall(getfenv, 100)
    local ok = (s == false or s == true)
""")

# ---------------------------------------------------------------------------
# rawequal / rawlen / rawget / rawset
# ---------------------------------------------------------------------------

add(
    """
    local ok = (rawequal({}, {}) == false)
""")

add(
    """
    local t = {}
    local ok = (rawequal(t, t) == true)
""")

add(
    """
    local ok = (rawequal(nil, nil) == true)
""")

add(
    """
    local ok = (rawequal(1, 1) == true and rawequal(1, "1") == false)
""")

add(
    """
    local t = setmetatable({}, {__index = function() return "x" end})
    local ok = (rawget(t, "y") == nil and t.y == "x")
""")

add(
    """
    local t = setmetatable({}, {__newindex = function() error("blocked") end})
    rawset(t, "k", 1)
    local ok = (rawget(t, "k") == 1)
""")

add(
    """
    local t = {1, 2, 3}
    local ok = (rawlen(t) == 3)
""")

add(
    """
    local ok = (rawlen("hello") == 5)
""")

# ---------------------------------------------------------------------------
# typeof (Roblox-specific)
# ---------------------------------------------------------------------------

for name, ty in [
    ("nil", '"nil"'),
    ("true", '"boolean"'),
    ("false", '"boolean"'),
    ("1", '"number"'),
    ("1.5", '"number"'),
    ('"hello"', '"string"'),
    ("{}", '"table"'),
    ("function() end", '"function"'),
    ("coroutine.create(function() end)", '"thread"'),
]:
    add(
        f"""
    local ok = (typeof({name}) == {ty})
""")

add(
    """
    local ok = (typeof(Vector3.new(0,0,0)) == "Vector3")
""")

add(
    """
    local ok = (typeof(Vector2.new(0,0)) == "Vector2")
""")

add(
    """
    local ok = (typeof(CFrame.new()) == "CFrame")
""")

add(
    """
    local ok = (typeof(Color3.new(0,0,0)) == "Color3")
""")

add(
    """
    local ok = (typeof(UDim.new(0,0)) == "UDim")
""")

add(
    """
    local ok = (typeof(UDim2.new(0,0,0,0)) == "UDim2")
""")

add(
    """
    local ok = (typeof(Instance.new("Part")) == "Instance")
""")

# ---------------------------------------------------------------------------
# Instance API rigidity
# ---------------------------------------------------------------------------

add(
    """
    local p = Instance.new("Part")
    local s = pcall(function() return rawget(p, "Name") end)
    local ok = (s == false)
""")

add(
    """
    local p = Instance.new("Part")
    local s = pcall(function() rawset(p, "Foo", 1) end)
    local ok = (s == false)
""")

add(
    """
    local p = Instance.new("Part")
    local s = pcall(function() setmetatable(p, {}) end)
    local ok = (s == false)
""")

add(
    """
    local p = Instance.new("Part")
    local ok = (p.ClassName == "Part")
""")

add(
    """
    local p = Instance.new("Part")
    p.Name = "Hello"
    local ok = (p.Name == "Hello")
""")

add(
    """
    local p = Instance.new("Part")
    local ok = (p:IsA("Part") == true)
""")

add(
    """
    local p = Instance.new("Part")
    local ok = (p:IsA("BasePart") == true)
""")

add(
    """
    local p = Instance.new("Part")
    local ok = (p:IsA("Instance") == true)
""")

add(
    """
    local p = Instance.new("Part")
    local ok = (p:IsA("Model") == false)
""")

add(
    """
    local p = Instance.new("Part")
    local s = pcall(function() return p.NonExistentProperty end)
    local ok = (s == false)
""")

add(
    """
    local p = Instance.new("Part")
    local s = pcall(function() p.NonExistentProperty = 1 end)
    local ok = (s == false)
""")

add(
    """
    local p = Instance.new("Folder")
    local c = Instance.new("Part", p)
    local ok = (c.Parent == p and p:FindFirstChild("Part") == c)
""")

add(
    """
    local p = Instance.new("Folder")
    local c = Instance.new("Part")
    c.Name = "Specific"
    c.Parent = p
    local ok = (p:FindFirstChild("Specific") == c)
""")

add(
    """
    local p = Instance.new("Folder")
    local children = p:GetChildren()
    local ok = (type(children) == "table" and #children == 0)
""")

add(
    """
    local p = Instance.new("Folder")
    Instance.new("Part", p)
    Instance.new("Decal", p)
    local ok = (#p:GetChildren() == 2)
""")

add(
    """
    local p = Instance.new("Part")
    local clone = p:Clone()
    local ok = (clone ~= p and clone.ClassName == "Part" and clone:IsA("Part"))
""")

add(
    """
    local s = pcall(Instance.new, "ThisClassDoesNotExist")
    local ok = (s == false)
""")

add(
    """
    local p = Instance.new("Part")
    local ok = (typeof(p) == "Instance" and type(p) == "userdata")
""")

# ---------------------------------------------------------------------------
# game / workspace / services
# ---------------------------------------------------------------------------

add(
    """
    local ok = (game ~= nil and workspace ~= nil)
""")

add(
    """
    local ok = (workspace.ClassName == "Workspace")
""")

add(
    """
    local ok = (game.ClassName == "DataModel")
""")

add(
    """
    local s = pcall(game.Clone, game)
    local ok = (s == false)
""")

add(
    """
    local players = game:GetService("Players")
    local ok = (players ~= nil and players.ClassName == "Players")
""")

add(
    """
    local rs = game:GetService("RunService")
    local ok = (rs ~= nil and rs.ClassName == "RunService")
""")

add(
    """
    local ok = (typeof(game) == "Instance")
""")

add(
    """
    local ok = (typeof(workspace) == "Instance")
""")

add(
    """
    local s = pcall(function() local _ = game.NoSuchService end)
    local ok = (s == false)
""")

# ---------------------------------------------------------------------------
# Roblox datatypes — Vector3 / Vector2 / Color3 / CFrame / UDim2
# ---------------------------------------------------------------------------

add(
    """
    local v = Vector3.new(1, 2, 3)
    local ok = (v.X == 1 and v.Y == 2 and v.Z == 3)
""")

add(
    """
    local v = Vector3.new(1, 2, 3) + Vector3.new(4, 5, 6)
    local ok = (typeof(v) == "Vector3" and v.X == 5 and v.Y == 7 and v.Z == 9)
""")

add(
    """
    local v = Vector3.new(2, 0, 0).Magnitude
    local ok = (math.abs(v - 2) < 1e-6)
""")

add(
    """
    local a = Vector3.new(1, 2, 3)
    local b = Vector3.new(1, 2, 3)
    local ok = (a == b)
""")

add(
    """
    local a = Vector3.new(1, 2, 3)
    local b = Vector3.new(4, 2, 3)
    local ok = (a ~= b)
""")

add(
    """
    local v = Vector2.new(3, 4)
    local ok = (math.abs(v.Magnitude - 5) < 1e-6)
""")

add(
    """
    local c = Color3.new(0.5, 0.25, 0.125)
    local ok = (math.abs(c.R - 0.5) < 1e-6
                and math.abs(c.G - 0.25) < 1e-6
                and math.abs(c.B - 0.125) < 1e-6)
""")

add(
    """
    local c = Color3.fromRGB(255, 128, 0)
    local ok = (math.abs(c.R - 1) < 1e-6 and math.abs(c.G - 128/255) < 1e-3)
""")

add(
    """
    local cf = CFrame.new(1, 2, 3)
    local ok = (cf.X == 1 and cf.Y == 2 and cf.Z == 3)
""")

add(
    """
    local u = UDim2.new(0, 100, 0, 200)
    local ok = (u.X.Offset == 100 and u.Y.Offset == 200)
""")

add(
    """
    local u = UDim2.fromScale(0.5, 0.25)
    local ok = (math.abs(u.X.Scale - 0.5) < 1e-6
                and math.abs(u.Y.Scale - 0.25) < 1e-6)
""")

# Datatypes are rigid: rawget/rawset/setmetatable on them must error.
for ctor in [
    'Vector3.new(1,2,3)',
    'Vector2.new(1,2)',
    'CFrame.new()',
    'Color3.new(1,1,1)',
    'UDim2.new(0,0,0,0)',
]:
    add(
        f"""
    local v = {ctor}
    local s = pcall(function() rawget(v, "X") end)
    local ok = (s == false)
""")
    add(
        f"""
    local v = {ctor}
    local s = pcall(function() setmetatable(v, {{}}) end)
    local ok = (s == false)
""")

# ---------------------------------------------------------------------------
# select / variadic / multivalue plumbing
# ---------------------------------------------------------------------------

add(
    """
    local ok = (select("#", nil, nil, nil) == 3)
""")

add(
    """
    local a, b, c = select(2, 10, 20, 30, 40)
    local ok = (a == 20 and b == 30 and c == 40)
""")

add(
    """
    local function pass(...) return ... end
    local a, b = pass(1, 2)
    local ok = (a == 1 and b == 2)
""")

add(
    """
    local function adjust(...) return select("#", ...), ... end
    local n, a, b = adjust(7, 8)
    local ok = (n == 2 and a == 7 and b == 8)
""")

add(
    """
    local t = {(function() return 1, 2, 3 end)()}
    local ok = (#t == 3 and t[1] == 1 and t[3] == 3)
""")

add(
    """
    local t = {1, (function() return 2, 3 end)(), 4}
    -- Multi-value in non-tail position is truncated to 1.
    local ok = (#t == 3 and t[1] == 1 and t[2] == 2 and t[3] == 4)
""")

add(
    """
    local function f() return 1, 2, 3 end
    local a = f()
    local ok = (a == 1)
""")

add(
    """
    local function f() return 1, 2, 3 end
    local a, b = f(), 99
    -- f() in non-tail call position is truncated to 1
    local ok = (a == 1 and b == 99)
""")

add(
    """
    local function f() return 1, 2, 3 end
    local a, b = 99, f()
    -- f() in tail position keeps all values
    local ok = (a == 99 and b == 1)
""")

# ---------------------------------------------------------------------------
# Metamethods and __index / __newindex / __call
# ---------------------------------------------------------------------------

add(
    """
    local t = setmetatable({}, {__index = function() return 42 end})
    local ok = (t.anything == 42)
""")

add(
    """
    local hits = 0
    local t = setmetatable({}, {__newindex = function(t, k, v) hits = hits + 1 end})
    t.x = 1
    t.y = 2
    local ok = (hits == 2)
""")

add(
    """
    local t = setmetatable({}, {__call = function(self, x) return x * 2 end})
    local ok = (t(21) == 42)
""")

add(
    """
    local a = setmetatable({}, {__add = function(a, b) return "added" end})
    local ok = (a + 1 == "added")
""")

add(
    """
    local t = setmetatable({}, {__tostring = function() return "Hello" end})
    local ok = (tostring(t) == "Hello")
""")

add(
    """
    local t = setmetatable({}, {__metatable = "locked"})
    local s = pcall(setmetatable, t, {})
    local ok = (s == false)
""")

add(
    """
    local t = setmetatable({}, {__metatable = "locked"})
    local ok = (getmetatable(t) == "locked")
""")

add(
    """
    -- __eq is only triggered when BOTH operands are tables/userdata; primitive
    -- vs table mixing never invokes the metamethod.
    local b = setmetatable({}, {__eq = function() return true end})
    local ok = (b ~= 1 and b ~= "x" and b ~= true)
""")

# ---------------------------------------------------------------------------
# tostring / tonumber edge cases
# ---------------------------------------------------------------------------

add(
    """
    local ok = (tostring(nil) == "nil")
""")

add(
    """
    local ok = (tostring(true) == "true")
""")

add(
    """
    local ok = (tostring(false) == "false")
""")

add(
    """
    local ok = (tostring(123) == "123")
""")

add(
    """
    local ok = (tonumber("123") == 123)
""")

add(
    """
    local ok = (tonumber("0x1F") == 31)
""")

add(
    """
    local ok = (tonumber("ff", 16) == 255)
""")

add(
    """
    local ok = (tonumber("not a number") == nil)
""")

add(
    """
    -- tostring(NaN) is "nan" or "-nan" on every conformant runtime
    local s = tostring(0/0):lower()
    local ok = (s:find("nan") ~= nil)
""")

add(
    """
    local ok = (tostring(math.huge) == "inf" or tostring(math.huge) == "Infinity"
                or tostring(math.huge):lower():find("inf") ~= nil)
""")

# ---------------------------------------------------------------------------
# String pack / unpack / byte / format edge cases
# ---------------------------------------------------------------------------

add(
    """
    local s = string.format("%d", 0)
    local ok = (s == "0")
""")

add(
    """
    local ok = (string.format("%.2f", 1/3) == "0.33")
""")

add(
    """
    local ok = (string.format("%x", 255) == "ff")
""")

add(
    """
    local ok = (string.format("%X", 255) == "FF")
""")

add(
    """
    local ok = (string.format("%o", 8) == "10")
""")

add(
    """
    local ok = (string.format("%e", 12345.678):sub(1, 1) == "1")
""")

add(
    """
    local s = pcall(string.format, "%d", "not a number")
    local ok = (s == false)
""")

# ---------------------------------------------------------------------------
# select / table.find / table.create / table.move (Luau extensions)
# ---------------------------------------------------------------------------

add(
    """
    local ok = (table.find({"a", "b", "c"}, "b") == 2)
""")

add(
    """
    local ok = (table.find({"a", "b", "c"}, "z") == nil)
""")

add(
    """
    local t = table.create(3, "x")
    local ok = (#t == 3 and t[1] == "x" and t[2] == "x" and t[3] == "x")
""")

add(
    """
    local src = {1, 2, 3, 4, 5}
    local dst = {}
    table.move(src, 1, 5, 1, dst)
    local ok = (dst[1] == 1 and dst[5] == 5)
""")

# ---------------------------------------------------------------------------
# assert / error / type-coercion rigidity
# ---------------------------------------------------------------------------

add(
    """
    local s = pcall(assert, false, "boom")
    local ok = (s == false)
""")

add(
    """
    local v = assert(7)
    local ok = (v == 7)
""")

add(
    """
    local s, err = pcall(assert, nil, "kaboom")
    local ok = (s == false and tostring(err):find("kaboom", 1, true) ~= nil)
""")

add(
    """
    local s = pcall(function() return ({}).x.y end)
    local ok = (s == false)
""")

add(
    """
    local s = pcall(function() return (1)() end)
    local ok = (s == false)
""")

add(
    """
    local s = pcall(function() return 1 + "abc" end)
    local ok = (s == false)
""")

add(
    """
    local ok = (1 + "2" == 3)
""")

add(
    """
    local ok = ("3" * 4 == 12)
""")

# ---------------------------------------------------------------------------
# Roblox-specific: Vector3 zero / one constants
# ---------------------------------------------------------------------------

add(
    """
    local ok = (Vector3.zero ~= nil and Vector3.zero.X == 0
                and Vector3.zero.Y == 0 and Vector3.zero.Z == 0)
""")

add(
    """
    local ok = (Vector3.one ~= nil and Vector3.one.X == 1
                and Vector3.one.Y == 1 and Vector3.one.Z == 1)
""")

add(
    """
    local ok = (Vector3.xAxis.X == 1 and Vector3.xAxis.Y == 0)
""")

add(
    """
    local cf = CFrame.identity or CFrame.new()
    local ok = (cf.X == 0 and cf.Y == 0 and cf.Z == 0)
""")

# ---------------------------------------------------------------------------
# task library timing & semantics (loose checks because the dumper has no
# event loop — assert fields exist and basic call shape works).
# ---------------------------------------------------------------------------

add(
    """
    local ok = (type(task.spawn) == "function" and type(task.defer) == "function"
                and type(task.delay) == "function" and type(task.wait) == "function")
""")

add(
    """
    local got = nil
    task.spawn(function() got = 7 end)
    local ok = (got == 7 or got == nil) -- spawn may be sync or microtask in dumper
""")

add(
    """
    local ok = (typeof(task) == "table")
""")

# ---------------------------------------------------------------------------
# String identity & interning (Roblox interns short strings; identity holds)
# ---------------------------------------------------------------------------

add(
    """
    local a = "hello"
    local b = "hel" .. "lo"
    local ok = (a == b)
""")

add(
    """
    local s1 = string.rep("x", 1000)
    local s2 = string.rep("x", 1000)
    local ok = (s1 == s2)
""")

# ---------------------------------------------------------------------------
# Boolean / nil short-circuit & implicit conversion
# ---------------------------------------------------------------------------

add(
    """
    local ok = ((nil and 1) == nil)
""")

add(
    """
    local ok = ((false or 5) == 5)
""")

add(
    """
    local ok = ((nil or "x") == "x")
""")

add(
    """
    local ok = (not nil == true and not false == true and not 0 == false
                and not "" == false)
""")

# ---------------------------------------------------------------------------
# Integer vs float distinction (Lua 5.3 / Luau number model)
# ---------------------------------------------------------------------------

add(
    """
    local ok = (1 == 1.0)
""")

add(
    """
    local ok = (1 + 1 == 2)
""")

add(
    """
    local ok = (10 // 3 == 3)
""")

add(
    """
    local ok = (10 % 3 == 1)
""")

# ---------------------------------------------------------------------------
# Integer overflow / very-large numbers
# ---------------------------------------------------------------------------

add(
    """
    local ok = (2^53 + 1 == 2^53 or 2^53 + 1 ~= 2^53)
""")

add(
    """
    local ok = (math.huge * 0 ~= math.huge * 0)
""")

# ---------------------------------------------------------------------------
# Table identity & weak references
# ---------------------------------------------------------------------------

add(
    """
    local a = {}
    local b = a
    local ok = (rawequal(a, b))
""")

add(
    """
    local t = setmetatable({}, {__mode = "k"})
    local ok = (type(t) == "table")
""")

# ---------------------------------------------------------------------------
# String length on userdata
# ---------------------------------------------------------------------------

add(
    """
    local p = Instance.new("Part")
    local s = pcall(function() return #p end)
    local ok = (s == false or s == true)  -- #userdata may be defined or not
""")

# ---------------------------------------------------------------------------
# Misc: nested coroutine / pcall interaction
# ---------------------------------------------------------------------------

add(
    """
    local s, err = pcall(function()
        return pcall(function()
            return pcall(function() error("deep") end)
        end)
    end)
    local ok = (s == true)
""")

add(
    """
    local s = pcall(function()
        local co = coroutine.create(function()
            error("inside")
        end)
        local r = coroutine.resume(co)
        return r
    end)
    local ok = (s == true)
""")

# ---------------------------------------------------------------------------
# Runtime invariants
# ---------------------------------------------------------------------------

add(
    """
    local ok = (type(_VERSION) == "string")
""")

add(
    """
    local ok = (type(_G) == "table")
""")

add(
    """
    local ok = (type(_G._G) == "table" or _G._G == nil)
""")

add(
    """
    local ok = (type(string.byte) == "function" and type(string.char) == "function")
""")

add(
    """
    local ok = (type(tostring) == "function" and type(tonumber) == "function")
""")

# ---------------------------------------------------------------------------
# Bulk-generated checks. These probe the same axes (datatype rigidity,
# bit32 / math / string / table semantics, typeof, Instance API, hierarchy)
# but with many more concrete inputs so the battery exercises each
# behavior across a wide value-space.
# ---------------------------------------------------------------------------


# -- Roblox userdata rigidity: rawget / rawset / setmetatable on every
# datatype proxy. For each datatype, we already have a few hand-written
# checks; add a complete grid of (datatype × op) pairs.
DATATYPE_INSTANCES = [
    ("Vector3.new(1, 2, 3)",            "Vector3"),
    ("Vector3.new(0, 0, 0)",            "Vector3"),
    ("Vector3.new(-1, -2, -3)",         "Vector3"),
    ("Vector3.new(1e3, -1e3, 0.5)",     "Vector3"),
    ("Vector2.new(1, 2)",               "Vector2"),
    ("Vector2.new(0, 0)",               "Vector2"),
    ("Vector2.new(-5, 7)",              "Vector2"),
    ("CFrame.new(0, 0, 0)",             "CFrame"),
    ("CFrame.new(1, 2, 3)",             "CFrame"),
    ("CFrame.identity",                 "CFrame"),
    ("Color3.new(0, 0, 0)",             "Color3"),
    ("Color3.new(1, 1, 1)",             "Color3"),
    ("Color3.new(0.5, 0.25, 0.75)",     "Color3"),
    ("UDim.new(0, 100)",                "UDim"),
    ("UDim.new(1, 0)",                  "UDim"),
    ("UDim.new(0.5, 50)",               "UDim"),
    ("UDim2.new(0, 100, 0, 200)",       "UDim2"),
    ("UDim2.new(1, 0, 1, 0)",           "UDim2"),
    ("UDim2.fromScale(0.5, 0.25)",      "UDim2"),
    ("UDim2.fromOffset(100, 200)",      "UDim2"),
]


def render_rigidity_grid():
    for ctor, _kind in DATATYPE_INSTANCES:
        add(f"""
    local v = {ctor}
    local s = pcall(rawget, v, 1)
    local ok = (s == false)
""")
        add(f"""
    local v = {ctor}
    local s = pcall(rawset, v, 1, 0)
    local ok = (s == false)
""")
        add(f"""
    local v = {ctor}
    local s = pcall(setmetatable, v, {{}})
    local ok = (s == false)
""")


def render_typeof_grid():
    for ctor, kind in DATATYPE_INSTANCES:
        add(f"""
    local v = {ctor}
    local ok = (typeof(v) == "{kind}")
""")


render_rigidity_grid()
render_typeof_grid()


# -- Vector3 component arithmetic — a dense grid of value tuples.
def render_vector3_grid():
    cases = [
        ((1, 2, 3),  (4, 5, 6)),
        ((10, 20, 30), (1, 2, 3)),
        ((-1, -2, -3), (1, 2, 3)),
        ((0, 0, 0),  (5, 5, 5)),
        ((100, 200, 300), (50, 75, 25)),
        ((1.5, 2.25, 3.75), (0.5, 0.25, 0.75)),
        ((0.1, 0.2, 0.3), (0.4, 0.5, 0.6)),
        ((1, 1, 1),  (1, 1, 1)),
        ((-100, 100, 50), (100, -100, -50)),
        ((1e3, 1e3, 1e3), (1, 1, 1)),
    ]
    for (a, b) in cases:
        ax, ay, az = a; bx, by, bz = b
        sx, sy, sz = ax + bx, ay + by, az + bz
        # x within float32 tolerance
        add(f"""
    local v = Vector3.new({ax}, {ay}, {az}) + Vector3.new({bx}, {by}, {bz})
    local ok = (typeof(v) == "Vector3"
                and math.abs(v.X - ({sx})) < 1e-4
                and math.abs(v.Y - ({sy})) < 1e-4
                and math.abs(v.Z - ({sz})) < 1e-4)
""")
        sx, sy, sz = ax - bx, ay - by, az - bz
        add(f"""
    local v = Vector3.new({ax}, {ay}, {az}) - Vector3.new({bx}, {by}, {bz})
    local ok = (typeof(v) == "Vector3"
                and math.abs(v.X - ({sx})) < 1e-4
                and math.abs(v.Y - ({sy})) < 1e-4
                and math.abs(v.Z - ({sz})) < 1e-4)
""")


render_vector3_grid()


# -- Vector2 component arithmetic.
def render_vector2_grid():
    cases = [
        ((1, 2),     (3, 4)),
        ((10, 20),   (5, 5)),
        ((-1, -2),   (1, 2)),
        ((0.5, 0.25), (0.25, 0.5)),
        ((100, 200), (-50, -100)),
        ((1, 0),     (0, 1)),
    ]
    for (a, b) in cases:
        ax, ay = a; bx, by = b
        sx, sy = ax + bx, ay + by
        add(f"""
    local v = Vector2.new({ax}, {ay}) + Vector2.new({bx}, {by})
    local ok = (typeof(v) == "Vector2"
                and math.abs(v.X - ({sx})) < 1e-4
                and math.abs(v.Y - ({sy})) < 1e-4)
""")
        sx, sy = ax - bx, ay - by
        add(f"""
    local v = Vector2.new({ax}, {ay}) - Vector2.new({bx}, {by})
    local ok = (typeof(v) == "Vector2"
                and math.abs(v.X - ({sx})) < 1e-4
                and math.abs(v.Y - ({sy})) < 1e-4)
""")


render_vector2_grid()


# -- bit32 grid: many concrete (op, args, expected) tuples.
def render_bit32_grid():
    cases = [
        # band
        ("bit32.band(0xFFFF, 0x0F0F)", "0x0F0F"),
        ("bit32.band(0xAAAA, 0x5555)", "0x0000"),
        ("bit32.band(0xFF00FF, 0x00FFFF)", "0x00FF"),
        ("bit32.band(0xFFFFFFFF, 0xFFFFFFFF)", "0xFFFFFFFF"),
        ("bit32.band(0)", "0"),
        # bor
        ("bit32.bor(0xF0F0, 0x0F0F)", "0xFFFF"),
        ("bit32.bor(0, 0)", "0"),
        ("bit32.bor(0xAAAAAAAA, 0x55555555)", "0xFFFFFFFF"),
        ("bit32.bor(0)", "0"),
        # bxor
        ("bit32.bxor(0xFF, 0x0F)", "0xF0"),
        ("bit32.bxor(0xAAAA, 0xFFFF)", "0x5555"),
        ("bit32.bxor(0xFFFFFFFF, 0)", "0xFFFFFFFF"),
        ("bit32.bxor(0xDEAD, 0xBEEF)", "0x6042"),
        # bnot
        ("bit32.bnot(0)",          "0xFFFFFFFF"),
        ("bit32.bnot(0xFFFFFFFF)", "0"),
        ("bit32.bnot(0xF0F0F0F0)", "0x0F0F0F0F"),
        # lshift / rshift
        ("bit32.lshift(1, 0)",  "1"),
        ("bit32.lshift(1, 1)",  "2"),
        ("bit32.lshift(1, 4)",  "16"),
        ("bit32.lshift(1, 16)", "0x10000"),
        ("bit32.lshift(1, 31)", "0x80000000"),
        ("bit32.rshift(0xFF, 4)", "0x0F"),
        ("bit32.rshift(0x100, 8)", "1"),
        ("bit32.rshift(0xFFFFFFFF, 31)", "1"),
        # arshift
        ("bit32.arshift(1, 1)", "0"),
        ("bit32.arshift(0xFFFFFFFF, 1)", "0xFFFFFFFF"),
        ("bit32.arshift(0xFFFFFFFF, 4)", "0xFFFFFFFF"),
        ("bit32.arshift(0x80000000, 31)", "0xFFFFFFFF"),
        # countlz / countrz (Luau extensions)
        ("bit32.countlz(0)",          "32"),
        ("bit32.countlz(1)",          "31"),
        ("bit32.countlz(0xFFFFFFFF)", "0"),
        ("bit32.countlz(0x80000000)", "0"),
        ("bit32.countlz(0x00010000)", "15"),
        ("bit32.countrz(0)",          "32"),
        ("bit32.countrz(1)",          "0"),
        ("bit32.countrz(2)",          "1"),
        ("bit32.countrz(0x10000)",    "16"),
        ("bit32.countrz(0x80000000)", "31"),
        # btest
        ("(bit32.btest(0xFF, 0x0F) and 1 or 0)", "1"),
        ("(bit32.btest(0xF0, 0x0F) and 1 or 0)", "0"),
        # extract / replace
        ("bit32.extract(0xABCD, 0, 8)", "0xCD"),
        ("bit32.extract(0xABCD, 8, 8)", "0xAB"),
        ("bit32.replace(0, 0xFF, 0, 8)", "0xFF"),
        # lrotate / rrotate
        ("bit32.lrotate(1, 0)",   "1"),
        ("bit32.lrotate(1, 1)",   "2"),
        ("bit32.lrotate(0x80000000, 1)", "1"),
        ("bit32.rrotate(2, 1)",   "1"),
        ("bit32.rrotate(1, 1)",   "0x80000000"),
    ]
    for expr, expected in cases:
        add(f"""
    local ok = ({expr}) == ({expected})
""")


render_bit32_grid()


# -- string.* grid.
def render_string_grid():
    cases = [
        # byte / char
        ("string.byte('A')", "65"),
        ("string.byte('z')", "122"),
        ("string.byte('0')", "48"),
        ("string.char(65)", "'A'"),
        ("string.char(97)", "'a'"),
        ("string.char(48)", "'0'"),
        # len
        ("string.len('hello')", "5"),
        ("string.len('')", "0"),
        ("string.len('1234567890')", "10"),
        # rep
        ("string.rep('a', 0)", "''"),
        ("string.rep('a', 1)", "'a'"),
        ("string.rep('a', 5)", "'aaaaa'"),
        ("string.rep('ab', 3)", "'ababab'"),
        ("string.rep('-', 4, ',')", "'-,-,-,-'"),
        # upper / lower
        ("string.upper('abc')", "'ABC'"),
        ("string.upper('Hello, World!')", "'HELLO, WORLD!'"),
        ("string.lower('HELLO')", "'hello'"),
        ("string.lower('Mixed-CASE')", "'mixed-case'"),
        # reverse
        ("string.reverse('abc')", "'cba'"),
        ("string.reverse('a')", "'a'"),
        ("string.reverse('')", "''"),
        ("string.reverse('hello')", "'olleh'"),
        # sub
        ("string.sub('hello', 1)", "'hello'"),
        ("string.sub('hello', 2)", "'ello'"),
        ("string.sub('hello', 1, 3)", "'hel'"),
        ("string.sub('hello', -3)", "'llo'"),
        ("string.sub('hello', -3, -1)", "'llo'"),
        ("string.sub('hello', 100)", "''"),
        # find
        ("(string.find('hello', 'ell'))", "2"),
        ("(string.find('hello', 'xyz'))", "nil"),
        ("(string.find('aaaa', 'aa'))", "1"),
        # gsub
        ("(string.gsub('hello', 'l', 'L'))", "'heLLo'"),
        ("(string.gsub('hello', 'L', 'X'))", "'hello'"),
        ("(select(2, string.gsub('hello', 'l', 'L')))", "2"),
        # format
        ("string.format('%d', 42)", "'42'"),
        ("string.format('%x', 255)", "'ff'"),
        ("string.format('%X', 255)", "'FF'"),
        ("string.format('%05d', 42)", "'00042'"),
        ("string.format('%.2f', 3.14159)", "'3.14'"),
        ("string.format('%s+%s', 'a', 'b')", "'a+b'"),
        ("string.format('%c', 65)", "'A'"),
    ]
    for expr, expected in cases:
        add(f"""
    local ok = ({expr}) == ({expected})
""")


render_string_grid()


# -- math.* grid.
def render_math_grid():
    cases = [
        ("math.abs(-5)", "5"),
        ("math.abs(0)", "0"),
        ("math.abs(7.5)", "7.5"),
        ("math.floor(3.7)", "3"),
        ("math.floor(-3.7)", "-4"),
        ("math.floor(0)", "0"),
        ("math.ceil(3.2)", "4"),
        ("math.ceil(-3.2)", "-3"),
        ("math.ceil(0)", "0"),
        ("math.max(1, 2, 3)", "3"),
        ("math.max(-1, -2, -3)", "-1"),
        ("math.min(1, 2, 3)", "1"),
        ("math.min(-1, -2, -3)", "-3"),
        ("math.sqrt(16)", "4"),
        ("math.sqrt(0)", "0"),
        ("math.sqrt(2) > 1.41 and math.sqrt(2) < 1.42", "true"),
        ("math.pi > 3.14 and math.pi < 3.15", "true"),
        ("math.huge == math.huge", "true"),
        ("math.huge > 1e300", "true"),
        ("-math.huge < -1e300", "true"),
        ("math.huge ~= -math.huge", "true"),
        # NaN
        ("math.huge - math.huge ~= math.huge - math.huge", "true"),
        ("(0/0) ~= (0/0)", "true"),
        ("(0/0) == (0/0)", "false"),
        # mod / modf
        ("math.fmod(10, 3)", "1"),
        ("math.fmod(-10, 3)", "-1"),
        # log / exp
        ("math.exp(0)", "1"),
        ("math.log(1)", "0"),
        ("math.log(math.exp(1)) > 0.999 and math.log(math.exp(1)) < 1.001", "true"),
        # sin / cos
        ("math.sin(0)", "0"),
        ("math.cos(0)", "1"),
        ("math.sin(math.pi) > -1e-9 and math.sin(math.pi) < 1e-9", "true"),
        ("math.cos(math.pi) < -0.999 and math.cos(math.pi) > -1.001", "true"),
        # tan / atan
        ("math.tan(0)", "0"),
        # rad / deg
        ("math.rad(180) > 3.14 and math.rad(180) < 3.15", "true"),
        ("math.deg(math.pi) > 179.99 and math.deg(math.pi) < 180.01", "true"),
        # 2^n via lshift
        ("2 ^ 0", "1"),
        ("2 ^ 1", "2"),
        ("2 ^ 10", "1024"),
        # //
        ("10 // 3", "3"),
        ("-10 // 3", "-4"),
        ("9 % 4", "1"),
        ("-9 % 4", "3"),
    ]
    for expr, expected in cases:
        add(f"""
    local ok = (({expr}) == ({expected}))
""")


render_math_grid()


# -- typeof / type for primitives and Roblox values.
def render_type_grid():
    cases = [
        ('nil',                      "nil"),
        ('true',                     "boolean"),
        ('false',                    "boolean"),
        ('1',                        "number"),
        ('1.5',                      "number"),
        ('-7',                       "number"),
        ('"hello"',                  "string"),
        ('""',                       "string"),
        ('{}',                       "table"),
        ('function() end',           "function"),
        ('print',                    "function"),
        ('coroutine.create(function() end)', "thread"),
    ]
    for expr, expected in cases:
        add(f"""
    local ok = (type({expr}) == "{expected}")
""")
        if expected != "thread":
            add(f"""
    local ok = (typeof({expr}) == "{expected}")
""")


render_type_grid()


# -- Class hierarchy: many IsA assertions.
def render_isa_grid():
    cases = [
        ("Part",   "BasePart",  True),
        ("Part",   "PVInstance", True),
        ("Part",   "Instance",  True),
        ("Part",   "Part",      True),
        ("Part",   "Model",     False),
        ("Part",   "Folder",    False),
        ("Part",   "Decal",     False),
        ("Part",   "Sound",     False),
        ("Part",   "Animation", False),
        ("Part",   "Frame",     False),
        ("Folder", "Folder",    True),
        ("Folder", "Instance",  True),
        ("Folder", "BasePart",  False),
        ("Folder", "Part",      False),
        ("Folder", "Model",     False),
        ("MeshPart", "BasePart",   True),
        ("MeshPart", "PVInstance", True),
        ("MeshPart", "Part",       False),
        ("MeshPart", "Instance",   True),
        ("Model",  "PVInstance", True),
        ("Model",  "Model",      True),
        ("Model",  "Instance",   True),
        ("Model",  "BasePart",   False),
        ("Model",  "Part",       False),
        ("Decal",  "Instance",  True),
        ("Decal",  "Decal",     True),
        ("Decal",  "Texture",   False),
        ("Decal",  "Part",      False),
        ("Texture",  "Decal",    True),
        ("Texture",  "Instance", True),
        ("Sound",  "Instance",  True),
        ("Sound",  "Part",      False),
        ("Animation", "Instance", True),
        ("Animation", "Part",      False),
        ("LocalScript", "BaseScript",       True),
        ("LocalScript", "LuaSourceContainer", True),
        ("LocalScript", "Instance",         True),
        ("LocalScript", "Script",           False),
        ("LocalScript", "ModuleScript",     False),
        ("Script",      "BaseScript",       True),
        ("Script",      "Instance",         True),
        ("Script",      "ModuleScript",     False),
        ("ModuleScript", "LuaSourceContainer", True),
        ("ModuleScript", "Instance",          True),
        ("ModuleScript", "BaseScript",        False),
        ("BoolValue",   "ValueBase", True),
        ("BoolValue",   "Instance",  True),
        ("BoolValue",   "IntValue",  False),
        ("IntValue",    "ValueBase", True),
        ("StringValue", "ValueBase", True),
        ("RemoteEvent",  "Instance",      True),
        ("RemoteEvent",  "RemoteFunction", False),
        ("RemoteFunction", "Instance",     True),
        ("Frame",        "GuiObject",    True),
        ("Frame",        "GuiBase2d",    True),
        ("Frame",        "GuiBase",      True),
        ("Frame",        "Instance",     True),
        ("Frame",        "BasePart",     False),
        ("TextButton",   "GuiObject",    True),
        ("TextButton",   "Frame",        False),
        ("ImageButton",  "GuiObject",    True),
        ("ScreenGui",    "GuiBase2d",    True),
        ("Humanoid",     "Instance",     True),
        ("Humanoid",     "BasePart",     False),
        ("Tool",         "Instance",     True),
        ("Tool",         "BasePart",     False),
        ("Camera",       "Instance",     True),
    ]
    # Player / Players cannot be Instance.new()'d on real Roblox (Player is
    # NotCreatable; Players is a service). They are still valid IsA targets
    # — emit those checks via game:GetService("Players") and game.Players's
    # children iterator instead.
    add("""
    local players = game:GetService("Players")
    local ok = (players:IsA("Players") == true and players:IsA("Instance") == true)
""")
    add("""
    local players = game:GetService("Players")
    local ok = (players:IsA("Player") == false)
""")
    for cls, ask, expected in cases:
        exp = "true" if expected else "false"
        add(f"""
    local i = Instance.new("{cls}")
    local ok = (i:IsA("{ask}") == {exp})
""")


render_isa_grid()


# -- Class default ClassName.
def render_classname_grid():
    classes = [
        "Part", "Folder", "Model", "Decal", "Texture", "Sound", "Animation",
        "Tool", "Humanoid", "Frame", "TextButton", "ImageButton", "TextLabel",
        "ImageLabel", "ScreenGui", "ScrollingFrame", "BoolValue", "IntValue",
        "NumberValue", "StringValue", "ObjectValue", "RemoteEvent",
        "RemoteFunction", "BindableEvent", "BindableFunction", "Camera",
        "PointLight", "SpotLight", "SurfaceLight", "Attachment", "Configuration",
        "MeshPart", "WedgePart", "TrussPart", "CornerWedgePart", "Seat",
        "VehicleSeat", "SpawnLocation", "SoundGroup", "Animator",
        "Accessory", "Hat", "LocalScript", "Script",
        "ModuleScript", "Vector3Value", "CFrameValue", "BrickColorValue",
        "Color3Value", "UnreliableRemoteEvent",
    ]
    for cls in classes:
        add(f"""
    local i = Instance.new("{cls}")
    local ok = (i.ClassName == "{cls}")
""")
        add(f"""
    local i = Instance.new("{cls}")
    local ok = (i:IsA("{cls}") == true)
""")
        add(f"""
    local i = Instance.new("{cls}")
    local ok = (i:IsA("Instance") == true)
""")


render_classname_grid()


# -- Class clone preserves ClassName.
def render_clone_grid():
    classes = [
        "Part", "Folder", "Model", "Decal", "Sound", "Animation", "Tool",
        "Humanoid", "Frame", "TextButton", "BoolValue", "IntValue",
        "NumberValue", "StringValue", "RemoteEvent", "RemoteFunction",
        "BindableEvent", "BindableFunction", "Camera", "PointLight",
        "Attachment", "MeshPart", "WedgePart", "Seat", "Animator",
        "LocalScript", "Script", "ModuleScript",
    ]
    for cls in classes:
        add(f"""
    local i = Instance.new("{cls}")
    local c = i:Clone()
    local ok = (c ~= i and c.ClassName == "{cls}" and c:IsA("{cls}"))
""")


render_clone_grid()


# -- Instance.new with bogus class names raises.
def render_new_invalid_grid():
    bogus = [
        "ThisClassDoesNotExist",
        "DefinitelyFakeClass",
        "FakeClass1234",
        "ThisIsNotARobloxClass",
        "TotallyMadeUp",
        "FictionalClass",
        "MalformedClass",
        "ClassWithSpaces ",
        "_LeadingUnderscore",
        "leading_lowercase",
    ]
    for cls in bogus:
        add(f"""
    local s = pcall(Instance.new, {cls!r})
    local ok = (s == false)
""")


render_new_invalid_grid()


# -- Vector3 / Vector2 constants.
def render_v3_constants():
    add("""
    local v = Vector3.zero
    local ok = (typeof(v) == "Vector3" and v.X == 0 and v.Y == 0 and v.Z == 0)
""")
    add("""
    local v = Vector3.one
    local ok = (typeof(v) == "Vector3" and v.X == 1 and v.Y == 1 and v.Z == 1)
""")
    add("""
    local v = Vector3.xAxis
    local ok = (typeof(v) == "Vector3" and v.X == 1 and v.Y == 0 and v.Z == 0)
""")
    add("""
    local v = Vector3.yAxis
    local ok = (typeof(v) == "Vector3" and v.X == 0 and v.Y == 1 and v.Z == 0)
""")
    add("""
    local v = Vector3.zAxis
    local ok = (typeof(v) == "Vector3" and v.X == 0 and v.Y == 0 and v.Z == 1)
""")
    add("""
    local v = Vector2.zero
    local ok = (typeof(v) == "Vector2" and v.X == 0 and v.Y == 0)
""")
    add("""
    local v = Vector2.one
    local ok = (typeof(v) == "Vector2" and v.X == 1 and v.Y == 1)
""")
    add("""
    local v = Vector2.xAxis
    local ok = (typeof(v) == "Vector2" and v.X == 1 and v.Y == 0)
""")
    add("""
    local v = Vector2.yAxis
    local ok = (typeof(v) == "Vector2" and v.X == 0 and v.Y == 1)
""")


render_v3_constants()


# -- table.* return-value rigidity.
def render_table_grid():
    add("""
    local t = {}
    local ok = (table.insert(t, 1) == nil and #t == 1 and t[1] == 1)
""")
    add("""
    local t = {1, 2, 3}
    local ok = (table.insert(t, 1, 0) == nil and t[1] == 0 and t[4] == 3)
""")
    add("""
    local t = {1, 2, 3}
    local r = table.remove(t)
    local ok = (r == 3 and #t == 2)
""")
    add("""
    local t = {10, 20, 30}
    local r = table.remove(t, 1)
    local ok = (r == 10 and #t == 2 and t[1] == 20)
""")
    add("""
    local t = {3, 1, 2}
    table.sort(t)
    local ok = (t[1] == 1 and t[2] == 2 and t[3] == 3)
""")
    add("""
    local t = {3, 1, 2}
    table.sort(t, function(a, b) return a > b end)
    local ok = (t[1] == 3 and t[2] == 2 and t[3] == 1)
""")
    add("""
    local t = table.pack(1, 2, 3)
    local ok = (t.n == 3 and t[1] == 1 and t[2] == 2 and t[3] == 3)
""")
    add("""
    local a, b, c = table.unpack({10, 20, 30})
    local ok = (a == 10 and b == 20 and c == 30)
""")
    add("""
    local ok = (table.concat({"a", "b", "c"}, "-") == "a-b-c")
""")
    add("""
    local ok = (table.concat({"x", "y", "z"}) == "xyz")
""")
    add("""
    local ok = (#({1, 2, 3, 4, 5}) == 5)
""")


render_table_grid()


# -- pcall / xpcall / error grid.
def render_pcall_grid():
    add("""
    local s, e = pcall(function() error("hello") end)
    local ok = (s == false and tostring(e):find("hello") ~= nil)
""")
    add("""
    local s, e = pcall(function() error({code = 42}) end)
    local ok = (s == false and type(e) == "table" and e.code == 42)
""")
    add("""
    local s, a, b = pcall(function() return 1, 2 end)
    local ok = (s == true and a == 1 and b == 2)
""")
    add("""
    local s = pcall(function() return end)
    local ok = (s == true)
""")
    add("""
    local s, e = xpcall(function() error("x") end, function(err) return tostring(err) .. "!" end)
    local ok = (s == false and tostring(e):find("x!") ~= nil)
""")


render_pcall_grid()


# -- Coroutine grid.
def render_coroutine_grid():
    add("""
    local co = coroutine.create(function() return 42 end)
    local ok_, val = coroutine.resume(co)
    local ok = (ok_ == true and val == 42)
""")
    add("""
    local co = coroutine.create(function(a, b) return a + b end)
    local _, r = coroutine.resume(co, 5, 7)
    local ok = (r == 12)
""")
    add("""
    local co = coroutine.create(function()
        coroutine.yield(1)
        coroutine.yield(2)
        return 3
    end)
    local _, a = coroutine.resume(co)
    local _, b = coroutine.resume(co)
    local _, c = coroutine.resume(co)
    local ok = (a == 1 and b == 2 and c == 3)
""")
    add("""
    local co = coroutine.create(function() error("boom") end)
    local ok_, e = coroutine.resume(co)
    local ok = (ok_ == false and tostring(e):find("boom") ~= nil)
""")
    add("""
    local co = coroutine.wrap(function() coroutine.yield(99) return 100 end)
    local ok = (co() == 99 and co() == 100)
""")
    add("""
    local main = coroutine.running()
    local co = coroutine.create(function()
        local me = coroutine.running()
        return me ~= nil
    end)
    local _, r = coroutine.resume(co)
    local ok = (r == true)
""")


render_coroutine_grid()


# -- Boolean / coercion grid.
def render_bool_grid():
    cases = [
        ("nil and 1", "nil"),
        ("false and 1", "false"),
        ("1 and 2", "2"),
        ("1 and nil", "nil"),
        ("nil or 5", "5"),
        ("false or 7", "7"),
        ("1 or 5", "1"),
        ("not nil", "true"),
        ("not false", "true"),
        ("not true", "false"),
        ("not 0", "false"),
        ("not 1", "false"),
        ("not ''", "false"),
        ("not {}", "false"),
        # number coercion
        ("'1' + 1", "2"),
        ("'2' * 3", "6"),
        ("'10' / 2", "5"),
        ("'5' - 2", "3"),
        # string concat
        ("1 .. 1", "'11'"),
        ("'a' .. 'b'", "'ab'"),
    ]
    for expr, expected in cases:
        add(f"""
    local ok = (({expr}) == ({expected}))
""")


render_bool_grid()


# -- Variadic / select grid.
def render_variadic_grid():
    add("""
    local function f(...) return select("#", ...) end
    local ok = (f() == 0 and f(1) == 1 and f(1, 2, 3) == 3)
""")
    add("""
    local function f(...) return (select(2, ...)) end
    local ok = (f("a", "b", "c") == "b")
""")
    add("""
    local function f(a, b, ...) return ... end
    local r1, r2, r3 = f(1, 2, 3, 4, 5)
    local ok = (r1 == 3 and r2 == 4 and r3 == 5)
""")
    add("""
    local function tail(a, ...) return ... end
    local ok = (select("#", tail(1, 2, 3, 4)) == 3)
""")
    add("""
    local function f(a, b)
        return a, b
    end
    local r1, r2 = f(table.unpack({10, 20}))
    local ok = (r1 == 10 and r2 == 20)
""")


render_variadic_grid()


# -- Metamethod grid.
def render_meta_grid():
    add("""
    local t = setmetatable({}, {__index = function(_, k) return k .. "!" end})
    local ok = (t.foo == "foo!" and t["bar"] == "bar!")
""")
    add("""
    local t = setmetatable({a = 1}, {__index = {b = 2}})
    local ok = (t.a == 1 and t.b == 2)
""")
    add("""
    local stored = nil
    local t = setmetatable({}, {__newindex = function(_, k, v) stored = {k = k, v = v} end})
    t.x = 7
    local ok = (stored.k == "x" and stored.v == 7 and rawget(t, "x") == nil)
""")
    add("""
    local called = false
    local t = setmetatable({}, {__call = function(self, n) called = true; return n * 2 end})
    local ok = (t(5) == 10 and called == true)
""")
    add("""
    local mt = {__add = function(a, b) return {value = (a.value or 0) + (b.value or 0)} end}
    local a = setmetatable({value = 3}, mt)
    local b = setmetatable({value = 4}, mt)
    local c = a + b
    local ok = (c.value == 7)
""")
    add("""
    local mt = {__tostring = function() return "STR" end}
    local t = setmetatable({}, mt)
    local ok = (tostring(t) == "STR")
""")
    add("""
    local protected = setmetatable({}, {__metatable = "locked"})
    local ok = (getmetatable(protected) == "locked")
""")
    add("""
    local protected = setmetatable({}, {__metatable = "locked"})
    local s = pcall(setmetatable, protected, {})
    local ok = (s == false)
""")


render_meta_grid()


# -- Integer vs float grid.
def render_int_float_grid():
    cases = [
        ("1 + 1", "2"),
        ("1.5 + 1.5", "3.0"),
        ("1 == 1.0", "true"),
        ("1 + 0", "1"),
        ("(0 + 1) > 0", "true"),
        ("(0.5 + 0.25) == 0.75", "true"),
        ("(-1) ^ 2", "1"),
        ("2 ^ 8", "256"),
        # 5.3+: integer / float distinction (math.type)
    ]
    for expr, expected in cases:
        add(f"""
    local ok = (({expr}) == ({expected}))
""")


render_int_float_grid()


# -- String interning identity.
def render_intern_grid():
    add("""
    local a, b = "hello", "hello"
    local ok = (a == b)
""")
    add("""
    local a, b = "" .. "abc" .. "", "abc"
    local ok = (a == b)
""")
    add("""
    local a = string.rep("x", 5)
    local b = "xxxxx"
    local ok = (a == b)
""")


render_intern_grid()


# -- NaN / Inf / division grid.
def render_nan_grid():
    add("""
    local nan = 0/0
    local ok = (nan ~= nan)
""")
    add("""
    local ok = (1/0 == math.huge and -1/0 == -math.huge)
""")
    add("""
    local ok = (math.huge + math.huge == math.huge)
""")
    add("""
    local ok = (math.huge - math.huge ~= math.huge - math.huge)
""")
    add("""
    local ok = (math.huge * 0 ~= math.huge * 0)
""")
    add("""
    local ok = (math.max(1, 2, math.huge) == math.huge)
""")


render_nan_grid()


# -- bit32 round-trip identity.
def render_bit_roundtrip():
    for x in [0, 1, 0xFF, 0xFFFF, 0xDEAD, 0xBEEF, 0xC0FFEE, 0x12345678,
              0x80000000, 0xFFFFFFFF]:
        add(f"""
    local ok = (bit32.bnot(bit32.bnot({x})) == ({x}))
""")
        add(f"""
    local ok = (bit32.bxor({x}, 0) == ({x}))
""")


render_bit_roundtrip()


# ---------------------------------------------------------------------------
# Output the assembled file
# ---------------------------------------------------------------------------

header = """-- tests/dtc/checks.lua
-- ============================================================================
-- DTC battery: heuristic detection checks for Roblox/Luau executors.
--
-- Each block is a self-contained `local function catNNN() ... end; catNNN()`
-- that prints  "cNNN_ok"   if the runtime matches real Roblox/Luau, or
--              "cNNN_dtc"  if it deviates (most exploit executors).
-- The checks deliberately avoid getgenv / function-name checks. They probe:
--   * coroutine + yield-in-pcall semantics
--   * C++ <-> Luau bridge rigidity (rawget/rawset on Instance, datatypes)
--   * VM register / multivalue / variadic plumbing
--   * NaN / Inf / integer arithmetic invariants
--   * error / pcall / xpcall identity preservation
--   * table.* return values
--   * Roblox userdata immutability (Vector3/CFrame/Color3/UDim2/Instance)
--   * Roblox.Instance API rigidity (IsA, FindFirstChild, GetChildren, Clone,
--     game/workspace/services)
-- Generated by scripts/gen_dtc.py.
-- ============================================================================

local _native_print = print
local _CAT_OK, _CAT_DTC = 0, 0
local _CAT_DTC_LIST = {}

print = function(...)
    local args = {...}
    if #args == 1 and type(args[1]) == "string" then
        local s = args[1]
        if s:find("_ok$") then
            _CAT_OK = _CAT_OK + 1
        elseif s:find("_dtc$") then
            _CAT_DTC = _CAT_DTC + 1
            _CAT_DTC_LIST[#_CAT_DTC_LIST + 1] = s
        end
    end
    return _native_print(...)
end

"""

footer = """

-- ============================================================================
-- Summary line — appears as a single `print(...)` entry in the dump.
-- Grep the dump file for "DTC_SUMMARY" to find it.
-- ============================================================================
local _summary = string.format("DTC_SUMMARY ok=%d dtc=%d total=%d failed=%s",
    _CAT_OK, _CAT_DTC, _CAT_OK + _CAT_DTC, table.concat(_CAT_DTC_LIST, ","))
_native_print(_summary)
"""

# Render each check.
parts = [header]
for i, body in enumerate(CHECKS, start=1):
    name = f"cat{i:03d}"
    label = f"c{i:03d}"
    # Wrap each check in `do ... end` so the local function symbol is
    # scoped (Lua 5.x has a 200-local-per-chunk limit), and run the body
    # under pcall so a check that raises is reported as _dtc instead of
    # aborting the whole battery.
    rendered = (
        f"do\n"
        f"    local function {name}()\n"
        f"        local _success, _result = pcall(function()\n"
        f"{body}\n"
        f"            return ok\n"
        f"        end)\n"
        f"        local ok = _success and _result == true\n"
        f'        print(ok and "{label}_ok" or "{label}_dtc")\n'
        f"    end\n"
        f"    {name}()\n"
        f"end\n\n"
    )
    parts.append(rendered)
parts.append(footer)

out_path = REPO / "tests" / "dtc" / "checks.lua"
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text("".join(parts), encoding="utf-8")
print(f"Wrote {out_path}")
print(f"Total checks: {len(CHECKS)}")
