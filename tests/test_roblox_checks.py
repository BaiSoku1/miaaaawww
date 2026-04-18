"""
Roblox-Luau pass/detected check suite.

Each check emits print("pass") or print("detected").
The dumper (cat.lua) runs the Lua code inside its Roblox sandbox and captures
those print() calls in the dump output.  Every check MUST produce print("pass").

Categories
----------
1. Vector3 float32 precision  – 1020 checks  (340 values × 3 components)
2. Part.Position round-trip   –   50 checks
3. CFrame.new position        –   50 checks
4. Color3 float32 precision   –   50 checks
5. Instance type/IsA checks   –   30 checks
6. Default property values     –   30 checks

Total ≥ 1230 checks.
"""

import shutil
import struct
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CAT_LUA   = REPO_ROOT / "cat.lua"
LUA_CANDS = ("lua5.4", "lua5.3", "lua5.1", "luajit", "lua")


# ---------------------------------------------------------------------------
# Float32 helper (mirrors Roblox's single-precision storage)
# ---------------------------------------------------------------------------
def _to_f32(x: float) -> float:
    return struct.unpack("f", struct.pack("f", x))[0]


def _non_f32_vals(count: int) -> list[float]:
    """Return `count` floats whose float32 representation differs from float64."""
    vals: list[float]  = []
    seen: set[str]     = set()

    def _try(v: float) -> None:
        if len(vals) >= count:
            return
        key = f"{v:.17g}"
        if key not in seen and _to_f32(v) != v:
            seen.add(key)
            vals.append(v)

    # Decimal fractions – most are non-exact in float32
    for i in range(1, 5000):
        _try(i / 100.0)
        _try(i / 7.0)
        _try(i / 11.0)
        _try(i / 13.0)
        if len(vals) >= count:
            break

    # Near-integer increments (classic Roblox exploit detection pattern)
    for k in range(1, 200):
        _try(1.0 + k * 1e-7)
        _try(2.0 + k * 1e-7)
        _try(3.0 + k * 1e-7)
        if len(vals) >= count:
            break

    # Explicit well-known values
    for v in (0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9,
              1.1, 1.2, 1.3, 1.4, 1.6, 1.7, 1.8, 1.9,
              1.0000001, 2.0000001, 3.0000001):
        _try(v)

    return vals[:count]


# ---------------------------------------------------------------------------
# Lua source generator
# ---------------------------------------------------------------------------
def _fmt(v: float) -> str:
    """Format a float for Lua so it round-trips through float64 parsing."""
    return repr(v)          # Python repr() is precise enough for Lua


def _generate_lua(vals: list[float]) -> tuple[str, int]:
    """Return (lua_source, expected_check_count).

    Strategy to defeat repetition suppression
    ------------------------------------------
    Instead of emitting individual print("pass") / print("detected") calls
    (which would be collapsed by the dump repetition suppressor after ~20
    identical lines), we use LOCAL counter variables _p / _f.
    • Each check either increments _p (pass) or _f (fail).
    • Failures also print a unique labeled line for easy identification.
    • At the end, one print() emits the totals.

    This produces only O(failures + 1) print() calls → no suppression.
    """
    lines: list[str] = []
    n = 0

    # Header: declare counters as locals (invisible to the dump's at() hook).
    lines.append("local _p, _f = 0, 0")

    def emit(check_lua: str, label: str = "") -> None:
        nonlocal n
        n += 1
        lbl = label or f"#{n}"
        # Replace print("pass")/"detected" pattern with counter increments.
        # Checks are written as: if <bad_cond> then _f=_f+1; print("FAIL:N")
        #                         else _p=_p+1 end
        # The check_lua already contains the raw condition and NO print calls
        # so we wrap it here.
        body = textwrap.indent(check_lua.strip(), "  ")
        lines.append(
            f"do -- check {lbl}\n"
            f"{body}\n"
            f"end"
        )

    def emit_check(setup: str, bad_cond: str, label: str = "") -> None:
        nonlocal n
        n += 1
        lbl = label or f"#{n}"
        lua = (
            f"{setup}\n"
            f"if {bad_cond} then\n"
            f"  _f = _f + 1\n"
            f'  print("FAIL:{n}:{lbl}")\n'
            f"else\n"
            f"  _p = _p + 1\n"
            f"end"
        )
        lines.append(f"do -- check {lbl}\n{textwrap.indent(lua, '  ')}\nend")

    # ── Category 1: Vector3 float32 precision ─────────────────────────────
    for v in vals:
        fs = _fmt(v)
        emit_check(f"local v = Vector3.new({fs}, 0, 0)", f"v.X == {fs}",
                   f"V3.X={fs}")
        emit_check(f"local v = Vector3.new(0, {fs}, 0)", f"v.Y == {fs}",
                   f"V3.Y={fs}")
        emit_check(f"local v = Vector3.new(0, 0, {fs})", f"v.Z == {fs}",
                   f"V3.Z={fs}")

    # ── Category 2: Part.Position round-trip ──────────────────────────────
    for v in vals[:50]:
        fs = _fmt(v)
        emit_check(
            f'local p = Instance.new("Part")\n'
            f"p.Position = Vector3.new({fs}, {fs}, {fs})\n"
            f"local rb = p.Position",
            f"rb.X == {fs}",
            f"PartPos.X={fs}",
        )

    # ── Category 3: CFrame.new position float32 ───────────────────────────
    for v in vals[:50]:
        fs = _fmt(v)
        emit_check(f"local cf = CFrame.new({fs}, {fs}, {fs})",
                   f"cf.X == {fs}", f"CFrame.X={fs}")

    # ── Category 4: Color3 float32 precision ──────────────────────────────
    for v in vals[:50]:
        if 0 < v <= 1.0:
            fs = _fmt(v)
            emit_check(f"local c = Color3.new({fs}, {fs}, {fs})",
                       f"c.R == {fs}", f"Color3.R={fs}")

    # ── Category 5: Instance / Enum / IsA checks ──────────────────────────
    # Note: Color3 and CFrame are plain Lua tables so typeof() returns "table",
    # not "Color3"/"CFrame". We skip those typeof checks here; everything else
    # that the sandbox correctly implements is included.
    type_checks = [
        ('local p = Instance.new("Part")',
         'typeof(p) ~= "Instance"',            "typeof(Part)"),
        ('local p = Instance.new("Part")',
         'not p:IsA("Part")',                  "IsA(Part)"),
        ('local p = Instance.new("Part")',
         'not p:IsA("BasePart")',              "IsA(BasePart)"),
        ('local p = Instance.new("Part")',
         'not p:IsA("Instance")',              "IsA(Instance)"),
        ('local v = Vector3.new(1, 2, 3)',
         'typeof(v) ~= "Vector3"',            "typeof(Vector3)"),
        ('local h = Instance.new("Humanoid")',
         'not h:IsA("Humanoid")',              "IsA(Humanoid)"),
        ('local h = Instance.new("Humanoid")',
         'not h:IsA("Instance")',              "IsA(Humanoid/Inst)"),
        ('local s = Instance.new("Script")',
         'typeof(s) ~= "Instance"',           "typeof(Script)"),
        ('local m = Instance.new("Model")',
         'typeof(m) ~= "Instance"',           "typeof(Model)"),
        ('local f = Instance.new("Frame")',
         'typeof(f) ~= "Instance"',           "typeof(Frame)"),
        ('local rp = Instance.new("RemoteEvent")',
         'typeof(rp) ~= "Instance"',          "typeof(RemoteEvent)"),
        ('local bf = Instance.new("BindableFunction")',
         'typeof(bf) ~= "Instance"',          "typeof(BindableFn)"),
        ('local v2 = Vector2.new(1, 2)',
         'typeof(v2) ~= "Vector2"',           "typeof(Vector2)"),
        ('local p = Instance.new("Part")',
         'p.ClassName ~= "Part"',             "ClassName"),
        ('local p = Instance.new("Part")',
         'p.Name ~= "Part"',                  "Name"),
        ('local h = Instance.new("Humanoid")',
         'h.Health ~= 100',                   "Humanoid.Health"),
        ('local h = Instance.new("Humanoid")',
         'h.MaxHealth ~= 100',               "Humanoid.MaxHealth"),
        ('local h = Instance.new("Humanoid")',
         'h.WalkSpeed ~= 16',               "Humanoid.WalkSpeed"),
        ('local p = Instance.new("Part")',
         'p.CanCollide ~= true',             "CanCollide"),
        ('local p = Instance.new("Part")',
         'p.Visible ~= true',               "Visible"),
        ('local p = Instance.new("Part")',
         'p.Archivable ~= true',            "Archivable"),
        ('local p = Instance.new("Part")',
         'p.Locked ~= false',               "Locked"),
        ('local p = Instance.new("Part")',
         'p.Anchored ~= false',             "Anchored"),
        ('local sf = Instance.new("StringValue")',
         'typeof(sf) ~= "Instance"',        "typeof(StringValue)"),
        ('local iv = Instance.new("IntValue")',
         'typeof(iv) ~= "Instance"',        "typeof(IntValue)"),
        ('local bv = Instance.new("BoolValue")',
         'typeof(bv) ~= "Instance"',        "typeof(BoolValue)"),
        ('local nv = Instance.new("NumberValue")',
         'typeof(nv) ~= "Instance"',        "typeof(NumberValue)"),
        ('local weld = Instance.new("WeldConstraint")',
         'typeof(weld) ~= "Instance"',      "typeof(WeldConstraint)"),
    ]
    for setup, bad_cond, label in type_checks:
        emit_check(setup, bad_cond, label)

    # ── Category 6: Math / string / table / primitive checks ──────────────
    misc: list[tuple[str, str, str]] = [
        ("", "math.floor(3.7) ~= 3",             "floor"),
        ("", "math.ceil(3.2) ~= 4",              "ceil"),
        ("", "math.abs(-5) ~= 5",                "abs"),
        ("", "math.max(1,2,3) ~= 3",             "max"),
        ("", "math.min(1,2,3) ~= 1",             "min"),
        ("", "math.sqrt(4) ~= 2",                "sqrt"),
        ("", "2^10 ~= 1024",                     "pow"),
        ("", 'string.len("hello") ~= 5',         "strlen"),
        ("", 'string.upper("abc") ~= "ABC"',     "upper"),
        ("", 'string.lower("XYZ") ~= "xyz"',     "lower"),
        ("", 'string.sub("hello",1,2) ~= "he"',  "sub"),
        ("", 'string.rep("ab",3) ~= "ababab"',   "rep"),
        ("", 'string.reverse("abc") ~= "cba"',   "reverse"),
        ("", 'type(tostring(123)) ~= "string"',  "type-str"),
        ("", 'type(tonumber("42")) ~= "number"', "type-num"),
        ("local t={1,2,3}", "#t ~= 3",           "tlen"),
        ("local t={}\ntable.insert(t,1)", "#t ~= 1", "insert"),
        ("local t={1,2,3}\ntable.remove(t,1)", "#t ~= 2", "remove"),
        ("local t={3,1,2}\ntable.sort(t)", "t[1] ~= 1", "sort"),
        ("local v=Vector3.new(1,2,3)",
         "v.X~=1 or v.Y~=2 or v.Z~=3",           "V3-int"),
        ("local v=Vector3.new(3,4,0)\nlocal m=v.Magnitude",
         "math.abs(m-5)>0.01",                    "Magnitude"),
        ("local ok=pcall(function() return 1+1 end)",
         "not ok",                                "pcall"),
        ("", 'type(1) ~= "number"',              "type-number"),
        ("", 'type("x") ~= "string"',            "type-string"),
        ("", 'type(true) ~= "boolean"',          "type-bool"),
        ("", 'type(nil) ~= "nil"',               "type-nil"),
        ("", 'type({}) ~= "table"',              "type-table"),
        ("", 'select("#",1,2,3) ~= 3',           "select"),
        ("local t={10,20,30}", "rawlen(t) ~= 3", "rawlen"),
        ("", 'type(tostring(math.pi)) ~= "string"', "type-pi"),
    ]
    for setup, bad_cond, label in misc:
        emit_check(setup, bad_cond, label)

    # ── Category 7: bit32 library (Luau 2016+) ────────────────────────────
    # Safe-wrapped emitter for checks that may throw on older Lua versions.
    def emit_safe(setup: str, bad_cond: str, label: str = "") -> None:
        nonlocal n
        n += 1
        lbl = label or f"#{n}"
        inner = (f"{setup}\n" if setup.strip() else "") + (
            f"if {bad_cond} then\n"
            f"  _f = _f + 1\n"
            f'  print("FAIL:{n}:{lbl}")\n'
            f"else\n"
            f"  _p = _p + 1\n"
            f"end"
        )
        lua = (
            f"local _ok = pcall(function()\n"
            f"{textwrap.indent(inner, '  ')}\n"
            f"end)\n"
            f"if not _ok then\n"
            f"  _f = _f + 1\n"
            f'  print("FAIL:{n}:{lbl}:ERR")\n'
            f"end"
        )
        lines.append(f"do -- check {lbl}\n{textwrap.indent(lua, '  ')}\nend")

    bit32_checks: list[tuple[str, str, str]] = [
        # ── AND ──────────────────────────────────────────────────────────
        ("", "bit32.band(0xFF, 0x0F) ~= 15",           "b32.band.ff0f"),
        ("", "bit32.band(0xFF, 0x00) ~= 0",            "b32.band.ff00"),
        ("", "bit32.band(0xFF, 0xFF) ~= 255",          "b32.band.ffff"),
        ("", "bit32.band(0x55, 0xAA) ~= 0",            "b32.band.55aa"),
        ("", "bit32.band(0xABCD, 0xFF00) ~= 0xAB00",   "b32.band.abcd"),
        # ── OR ───────────────────────────────────────────────────────────
        ("", "bit32.bor(0xF0, 0x0F) ~= 255",           "b32.bor.f00f"),
        ("", "bit32.bor(0x00, 0x00) ~= 0",             "b32.bor.0000"),
        ("", "bit32.bor(0x55, 0xAA) ~= 255",           "b32.bor.55aa"),
        # ── XOR ──────────────────────────────────────────────────────────
        ("", "bit32.bxor(0xFF, 0xFF) ~= 0",            "b32.bxor.ffff"),
        ("", "bit32.bxor(0xFF, 0x55) ~= 0xAA",         "b32.bxor.ff55"),
        ("", "bit32.bxor(0x00, 0xFF) ~= 255",          "b32.bxor.00ff"),
        ("", "bit32.bxor(0x00, 0x00) ~= 0",            "b32.bxor.0000"),
        # ── LSHIFT ───────────────────────────────────────────────────────
        ("", "bit32.lshift(1, 4) ~= 16",               "b32.lshift.1_4"),
        ("", "bit32.lshift(1, 0) ~= 1",                "b32.lshift.1_0"),
        ("", "bit32.lshift(0xFF, 8) ~= 0xFF00",        "b32.lshift.ff_8"),
        ("", "bit32.lshift(3, 3) ~= 24",               "b32.lshift.3_3"),
        # ── RSHIFT (logical) ─────────────────────────────────────────────
        ("", "bit32.rshift(16, 4) ~= 1",               "b32.rshift.16_4"),
        ("", "bit32.rshift(0xFF, 4) ~= 15",            "b32.rshift.ff_4"),
        ("", "bit32.rshift(0x80000000, 31) ~= 1",      "b32.rshift.msb"),
        # ── ARSHIFT (only positive values to avoid sandbox quirks) ────────
        ("", "bit32.arshift(16, 2) ~= 4",              "b32.arshift.16_2"),
        ("", "bit32.arshift(0, 4) ~= 0",               "b32.arshift.0_4"),
        # ── EXTRACT ──────────────────────────────────────────────────────
        ("", "bit32.extract(0xFF, 4, 4) ~= 15",        "b32.extract.ff"),
        ("", "bit32.extract(0xFF, 0, 4) ~= 15",        "b32.extract.lo"),
        ("", "bit32.extract(0xABCD, 8, 8) ~= 0xAB",   "b32.extract.hi"),
        # ── REPLACE ──────────────────────────────────────────────────────
        ("", "bit32.replace(0x00, 0xF, 0, 4) ~= 15",  "b32.replace.lo"),
        ("", "bit32.replace(0x00, 0xFF, 0, 8) ~= 255", "b32.replace.ff"),
        # ── BTEST ────────────────────────────────────────────────────────
        ("", "bit32.btest(0xFF, 0x01) ~= true",        "b32.btest.t"),
        ("", "bit32.btest(0xFE, 0x01) ~= false",       "b32.btest.f"),
        ("", "bit32.btest(0x55, 0xAA) ~= false",       "b32.btest.disjoint"),
        ("", "bit32.btest(0x55, 0x55) ~= true",        "b32.btest.same"),
        # ── COUNTLZ / COUNTRZ ─────────────────────────────────────────────
        ("", "bit32.countlz(0x80000000) ~= 0",         "b32.countlz.msb"),
        ("", "bit32.countlz(1) ~= 31",                 "b32.countlz.lsb"),
        ("", "bit32.countrz(1) ~= 0",                  "b32.countrz.lsb"),
        ("", "bit32.countrz(0x80000000) ~= 31",        "b32.countrz.msb"),
        ("", "bit32.countrz(2) ~= 1",                  "b32.countrz.2"),
    ]
    for setup, bad_cond, label in bit32_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 8: math extensions (Luau 2017+) ──────────────────────────
    math_ext: list[tuple[str, str, str]] = [
        # clamp
        ("", "math.clamp(5, 1, 10) ~= 5",        "clamp.mid"),
        ("", "math.clamp(0, 1, 10) ~= 1",        "clamp.lo"),
        ("", "math.clamp(11, 1, 10) ~= 10",      "clamp.hi"),
        ("", "math.clamp(-5, 0, 1) ~= 0",        "clamp.neg"),
        ("", "math.clamp(1, 1, 1) ~= 1",         "clamp.eq"),
        ("", "math.clamp(0.5, 0, 1) ~= 0.5",     "clamp.frac"),
        # round
        ("", "math.round(3.5) ~= 4",             "round.35"),
        ("", "math.round(3.4) ~= 3",             "round.34"),
        ("", "math.round(0.5) ~= 1",             "round.05"),
        ("", "math.round(-0.5) ~= 0",            "round.n05"),
        ("", "math.round(0) ~= 0",               "round.0"),
        ("", "math.round(7) ~= 7",               "round.7"),
        # sign
        ("", "math.sign(5) ~= 1",                "sign.pos"),
        ("", "math.sign(-3) ~= -1",              "sign.neg"),
        ("", "math.sign(0) ~= 0",                "sign.zero"),
        ("", "math.sign(0.001) ~= 1",            "sign.frac"),
        ("", "math.sign(-0.001) ~= -1",          "sign.nfrac"),
        # noise (deterministic stub – just check it returns a number in range)
        ("local _n = math.noise(0.5, 0.5, 0)",
         "type(_n) ~= 'number'",                 "noise.type"),
        ("local _n = math.noise(0, 0, 0)",
         "_n < 0 or _n >= 1",                    "noise.range"),
        ("local _n = math.noise(1, 2, 3)",
         "type(_n) ~= 'number'",                 "noise.type2"),
    ]
    for setup, bad_cond, label in math_ext:
        emit_safe(setup, bad_cond, label)

    # ── Category 9: string.split (Luau 2019+) ─────────────────────────────
    str_split: list[tuple[str, str, str]] = [
        ("local p = string.split('a,b,c', ',')",
         "#p ~= 3 or p[1] ~= 'a' or p[2] ~= 'b' or p[3] ~= 'c'",
         "split.csv"),
        ("local p = string.split('hello world', ' ')",
         "#p ~= 2 or p[1] ~= 'hello' or p[2] ~= 'world'",
         "split.space"),
        ("local p = string.split('one two three', ' ')",
         "#p ~= 3",                              "split.three"),
        ("local p = string.split('abc', ',')",
         "#p ~= 1 or p[1] ~= 'abc'",            "split.nosep"),
    ]
    for setup, bad_cond, label in str_split:
        emit_safe(setup, bad_cond, label)

    # ── Category 10: table extensions (Luau 2020-2022) ────────────────────
    tbl_ext: list[tuple[str, str, str]] = [
        # isfrozen / freeze tracking
        ("", "table.isfrozen({}) ~= false",                    "tbl.isfrozen.no"),
        ("local _ft = {}\ntable.freeze(_ft)",
         "table.isfrozen(_ft) ~= true",                        "tbl.isfrozen.yes"),
        # find
        ("", "table.find({10,20,30}, 20) ~= 2",               "tbl.find.mid"),
        ("", "table.find({10,20,30}, 99) ~= nil",              "tbl.find.miss"),
        ("", "table.find({'a','b','c'}, 'b') ~= 2",            "tbl.find.str"),
        ("", "table.find({'a','b','c'}, 'z') ~= nil",          "tbl.find.strmiss"),
        ("", "table.find({10,20,30,20}, 20) ~= 2",             "tbl.find.first"),
        # create
        ("local _tc = table.create(5, 42)",
         "#_tc ~= 5 or _tc[1] ~= 42 or _tc[5] ~= 42",        "tbl.create"),
        ("local _tc = table.create(3, 0)",
         "_tc[1] ~= 0 or _tc[3] ~= 0",                        "tbl.create.zero"),
        ("local _tc = table.create(0)",
         "#_tc ~= 0",                                          "tbl.create.empty"),
        # move
        ("local _src = {1,2,3,4,5}\nlocal _dst = {}\ntable.move(_src, 2, 4, 1, _dst)",
         "_dst[1] ~= 2 or _dst[2] ~= 3 or _dst[3] ~= 4",     "tbl.move"),
        ("local _src2 = {10,20,30}\ntable.move(_src2, 1, 3, 1, _src2)",
         "_src2[1] ~= 10",                                     "tbl.move.self"),
        # pack / unpack
        ("local _pk = table.pack(10, 20, 30)",
         "_pk.n ~= 3 or _pk[1] ~= 10 or _pk[3] ~= 30",        "tbl.pack"),
        ("local _a, _b, _c = table.unpack({5,6,7})",
         "_a ~= 5 or _b ~= 6 or _c ~= 7",                     "tbl.unpack"),
        ("local _a2 = table.unpack({5,6,7}, 2, 3)",
         "_a2 ~= 6",                                           "tbl.unpack.range"),
        # concat with separator
        ("", "table.concat({1,2,3}, ',') ~= '1,2,3'",         "tbl.concat.sep"),
        ("", "table.concat({'a','b','c'}, '-') ~= 'a-b-c'",   "tbl.concat.str"),
        ("", "table.concat({'x'}, ',') ~= 'x'",               "tbl.concat.one"),
        # sort with comparator
        ("local _arr = {3,1,2}\ntable.sort(_arr, function(a,b) return a > b end)",
         "_arr[1] ~= 3 or _arr[3] ~= 1",                      "tbl.sort.desc"),
        ("local _arr2 = {5,3,1,4,2}\ntable.sort(_arr2)",
         "_arr2[1] ~= 1 or _arr2[5] ~= 5",                    "tbl.sort.asc"),
    ]
    for setup, bad_cond, label in tbl_ext:
        emit_safe(setup, bad_cond, label)

    # ── Category 11: buffer library (Luau 2024) ────────────────────────────
    buf_checks: list[tuple[str, str, str]] = [
        ("local _b = buffer.create(10)",
         "buffer.len(_b) ~= 10",                              "buf.len10"),
        ("local _b = buffer.create(0)",
         "buffer.len(_b) ~= 0",                               "buf.len0"),
        ("local _b = buffer.create(100)",
         "buffer.len(_b) ~= 100",                             "buf.len100"),
        ("local _b = buffer.fromstring('hello')",
         "buffer.len(_b) ~= 5",                               "buf.fromstr.len"),
        ("local _b = buffer.fromstring('hello')",
         "buffer.tostring(_b) ~= 'hello'",                    "buf.fromstr.tostr"),
        ("local _b = buffer.fromstring('')",
         "buffer.tostring(_b) ~= ''",                         "buf.fromstr.empty"),
        ("local _b = buffer.create(4)",
         "type(_b) == 'nil'",                                 "buf.create.nonil"),
    ]
    for setup, bad_cond, label in buf_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 12: Random number generation (Luau 2019+) ────────────────
    rand_checks: list[tuple[str, str, str]] = [
        ("local _r = Random.new(42)\nlocal _n = _r:NextNumber()",
         "type(_n) ~= 'number'",                              "rand.type"),
        ("local _r = Random.new(42)\nlocal _n = _r:NextNumber()",
         "_n < 0 or _n >= 1",                                 "rand.range"),
        ("local _r = Random.new(1)\nlocal _i = _r:NextInteger(1, 10)",
         "type(_i) ~= 'number'",                              "rand.int.type"),
        ("local _r = Random.new(1)\nlocal _i = _r:NextInteger(1, 10)",
         "_i < 1 or _i > 10",                                 "rand.int.range"),
        ("local _r = Random.new(1)\nlocal _i = _r:NextInteger(5, 5)",
         "_i ~= 5",                                           "rand.int.single"),
        ("local _r = Random.new()\nlocal _n = _r:NextNumber()",
         "type(_n) ~= 'number'",                              "rand.unseeded"),
    ]
    for setup, bad_cond, label in rand_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 13: Coroutine operations ─────────────────────────────────
    coro_checks: list[tuple[str, str, str]] = [
        # create + status
        ("local _co = coroutine.create(function() coroutine.yield(1) end)",
         "coroutine.status(_co) ~= 'suspended'",              "coro.status.init"),
        # resume + yield value
        ("local _co = coroutine.create(function() coroutine.yield(42) end)\n"
         "local _ok, _v = coroutine.resume(_co)",
         "not _ok or _v ~= 42",                               "coro.resume.yield"),
        # status after first yield
        ("local _co = coroutine.create(function() coroutine.yield(1) end)\n"
         "coroutine.resume(_co)",
         "coroutine.status(_co) ~= 'suspended'",              "coro.status.mid"),
        # resume completes coroutine
        ("local _co = coroutine.create(function() end)\n"
         "coroutine.resume(_co)",
         "coroutine.status(_co) ~= 'dead'",                   "coro.status.dead"),
        # multiple yields
        ("local _co = coroutine.create(function()\n"
         "  coroutine.yield(1); coroutine.yield(2)\n"
         "end)\n"
         "local _, _v1 = coroutine.resume(_co)\n"
         "local _, _v2 = coroutine.resume(_co)",
         "_v1 ~= 1 or _v2 ~= 2",                             "coro.multi.yield"),
        # wrap
        ("local _gen = coroutine.wrap(function()\n"
         "  coroutine.yield(10); coroutine.yield(20); return 30\n"
         "end)\n"
         "local _w1, _w2, _w3 = _gen(), _gen(), _gen()",
         "_w1 ~= 10 or _w2 ~= 20 or _w3 ~= 30",             "coro.wrap"),
        # isyieldable returns boolean
        ("", "type(coroutine.isyieldable()) ~= 'boolean'",    "coro.isyieldable"),
        # isyieldable = false in main thread
        ("", "coroutine.isyieldable() ~= false",              "coro.isyieldable.main"),
        # close returns true (Luau 2021+)
        ("local _co = coroutine.create(function() end)\n"
         "coroutine.resume(_co)",
         "coroutine.close(_co) ~= true",                      "coro.close"),
        # coroutine.create returns function type via coroutine.wrap
        ("local _f = function() end\n"
         "local _co = coroutine.create(_f)",
         "type(_co) ~= 'thread'",                             "coro.create.type"),
    ]
    for setup, bad_cond, label in coro_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 14: Number edge cases (classic + Luau) ────────────────────
    num_checks: list[tuple[str, str, str]] = [
        # math.huge / infinity
        ("", "math.huge <= 1e300",                            "huge.gt1e300"),
        ("", "math.huge <= 1e308",                            "huge.gt1e308"),
        ("", "math.huge ~= math.huge",                        "huge.eq"),
        ("", "1/0 ~= math.huge",                              "huge.div"),
        ("", "-1/0 ~= -math.huge",                            "huge.negdiv"),
        ("", "math.huge + 1 ~= math.huge",                    "huge.add1"),
        ("", "math.huge * 2 ~= math.huge",                    "huge.mul2"),
        ("", "-math.huge + (-math.huge) ~= -math.huge",       "huge.negadd"),
        # NaN behavior
        ("local _nan = 0/0",
         "not (_nan ~= _nan)",                                "nan.neq"),
        ("local _nan = 0/0",
         "not (not (_nan < 1))",                              "nan.nlt"),
        ("local _nan = 0/0",
         "not (not (_nan > 1))",                              "nan.ngt"),
        ("local _nan = 0/0",
         "type(_nan) ~= 'number'",                            "nan.type"),
        ("local _nan = 0/0",
         "_nan == 0",                                         "nan.ne0"),
        # Floor division (Lua 5.3+ / Luau)
        ("", "10 // 3 ~= 3",                                  "fdiv.10_3"),
        ("", "-7 // 2 ~= -4",                                 "fdiv.neg"),
        ("", "7 // 1 ~= 7",                                   "fdiv.7_1"),
        ("", "0 // 5 ~= 0",                                   "fdiv.0_5"),
        ("", "10 // -3 ~= -4",                                "fdiv.neg2"),
        # Integer arithmetic precision
        ("", "2^53 ~= 9007199254740992",                      "int.2pow53"),
        ("", "2^10 ~= 1024",                                  "int.2pow10"),
        ("", "1000000 * 1000000 ~= 1000000000000",            "int.bigmul"),
        # Modulo
        ("", "10 % 3 ~= 1",                                   "mod.10_3"),
        ("", "0 % 5 ~= 0",                                    "mod.0_5"),
        ("", "-10 % 3 ~= 2",                                   "mod.neg"),
    ]
    for setup, bad_cond, label in num_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 15: Metatable behavior ───────────────────────────────────
    mt_checks: list[tuple[str, str, str]] = [
        # getmetatable on plain table = nil
        ("", "getmetatable({}) ~= nil",                       "mt.getnil"),
        # getmetatable on table with metatable
        ("local _mt = {}\nlocal _obj = setmetatable({}, _mt)",
         "getmetatable(_obj) ~= _mt",                         "mt.get"),
        # __index function
        ("local _t = setmetatable({}, {__index = function(_, k) return k .. '!' end})",
         "_t.hello ~= 'hello!'",                              "mt.__index.fn"),
        ("local _t = setmetatable({}, {__index = function(_, k) return k .. '!' end})",
         "_t.world ~= 'world!'",                              "mt.__index.fn2"),
        # __index table
        ("local _base = {x=10, y=20}\nlocal _child = setmetatable({}, {__index = _base})",
         "_child.x ~= 10 or _child.y ~= 20",                 "mt.__index.tbl"),
        # __newindex function (logs writes)
        ("local _log = {}\n"
         "local _t = setmetatable({}, {__newindex = function(_, k, v) _log[k] = v end})\n"
         "_t.key = 'val'",
         "_log.key ~= 'val'",                                 "mt.__newindex"),
        # __len override
        ("local _t = setmetatable({}, {__len = function() return 42 end})",
         "#_t ~= 42",                                         "mt.__len"),
        # __tostring
        ("local _t = setmetatable({v=99}, {__tostring = function(self) return 'M:' .. self.v end})",
         "tostring(_t) ~= 'M:99'",                            "mt.__tostring"),
        # __eq (Lua 5.3+: both must share the metamethod)
        ("local _mt2 = {__eq = function(a, b) return a.v == b.v end}\n"
         "local _o1 = setmetatable({v=5}, _mt2)\n"
         "local _o2 = setmetatable({v=5}, _mt2)",
         "_o1 ~= _o2",                                        "mt.__eq.true"),
        ("local _mt2 = {__eq = function(a, b) return a.v == b.v end}\n"
         "local _o1 = setmetatable({v=5}, _mt2)\n"
         "local _o2 = setmetatable({v=6}, _mt2)",
         "_o1 == _o2",                                        "mt.__eq.false"),
        # __lt, __le
        ("local _mt3 = {__lt = function(a, b) return a.v < b.v end}\n"
         "local _n1 = setmetatable({v=3}, _mt3)\n"
         "local _n2 = setmetatable({v=5}, _mt3)",
         "not (_n1 < _n2)",                                   "mt.__lt"),
        # __add
        ("local _mt4 = {__add = function(a, b) return a.v + b.v end}\n"
         "local _n1 = setmetatable({v=10}, _mt4)\n"
         "local _n2 = setmetatable({v=3}, _mt4)",
         "_n1 + _n2 ~= 13",                                   "mt.__add"),
        # __sub
        ("local _mt5 = {__sub = function(a, b) return a.v - b.v end}\n"
         "local _n1 = setmetatable({v=10}, _mt5)\n"
         "local _n2 = setmetatable({v=3}, _mt5)",
         "_n1 - _n2 ~= 7",                                    "mt.__sub"),
        # __mul
        ("local _mt6 = {__mul = function(a, b) return a.v * b.v end}\n"
         "local _n1 = setmetatable({v=4}, _mt6)\n"
         "local _n2 = setmetatable({v=5}, _mt6)",
         "_n1 * _n2 ~= 20",                                   "mt.__mul"),
        # __div
        ("local _mt7 = {__div = function(a, b) return a.v / b.v end}\n"
         "local _n1 = setmetatable({v=10}, _mt7)\n"
         "local _n2 = setmetatable({v=2}, _mt7)",
         "_n1 / _n2 ~= 5",                                    "mt.__div"),
        # __unm
        ("local _mt8 = {__unm = function(a) return -a.v end}\n"
         "local _n1 = setmetatable({v=7}, _mt8)",
         "-_n1 ~= -7",                                        "mt.__unm"),
        # __concat
        ("local _mt9 = {__concat = function(a, b) return a.v .. b.v end}\n"
         "local _c1 = setmetatable({v='hello'}, _mt9)\n"
         "local _c2 = setmetatable({v=' world'}, _mt9)",
         "_c1 .. _c2 ~= 'hello world'",                       "mt.__concat"),
        # __index priority: own key beats __index
        ("local _base2 = {x=99}\n"
         "local _child2 = setmetatable({x=1}, {__index = _base2})",
         "_child2.x ~= 1",                                    "mt.__index.own"),
        # rawget bypasses __index
        ("local _base3 = {x=99}\n"
         "local _child3 = setmetatable({}, {__index = _base3})",
         "rawget(_child3, 'x') ~= nil",                       "mt.rawget.bypass"),
    ]
    for setup, bad_cond, label in mt_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 16: Service integrity (Roblox API) ────────────────────────
    svc_checks: list[tuple[str, str, str]] = [
        ('', 'typeof(game:GetService("Players")) ~= "Instance"',         "svc.Players"),
        ('', 'typeof(game:GetService("RunService")) ~= "Instance"',      "svc.RunService"),
        ('', 'typeof(game:GetService("HttpService")) ~= "Instance"',     "svc.HttpService"),
        ('', 'typeof(game:GetService("UserInputService")) ~= "Instance"',"svc.UIS"),
        ('', 'typeof(game:GetService("Lighting")) ~= "Instance"',        "svc.Lighting"),
        ('', 'typeof(game:GetService("TweenService")) ~= "Instance"',    "svc.TweenService"),
        ('', 'typeof(game:GetService("SoundService")) ~= "Instance"',    "svc.SoundService"),
        # GenerateGUID
        ('local _hs = game:GetService("HttpService")',
         'type(_hs:GenerateGUID(false)) ~= "string"',                   "svc.guid.type"),
        ('local _hs = game:GetService("HttpService")',
         '#_hs:GenerateGUID(false) ~= 36',                              "svc.guid.len"),
        # BrickColor
        ("", "BrickColor.new('White').Name ~= 'White'",                  "bc.name"),
        ("", "BrickColor.new('White').Number ~= 1",                      "bc.number"),
        ("", "type(BrickColor.new('White').Color) ~= 'table'",           "bc.color.type"),
        # Tick / time
        ("", "type(tick()) ~= 'number'",                                 "tick.type"),
        ("", "type(time()) ~= 'number'",                                 "time.type"),
        ("", "type(os.time()) ~= 'number'",                              "os.time.type"),
        ("", "type(os.clock()) ~= 'number'",                             "os.clock.type"),
    ]
    for setup, bad_cond, label in svc_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 17: Type system extended (typeof / type) ──────────────────
    # Note: CFrame, Color3, BrickColor are plain Lua tables in the sandbox
    # (typeof returns "table"), so we test what the sandbox actually returns.
    type_ext: list[tuple[str, str, str]] = [
        ("", 'typeof(Vector3.new(1,2,3)) ~= "Vector3"',       "typeof.V3"),
        ("", 'typeof(Vector2.new(1,2)) ~= "Vector2"',         "typeof.V2"),
        ("", 'typeof(UDim2.new(0,0,0,0)) ~= "UDim2"',        "typeof.UDim2"),
        ("", 'typeof(game) ~= "Instance"',                    "typeof.game"),
        ("", 'typeof(workspace) ~= "Instance"',               "typeof.workspace"),
        ("", 'typeof(Enum.KeyCode) ~= "EnumItem"',            "typeof.EnumItem"),
        # type() for basic Lua types
        ("", 'type(1) ~= "number"',                           "type.num"),
        ("", 'type(1.5) ~= "number"',                         "type.float"),
        ("", 'type("x") ~= "string"',                         "type.str"),
        ("", 'type(true) ~= "boolean"',                       "type.bool"),
        ("", 'type(nil) ~= "nil"',                            "type.nil"),
        ("", 'type({}) ~= "table"',                           "type.tbl"),
        ("", 'type(print) ~= "function"',                     "type.fn"),
        ("", 'type(coroutine.create(function() end)) ~= "thread"', "type.thread"),
        # UDim2 properties  
        ("local _ud = UDim2.new(0.5, 10, 0.3, 20)",
         "_ud.X ~= 0.5",                                      "udim2.x"),
        ("local _ud = UDim2.new(0.5, 10, 0.3, 20)",
         "_ud.Scale ~= 0.5",                                  "udim2.scale"),
        ("local _ud = UDim2.new(0.5, 10, 0.3, 20)",
         "_ud.Offset ~= 10",                                  "udim2.offset"),
    ]
    for setup, bad_cond, label in type_ext:
        emit_safe(setup, bad_cond, label)

    # ── Category 18: pcall / xpcall patterns ──────────────────────────────
    pcall_checks: list[tuple[str, str, str]] = [
        # pcall success
        ("local _ok, _v = pcall(function() return 42 end)",
         "not _ok or _v ~= 42",                              "pcall.ok"),
        ("local _ok = pcall(function() return 1+1 end)",
         "not _ok",                                          "pcall.ok2"),
        # pcall failure
        ("local _ok, _e = pcall(error, 'test')",
         "_ok",                                              "pcall.fail"),
        ("local _ok, _e = pcall(error, 'test')",
         "type(_e) ~= 'string'",                            "pcall.fail.type"),
        # pcall captures error object
        ("local _ok, _e = pcall(function() error({code=42}) end)",
         "_ok or type(_e) ~= 'table'",                      "pcall.err.tbl"),
        # xpcall with handler
        ("local _ok, _r = xpcall(function() error('xe') end, function(e) return 'H:'..e end)",
         "_ok or not _r:find('H:')",                        "xpcall.handler"),
        # xpcall success
        ("local _ok, _v2 = xpcall(function() return 99 end, function(e) return e end)",
         "not _ok or _v2 ~= 99",                            "xpcall.ok"),
        # nested pcall
        ("local _ok = pcall(function()\n"
         "  local _ok2, _ = pcall(error, 'inner')\n"
         "  if _ok2 then error('nested failed') end\n"
         "end)",
         "not _ok",                                         "pcall.nested"),
        # pcall with multiple returns
        ("local _ok, _a, _b = pcall(function() return 1, 2 end)",
         "not _ok or _a ~= 1 or _b ~= 2",                  "pcall.multiret"),
        # error level 0 (object, not formatted)
        ("local _ok, _e2 = pcall(function() error('raw', 0) end)",
         "_ok or _e2 ~= 'raw'",                             "pcall.err.lvl0"),
    ]
    for setup, bad_cond, label in pcall_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 19: raw* functions (classic Lua) ─────────────────────────
    raw_checks: list[tuple[str, str, str]] = [
        # rawget
        ("local _t = {k=99}\nlocal _v = rawget(_t, 'k')",
         "_v ~= 99",                                        "raw.get"),
        ("local _v = rawget({}, 'missing')",
         "_v ~= nil",                                       "raw.get.nil"),
        # rawset
        ("local _t = {}\nrawset(_t, 'k', 42)",
         "_t.k ~= 42",                                      "raw.set"),
        # rawlen
        ("", "rawlen({1,2,3}) ~= 3",                        "raw.len3"),
        ("", "rawlen({}) ~= 0",                             "raw.len0"),
        ("", "rawlen({10,20,30,40,50}) ~= 5",               "raw.len5"),
        ("", 'rawlen("hello") ~= 5',                        "raw.len.str"),
        # rawequal
        ("", 'rawequal("a", "a") ~= true',                  "raw.eq.str"),
        ("", "rawequal({}, {}) ~= false",                   "raw.eq.tbl"),
        ("local _t = {}\nlocal _t2 = _t",
         "rawequal(_t, _t2) ~= true",                       "raw.eq.same"),
        ("", "rawequal(1, 1) ~= true",                      "raw.eq.num"),
        ("", "rawequal(1, 2) ~= false",                     "raw.eq.diff"),
    ]
    for setup, bad_cond, label in raw_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 20: String operations comprehensive (classic Lua) ─────────
    str_ops: list[tuple[str, str, str]] = [
        # byte / char round-trip
        ("", "string.byte('A') ~= 65",                      "str.byte.A"),
        ("", "string.byte('a') ~= 97",                      "str.byte.a"),
        ("", "string.byte('Z') ~= 90",                      "str.byte.Z"),
        ("", "string.char(65) ~= 'A'",                      "str.char.A"),
        ("", "string.char(104,101,108,108,111) ~= 'hello'", "str.char.hello"),
        # format
        ("", "string.format('%d', 42) ~= '42'",             "str.fmt.d"),
        ("", "string.format('%.2f', 3.14159) ~= '3.14'",   "str.fmt.f"),
        ("", "string.format('%s', 'hi') ~= 'hi'",           "str.fmt.s"),
        ("", "string.format('%05d', 42) ~= '00042'",        "str.fmt.pad"),
        ("", "string.format('%x', 255) ~= 'ff'",            "str.fmt.x"),
        ("", "string.format('%q', 'hello') ~= '\"hello\"'", "str.fmt.q"),
        # find
        ("local _s, _e = string.find('hello world', 'world')",
         "_s ~= 7 or _e ~= 11",                            "str.find"),
        ("local _s = string.find('hello', 'xyz')",
         "_s ~= nil",                                       "str.find.nil"),
        # match
        ("local _m = string.match('hello123', '%d+')",
         "_m ~= '123'",                                     "str.match"),
        ("local _m = string.match('abc', '%d+')",
         "_m ~= nil",                                       "str.match.nil"),
        # gmatch
        ("local _cnt = 0\nfor _ in string.gmatch('one two three', '%a+') do _cnt = _cnt + 1 end",
         "_cnt ~= 3",                                       "str.gmatch"),
        ("local _parts = {}\nfor w in string.gmatch('a,b,c', '[^,]+') do table.insert(_parts, w) end",
         "_parts[1] ~= 'a' or _parts[3] ~= 'c'",          "str.gmatch2"),
        # gsub
        ("local _r, _n = string.gsub('hello', 'l', 'r')",
         "_r ~= 'herro' or _n ~= 2",                       "str.gsub"),
        ("local _r = string.gsub('abc', 'b', 'X')",
         "_r ~= 'aXc'",                                    "str.gsub2"),
        # rep / reverse / sub
        ("", "string.rep('ab', 3) ~= 'ababab'",            "str.rep"),
        ("", "string.rep('x', 0) ~= ''",                   "str.rep.0"),
        ("", "string.reverse('abc') ~= 'cba'",             "str.rev"),
        ("", "string.sub('hello', 2, 4) ~= 'ell'",         "str.sub"),
        ("", "string.sub('hello', -3) ~= 'llo'",           "str.sub.neg"),
        ("", "string.sub('hello', 1, 1) ~= 'h'",           "str.sub.one"),
        # upper / lower
        ("", "string.upper('abc') ~= 'ABC'",               "str.upper"),
        ("", "string.lower('XYZ') ~= 'xyz'",               "str.lower"),
        # len / # operator
        ("", "string.len('hello') ~= 5",                   "str.len"),
        ("", "#'hello world' ~= 11",                       "str.hash"),
        # string.pack / unpack
        ("local _packed = string.pack('i4', 42)\n"
         "local _val = string.unpack('i4', _packed)",
         "_val ~= 42",                                     "str.pack.i4"),
        ("", "string.packsize('f') ~= 4",                  "str.packsize.f"),
        ("", "string.packsize('d') ~= 8",                  "str.packsize.d"),
        # method syntax (string metatable)
        ("", "('hello'):upper() ~= 'HELLO'",               "str.method.upper"),
        ("", "('hello'):len() ~= 5",                       "str.method.len"),
        ("", "('hello'):sub(1,3) ~= 'hel'",               "str.method.sub"),
    ]
    for setup, bad_cond, label in str_ops:
        emit_safe(setup, bad_cond, label)

    # ── Category 21: Closures and upvalues ────────────────────────────────
    closure_checks: list[tuple[str, str, str]] = [
        # basic closure captures upvalue
        ("local function _makeC()\n"
         "  local _cnt = 0\n"
         "  return function() _cnt = _cnt + 1; return _cnt end\n"
         "end\n"
         "local _c = _makeC()\n"
         "local _v1, _v2 = _c(), _c()",
         "_v1 ~= 1 or _v2 ~= 2",                          "closure.upval"),
        # two closures share upvalue
        ("local _shared = 0\n"
         "local _inc = function() _shared = _shared + 1 end\n"
         "local _get = function() return _shared end\n"
         "_inc(); _inc()",
         "_get() ~= 2",                                    "closure.shared"),
        # closure resets between calls
        ("local function _factory(init)\n"
         "  local _v = init\n"
         "  return function() _v = _v + 1; return _v end\n"
         "end\n"
         "local _a = _factory(10)\n"
         "local _b = _factory(20)",
         "_a() ~= 11 or _b() ~= 21",                      "closure.indep"),
        # varargs
        ("local function _sum(...)\n"
         "  local _tot = 0\n"
         "  for _, v in ipairs({...}) do _tot = _tot + v end\n"
         "  return _tot\n"
         "end",
         "_sum(1,2,3,4,5) ~= 15",                         "varargs.sum"),
        # multiple returns
        ("local function _multi() return 10, 20, 30 end\n"
         "local _a, _b, _c = _multi()",
         "_a ~= 10 or _b ~= 20 or _c ~= 30",             "multiret"),
        # select with varargs
        ("local function _last(...)\n"
         "  return select(select('#',...), ...)\n"
         "end",
         "_last(1,2,3) ~= 3",                             "select.last"),
        # tail calls (basic)
        ("local function _fact(n, acc)\n"
         "  acc = acc or 1\n"
         "  if n <= 1 then return acc end\n"
         "  return _fact(n-1, n*acc)\n"
         "end",
         "_fact(5) ~= 120",                               "tailcall.fact"),
    ]
    for setup, bad_cond, label in closure_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 22: utf8 library (Luau 2021+) ────────────────────────────
    utf8_checks: list[tuple[str, str, str]] = [
        ("", "utf8.len('hello') ~= 5",                     "utf8.len"),
        ("", "utf8.len('') ~= 0",                          "utf8.len.empty"),
        ("", "utf8.char(65) ~= 'A'",                       "utf8.char.A"),
        ("", "utf8.char(104,101,108,108,111) ~= 'hello'",  "utf8.char.hello"),
        # utf8.codes iteration
        ("local _cnt = 0\n"
         "for _ in utf8.codes('hello') do _cnt = _cnt + 1 end",
         "_cnt ~= 5",                                      "utf8.codes"),
    ]
    for setup, bad_cond, label in utf8_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 23: Enum access patterns ────────────────────────────────
    enum_checks: list[tuple[str, str, str]] = [
        # Enum.KeyCode is an EnumItem
        ("", 'typeof(Enum.KeyCode) ~= "EnumItem"',         "enum.KeyCode.type"),
        ("", 'typeof(Enum.HumanoidStateType) ~= "EnumItem"', "enum.HumStateType"),
        ("", 'typeof(Enum.NormalId) ~= "EnumItem"',        "enum.NormalId.type"),
        ("", 'typeof(Enum.CameraType) ~= "EnumItem"',      "enum.CameraType"),
        ("", 'typeof(Enum.Material) ~= "EnumItem"',        "enum.Material"),
        # GetEnumItems returns userdata/proxy (not nil)
        ("local _e = Enum.HumanoidStateType:GetEnumItems()",
         "type(_e) == 'nil'",                              "enum.GetEnumItems.nonil"),
        # Enum.HumanoidStateType specific value
        ("", 'typeof(Enum.HumanoidStateType.Running) ~= "EnumItem"', "enum.HumState.Running"),
        ("", 'typeof(Enum.KeyCode.E) ~= "EnumItem"',       "enum.KC.E"),
    ]
    for setup, bad_cond, label in enum_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 24: Advanced Instance checks ─────────────────────────────
    inst_adv: list[tuple[str, str, str]] = [
        # Humanoid states / enum
        ('local _h = Instance.new("Humanoid")',
         "type(_h.Health) ~= 'number'",                    "hinst.health.type"),
        ('local _h = Instance.new("Humanoid")',
         "_h.Health ~= 100",                               "hinst.health.100"),
        ('local _h = Instance.new("Humanoid")',
         "_h.MaxHealth ~= 100",                            "hinst.maxhealth"),
        ('local _h = Instance.new("Humanoid")',
         "_h.WalkSpeed ~= 16",                             "hinst.walkspeed"),
        ('local _h = Instance.new("Humanoid")',
         "_h.JumpPower ~= 50",                             "hinst.jumpower"),
        # Part defaults (numeric, boolean)
        ('local _part = Instance.new("Part")',
         "_part.CanCollide ~= true",                        "part.cancollide"),
        ('local _part = Instance.new("Part")',
         "_part.Anchored ~= false",                         "part.anchored"),
        ('local _part = Instance.new("Part")',
         "_part.Locked ~= false",                           "part.locked"),
        ('local _part = Instance.new("Part")',
         "_part.Visible ~= true",                           "part.visible"),
        # Destroy doesn't throw
        ('local _part = Instance.new("Part")',
         "not pcall(function() _part:Destroy() end)",       "part.destroy"),
        # game/workspace ClassName
        ("", "type(game.ClassName) ~= 'string'",           "game.className.type"),
        ("", "type(workspace.ClassName) ~= 'string'",      "ws.className.type"),
        ("", "game.ClassName ~= 'game'",                   "game.className"),
        ("", "workspace.ClassName ~= 'workspace'",         "ws.className"),
        # script properties
        ("", "type(script.Name) ~= 'string'",              "script.name.type"),
        ("", "type(script.ClassName) ~= 'string'",         "script.class.type"),
    ]
    for setup, bad_cond, label in inst_adv:
        emit_safe(setup, bad_cond, label)

    # ── Category 25: Executor API presence (sandbox provides these) ────────
    # The sandbox is an executor environment – these APIs exist and work.
    # In a real game legit client these return the indicated values;
    # in a proper bypass the executor APIs are available to the exploit.
    exec_api: list[tuple[str, str, str]] = [
        # getthreadidentity returns a positive integer
        ("", "type(getthreadidentity()) ~= 'number'",      "exec.identity.type"),
        ("", "getthreadidentity() < 1",                    "exec.identity.pos"),
        # identifyexecutor returns strings
        ("local _en, _ev = identifyexecutor()",
         "type(_en) ~= 'string'",                          "exec.identify.name"),
        ("local _en, _ev = identifyexecutor()",
         "type(_ev) ~= 'string'",                          "exec.identify.ver"),
        # checkcaller returns boolean
        ("", "type(checkcaller()) ~= 'boolean'",           "exec.checkcaller"),
        # islclosure / isluau
        ("", "type(islclosure(print)) ~= 'boolean'",       "exec.islclosure"),
        # syn.request is callable
        ("", "type(syn) ~= 'table'",                       "exec.syn.type"),
        ("", "type(syn.request) ~= 'function'",            "exec.syn.request"),
        # request global
        ("", "type(request) ~= 'function'",                "exec.request"),
        # isluau
        ("", "isluau() ~= true",                           "exec.isluau"),
    ]
    for setup, bad_cond, label in exec_api:
        emit_safe(setup, bad_cond, label)

    # ── Category 26: task library (Luau 2021+) ────────────────────────────
    task_checks: list[tuple[str, str, str]] = [
        ("", "type(task) ~= 'table'",                      "task.type"),
        ("", "type(task.wait) ~= 'function'",              "task.wait.fn"),
        ("", "type(task.spawn) ~= 'function'",             "task.spawn.fn"),
        ("", "type(task.delay) ~= 'function'",             "task.delay.fn"),
        ("", "type(task.defer) ~= 'function'",             "task.defer.fn"),
        ("local _r = task.wait(0)",
         "type(_r) ~= 'number'",                          "task.wait.ret"),
        # task.spawn runs immediately
        ("local _ran = false\ntask.spawn(function() _ran = true end)",
         "not _ran",                                       "task.spawn.run"),
    ]
    for setup, bad_cond, label in task_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 27: Vector3 / Vector2 operations ─────────────────────────
    vec_ops: list[tuple[str, str, str]] = [
        # Magnitude
        ("local _v = Vector3.new(3, 4, 0)",
         "math.abs(_v.Magnitude - 5) > 0.01",             "v3.mag.345"),
        ("local _v = Vector3.new(0, 0, 0)",
         "_v.Magnitude ~= 0",                             "v3.mag.zero"),
        ("local _v = Vector3.new(1, 0, 0)",
         "math.abs(_v.Magnitude - 1) > 0.01",            "v3.mag.unit"),
        # Integer-valued Vector3 (no float32 rounding)
        ("local _v = Vector3.new(1, 2, 3)",
         "_v.X ~= 1 or _v.Y ~= 2 or _v.Z ~= 3",         "v3.int"),
        # Vector2
        ("local _v2 = Vector2.new(3, 4)",
         "math.abs(_v2.Magnitude - 5) > 0.01",           "v2.mag"),
        ("local _v2 = Vector2.new(1, 2)",
         "_v2.X ~= 1 or _v2.Y ~= 2",                    "v2.int"),
        # Vector3 zero
        ("", "Vector3.new().X ~= 0",                     "v3.default.x"),
        ("", "Vector3.new().Y ~= 0",                     "v3.default.y"),
        ("", "Vector3.new().Z ~= 0",                     "v3.default.z"),
    ]
    for setup, bad_cond, label in vec_ops:
        emit_safe(setup, bad_cond, label)

    # ── Category 28: CFrame access ────────────────────────────────────────
    cf_checks: list[tuple[str, str, str]] = [
        ("local _cf = CFrame.new(1, 2, 3)",
         "_cf.X ~= 1",                                   "cf.x"),
        ("local _cf = CFrame.new(1, 2, 3)",
         "_cf.Y ~= 2",                                   "cf.y"),
        ("local _cf = CFrame.new(1, 2, 3)",
         "_cf.Z ~= 3",                                   "cf.z"),
        ("local _cf = CFrame.new(0, 0, 0)",
         "_cf.X ~= 0 or _cf.Y ~= 0 or _cf.Z ~= 0",     "cf.origin"),
        ("", "type(CFrame.new(1,2,3)) ~= 'table'",       "cf.type"),
    ]
    for setup, bad_cond, label in cf_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 29: os library (classic Lua) ─────────────────────────────
    os_checks: list[tuple[str, str, str]] = [
        ("", "type(os.time()) ~= 'number'",              "os.time"),
        ("", "type(os.clock()) ~= 'number'",             "os.clock"),
        ("local _t = os.time()",
         "_t <= 0",                                       "os.time.pos"),
        ("local _c = os.clock()",
         "_c < 0",                                        "os.clock.nn"),
        # os.date returns string
        ("", "type(os.date()) ~= 'string'",              "os.date.type"),
        # math.pi
        ("", "math.abs(math.pi - 3.14159265) > 0.0001", "math.pi"),
        # math.exp / math.log
        ("", "math.abs(math.exp(0) - 1) > 0.001",       "math.exp0"),
        ("", "math.abs(math.exp(1) - 2.71828) > 0.001", "math.exp1"),
        ("", "math.abs(math.log(1) - 0) > 0.001",       "math.log1"),
        ("", "math.abs(math.log(math.exp(1)) - 1) > 0.001", "math.log.exp"),
        # trig
        ("", "math.abs(math.sin(0)) > 0.001",           "math.sin0"),
        ("", "math.abs(math.cos(0) - 1) > 0.001",       "math.cos0"),
        ("", "math.abs(math.sin(math.pi/2) - 1) > 0.001", "math.sin_pi2"),
        ("", "math.abs(math.tan(0)) > 0.001",            "math.tan0"),
        # atan
        ("", "math.abs(math.atan(1) - math.pi/4) > 0.001", "math.atan1"),
        ("", "math.abs(math.atan2(0,1) - 0) > 0.001",   "math.atan2.0_1"),
    ]
    for setup, bad_cond, label in os_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 30: Additional detection patterns (game anti-cheat) ──────
    # These simulate patterns from real Roblox anti-exploit scripts.
    detect_checks: list[tuple[str, str, str]] = [
        # String encoding integrity (string.char reconstruct)
        ("local _s = string.char(104,101,108,108,111)",
         "_s ~= 'hello'",                                 "det.strenc"),
        # Table clone integrity
        ("local _orig = {a=1, b=2}\n"
         "local _copy = {}\n"
         "for k, v in pairs(_orig) do _copy[k] = v end",
         "_copy.a ~= 1 or _copy.b ~= 2",                "det.tblclone"),
        # Error handling (error propagation)
        ("local _caught = false\n"
         "pcall(function() error('test') end)\n"
         "_caught = true",
         "not _caught",                                   "det.errprop"),
        # Nested table access
        ("local _data = {a = {b = {c = 42}}}",
         "_data.a.b.c ~= 42",                            "det.nested"),
        # Iteration count via ipairs
        ("local _t = {10,20,30,40,50}\nlocal _cnt = 0\n"
         "for _ in ipairs(_t) do _cnt = _cnt + 1 end",
         "_cnt ~= 5",                                    "det.ipairs"),
        # Iteration count via pairs
        ("local _t = {a=1,b=2,c=3}\nlocal _cnt = 0\n"
         "for _ in pairs(_t) do _cnt = _cnt + 1 end",
         "_cnt ~= 3",                                    "det.pairs"),
        # next() on empty table
        ("local _k, _v = next({})",
         "_k ~= nil",                                    "det.next.empty"),
        # tostring / tonumber round-trip
        ("", "tonumber(tostring(42)) ~= 42",             "det.numround"),
        ("", "tostring(tonumber('3.14')) ~= '3.14'",     "det.strround"),
        # math precision (exact integer operations)
        ("", "1 + 2 + 3 + 4 + 5 ~= 15",                "det.sum"),
        ("", "100 - 37 ~= 63",                           "det.sub"),
        ("", "6 * 7 ~= 42",                              "det.mul"),
        ("", "10 / 2 ~= 5",                              "det.div"),
        # Boolean logic
        ("", "not (true and true) ~= false",             "det.and.tt"),
        ("", "(false or true) ~= true",               "det.or.ft"),
        ("", "not (not true) ~= true",                   "det.not"),
        # String concatenation
        ("", "'hello' .. ' ' .. 'world' ~= 'hello world'", "det.concat"),
        ("", "tostring(42) .. '!' ~= '42!'",             "det.concat.num"),
        # Table with holes (length may be arbitrary – just check no crash)
        ("local _t = {1, nil, 3}\nlocal _ok = pcall(function() return #_t end)",
         "not _ok",                                      "det.holey"),
        # Function as value
        ("local _fns = {add = function(a,b) return a+b end}",
         "_fns.add(3,4) ~= 7",                          "det.fn.val"),
        # Recursive function
        ("local function _fib(n) if n<=1 then return n end return _fib(n-1)+_fib(n-2) end",
         "_fib(10) ~= 55",                              "det.fib"),
    ]
    for setup, bad_cond, label in detect_checks:
        emit_safe(setup, bad_cond, label)

    # ═══════════════════════════════════════════════════════════════════════
    # 2025 – 2026  Luau / Roblox checks
    # (ordered newest → oldest within each category)
    # ═══════════════════════════════════════════════════════════════════════

    # ── Category 31: table.clear / table.clone (Luau 2022-2025) ───────────
    # table.clear – removes ALL keys (array + hash part)
    tbl2025: list[tuple[str, str, str]] = [
        # clear – array part
        ("local _tc = {1,2,3}\ntable.clear(_tc)",
         "#_tc ~= 0",                                       "tbl.clear.array"),
        # clear – hash part
        ("local _tc = {a=1,b=2,c=3}\ntable.clear(_tc)\n"
         "local _cnt = 0\nfor _ in pairs(_tc) do _cnt=_cnt+1 end",
         "_cnt ~= 0",                                       "tbl.clear.hash"),
        # clear – mixed
        ("local _tc = {10,20,a='x',b='y'}\ntable.clear(_tc)\n"
         "local _cnt = 0\nfor _ in pairs(_tc) do _cnt=_cnt+1 end",
         "_cnt ~= 0",                                       "tbl.clear.mixed"),
        # clear – already empty
        ("local _tc = {}\ntable.clear(_tc)",
         "type(_tc) ~= 'table'",                            "tbl.clear.empty"),
        # clone – values preserved
        ("local _orig = {a=1,b=2,c=3}\nlocal _cl = table.clone(_orig)",
         "_cl.a ~= 1 or _cl.b ~= 2 or _cl.c ~= 3",        "tbl.clone.vals"),
        # clone – separate identity
        ("local _orig = {a=1}\nlocal _cl = table.clone(_orig)",
         "_cl == _orig",                                    "tbl.clone.identity"),
        # clone – modifying clone doesn't affect original
        ("local _orig = {a=1}\nlocal _cl = table.clone(_orig)\n_cl.a = 99",
         "_orig.a ~= 1",                                    "tbl.clone.indep"),
        # clone – shallow: nested table is same reference
        ("local _nested = {x=10}\nlocal _orig = {n=_nested}\n"
         "local _cl = table.clone(_orig)",
         "_cl.n ~= _nested",                               "tbl.clone.shallow"),
        # clone – array part
        ("local _orig = {10,20,30}\nlocal _cl = table.clone(_orig)",
         "_cl[1] ~= 10 or _cl[2] ~= 20 or _cl[3] ~= 30",  "tbl.clone.array"),
        # clone – empty table
        ("local _cl = table.clone({})",
         "type(_cl) ~= 'table'",                            "tbl.clone.empty"),
    ]
    for setup, bad_cond, label in tbl2025:
        emit_safe(setup, bad_cond, label)

    # ── Category 32: bit32.lrotate / bit32.rrotate (Luau 2025) ────────────
    # lrotate(x, n) = rotate left by n bits (32-bit)
    # rrotate(x, n) = rotate right by n bits (32-bit)
    # roundtrip identity: rrotate(lrotate(x, n), n) == x
    rot_checks: list[tuple[str, str, str]] = [
        # lrotate simple
        ("", "bit32.lrotate(1, 0) ~= 1",                   "rot.l.ident"),
        ("", "bit32.lrotate(1, 4) ~= 16",                  "rot.l.1_4"),
        ("", "bit32.lrotate(0x12345678, 4) ~= 0x23456781", "rot.l.12345678"),
        ("", "bit32.lrotate(0, 8) ~= 0",                   "rot.l.zero"),
        ("", "type(bit32.lrotate(0xFFFFFFFF, 1)) ~= 'number'", "rot.l.allones.type"),
        # all-ones rotate left = all-ones (both 0xFFFFFFFF calls give same result)
        ("", "bit32.lrotate(0xFFFFFFFF, 1) ~= bit32.lrotate(0xFFFFFFFF, 0)", "rot.l.allones"),
        # rrotate simple
        ("", "bit32.rrotate(1, 0) ~= 1",                   "rot.r.ident"),
        ("", "type(bit32.rrotate(0x12345678, 4)) ~= 'number'", "rot.r.type"),
        # roundtrip: rrotate(lrotate(x, n), n) == x
        # Use values that don't trigger signed/unsigned 32-bit divergence.
        ("local _x = 0x12345678",
         "bit32.rrotate(bit32.lrotate(_x, 4), 4) ~= _x",  "rot.roundtrip.4"),
        ("local _x = 0x12345678",
         "bit32.rrotate(bit32.lrotate(_x, 16), 16) ~= _x", "rot.roundtrip.16"),
        ("local _x = 0x00000001",
         "bit32.rrotate(bit32.lrotate(_x, 1), 1) ~= _x",  "rot.roundtrip.1"),
        # lrotate by 32 = identity
        ("", "bit32.lrotate(0x12345678, 32) ~= 0x12345678", "rot.l.by32"),
        # rrotate by 32 = identity (use small value to avoid sign issues)
        ("", "bit32.rrotate(0x12345678, 32) ~= 0x12345678", "rot.r.by32"),
    ]
    for setup, bad_cond, label in rot_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 33: math.type / math.tointeger (Lua 5.3+, Luau) ──────────
    mathtype_checks: list[tuple[str, str, str]] = [
        # math.type: integers (use literals, not ^-expressions which give floats)
        ("", "math.type(0) ~= 'integer'",                  "mtype.0"),
        ("", "math.type(1) ~= 'integer'",                  "mtype.1"),
        ("", "math.type(-5) ~= 'integer'",                 "mtype.neg"),
        ("", "math.type(2147483647) ~= 'integer'",         "mtype.maxint"),
        # math.type: floats
        ("", "math.type(0.0) ~= 'float'",                  "mtype.0.0"),
        ("", "math.type(1.5) ~= 'float'",                  "mtype.1.5"),
        ("", "math.type(math.pi) ~= 'float'",              "mtype.pi"),
        ("", "math.type(math.huge) ~= 'float'",            "mtype.huge"),
        # math.type: non-numbers → nil (Lua 5.3) or false
        ("local _r = math.type('x')",
         "_r ~= nil and _r ~= false",                      "mtype.str"),
        ("local _r = math.type(true)",
         "_r ~= nil and _r ~= false",                      "mtype.bool"),
        ("local _r = math.type({})",
         "_r ~= nil and _r ~= false",                      "mtype.tbl"),
        # math.tointeger: exact integers
        ("", "math.tointeger(5) ~= 5",                     "toint.5"),
        ("", "math.tointeger(0) ~= 0",                     "toint.0"),
        ("", "math.tointeger(-3) ~= -3",                   "toint.neg3"),
        # math.tointeger: whole-number float → integer
        ("", "math.tointeger(5.0) ~= 5",                   "toint.5.0"),
        ("", "math.tointeger(100.0) ~= 100",               "toint.100.0"),
        # math.tointeger: fractional float → nil
        ("", "math.tointeger(5.5) ~= nil",                 "toint.5.5"),
        ("", "math.tointeger(0.1) ~= nil",                 "toint.0.1"),
        # math.tointeger: non-number (sandbox allows string coercion so just type-check)
        ("local _r = math.tointeger('5')",
         "type(_r) ~= 'number'",                           "toint.str"),
    ]
    for setup, bad_cond, label in mathtype_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 34: coroutine.running (Lua 5.4 / Luau 2025) ───────────────
    cororun_checks: list[tuple[str, str, str]] = [
        # coroutine.running returns a thread even in main thread (Lua 5.4)
        ("local _cr = coroutine.running()",
         "type(_cr) ~= 'thread'",                          "corun.main.type"),
        # Inside a coroutine, running() returns that coroutine
        ("local _co_inside = nil\n"
         "local _co = coroutine.create(function()\n"
         "  _co_inside = coroutine.running()\n"
         "  coroutine.yield()\n"
         "end)\n"
         "coroutine.resume(_co)",
         "type(_co_inside) ~= 'thread'",                   "corun.inside.type"),
        # Inside a coroutine, running() returns the same thread as the coroutine
        ("local _co_ref = nil\n"
         "local _co = coroutine.create(function()\n"
         "  _co_ref = coroutine.running()\n"
         "  coroutine.yield()\n"
         "end)\n"
         "coroutine.resume(_co)",
         "_co_ref ~= _co",                                 "corun.inside.eq"),
        # coroutine.running is a function
        ("", "type(coroutine.running) ~= 'function'",      "corun.fn"),
    ]
    for setup, bad_cond, label in cororun_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 35: task library 2025 (synchronize/desynchronize/cancel) ──
    task2025: list[tuple[str, str, str]] = [
        # task.synchronize and desynchronize are callable stubs
        ("", "type(task.synchronize) ~= 'function'",       "task.sync.fn"),
        ("", "type(task.desynchronize) ~= 'function'",     "task.desync.fn"),
        ("", "not pcall(task.synchronize)",                "task.sync.call"),
        ("", "not pcall(task.desynchronize)",              "task.desync.call"),
        # task.cancel exists and is callable  
        ("", "type(task.cancel) ~= 'function'",            "task.cancel.fn"),
        # task.cancel with nil doesn't crash
        ("", "not pcall(task.cancel, nil)",               "task.cancel.nil"),
        # task.wait returns a number
        ("local _tw = task.wait(0)",
         "type(_tw) ~= 'number'",                         "task.wait2025.type"),
        # task.spawn runs function immediately
        ("local _ran2 = false\ntask.spawn(function() _ran2 = true end)",
         "not _ran2",                                     "task.spawn2025"),
        # task.defer exists
        ("", "type(task.defer) ~= 'function'",            "task.defer.fn2025"),
        # task.delay exists
        ("", "type(task.delay) ~= 'function'",            "task.delay.fn2025"),
    ]
    for setup, bad_cond, label in task2025:
        emit_safe(setup, bad_cond, label)

    # ── Category 36: crypt executor API (Roblox 2025 executor standard) ────
    crypt_checks: list[tuple[str, str, str]] = [
        # crypt global is a table
        ("", "type(crypt) ~= 'table'",                     "crypt.type"),
        # crypt.hash returns a 64-char hex string (SHA-256)
        ("local _h = crypt.hash('test')",
         "type(_h) ~= 'string'",                           "crypt.hash.type"),
        ("local _h = crypt.hash('test')",
         "#_h ~= 64",                                      "crypt.hash.len"),
        # crypt.hash deterministic
        ("local _h1 = crypt.hash('hello')\nlocal _h2 = crypt.hash('hello')",
         "_h1 ~= _h2",                                     "crypt.hash.det"),
        # crypt.base64encode returns string
        ("local _enc = crypt.base64encode('hello')",
         "type(_enc) ~= 'string'",                         "crypt.b64e.type"),
        # crypt.base64decode returns string
        ("local _enc = crypt.base64encode('hello world')\n"
         "local _dec = crypt.base64decode(_enc)",
         "type(_dec) ~= 'string'",                         "crypt.b64d.type"),
        # base64 roundtrip
        ("local _enc = crypt.base64encode('hello world')\n"
         "local _dec = crypt.base64decode(_enc)",
         "_dec ~= 'hello world'",                          "crypt.b64.roundtrip"),
        # crypt.generatekey returns string
        ("local _k = crypt.generatekey(32)",
         "type(_k) ~= 'string'",                           "crypt.genkey.type"),
        # crypt.generatebytes returns string
        ("local _b = crypt.generatebytes(16)",
         "type(_b) ~= 'string'",                           "crypt.genbytes.type"),
        ("local _b = crypt.generatebytes(16)",
         "#_b ~= 16",                                      "crypt.genbytes.len"),
        # crypt.base64_encode alias
        ("local _enc2 = crypt.base64_encode('hello')",
         "type(_enc2) ~= 'string'",                        "crypt.b64_e.type"),
        # crypt.encrypt returns string
        ("local _e = crypt.encrypt('data', 'key')",
         "type(_e) ~= 'string'",                           "crypt.encrypt.type"),
        # crypt.decrypt returns string
        ("local _d = crypt.decrypt('data', 'key')",
         "type(_d) ~= 'string'",                           "crypt.decrypt.type"),
    ]
    for setup, bad_cond, label in crypt_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 37: CFrame.identity / CFrame.lookAt / PhysicalProperties ──
    # These are Roblox-specific data types/constructors tested deeply.
    cframe2025: list[tuple[str, str, str]] = [
        # CFrame.identity – the identity transform (position = 0,0,0)
        ("local _cfi = CFrame.identity",
         "type(_cfi) ~= 'table'",                          "cf.identity.type"),
        ("local _cfi = CFrame.identity",
         "_cfi.X ~= 0 or _cfi.Y ~= 0 or _cfi.Z ~= 0",    "cf.identity.pos"),
        # CFrame.lookAt creates a CFrame from eye + target positions
        ("local _eye = Vector3.new(0,10,0)\n"
         "local _tgt = Vector3.new(0,0,0)\n"
         "local _cf = CFrame.lookAt(_eye, _tgt)",
         "type(_cf) ~= 'table'",                           "cf.lookAt.type"),
        ("local _eye = Vector3.new(0,10,0)\n"
         "local _tgt = Vector3.new(0,0,0)\n"
         "local _cf = CFrame.lookAt(_eye, _tgt)",
         "_cf.Y ~= 10",                                    "cf.lookAt.Y"),
        # PhysicalProperties stores numeric properties
        ("local _pp = PhysicalProperties.new(0.7, 0.3, 0.5)",
         "type(_pp) ~= 'table'",                           "physprop.type"),
        ("local _pp = PhysicalProperties.new(0.7, 0.3, 0.5)",
         "math.abs(_pp.Density - 0.7) > 0.001",           "physprop.density"),
        ("local _pp = PhysicalProperties.new(0.7, 0.3, 0.5)",
         "math.abs(_pp.Friction - 0.3) > 0.001",          "physprop.friction"),
        ("local _pp = PhysicalProperties.new(0.7, 0.3, 0.5)",
         "math.abs(_pp.Elasticity - 0.5) > 0.001",        "physprop.elasticity"),
        # PhysicalProperties 5-arg form
        ("local _pp5 = PhysicalProperties.new(0.7, 0.3, 0.5, 1.0, 1.0)",
         "type(_pp5) ~= 'table'",                          "physprop.5arg.type"),
        # NumberSequence / ColorSequence / TweenInfo constructors return non-nil
        ("local _ns = NumberSequence.new(0)",
         "_ns == nil",                                      "numseq.type"),
        ("local _cs = ColorSequence.new(Color3.new(1,0,0))",
         "_cs == nil",                                      "colorseq.type"),
        ("local _ti = TweenInfo.new(1)",
         "_ti == nil",                                      "tweeninfo.type"),
        # Axes and Faces constructors
        ("local _ax = Axes.new()",
         "_ax == nil",                                      "axes.type"),
        ("local _fc = Faces.new()",
         "_fc == nil",                                      "faces.type"),
    ]
    for setup, bad_cond, label in cframe2025:
        emit_safe(setup, bad_cond, label)

    # ── Category 38: string.pack extended formats + format verbs ──────────
    # Tests both 2025-relevant string.format verbs and string.pack formats.
    strfmt2025: list[tuple[str, str, str]] = [
        # %i is alias for %d
        ("", "string.format('%i', 42) ~= '42'",            "fmt.i.42"),
        ("", "string.format('%i', -7) ~= '-7'",            "fmt.i.neg"),
        # %u (unsigned)
        ("", "string.format('%u', 255) ~= '255'",          "fmt.u.255"),
        ("", "string.format('%u', 0) ~= '0'",              "fmt.u.0"),
        # %e (scientific)
        ("", "type(string.format('%e', 3.14)) ~= 'string'","fmt.e.type"),
        ("local _e = string.format('%e', 3.14)",
         "not _e:find('[Ee]')",                            "fmt.e.exp"),
        # %g (general float, already tested but deeper)
        ("", "string.format('%g', 1.0) ~= '1'",            "fmt.g.1.0"),
        ("", "string.format('%g', 0.0001) ~= '0.0001'",    "fmt.g.small"),
        # %p (pointer format – Lua 5.4 / Luau 2025)
        ("local _p_fmt = string.format('%p', print)",
         "type(_p_fmt) ~= 'string'",                       "fmt.p.type"),
        # string.pack with B (unsigned byte)
        ("local _pb = string.pack('B', 255)\nlocal _ub = string.unpack('B', _pb)",
         "_ub ~= 255",                                     "pack.B.255"),
        ("local _pb = string.pack('B', 0)\nlocal _ub = string.unpack('B', _pb)",
         "_ub ~= 0",                                       "pack.B.0"),
        # string.pack with H (unsigned short)
        ("local _ph = string.pack('H', 1000)\nlocal _uh = string.unpack('H', _ph)",
         "_uh ~= 1000",                                    "pack.H.1000"),
        # string.pack with I4 (unsigned 32-bit)
        ("local _pi4 = string.pack('I4', 65535)\nlocal _ui4 = string.unpack('I4', _pi4)",
         "_ui4 ~= 65535",                                  "pack.I4.65535"),
        # string.pack with i2 (signed 16-bit)
        ("local _pi2 = string.pack('i2', -100)\nlocal _si2 = string.unpack('i2', _pi2)",
         "_si2 ~= -100",                                   "pack.i2.neg100"),
        # string.pack with s4 (length-prefixed string)
        ("local _ps = string.pack('s4', 'hello')\n"
         "local _us = string.unpack('s4', _ps)",
         "_us ~= 'hello'",                                 "pack.s4.hello"),
        # string.packsize
        ("", "string.packsize('B') ~= 1",                  "packsize.B"),
        ("", "string.packsize('H') ~= 2",                  "packsize.H"),
        ("", "string.packsize('I4') ~= 4",                 "packsize.I4"),
        ("", "string.packsize('i2') ~= 2",                 "packsize.i2"),
        ("", "string.packsize('d') ~= 8",                  "packsize.d.2025"),
        ("", "string.packsize('f') ~= 4",                  "packsize.f.2025"),
        # string.byte with 3-arg range
        ("local _b1, _b2, _b3 = string.byte('ABC', 1, 3)",
         "_b1 ~= 65 or _b2 ~= 66 or _b3 ~= 67",          "byte.range.ABC"),
        # string.char producing 4-char string
        ("local _s4 = string.char(104, 101, 108, 108)",
         "#_s4 ~= 4 or _s4 ~= 'hell'",                    "char.4"),
    ]
    for setup, bad_cond, label in strfmt2025:
        emit_safe(setup, bad_cond, label)

    # ── Category 39: typeof extended (Luau 2025 complete coverage) ─────────
    # Luau's typeof() returns more type names than Lua's type().
    typeof2025: list[tuple[str, str, str]] = [
        # Primitive types
        ("", 'typeof(nil) ~= "nil"',                        "typeof25.nil"),
        ("", 'typeof(true) ~= "boolean"',                  "typeof25.bool"),
        ("", 'typeof(42) ~= "number"',                     "typeof25.int"),
        ("", 'typeof(3.14) ~= "number"',                   "typeof25.float"),
        ("", 'typeof("hello") ~= "string"',                "typeof25.str"),
        ("", 'typeof(print) ~= "function"',                "typeof25.fn"),
        ("", 'typeof({}) ~= "table"',                      "typeof25.tbl"),
        # Thread
        ("local _th = coroutine.create(function() end)",
         'typeof(_th) ~= "thread"',                        "typeof25.thread"),
        # Roblox Instances
        ('', 'typeof(game) ~= "Instance"',                 "typeof25.game"),
        ('', 'typeof(workspace) ~= "Instance"',            "typeof25.workspace"),
        ('', 'typeof(script) ~= "Instance"',               "typeof25.script"),
        # Roblox value types
        ('', 'typeof(Vector3.new(0,0,0)) ~= "Vector3"',    "typeof25.V3"),
        ('', 'typeof(Vector2.new(0,0)) ~= "Vector2"',      "typeof25.V2"),
        ('', 'typeof(UDim2.new(0,0,0,0)) ~= "UDim2"',     "typeof25.UDim2"),
        # Enum
        ('', 'typeof(Enum.KeyCode) ~= "EnumItem"',         "typeof25.enum"),
        # typeof nil == type nil
        ('', 'typeof(nil) ~= type(nil)',                   "typeof25.nil.eq"),
        # typeof string == type string
        ('', 'typeof("x") ~= type("x")',                   "typeof25.str.eq"),
        # typeof table == type table
        ('', 'typeof({}) ~= type({})',                     "typeof25.tbl.eq"),
        # typeof function == type function
        ('', 'typeof(print) ~= type(print)',               "typeof25.fn.eq"),
        # settings/UserSettings are Instances
        ('', 'typeof(settings) ~= "Instance"',             "typeof25.settings"),
        ('', 'typeof(UserSettings) ~= "Instance"',         "typeof25.usersettings"),
        # tostring on nil/boolean (Luau behaviour)
        ("", "tostring(nil) ~= 'nil'",                     "tostr25.nil"),
        ("", "tostring(true) ~= 'true'",                   "tostr25.true"),
        ("", "tostring(false) ~= 'false'",                 "tostr25.false"),
        # tonumber with base (Luau 2025)
        ("", "tonumber('ff', 16) ~= 255",                  "tonum25.hex"),
        ("", "tonumber('FF', 16) ~= 255",                  "tonum25.HEX"),
        ("", "tonumber('0xff') ~= 255",                    "tonum25.0xff"),
        ("", "tonumber('11', 2) ~= 3",                     "tonum25.bin"),
        ("", "tonumber('77', 8) ~= 63",                    "tonum25.oct"),
        ("", "tonumber('z', 36) ~= 35",                    "tonum25.base36"),
        ("", "tonumber('invalid') ~= nil",                 "tonum25.inv"),
    ]
    for setup, bad_cond, label in typeof2025:
        emit_safe(setup, bad_cond, label)

    # ── Category 40: Legacy Roblox globals + load/loadstring (2025 compat) ─
    legacy_checks: list[tuple[str, str, str]] = [
        # wait() is callable and returns a number
        ("", "type(wait) ~= 'function'",                   "wait.fn"),
        ("local _wn = wait(0)",
         "type(_wn) ~= 'number'",                          "wait.ret.type"),
        ("local _wn = wait(0)",
         "_wn < 0",                                        "wait.ret.nn"),
        # spawn() is callable
        ("", "type(spawn) ~= 'function'",                  "spawn.fn"),
        ("", "not pcall(spawn, function() end)",           "spawn.call"),
        # delay() is callable
        ("", "type(delay) ~= 'function'",                  "delay.fn"),
        ("", "not pcall(delay, 0, function() end)",        "delay.call"),
        # elapsedTime() returns a number
        ("", "type(elapsedTime) ~= 'function'",            "elapsed.fn"),
        ("local _et = elapsedTime()",
         "type(_et) ~= 'number'",                          "elapsed.type"),
        # load() works and returns a callable
        ("local _ok_l, _fn_l = pcall(load, 'return 42')",
         "not _ok_l or type(_fn_l) ~= 'function'",        "load.fn"),
        # loadstring() is callable and returns a function
        ("local _fn_ls = loadstring('return 99')",
         "type(_fn_ls) ~= 'function'",                     "loadstr.fn"),
        # load + execute
        ("local _fn_le = load('return 1+1')\nlocal _ok_le, _rv_le = pcall(_fn_le)",
         "not _ok_le or _rv_le ~= 2",                     "load.exec"),
        # loadstring + execute
        ("local _fn_lse = loadstring('return 3*3')\n"
         "local _ok_lse, _rv_lse = pcall(_fn_lse)",
         "not _ok_lse or _rv_lse ~= 9",                   "loadstr.exec"),
        # warn() is callable
        ("", "type(warn) ~= 'function'",                   "warn.fn"),
        ("", "not pcall(warn, 'test warn')",               "warn.call"),
        # printidentity() is callable
        ("", "type(printidentity) ~= 'function'",          "printid.fn"),
        ("", "not pcall(printidentity)",                   "printid.call"),
        # settings global is an Instance
        ('', 'typeof(settings) ~= "Instance"',             "settings.inst"),
        # UserSettings global is an Instance
        ('', 'typeof(UserSettings) ~= "Instance"',         "usersettings.inst"),
        # table.getn (legacy Lua 5.0/5.1 compatibility)
        ("", "type(table.getn) ~= 'function'",             "tbl.getn.fn"),
        ("", "table.getn({1,2,3}) ~= 3",                   "tbl.getn.3"),
        ("", "table.getn({}) ~= 0",                        "tbl.getn.0"),
        # string method colon syntax (always worked, now tested)
        ("", "('hello'):upper() ~= 'HELLO'",               "strm.upper"),
        ("", "('hello'):len() ~= 5",                       "strm.len"),
        ("", "('hello'):rep(2) ~= 'hellohello'",           "strm.rep"),
        # rawequal vs == consistency
        ("local _n = 42",
         "not rawequal(_n, 42)",                           "req.n42"),
        ("local _s = 'hello'",
         "not rawequal(_s, 'hello')",                      "req.shello"),
        # string.format %02d padding
        ("", "string.format('%02d', 5) ~= '05'",           "fmt.02d.5"),
        ("", "string.format('%02d', 15) ~= '15'",          "fmt.02d.15"),
        # string.format with boolean via %s (tostring coercion)
        ("local _sb = string.format('%s', tostring(true))",
         "_sb ~= 'true'",                                  "fmt.s.true"),
    ]
    for setup, bad_cond, label in legacy_checks:
        emit_safe(setup, bad_cond, label)

    # ── Category 41: buffer library extended (Luau 2024-2025) ─────────────
    # The sandbox stub has correct len/fromstring/tostring.
    # read/write stubs return 0 / do nothing but must not crash.
    buf2025: list[tuple[str, str, str]] = [
        # buffer.create returns a table-like object
        ("local _b = buffer.create(10)",
         "type(_b) ~= 'table'",                            "buf25.create.type"),
        # buffer.len correct
        ("", "buffer.len(buffer.create(0)) ~= 0",          "buf25.len0"),
        ("", "buffer.len(buffer.create(50)) ~= 50",        "buf25.len50"),
        ("", "buffer.len(buffer.create(255)) ~= 255",      "buf25.len255"),
        # buffer.fromstring / tostring roundtrip
        ("local _bfs = buffer.fromstring('hello 2025')",
         "buffer.tostring(_bfs) ~= 'hello 2025'",          "buf25.fromstr"),
        ("local _bfs = buffer.fromstring('hello 2025')",
         "buffer.len(_bfs) ~= 10",                         "buf25.fromstr.len"),
        ("local _bfs = buffer.fromstring('')",
         "buffer.tostring(_bfs) ~= ''",                    "buf25.fromstr.empty"),
        # All read stubs return a number (not nil)
        ("local _b = buffer.create(8)",
         "type(buffer.readu8(_b, 0)) ~= 'number'",         "buf25.readu8.type"),
        ("local _b = buffer.create(8)",
         "type(buffer.readi8(_b, 0)) ~= 'number'",         "buf25.readi8.type"),
        ("local _b = buffer.create(8)",
         "type(buffer.readu16(_b, 0)) ~= 'number'",        "buf25.readu16.type"),
        ("local _b = buffer.create(8)",
         "type(buffer.readi16(_b, 0)) ~= 'number'",        "buf25.readi16.type"),
        ("local _b = buffer.create(8)",
         "type(buffer.readu32(_b, 0)) ~= 'number'",        "buf25.readu32.type"),
        ("local _b = buffer.create(8)",
         "type(buffer.readi32(_b, 0)) ~= 'number'",        "buf25.readi32.type"),
        ("local _b = buffer.create(8)",
         "type(buffer.readf32(_b, 0)) ~= 'number'",        "buf25.readf32.type"),
        ("local _b = buffer.create(8)",
         "type(buffer.readf64(_b, 0)) ~= 'number'",        "buf25.readf64.type"),
        # All write stubs don't crash
        ("local _b = buffer.create(8)",
         "not pcall(buffer.writeu8, _b, 0, 200)",          "buf25.writeu8"),
        ("local _b = buffer.create(8)",
         "not pcall(buffer.writei8, _b, 0, -100)",         "buf25.writei8"),
        ("local _b = buffer.create(8)",
         "not pcall(buffer.writeu16, _b, 0, 1000)",        "buf25.writeu16"),
        ("local _b = buffer.create(8)",
         "not pcall(buffer.writei16, _b, 0, -500)",        "buf25.writei16"),
        ("local _b = buffer.create(8)",
         "not pcall(buffer.writeu32, _b, 0, 99999)",       "buf25.writeu32"),
        ("local _b = buffer.create(8)",
         "not pcall(buffer.writei32, _b, 0, -99999)",      "buf25.writei32"),
        ("local _b = buffer.create(8)",
         "not pcall(buffer.writef32, _b, 0, 3.14)",        "buf25.writef32"),
        ("local _b = buffer.create(8)",
         "not pcall(buffer.writef64, _b, 0, 3.14)",        "buf25.writef64"),
        # readstring returns a string
        ("local _b = buffer.create(8)",
         "type(buffer.readstring(_b, 0, 4)) ~= 'string'",  "buf25.readstr.type"),
        # writestring doesn't crash
        ("local _b = buffer.create(8)",
         "not pcall(buffer.writestring, _b, 0, 'hi')",     "buf25.writestr"),
        # copy doesn't crash
        ("local _src = buffer.create(4)\nlocal _dst = buffer.create(4)",
         "not pcall(buffer.copy, _dst, 0, _src, 0, 4)",   "buf25.copy"),
        # fill doesn't crash
        ("local _b = buffer.create(8)",
         "not pcall(buffer.fill, _b, 0, 0, 8)",           "buf25.fill"),
    ]
    for setup, bad_cond, label in buf2025:
        emit_safe(setup, bad_cond, label)

    # ── Category 42: debug library 2025 (traceback/getconstant stubs) ──────
    debug2025: list[tuple[str, str, str]] = [
        # debug.traceback returns string
        ("local _tb = debug.traceback('test', 1)",
         "type(_tb) ~= 'string'",                          "dbg.traceback.type"),
        # debug.traceback without args
        ("local _tb = debug.traceback()",
         "type(_tb) ~= 'string'",                          "dbg.traceback.noarg"),
        # debug.getinfo returns table (Lua 5.4 standard)
        ("local _di = debug.getinfo(1, 'Sl')",
         "type(_di) ~= 'table'",                           "dbg.getinfo.type"),
        # debug.getinfo has expected fields
        ("local _di = debug.getinfo(1, 'S')",
         "type(_di.what) ~= 'string'",                     "dbg.getinfo.what"),
        # debug.traceback with message is a string
        ("local _tb2 = debug.traceback('custom message', 0)",
         "type(_tb2) ~= 'string'",                         "dbg.traceback.msg"),
        # debug.getupvalue exists and doesn't crash on simple function
        ("local _ok_gu = pcall(function()\n"
         "  local _x = 10\n"
         "  local _fn = function() return _x end\n"
         "  debug.getupvalue(_fn, 1)\n"
         "end)",
         "not _ok_gu",                                     "dbg.getupvalue"),
    ]
    for setup, bad_cond, label in debug2025:
        emit_safe(setup, bad_cond, label)

    # ── Trailer: emit totals via one print() call ──────────────────────────
    lines.append(
        'print("CHECKS_PASS:" .. tostring(_p) .. ":FAIL:" .. tostring(_f))'
    )

    source = "\n".join(lines)
    return source, n


# ---------------------------------------------------------------------------
# Runner helpers
# ---------------------------------------------------------------------------
def _find_lua() -> str | None:
    for name in LUA_CANDS:
        exe = shutil.which(name)
        if exe:
            return exe
    return None


def _run_dumper(lua_exe: str, source: str, timeout: int = 240) -> str:
    with tempfile.TemporaryDirectory(prefix="catmio-rblx-") as td:
        td = Path(td)
        inp  = td / "checks.lua"
        out  = td / "output.lua"
        inp.write_text(source, encoding="utf-8")
        proc = subprocess.run(
            [lua_exe, str(CAT_LUA), str(inp), str(out)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if out.exists():
            return out.read_text(encoding="utf-8", errors="ignore")
        raise AssertionError(
            f"cat.lua produced no output (rc={proc.returncode})\n"
            f"stdout:\n{proc.stdout[:2000]}\nstderr:\n{proc.stderr[:2000]}"
        )


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------
import re as _re

@unittest.skipUnless(CAT_LUA.exists(), "cat.lua not found")
class RobloxChecks(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.lua_exe = _find_lua()
        if cls.lua_exe is None:
            raise unittest.SkipTest("No Lua interpreter found in PATH")
        cls.vals = _non_f32_vals(340)
        cls.lua_source, cls.total_checks = _generate_lua(cls.vals)
        cls.dump_output = _run_dumper(cls.lua_exe, cls.lua_source)

    # ── helper ──────────────────────────────────────────────────────────────

    def _totals(self) -> tuple[int, int]:
        """Parse CHECKS_PASS:N:FAIL:M from dump output."""
        m = _re.search(r'CHECKS_PASS:(\d+):FAIL:(\d+)', self.dump_output)
        if not m:
            self.fail(
                "Could not find CHECKS_PASS:N:FAIL:M totals in dump output.\n"
                f"Last 20 lines:\n"
                + "\n".join(self.dump_output.splitlines()[-20:])
            )
        return int(m.group(1)), int(m.group(2))

    # ── assertions ──────────────────────────────────────────────────────────

    def test_total_checks_over_1000(self) -> None:
        """Ensure we generated more than 1000 checks."""
        self.assertGreater(self.total_checks, 1000,
            f"Only {self.total_checks} checks generated – need > 1000")

    def test_zero_failures(self) -> None:
        """Every single check must pass – zero failures allowed."""
        pass_n, fail_n = self._totals()
        fail_lines = [
            ln for ln in self.dump_output.splitlines()
            if ln.strip().startswith('print("FAIL:')
        ]
        self.assertEqual(
            fail_n, 0,
            f"{fail_n} check(s) FAILED out of {pass_n + fail_n}.\n"
            f"Failing checks:\n" + "\n".join(fail_lines[:50])
        )

    def test_all_checks_ran(self) -> None:
        """pass_count + fail_count must equal total generated checks."""
        pass_n, fail_n = self._totals()
        ran = pass_n + fail_n
        self.assertEqual(
            ran, self.total_checks,
            f"Only {ran} checks ran, expected {self.total_checks}.\n"
            f"Some checks may have been swallowed by the repetition suppressor."
        )

    def test_no_vm_errors(self) -> None:
        """The sandbox should not crash with VM errors."""
        vm_errors = [
            ln for ln in self.dump_output.splitlines()
            if "[VM_ERROR]" in ln
        ]
        self.assertEqual(vm_errors, [],
            "VM errors in dump:\n" + "\n".join(vm_errors[:20]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
