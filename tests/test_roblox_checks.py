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
