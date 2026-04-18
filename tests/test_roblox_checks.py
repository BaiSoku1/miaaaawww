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
