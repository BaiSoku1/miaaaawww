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
    """Return (lua_source, expected_pass_count)."""
    lines: list[str] = []
    n = 0

    def emit(check_lua: str) -> None:
        nonlocal n
        n += 1
        lines.append(f"do -- check #{n}\n{textwrap.indent(check_lua.strip(), '  ')}\nend")

    # ── Category 1: Vector3 float32 precision ─────────────────────────────
    # Each value is tested as X, Y, and Z independently → 3 checks per value.
    # In Roblox (and in our fixed sandbox) Vector3 stores float32, so
    # reading back a non-exact value never equals the original float64 literal.
    for v in vals:
        fs = _fmt(v)
        emit(f'local v = Vector3.new({fs}, 0, 0)\n'
             f'if v.X == {fs} then print("detected") else print("pass") end')
        emit(f'local v = Vector3.new(0, {fs}, 0)\n'
             f'if v.Y == {fs} then print("detected") else print("pass") end')
        emit(f'local v = Vector3.new(0, 0, {fs})\n'
             f'if v.Z == {fs} then print("detected") else print("pass") end')

    # ── Category 2: Part.Position round-trip ──────────────────────────────
    # Assign a Vector3 with a non-exact float32 value to Part.Position, read
    # back, and verify the stored component ≠ the original double literal.
    for v in vals[:50]:
        fs = _fmt(v)
        emit(f'local p = Instance.new("Part")\n'
             f'p.Position = Vector3.new({fs}, {fs}, {fs})\n'
             f'local rb = p.Position\n'
             f'if rb.X == {fs} then print("detected") else print("pass") end\n'
             f'p:Destroy()')

    # ── Category 3: CFrame.new position float32 ───────────────────────────
    for v in vals[:50]:
        fs = _fmt(v)
        emit(f'local cf = CFrame.new({fs}, {fs}, {fs})\n'
             f'if cf.X == {fs} then print("detected") else print("pass") end')

    # ── Category 4: Color3 float32 precision ──────────────────────────────
    for v in vals[:50]:
        fs = _fmt(v)
        # Clamp to [0,1] range for Color3
        if 0 < v <= 1.0:
            emit(f'local c = Color3.new({fs}, {fs}, {fs})\n'
                 f'if c.R == {fs} then print("detected") else print("pass") end')

    # ── Category 5: Instance typeof / IsA checks ──────────────────────────
    type_checks = [
        ('local p = Instance.new("Part")',
         'typeof(p) ~= "Instance"'),
        ('local p = Instance.new("Part")',
         'not p:IsA("Part")'),
        ('local p = Instance.new("Part")',
         'not p:IsA("BasePart")'),
        ('local p = Instance.new("Part")',
         'not p:IsA("Instance")'),
        ('local v = Vector3.new(1, 2, 3)',
         'typeof(v) ~= "Vector3"'),
        ('local c = Color3.new(1, 0, 0)',
         'typeof(c) ~= "Color3"'),
        ('local cf = CFrame.new(0, 0, 0)',
         'typeof(cf) ~= "CFrame"'),
        ('local h = Instance.new("Humanoid")',
         'not h:IsA("Humanoid")'),
        ('local h = Instance.new("Humanoid")',
         'not h:IsA("Instance")'),
        ('local s = Instance.new("Script")',
         'typeof(s) ~= "Instance"'),
        ('local m = Instance.new("Model")',
         'typeof(m) ~= "Instance"'),
        ('local f = Instance.new("Frame")',
         'typeof(f) ~= "Instance"'),
        ('local rp = Instance.new("RemoteEvent")',
         'typeof(rp) ~= "Instance"'),
        ('local bf = Instance.new("BindableFunction")',
         'typeof(bf) ~= "Instance"'),
        ('local v2 = Vector2.new(1, 2)',
         'typeof(v2) ~= "Vector2"'),
        ('local p = Instance.new("Part")',
         'p.ClassName ~= "Part"'),
        ('local p = Instance.new("Part")',
         'p.Name ~= "Part"'),
        ('local h = Instance.new("Humanoid")',
         'h.Health ~= 100'),
        ('local h = Instance.new("Humanoid")',
         'h.MaxHealth ~= 100'),
        ('local h = Instance.new("Humanoid")',
         'h.WalkSpeed ~= 16'),
        ('local p = Instance.new("Part")',
         'p.CanCollide ~= true'),
        ('local p = Instance.new("Part")',
         'p.Visible ~= true'),
        ('local p = Instance.new("Part")',
         'p.Archivable ~= true'),
        ('local p = Instance.new("Part")',
         'p.Locked ~= false'),
        ('local p = Instance.new("Part")',
         'p.Anchored ~= false'),
        ('local sf = Instance.new("StringValue")',
         'typeof(sf) ~= "Instance"'),
        ('local iv = Instance.new("IntValue")',
         'typeof(iv) ~= "Instance"'),
        ('local bv = Instance.new("BoolValue")',
         'typeof(bv) ~= "Instance"'),
        ('local nv = Instance.new("NumberValue")',
         'typeof(nv) ~= "Instance"'),
        ('local weld = Instance.new("WeldConstraint")',
         'typeof(weld) ~= "Instance"'),
    ]
    for setup, cond in type_checks:
        emit(f'{setup}\nif {cond} then print("detected") else print("pass") end')

    # ── Category 6: Default property / math / string checks ───────────────
    misc_checks = [
        # Math operations that are exact
        'if math.floor(3.7) ~= 3 then print("detected") else print("pass") end',
        'if math.ceil(3.2) ~= 4 then print("detected") else print("pass") end',
        'if math.abs(-5) ~= 5 then print("detected") else print("pass") end',
        'if math.max(1, 2, 3) ~= 3 then print("detected") else print("pass") end',
        'if math.min(1, 2, 3) ~= 1 then print("detected") else print("pass") end',
        'if math.sqrt(4) ~= 2 then print("detected") else print("pass") end',
        'if 2^10 ~= 1024 then print("detected") else print("pass") end',
        # String operations
        'if string.len("hello") ~= 5 then print("detected") else print("pass") end',
        'if string.upper("abc") ~= "ABC" then print("detected") else print("pass") end',
        'if string.lower("XYZ") ~= "xyz" then print("detected") else print("pass") end',
        'if string.sub("hello", 1, 2) ~= "he" then print("detected") else print("pass") end',
        'if string.rep("ab", 3) ~= "ababab" then print("detected") else print("pass") end',
        'if string.reverse("abc") ~= "cba" then print("detected") else print("pass") end',
        'if type(tostring(123)) ~= "string" then print("detected") else print("pass") end',
        'if type(tonumber("42")) ~= "number" then print("detected") else print("pass") end',
        # Table operations
        'local t={1,2,3}\nif #t ~= 3 then print("detected") else print("pass") end',
        'local t={}\ntable.insert(t,1)\nif #t ~= 1 then print("detected") else print("pass") end',
        'local t={1,2,3}\ntable.remove(t,1)\nif #t ~= 2 then print("detected") else print("pass") end',
        'local t={3,1,2}\ntable.sort(t)\nif t[1] ~= 1 then print("detected") else print("pass") end',
        # Exact integer Vector3
        'local v=Vector3.new(1,2,3)\nif v.X~=1 or v.Y~=2 or v.Z~=3 then print("detected") else print("pass") end',
        # Magnitude of known vector
        ('local v=Vector3.new(3,4,0)\n'
         'local m=v.Magnitude\n'
         'if math.abs(m-5) > 0.01 then print("detected") else print("pass") end'),
        # pcall succeeds on valid code
        'local ok=pcall(function() return 1+1 end)\nif not ok then print("detected") else print("pass") end',
        # type checks on primitives
        'if type(1) ~= "number" then print("detected") else print("pass") end',
        'if type("x") ~= "string" then print("detected") else print("pass") end',
        'if type(true) ~= "boolean" then print("detected") else print("pass") end',
        'if type(nil) ~= "nil" then print("detected") else print("pass") end',
        'if type({}) ~= "table" then print("detected") else print("pass") end',
        # select
        'if select("#",1,2,3) ~= 3 then print("detected") else print("pass") end',
        # rawlen
        'local t={10,20,30}\nif rawlen(t) ~= 3 then print("detected") else print("pass") end',
        # tostring of number
        'if type(tostring(math.pi)) ~= "string" then print("detected") else print("pass") end',
    ]
    for check in misc_checks:
        emit(check)

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

    # ── individual assertions ──────────────────────────────────────────────

    def test_total_checks_over_1000(self) -> None:
        """Ensure we generated more than 1000 checks."""
        self.assertGreater(self.total_checks, 1000,
            f"Only {self.total_checks} checks generated – need > 1000")

    def test_no_detected_in_output(self) -> None:
        """No check may produce print("detected") in the dump."""
        detected_lines = [
            ln for ln in self.dump_output.splitlines()
            if 'print("detected")' in ln or "print('detected')" in ln
        ]
        if detected_lines:
            self.fail(
                f'{len(detected_lines)} "detected" line(s) found:\n'
                + "\n".join(detected_lines[:30])
            )

    def test_all_pass_present(self) -> None:
        """Every check should have contributed a print("pass") call."""
        pass_count = self.dump_output.count('print("pass")')
        self.assertGreaterEqual(
            pass_count, self.total_checks,
            f"Expected ≥{self.total_checks} print(\"pass\") but found {pass_count}"
        )

    def test_no_vm_errors(self) -> None:
        """The sandbox should not crash with VM errors."""
        vm_errors = [
            ln for ln in self.dump_output.splitlines()
            if "[VM_ERROR]" in ln
        ]
        self.assertEqual(vm_errors, [],
            f"VM errors in dump:\n" + "\n".join(vm_errors[:20]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
