import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CAT_LUA = REPO_ROOT / "cat.lua"
LUA_CANDIDATES = ("lua5.3", "lua5.1", "lua5.4", "luajit", "lua")


def _find_lua() -> str | None:
    for name in LUA_CANDIDATES:
        exe = shutil.which(name)
        if exe:
            return exe
    return None


def _run_cat(lua_exe: str, source: str, timeout: int = 120) -> str:
    with tempfile.TemporaryDirectory(prefix="catmio-tests-") as td:
        td_path = Path(td)
        input_path = td_path / "input.lua"
        output_path = td_path / "output.lua"
        input_path.write_text(source, encoding="utf-8")
        proc = subprocess.run(
            [lua_exe, str(CAT_LUA), str(input_path), str(output_path)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if output_path.exists():
            return output_path.read_text(encoding="utf-8", errors="ignore")
        raise AssertionError(
            f"cat.lua did not produce output (rc={proc.returncode})\n"
            f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        )


@unittest.skipUnless(CAT_LUA.exists(), "cat.lua not found")
class EnvloggerLuauSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lua_exe = _find_lua()
        if cls.lua_exe is None:
            raise unittest.SkipTest("No Lua interpreter found in PATH")

    def test_vector3_part_position_roundtrip_over_1000_cases(self) -> None:
        total_cases = 1024
        lua = textwrap.dedent(
            f"""
            local total = 0
            for i = 1, {total_cases} do
                local p = Instance.new("Part")
                local x = (i * 37) % 401 - 200
                local y = (i * 59) % 503 - 251
                local z = (i * 83) % 607 - 303
                p.Position = Vector3.new(x, y, z)
                local back = p.Position
                if back.X ~= x or back.Y ~= y or back.Z ~= z then
                    error(string.format("PRECISION_CASE_%d_FAIL (%s,%s,%s) != (%s,%s,%s)",
                        i, tostring(back.X), tostring(back.Y), tostring(back.Z), tostring(x), tostring(y), tostring(z)))
                end
                total = total + 1
            end
            print("ENVLOGGER_CASES_OK:" .. total)
            """
        )
        dumped = _run_cat(self.lua_exe, lua)
        self.assertIn("ENVLOGGER_CASES_OK:1024", dumped)
        self.assertNotIn("[VM_ERROR]", dumped)
        self.assertNotIn("[ANTI_TAMPER]", dumped)

    def test_precision_failure_is_reported_as_vm_error(self) -> None:
        lua = textwrap.dedent(
            """
            local p = Instance.new("Part")
            p.Position = Vector3.new(1, 2, 3)
            local back = p.Position
            if back.X ~= 999 then
                error("PRECISION_ASSERT_FAIL")
            end
            """
        )
        dumped = _run_cat(self.lua_exe, lua)
        self.assertTrue(
            any("PRECISION_ASSERT_FAIL" in ln and "VM_ERROR" in ln
                for ln in dumped.splitlines()),
            f"Expected a [VM_ERROR] line containing 'PRECISION_ASSERT_FAIL'.\n"
            f"Dump output:\n{dumped[:1000]}"
        )
        self.assertNotIn("[ANTI_TAMPER]", dumped)
        self.assertNotIn("Detected loops", dumped)


if __name__ == "__main__":
    unittest.main()
