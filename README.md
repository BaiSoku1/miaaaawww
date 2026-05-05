# senvielle ;>

Sandbox + deobfuscator for Roblox/Luau scripts. The engine is split across
seven Lua modules; `senvielle_dump.lua` is a single-file bundle of all of them so
the dumper can be distributed and run as one self-contained script.

## Layout

| File                  | Purpose                                                                                    |
|-----------------------|--------------------------------------------------------------------------------------------|
| `senvielle_dump.lua`             | Glue + Roblox proxy + main loop (entrypoint when running modular)                          |
| `senvielle_config.lua`      | Configuration table + `BLOCKED_OUTPUT_PATTERNS`                                            |
| `senvielle_bit.lua`         | Portable bitwise library (Lua 5.1 compatible)                                              |
| `senvielle_stubs.lua`       | Exploit-executor function stubs (sandbox shim)                                             |
| `senvielle_deobf.lua`       | Static deobfuscator / string-pool extractor                                                |
| `senvielle_envlogger.lua`   | Output / dump layer (envlogger v3, [`docs/envlogger.md`](docs/envlogger.md))               |
| `senvielle_sandbox.lua`     | Sandbox execution + `q.dump_file` / `q.dump_string` entrypoints                            |
| `catmio.lua`          | **Generated bundle** — every module above inlined into a single `lua` chunk                |
| `cat.py`              | Discord bot wrapper (orchestrator)                                                         |

## Running

### Bundled (single file, no other `senvielle_*.lua` needed)

```sh
lua5.3 catmio.lua input.lua [output.lua]
```

### Modular (uses `dofile` to load the other modules from the same directory)

```sh
lua5.3 cat.lua input.lua [output.lua]
```

Both produce identical output (sans line-number references inside
`HOT-LINE LOOP SUMMARY`, which differ because the bundle changes line
numbering).

## Regenerating the bundle

`catmio.lua` is generated from the seven module files with a small
Python script:

```sh
python3 scripts/bundle.py
```

The script inlines each `_load_module(...)` call site in `cat.lua` with
the contents of the corresponding module, wrapped in an immediately
invoked function so each module's `return` statement keeps working.

Re-run `scripts/bundle.py` whenever any of the `senvielle_*.lua` files change.

## Tests

```sh
lua5.3 tests/test_envlogger.lua
lua5.1 tests/test_envlogger.lua
```

105 assertions across 30 cases covering every public dumper, the run
summary, dedup, per-section budget, threat assessment, fingerprint, the
classifier, and the analytical helpers. See
[`docs/envlogger.md`](docs/envlogger.md) for full envlogger reference.
