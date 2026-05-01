# Envlogger v2

`cat_envlogger.lua` is the output/logging layer of catmio. After the
sandbox finishes executing the target script, the envlogger walks the
collected runtime state and writes the human-readable Lua dump that the
analyst reads.

## Section registry

Every dumper is declared as a **section**. Sections have a name, title,
gating function, category, and `run()` body. Adding a new dumper is a
five-line registration:

```lua
_register("my_thing", {
    title    = "MY THING",
    category = "calls",
    gate     = function() return r.MY_THING_ENABLED end,
    run      = function() ... end,
})
```

The legacy `q.dump_<name>()` functions are thin wrappers around `_run(...)`
so the existing `cat_sandbox.lua` call sequence is unchanged.

## Public API

### Backwards-compatible (called by `cat_sandbox.lua`)

| Function                          | Purpose                                                |
|-----------------------------------|--------------------------------------------------------|
| `q.dump_captured_globals(env, b)` | New global writes (skips baseline keys)                |
| `q.dump_captured_upvalues()`      | Upvalues of every registered closure                   |
| `q.dump_string_constants()`       | Dedup'd string refs collected at runtime               |
| `q.dump_wad_strings()`            | WeAreDevs decoded string pool                          |
| `q.dump_xor_strings()`            | XOR-decrypted string constants                         |
| `q.dump_k0lrot_strings()`         | Generic-wrapper / K0lrot decoded pool                  |
| `q.dump_lightcate_strings()`      | Lightcate v2.0.0 decoded pool                          |
| `q.dump_prometheus_strings()`     | Prometheus decoded pool                                |
| `q.dump_lunr_strings()`           | Lunr v1.0.7 decoded pool                               |
| `q.dump_remote_summary()`         | Per-remote call counts (sorted by count desc)          |
| `q.dump_instance_creations()`     | `Instance.new()` class histogram                       |
| `q.dump_script_loads()`           | `require()` / `loadstring()` event log                 |
| `q.dump_gc_scan()`                | Closures + upvalues found via GC scan                  |
| `q.run_deferred_hooks()`          | Drain & execute hooks queued during execution          |

### New (additive)

| Function                            | Purpose                                              |
|-------------------------------------|------------------------------------------------------|
| `q.envlogger_run_all(env, b)`       | Run every registered section in canonical order      |
| `q.envlogger_stats()`               | Read-only counters (sections run, lines, dedup, ...) |
| `q.envlogger_sections()`            | List of `{name, title, category}` for every section  |
| `q.envlogger_reset()`               | Reset stats + interner state between runs            |

## Config flags (`cat_config.lua`)

All envlogger-specific flags default to safe values; existing dump output
is unchanged unless you opt in.

| Flag                       | Default | Effect                                                       |
|----------------------------|---------|--------------------------------------------------------------|
| `ENVLOGGER_RUN_SUMMARY`         | `false` | Emit a one-shot dashboard summarising what was produced  |
| `ENVLOGGER_INTERN_POOLS`        | `false` | Cross-section string interning (dedup pool entries by value) |
| `ENVLOGGER_DIAGNOSTICS`         | `false` | Emit a diagnostics block (caught errors, truncations)    |
| `ENVLOGGER_LABEL_GLOBAL_SOURCE` | `false` | Annotate `dump_captured_globals` rows with `-- (env)` / `-- (_G)` |
| `MAX_LINES_PER_SECTION`         | `10000` | Per-section line budget; truncation is announced as a comment    |

## Smart string classification

When emitting a pool entry, the envlogger picks a meaningful variable
prefix based on what the value looks like:

| Prefix      | Matches                                                   |
|-------------|-----------------------------------------------------------|
| `_webhook_` | `discord.com/api/webhooks/` and `discordapp.com/...`      |
| `_url_`     | `^https?://`                                              |
| `_asset_`   | `rbxassetid://`, `rbxthumb://`, `rbxhttp://`, `rbx://`    |
| `_src_`     | `function(`, `local <ident>`, `return ` (and len > 80)    |
| `_json_`    | starts with `{`/`[` and ends with `}`/`]`                 |
| `_jwt_`     | three base64url segments separated by `.`                 |
| `_token_`   | three base64url segments separated by `.`, len ≥ 50       |
| `_hex_`     | all hex, length ≥ 16                                      |
| `_b64_`     | all base64, length ≥ 32                                   |
| `_ip_`      | dotted-quad IPv4                                          |
| pool-default | anything else (`_wad_`, `_xor_`, `_lc_`, ...)            |

## Defenses

- Reserved-word safe: identifiers matching Lua keywords (`end`, `local`, ...)
  are rejected before emission so the dump always parses.
- pcall-wrapped iteration: every `pairs`/`ipairs`/`getupvalue` call is
  guarded against runtime iterator failures.
- Per-section budgets with announced truncation.
- Output-stage `BLOCKED_OUTPUT_PATTERNS` still apply on top.

## Tests

```sh
lua5.3 tests/test_envlogger.lua
lua5.1 tests/test_envlogger.lua
```

The harness mocks `_CATMIO`, `loadfile()`s the real envlogger, and
asserts behavior for each public dumper, plus run-summary, dedup,
section-budget, and reserved-word handling.
