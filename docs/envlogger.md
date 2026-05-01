# Envlogger v3

`cat_envlogger.lua` is the output/logging layer of catmio. After the
sandbox finishes executing the target script, the envlogger walks the
collected runtime state and writes the human-readable Lua dump that the
analyst reads.

v3 keeps every public function from v1/v2 (so `cat_sandbox.lua` works
unchanged) and adds nine new sections that surface tracking state the
sandbox already collects but earlier versions never wrote out:

- **INSTANCE PROPERTY STORE** — `gethiddenproperty` / `sethiddenproperty`
  / `setinstanceproperty` writes per Instance, sorted by write count.
- **HOOK CALL TRACKER** — every `hookfunction`, `hookmetamethod`,
  `replaceclosure`, `detourfn` registration and call, grouped by target.
- **HOT-LINE LOOP SUMMARY** — top-N lines from `t.loop_line_counts` with
  `[HOT]` markers when the loop-detection threshold was exceeded.
- **RUNTIME COUNTERS** — non-zero values from `t.instance_count`,
  `t.tween_count`, `t.connection_count`, `t.task_count`, etc.
- **RUNTIME POINTERS** — `t.last_http_url`, `t.namecall_method`,
  `t.last_error`, `t.exec_start_time`.
- **OBFUSCATOR FINGERPRINT** — heuristic identification of the
  obfuscator(s) that produced the input, by string-pool size.
- **THREAT ASSESSMENT** — 0..100 risk score with `CLEAN/LOW/ELEVATED/
  HIGH/CRITICAL` verdict, indicator histogram, and redacted samples.
- **STRING CROSS-REFERENCES** — interner digest (id, first-seen pool,
  preview) when `ENVLOGGER_INTERN_POOLS=true`.
- **EVENT TIMELINE** — chronological merge of script loads, instance
  creations, remote calls, and hook events.

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

The legacy `q.dump_<name>()` functions are thin wrappers around
`_public_run(...)` (which `pcall`s `_run`, which itself `pcall`s the
gate predicate). A single broken section can never abort the post-exec
sequence in `cat_sandbox.lua`.

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

### v3 sections (called by `cat_sandbox.lua` after the legacy 14)

| Function                            | Purpose                                                 |
|-------------------------------------|---------------------------------------------------------|
| `q.dump_property_writes()`          | `t.property_store` (Instance → {prop → value})          |
| `q.dump_hook_calls()`               | `t.hook_calls` aggregated per target / kind             |
| `q.dump_loop_summary()`             | `t.loop_line_counts` top-N with `[HOT]` markers         |
| `q.dump_counters()`                 | non-zero `t.*_count` / depth / score counters           |
| `q.dump_runtime_pointers()`         | `last_http_url`, `namecall_method`, `last_error`, ...   |
| `q.dump_obfuscator_fingerprint()`   | which obfuscator(s) produced this input                 |
| `q.dump_threat_assessment()`        | risk score 0..100 + indicator table                     |
| `q.dump_cross_references()`         | string-interner digest (when `ENVLOGGER_INTERN_POOLS`)  |
| `q.dump_timeline()`                 | chronological event log (LOAD/NEW/REMOTE/HOOK)          |

### Analytical helpers

| Function                        | Returns                                                                |
|---------------------------------|------------------------------------------------------------------------|
| `q.envlogger_run_all(env, b)`   | Run every registered section in canonical order (incl. v3 ones)        |
| `q.envlogger_stats()`           | Read-only counters (sections run, lines, dedup, errors, ...)           |
| `q.envlogger_sections()`        | List of `{name, title, category}` for every section                    |
| `q.envlogger_reset()`           | Reset stats + interner state between runs                              |
| `q.envlogger_threat_score()`    | `{risk, verdict, sources_scanned, fragment_counts, class_counts}`      |
| `q.envlogger_fingerprint()`     | Sorted list of `{label, field, count, score}` for obfuscator detection |
| `q.envlogger_string_entropy(s)` | Shannon bits-per-byte                                                  |
| `q.envlogger_classify(s)`       | `(classifier_name, prefix)` (e.g. `"webhook", "_webhook"`)             |
| `q.envlogger_pretty_print(v)`   | Multi-line table renderer with cycle detection                         |

## Config flags (`cat_config.lua`)

Every v3 section is gated by a `DUMP_*` flag that defaults to `true`.
Disabling a section is a one-line config edit; the legacy v1/v2 output
is unchanged when all `DUMP_*` v3 flags are set to `false`.

| Flag                            | Default | Effect                                                          |
|---------------------------------|---------|-----------------------------------------------------------------|
| `ENVLOGGER_RUN_SUMMARY`         | `false` | Emit a one-shot dashboard summarising what was produced         |
| `ENVLOGGER_INTERN_POOLS`        | `false` | Cross-section string interning (dedup pool entries by value)    |
| `ENVLOGGER_DIAGNOSTICS`         | `false` | Emit a diagnostics block (caught errors, truncations)           |
| `ENVLOGGER_LABEL_GLOBAL_SOURCE` | `false` | Annotate `dump_captured_globals` rows with `-- (env)` / `-- (_G)` |
| `MAX_LINES_PER_SECTION`         | `10000` | Per-section line budget; truncation is announced as a comment   |
| `DUMP_PROPERTY_STORE`           | `true`  | Enable INSTANCE PROPERTY STORE section                          |
| `DUMP_HOOK_CALLS`               | `true`  | Enable HOOK CALL TRACKER section                                |
| `DUMP_LOOP_SUMMARY`             | `true`  | Enable HOT-LINE LOOP SUMMARY section                            |
| `DUMP_COUNTERS`                 | `true`  | Enable RUNTIME COUNTERS section                                 |
| `DUMP_RUNTIME_POINTERS`         | `true`  | Enable RUNTIME POINTERS section                                 |
| `DUMP_OBFUSCATOR_FINGERPRINT`   | `true`  | Enable OBFUSCATOR FINGERPRINT section                           |
| `DUMP_THREAT_ASSESSMENT`        | `true`  | Enable THREAT ASSESSMENT section                                |
| `DUMP_TIMELINE`                 | `true`  | Enable EVENT TIMELINE section                                   |
| `LOOP_SUMMARY_TOP_N`            | `25`    | Number of hot lines shown in HOT-LINE LOOP SUMMARY              |
| `THREAT_SAMPLE_CAP`             | `20`    | Max indicator samples emitted in THREAT ASSESSMENT              |
| `THREAT_SCAN_GLOBAL_TABLE`      | `true`  | Include `_G` (not just sandbox env) in threat scan              |
| `TIMELINE_CAP`                  | `200`   | Max events shown in EVENT TIMELINE                              |

## Smart string classification

When emitting a pool entry — and when computing the threat score — the
envlogger picks a meaningful variable prefix and intent-name based on
what the value looks like. Order is most-specific first; the first
match wins.

| Prefix       | Name             | Matches                                                          |
|--------------|------------------|------------------------------------------------------------------|
| `_webhook`   | `webhook`        | `discord[app]?.com/api/webhooks/`                                |
| `_tgbot`     | `telegram_bot`   | `api.telegram.org/bot…`                                          |
| `_bytecode`  | `lua_bytecode`   | starts with `\27Lua`, `\27Luau`, or `\27\76uau`                  |
| `_asset`     | `roblox_uri`     | `rbxassetid://`, `rbxthumb://`, `rbxhttp://`, `rbx://`, `rbxasset://` |
| `_url`       | `url_https`/`url_http`/`url_ftp` | `^https://`, `^http://`, `^ftp[s]?://`            |
| `_ws`        | `url_ws`         | `^ws[s]?://`                                                     |
| `_rbxval`    | `roblox_literal` | `Color3.fromRGB`, `Vector3.new`, `CFrame.new`, `UDim2.new`, ...  |
| `_src`       | `lua_source`     | length > 60 with ≥2 of: `function(`, `local <ident>`, `return `, `end…`, `then…` |
| `_json`      | `json`           | wraps `{}`/`[]` and contains a delimiter near the start          |
| `_jwt`       | `jwt`            | three base64url segments separated by `.`, length ≥ 40, starts `e` |
| `_uuid`      | `uuid`           | 8-4-4-4-12 hex                                                   |
| `_ipv6`      | `ipv6`           | hex groups separated by `:`                                      |
| `_ip`        | `ip`             | dotted-quad IPv4                                                 |
| `_email`     | `email`          | RFC-shape `local@domain.tld`                                     |
| `_rbxid`     | `rbx_id`         | pure numeric, 7..19 digits                                       |
| `_hex`       | `hex`            | all hex, even length ≥ 16                                        |
| `_b64`       | `b64`            | all base64, length ≥ 32, entropy > 4.5                           |
| `_b32`       | `b32`            | RFC-4648 `[A-Z2-7]+=*`, length divisible by 8                    |
| `_token`     | `discord_token`  | three base64url segments separated by `.`, length ≥ 50           |
| `_bin`       | `binary_blob`    | non-printable byte present, entropy > 5.5                        |
| `_ident`     | `ident`          | safe Lua identifier shape                                        |
| pool-default | `ref`            | anything else (e.g. `_wad_…`, `_xor_…`)                          |

## Threat assessment

`q.envlogger_threat_score()` walks every emitted string source
(interner, all pools, captured globals, `_G`, property store, hook
args, remote args, `last_http_url`) and accumulates a risk score:

- Each unique fragment hit from `_THREAT_FRAGMENTS` adds
  `min(40, 8 + log(1+n)*6)` points.
- A `webhook` classifier hit adds 30; `telegram_bot` 20;
  `discord_token` 15; `lua_bytecode` 10.
- The total is capped at 100.

Verdicts: `risk >= 80` → `CRITICAL`, `>= 50` → `HIGH`, `>= 25` →
`ELEVATED`, `>= 5` → `LOW`, else `CLEAN`.

The dumped section reports a fragment-hit table and a redacted sample
list. **Sample lines never print the actual matched string** — only
the matched fragment, its length, entropy, and classifier — to avoid
bypassing `BLOCKED_OUTPUT_PATTERNS` (which strips webhooks/tokens
from the final dump).

## Defenses

- **Crash-proofing:** every `q.dump_*` and `q.envlogger_*` entrypoint
  funnels through `_public_run`, which `pcall`s `_run`, which itself
  `pcall`s the gate predicate. A bug or `_G` pollution in any single
  section can never abort the post-exec sequence in `cat_sandbox.lua`.
- **Reserved-word safe:** identifiers matching Lua keywords (`end`,
  `local`, ...) are rejected before emission so the dump always parses.
- **pcall-wrapped iteration:** every `pairs`/`ipairs`/`getupvalue` call
  is guarded against runtime iterator failures.
- **Per-section budgets** with announced truncation
  (`MAX_LINES_PER_SECTION`).
- **Output-stage redaction:** `BLOCKED_OUTPUT_PATTERNS` still applies
  on top — webhooks, tokens, and PATH/HOME-style env leaks are
  stripped from the final file. The threat-assessment section is
  intentionally designed to surface their *presence* without echoing
  the value.

## Tests

```sh
lua5.3 tests/test_envlogger.lua
lua5.1 tests/test_envlogger.lua
```

The harness mocks `_CATMIO`, `loadfile()`s the real envlogger, and
asserts behavior for each public dumper plus the run-summary, dedup,
budget, and v3 analytical sections (105+ assertions total).
