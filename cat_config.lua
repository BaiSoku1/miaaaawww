-- cat_config.lua: Configuration and output-safety patterns for the catmio dumper.
-- Returns two values: (config_table, blocked_patterns_list)
local r = {
    MAX_DEPTH = 50,
    MAX_TABLE_ITEMS = 10000,
    OUTPUT_FILE = "dumped_output.lua",
    VERBOSE = false,
    TRACE_CALLBACKS = true,
    TIMEOUT_SECONDS = 120,  -- Internal limit; must be < DUMP_TIMEOUT in cat.py (130s) to allow cleanup
    MAX_REPEATED_LINES = 200,
    MIN_DEOBF_LENGTH = 50,
    MAX_OUTPUT_SIZE = 200 * 1024 * 1024,
    CONSTANT_COLLECTION = true,
    INSTRUMENT_LOGIC = true,
    DUMP_GLOBALS = true,
    DUMP_ALL_STRINGS = false,
    DUMP_WAD_STRINGS = false,
    DUMP_DECODED_STRINGS = false,
    DUMP_LIGHTCATE_STRINGS = false,
    EMIT_XOR = false,
    DUMP_UPVALUES = true,
    MAX_UPVALUES_PER_FUNCTION = 200,
    DUMP_GC_SCAN = true,
    DUMP_INSTANCE_CREATIONS = true,
    DUMP_SCRIPT_LOADS = true,
    DUMP_REMOTE_SUMMARY = true,
    -- Maximum objects returned by getgc() stubs (limits memory / iteration cost)
    MAX_GC_OBJECTS = 500,
    -- Maximum functions scanned by dump_gc_scan() (separate from getgc return limit)
    MAX_GC_SCAN_FUNCTIONS = 500,
    MAX_INSTANCE_CREATIONS = 1000,
    MAX_SCRIPT_LOADS = 200,
    -- Maximum characters of a loadstring payload kept as a diagnostic snippet
    MAX_SCRIPT_LOAD_SNIPPET = 80,
    -- Extra collection options
    DUMP_FUNCTIONS = true,
    DUMP_METATABLES = true,
    DUMP_CLOSURES = true,
    DUMP_REMOTE_CALLS = true,
    DUMP_CONSTANTS = true,
    DUMP_HOOKS = true,
    DUMP_SIGNALS = true,
    DUMP_ATTRIBUTES = true,
    DUMP_PROPERTIES = true,
    TRACK_ENV_WRITES = true,
    TRACK_ENV_READS = false,
    COLLECT_ALL_CALLS = true,
    EMIT_COMMENTS = true,
    STRIP_WHITESPACE = false,
    MAX_STRING_LENGTH = 65536,
    MAX_PROXY_DEPTH = 32,
    MAX_HOOK_CALLS = 500,
    MAX_REMOTE_CALLS = 1000,
    MAX_SIGNAL_CALLBACKS = 100,
    MAX_CLOSURE_REFS = 500,
    MAX_CONST_PER_FUNCTION = 512,
    MAX_DEFERRED_HOOKS = 200,
    OBFUSCATION_THRESHOLD = 0.35,
    INLINE_SMALL_FUNCTIONS = true,
    EMIT_LOOP_COUNTER = false,
    EMIT_CALL_GRAPH = true,
    EMIT_STRING_REFS = true,
    EMIT_TYPE_ANNOTATIONS = false,
    -- Loop detection threshold: how many times the same source line must be
    -- hit (via the count hook) before a "-- Detected loops N" marker is emitted.
    LOOP_DETECT_THRESHOLD = 100,
    -- ----------------------------------------------------------------------
    -- Envlogger v2 knobs (cat_envlogger.lua).
    -- ----------------------------------------------------------------------
    -- Emit a one-shot dashboard at the end of the dump summarising what was
    -- produced (string-pool sizes, remote-call counts, etc.).
    ENVLOGGER_RUN_SUMMARY = false,
    -- Cross-section string interning: when the same value appears in more
    -- than one decoded pool, only emit it as a literal once and reference
    -- the canonical _str_N id from later pools.
    ENVLOGGER_INTERN_POOLS = false,
    -- Emit an envlogger diagnostics block (truncations, caught errors,
    -- dedup hits). Off by default so existing dump output is unchanged.
    ENVLOGGER_DIAGNOSTICS = false,
    -- Maximum lines any single envlogger section may emit before it is
    -- forcibly truncated. Per-section cap; the global MAX_OUTPUT_SIZE
    -- still applies on top.
    MAX_LINES_PER_SECTION = 10000,
    -- When true, captured global writes get a trailing comment indicating
    -- whether they came from the sandboxed env table or the real _G:
    --   foo = "bar" -- (env)
    -- Off by default so the dump format matches the original cat_envlogger.
    ENVLOGGER_LABEL_GLOBAL_SOURCE = false,
    -- ----------------------------------------------------------------------
    -- Envlogger v3 supplemental sections (cat_envlogger.lua).
    -- Each gate flag is checked with `~= false`, so these default to ON.
    -- Set to false to silence an individual section.
    -- ----------------------------------------------------------------------
    DUMP_PROPERTY_STORE        = true,  -- Instance.* property writes
    DUMP_HOOK_CALLS            = true,  -- hookfunction/hookmetamethod/etc.
    DUMP_LOOP_SUMMARY          = true,  -- top-N hot lines + [HOT] markers
    DUMP_COUNTERS              = true,  -- non-zero runtime counters
    DUMP_RUNTIME_POINTERS      = true,  -- last_http_url, namecall_method, ...
    DUMP_OBFUSCATOR_FINGERPRINT = true, -- which obfuscator(s) produced input
    DUMP_THREAT_ASSESSMENT     = true,  -- 0..100 risk score + indicators
    DUMP_TIMELINE              = true,  -- chronological event log
    -- Tunables for the v3 sections.
    LOOP_SUMMARY_TOP_N         = 25,    -- hot-line table size
    THREAT_SAMPLE_CAP          = 20,    -- max indicator samples emitted
    THREAT_SCAN_GLOBAL_TABLE   = true,  -- include _G in threat scan
    TIMELINE_CAP               = 200,   -- chronological event log size
}
local BLOCKED_OUTPUT_PATTERNS = {
    "os%.execute",
    "os%.getenv",
    "os%.exit",
    "os%.remove",
    "os%.rename",
    "os%.tmpname",
    "io%.open",
    "io%.popen",
    "io%.lines",
    "io%.read",
    "io%.write",
    -- shell-style directory / file listing indicators
    "total %d",             -- output of `ls -l`
    "^drwx", "^%-rwx",     -- Unix file-permission lines
    "^[dD]irectory of ",   -- Windows `dir` header
    "[Vv]olume in drive",  -- Windows `dir` header
    -- absolute filesystem paths that might be leaked
    "/etc/",
    "/home/",
    "/root/",
    "/var/",
    "/tmp/",
    "/proc/",
    "/sys/",
    "C:\\[Uu]sers\\",
    "C:\\[Ww]indows\\",
    "C:\\[Pp]rogram",
    -- environment-variable style leaks
    "PATH=",
    "HOME=",
    "USER=",
    "SHELL=",
    -- credential / secret leaks
    "TOKEN%s*=",
    "SECRET%s*=",
    "PASSWORD%s*=",
    "API_KEY%s*=",
    "WEBHOOK%s*=",
    -- Discord bot token format (starts with a base64-ish string of ~24 chars
    -- followed by a dot; we match the canonical NTKâ€¦. prefix shape)
    "Nz[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+",
    -- Discord webhook URLs
    "discord%.com/api/webhooks/",
    "discordapp%.com/api/webhooks/",
    -- GitHub personal-access token prefixes
    "ghp_[A-Za-z0-9]+",
    "gho_[A-Za-z0-9]+",
    "ghs_[A-Za-z0-9]+",
}
return r, BLOCKED_OUTPUT_PATTERNS
