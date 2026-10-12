# New module conventions (observed from the existing 32)

These are the contracts the GUI and the rest of the tree already assume.
Most were confirmed by finding real bugs in existing modules, noted inline.

## 1. `info` shim — use `declare -F`, never `command -v`

```bash
command -v info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
```

This is **broken**: `/usr/bin/info` (texinfo) exists, so `command -v` succeeds,
the shim is never defined, and every `info "msg"` call execs texinfo, which
treats the message as a filename:

```
info: ./btmon passive capture for 3s → /path/log: No such file or directory
```

Correct form (fixed in all 29 affected modules):

```bash
declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
```

`warn`, `err`, `banner` have no external counterparts, so `command -v` happens
to work for them — but `declare -F` is correct for all four.

## 2. Self-locate `WIFISTING_ROOT`, then reset `HOME`

Under `pkexec`, `HOME=/root`, so any `$HOME`-relative path lands in the wrong
place. Every module must resolve its root from its own path and fix `HOME`:

```bash
if [[ -z "${WIFISTING_ROOT:-}" ]]; then
    _sl_src="${BASH_SOURCE[0]}"
    while [ -L "$_sl_src" ]; do
        _sl_dir="$(cd -P "$(dirname "$_sl_src")" && pwd)"
        _sl_tgt="$(readlink "$_sl_src")"
        [[ "$_sl_tgt" != /* ]] && _sl_tgt="$_sl_dir/$_sl_tgt"
        _sl_src="$_sl_tgt"
    done
    WIFISTING_ROOT="$(cd -P "$(dirname "$_sl_src")/.." && pwd)"
    export WIFISTING_ROOT
fi
if [[ -n "${WIFISTING_ROOT:-}" ]]; then
    _real_home="$(dirname "$WIFISTING_ROOT")"
    if [[ -n "$_real_home" && -d "$_real_home" && "$HOME" != "$_real_home" ]]; then
        export HOME="$_real_home"
    fi
fi
```

## 3. pkexec rules

- The polkit rule `/etc/polkit-1/rules.d/49-wifisting.rules` matches on the
  **program path** under `/wifisting/modules/`. So the script must be invoked
  directly as `pkexec /path/to/modules/NN_name.sh ...`.
- **Never** `pkexec env VAR=val SCRIPT ...` — the program is then `/usr/bin/env`
  and the rule never matches (silent failure or an unreadable prompt).
- Do **not** self-elevate inside the script; the GUI decides, via
  `wf_action_run(..., privileged=TRUE)` which prepends `pkexec`.
- Decide privilege by **where the module writes**, not by what it sounds like.
  A `git clone` sounds unprivileged but `$WIFISTING_ROOT/external/` is
  root-owned, so it needs pkexec.

## 4. CLI dispatch and non-interactive mode

```bash
my_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   my_cli_status_tsv ;;
        --do-thing)     my_cli_do_thing "$@" ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --do-thing ARG
EOF
            return 2 ;;
    esac
}
```

Guard every `read -rp` with a CLI check, or the GUI will hang on a prompt:

```bash
if [[ -n "${WIFISTING_CLI:-}" ]]; then
    echo "[-] need X; cannot prompt in CLI mode" >&2; return 1
fi
read -rp "select: " sel
```

## 5. Output contract

- Machine-readable commands emit **TSV**, one record per line:
  `KEY\tVALUE` for key/value, or bare rows for lists.
- Success/terminal lines use `OK\t`, `ERROR\t`, `MISSING\t`, etc.
- Errors go to **stderr** and the function returns non-zero.
- **Never print a success line when the operation failed.** A live bug:
  `05_bt_recon.sh --db-clear` prints `CLEARED` and exits 0 even when the write
  fails with `Permission denied`, so the GUI reports success.

## 6. Paths

| Purpose | Variable | Location |
|---|---|---|
| Scratch, pidfiles, fifos | `$TMP_DIR` | `/tmp/wifisting/<module>/` (use `/tmp/wifisting` if not set) |
| Loot, hashes, creds | `$LOOT_DIR` | `$WIFISTING_ROOT/loot/<module>/` |
| Captures | — | `$WIFISTING_ROOT/captures/` or `captures/attack/` |
| Logs | `$LOG_DIR` | `$WIFISTING_ROOT/logs/` |
| State | `$STATE_DIR` | `$WIFISTING_ROOT/state/` |

`mkdir -p` everything you write to before writing.

## 7. Long-running commands: pidfile + reaping

If a module has `--start` / `--stop`, the `--stop` must actually reap children:

- Write the pid with **`${BASHPID:-$$}`**, not `$$`. Under a subshell `$$` is the
  *parent's* pid, so `--stop` would signal the wrong process.
- Give each child its own pidfile (e.g. `tshark`) so a fallback path can reap it
  if the main trap never ran (e.g. after `SIGKILL`).
- Set the `trap` **after** the child pids are known, so the handler can kill them.
- Make `--stop` idempotent: exiting 0 when nothing was running is fine.

## 8. Scheduling / async

- Scripts may block; the GUI runs them async and streams stdout/stderr.
- Anything the GUI should surface as a toast/event must print to stdout or
  stderr — output is captured and shown.
- Prefer short-lived subcommands that exit; the GUI's `wf_action_run` waits for
  completion. A `--start` that never returns is handled as a persistent service
  and must not be routed through `wf_action_run`.

## 9. Honesty about capability

If a subcommand documents a workflow instead of performing the action, say so in
its own output and name it accordingly. `26_zigbee.sh --ota-downgrade` writes a
plan file rather than attacking; the GUI labels that button "Generate plan" and
the card states it does not perform the downgrade. A button that looks like an
attack but produces a README is worse than no button.

## 10. After adding a module

- `bash -n modules/NN_name.sh` must pass.
- The GUI needs a `#define NN_SCRIPT PROJECT_DIR "/modules/NN_name.sh"`, page
  builders, and a `module_registry_register(...)` call plus a metadata row in
  the module definition table.

## 11. Exported tools (`tools/`)

These live outside the modules and operate on them, so no module needs to
change when a tree-wide capability is added.

| Tool | Purpose |
|---|---|
| `tools/run-selftests.sh` | Runs every module's `--selftest`. `--json` for machine output. Exit 0 only if all pass. |
| `tools/gen-module-index.sh` | Harvests each module's `--info` and verbs into `module_index.tsv` + `native/src/module_index.c` (included by the GUI). `--check` fails if stale. |
| `tools/stats.sh` | Real analytics over `state/fingerprint.db`, `recon.json`, scans, module TSVs and the capture tree. Emits `SECTION<TAB>KEY<TAB>VALUE<TAB>DETAIL`. |
| `tools/export.sh` | Emits any module verb's TSV as JSON. `--list` shows what is exportable; `--all` snapshots every module's `--status-tsv`. |
| `tools/search.sh` | Finds a value across `loot/`, `state/` and scratch. MACs match in every written form (bare, colon, dash, case). |
| `tools/smoke-pages.sh` | Constructs each module page in turn to catch construction-time crashes. Requires `--i-know-it-pops-windows` because it maps a window per module and there is no Xvfb here. |

### `--export-json` convention

A module does not implement `--export-json` itself. Because every module
already emits TSV, `tools/export.sh MODULE VERB` is the export:

```
tools/export.sh 34_pmf_bypass --list-tsv
```

`KEY<TAB>VALUE` output becomes `{"KEY": value}`; a table with a header row
becomes an array of objects keyed by that header. Values are typed (ints,
booleans) so diffs are meaningful.

**Heredoc hazard:** `python3 - <<'EOF'` replaces stdin, so a piped TSV is
lost and the script itself is read as data. Stage piped data through a file
or use `python3 -c`. This has bitten three separate tools in this tree.
