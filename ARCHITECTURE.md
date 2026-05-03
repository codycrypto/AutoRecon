# AutoRecon — Architecture Notes for New Agents

Onboarding doc for an agent picking up this repo cold. Skim this first instead of re-reading the whole tree. Upstream is `Tib3rius/AutoRecon` (added as `upstream` remote).

## TL;DR

AutoRecon is an asyncio orchestrator that:
1. Loads every `*.py` in a plugins directory at startup, instantiates each `PortScan`/`ServiceScan`/`Report` subclass, and registers it.
2. Runs port-scan plugins per target, parses their stdout into `Service` objects.
3. Matches each `Service` against every `ServiceScan` plugin's declared `match_service_name` / `match_port` rules and dispatches matching ones.
4. Runs `Report` plugins after scans complete.

There is **no central service-tool dispatch table**. Each plugin declares what it matches in its own `configure()`.

## Layout

```
autorecon.py                       # entrypoint -> autorecon.main:main()
autorecon/
  main.py        (1653 lines)      # argparse, plugin loader, asyncio scheduler, scan_target loop
  plugins.py     (377 lines)       # base classes + AutoRecon registry
  targets.py     (225 lines)       # Target / Service domain objects + their .execute()
  io.py          (184 lines)       # logging, slugify, CommandStreamReader (stdout pipe -> pattern matcher)
  config.py      (81 lines)        # global config dict + configurable_keys whitelist
  config.toml                      # default user config (copied to ~/.config/AutoRecon)
  global.toml                      # [global.*] cross-plugin args + [[pattern]] global regexes
  default-plugins/                 # ~84 plugins, copied to ~/.local/share/AutoRecon/plugins
  wordlists/                       # shipped wordlists (dirbuster.txt, ...)
```

`main.py:22-49` copies `config.toml`, `global.toml`, `default-plugins/`, and `wordlists/` into `platformdirs` user dirs on first run, then warns when `VERSION-<x>` marker is missing (config drift).

## Plugin model

Three abstract bases in `plugins.py:113-222`:

| Class | Required | Returns | Notes |
|---|---|---|---|
| `PortScan` | `async run(self, target)` | `list[Service]` | Set `self.type = 'tcp'\|'udp'` and optionally `self.specific_ports = True` if it can honor `--ports`. |
| `ServiceScan` | `async run(self, service)` and/or `def manual(self, service, plugin_was_run)` | None | Use `configure()` to declare matchers, options, and patterns. |
| `Report` | `async run(self, targets)` | None | Receives the per-target list (or full completed list at end). |

Optional `def configure(self)` runs at register time; optional `def check(self)` lets plugins verify binaries exist (e.g. `shutil.which('feroxbuster')`).

`AutoRecon.register()` (`plugins.py:288-357`) enforces:
- unique `name` and `slug` (slug auto-derived via `slugify()` if absent)
- slug not in `config['protected_classes']` (`config.py:48`)
- coroutine `run` has exactly 2 args; `manual` has 3
- correct subclassing (otherwise `fail()`)

### Plugin-side helpers (`plugins.py:25-99`)
- `add_option / add_true_option / add_false_option / add_constant_option / add_list_option / add_choice_option` — each creates an argparse flag named `--<slug>.<arg>` injected into the global parser via `AutoRecon.add_argument()` (`plugins.py:247-253`).
- `get_option(name, default)` and `get_global_option(name, default)` — read parsed args. Note: keys are `<slug>.<arg>` with hyphens swapped for underscores.
- `add_pattern(regex, description=None)` — appends a compiled `Pattern`. Description supports `{match}`, `{match1}`, `{match2}`, ... templating.
- `match_service_name(name|list, negative_match=False)` — service name regex.
- `match_port(protocol, port|list, negative_match=False)` — literal port filtering (or ignore list).
- `match_service(protocol, port, name)` — combined matcher.
- `require_ssl(bool)`, `run_once(bool)`, `match_all_service_names(bool)`.

## Execution flow

### Bootstrap (`main.py:854-1530`)
1. Locate `config.toml` and `global.toml` (CLI args > user dir > error out).
2. argparse defines core flags (`main.py:873-908`); `parse_known_args()` keeps unknown flags for later plugin args.
3. Load every `*.py` not starting with `_` in `plugins_dir` (and `add_plugins_dir`) via `importlib.util.spec_from_file_location` (`main.py:975-1006`). Any class subclassing `PortScan`/`ServiceScan`/`Report` gets instantiated and registered.
4. Load `global.toml` `[global.*]` entries — these become `--global.<name>` argparse options shared across plugins (`main.py:1032-...`).
5. Re-parse argv now that all plugin flags are registered.
6. Two semaphores cap concurrency: `port_scan_semaphore` (`max-port-scans`) and `service_scan_semaphore` (`max-scans`). `get_semaphore()` (`main.py:235-267`) lets idle service-scan slots steal port-scan capacity once all targets are queued.

### Per-target loop (`scan_target` `main.py:472-852`)
1. Build `<output>/<target>/{scans,exploit,loot,report}` (skippable: `--single-target`, `--only-scans-dir`).
2. For each enabled `PortScan` (tag-filtered), `asyncio.create_task(port_scan(plugin, target))`.
3. Drain `target.pending_services` (added either by port scan results or `--force-services`).
4. For each new `Service`, walk every `ServiceScan` plugin (`main.py:654-799`):
   - Confirm `match_service_name`, port-include/exclude, `require_ssl`, `run_once`, `max_*_instances`.
   - If `run` is runnable → queue `service_scan(plugin, service)` task.
   - Always invoke `plugin.manual(service, plugin_was_run)` — manual commands flushed to `<scandir>/_manual_commands.txt` even when `run` was skipped.
5. After scans drain, run per-target `Report` plugins.
6. After ALL targets done, run combined `Report` plugins on `autorecon.completed_targets` (`main.py:1595-1619`).

### Subprocess + stream layer
- `Target.execute(cmd)` / `Service.execute(cmd)` (`targets.py:49-104, 153-225`) pre-format the command via `e()` in `io.py:8-17`. `e()` walks the caller's frame and uses `string.Formatter` to substitute `{address}`, `{addressv6}`, `{ipaddress}`, `{ipaddressv6}`, `{scandir}`, `{port}`, `{protocol}`, `{name}`, `{http_scheme}`, `{nmap_extra}` (and any plugin local). **This is why plugin command strings look like template literals** (e.g. `nmap-http.py:17`).
- `AutoRecon.execute()` (`plugins.py:359-377`) spawns the shell with `asyncio.create_subprocess_shell`, wraps stdout and stderr in `CommandStreamReader` (`io.py:98-184`).
- `CommandStreamReader._read()` tees lines to `outfile`, runs every `Pattern` (plugin + global) against each line, and writes hits with description templating to `<scandir>/_patterns.log`.
- All commands run by a target are journaled to `<scandir>/_commands.log`.
- Non-zero exit codes (except `curl` rc=22) are written to `<scandir>/_errors.log`.

### Service extraction (`plugins.py:255-286`)
Default regex: `^(?P<port>\d+)\/(?P<protocol>(tcp|udp))(.*)open(\s*)(?P<service>[\w\-\/]+)(\s*)(.*)$`. SSL/TLS prefix stripping sets `service.secure = True`. Plugins can pass a custom regex if needed.

## Tag system (`main.py:543-559`, `1500-1513`)

`--tags a+b,c` means *(a AND b) OR c*. Each plugin's slug is appended to its tag list (`main.py:1013`), so `--tags dirbuster` works as well as `--tags default`. `--exclude-tags` mirrors the same syntax. `--port-scans / --service-scans / --reports` short-circuit tag filtering with explicit slug lists.

## Configuration sources (priority high → low)

1. CLI flags
2. `config.toml` (user dir or `--config`)
3. argparse defaults / `config.py` defaults

`global.toml` is separate: it declares cross-plugin args and global `[[pattern]]` regexes. Don't conflate the two files.

## Where to add what

| Want to... | Edit |
|---|---|
| Add a new tool that scans a service | New file in `autorecon/default-plugins/<tool>.py` subclassing `ServiceScan`. Register matchers in `configure()`, run command in `run()`, add manual fallback in `manual()`. |
| Add a new port scanner | New `PortScan` subclass; set `self.type` and return list of `Service`. Use `target.extract_services(stdout)` for nmap-style output. |
| Add a global option used by many plugins | Add `[global.<name>]` block to `autorecon/global.toml`. Read via `self.get_global_option('<name>')`. |
| Add a global regex pattern | `[[pattern]]` block in `global.toml`. |
| Change scheduling behavior | `main.py` — `port_scan`, `service_scan`, `scan_target`, `get_semaphore`. |
| Change command formatting / log destinations | `targets.py` (`Target.execute` / `Service.execute`) and `io.py` (`CommandStreamReader`). |

## Plugin example skeleton

```python
from autorecon.plugins import ServiceScan
from shutil import which

class MyTool(ServiceScan):
    def __init__(self):
        super().__init__()
        self.name = "MyTool"           # required, must be unique
        self.slug = "mytool"           # optional, auto-slugged from name
        self.tags = ['default', 'safe', 'http']
        self.priority = 1

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)
        self.add_option('threads', default=10, help='...')
        self.add_pattern(r'Server: ([^\n]+)', description='Server: {match1}')

    def check(self):
        if which('mytool') is None:
            self.error('mytool not installed')
            return False

    async def run(self, service):
        await service.execute(
            'mytool -t ' + str(self.get_option('threads'))
            + ' {http_scheme}://{addressv6}:{port}/',
            outfile='{protocol}_{port}_{http_scheme}_mytool.txt'
        )

    def manual(self, service, plugin_was_run):
        service.add_manual_command(
            'Run MyTool with custom flags:',
            ['mytool {http_scheme}://{addressv6}:{port}/ --extra']
        )
```

Drop the file in `autorecon/default-plugins/`. After install, the user-facing copy lives in `~/.local/share/AutoRecon/plugins/` and is loaded from there at runtime — editing only the repo copy will not affect an already-installed instance unless the user removes `VERSION-*` and reruns, or edits the data dir directly.

## Friction points and gotchas

- **`main.py` is huge.** `scan_target` is ~380 lines and intermixes service matching, manual-command flushing, and tag filtering. Refactor risk: high but valuable.
- **Frame-walking command formatter.** `io.py:e()` and `Target.execute` rely on `inspect.currentframe().f_back.f_locals`. Renaming locals like `nmap_extra` or `http_scheme` in `targets.py` will silently break every plugin that references them.
- **Network side effects in port-scan plugins.** `portscan-top-tcp-ports.py:28-37` and `portscan-all-tcp-ports.py:39-46` issue `requests.get('/wsman')` to disambiguate WinRM. Surprising for users running offline / proxied.
- **`config.toml` vs `global.toml` are not interchangeable.** `[global.foo]` only works in `global.toml`; plugin-keyed tables (`[dirbuster]`) only work in `config.toml`.
- **First-run config copy** (`main.py:22-49`) only re-copies if a file is missing, not if it is stale. The `VERSION-*` marker triggers a warning but no auto-update.
- **`cancel_all_tasks`** (`main.py:98-127`) uses `psutil` to walk children — Linux/macOS-friendly, not great on Windows.
- **`run_once_boolean`** plugins use a different tag in `target.scans['services']` (just the slug, no port) — important if you write a Report plugin and walk that dict.
- **`--proxychains` forces `-sT`** in nmap and skips UDP port scans (`main.py:540`). Plugins that hardcode UDP need their own guard.
- **Plugin args use slug.arg with hyphens turned to underscores.** `--my-tool.thread-count` becomes `my_tool.thread_count` in `args` namespace.
- **`extract_service` regex** does not handle nmap "service info" extras well (e.g. `tcpwrapped`); these are filtered by `service_exceptions` in `config.py:49` so they're not flagged as missing.

## Useful greps

```bash
grep -rn "class .*ServiceScan" autorecon/default-plugins/   # all service plugins
grep -rn "match_service_name" autorecon/default-plugins/     # what matches what
grep -n "def \|async def \|class " autorecon/main.py          # main.py index
```

## Recent upstream changes (post-fork)

Pulled from `upstream/main` on 2026-05-03:
- `redirect-host-discovery.py` plugin added (auto-detects HTTP redirects, optional `/etc/hosts` injection via `--redirect-host-discovery.update-hosts`).
- `wkhtmltoimage.py` removed (dead deps).
- `appdirs` -> `platformdirs` migration in `config.py` and `requirements.txt`.
- Improvements to `virtual-host-enumeration.py` and `main.py`.
- README expanded with more plugin args; version bumped in `pyproject.toml`.

To resync later:

```bash
git fetch upstream
git merge upstream/main
```
