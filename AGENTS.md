# Repository Guidelines

## Project Overview

tinyPortMapper (`tinymapper`) is a lightweight C++11 TCP/UDP port mapping and forwarding utility. It supports single-rule CLI startup and config-file startup with multiple forwarding rules in one process, forwarding IPv4, IPv6, and 4-to-6 / 6-to-4 traffic. The data plane is event-driven and embeds `libev` directly into the binary.

## Architecture & Data Flow

- `main.cpp` owns the application flow: CLI parsing, socket setup, libev watcher registration, signal handling, TCP/UDP callbacks, and connection cleanup.
- `process_arg()` parses single-rule CLI options (`-l`, `-r`, `-t`, `-u`) or `-c/--config <path>` into `app_config.rules`; log, color, socket-buffer, and `--disable-tcp-nodelay` options remain process-wide.
- `event_loop()` materializes `forward_rule_t` objects from `app_config`, creates only the enabled TCP/UDP listeners for each rule, registers `ev_io` accept/read watchers with `watcher->data` pointing at the owning rule, starts a periodic `ev_timer`, then calls `ev_run()`.
- TCP flow: `tcp_accept_cb()` accepts the pending local clients of one `forward_rule_t`, calling `tcp_accept_one()` until `accept4(SOCK_NONBLOCK|SOCK_CLOEXEC)` returns EAGAIN (silently) or `max_accept_per_round` (8) clients were taken in this loop iteration (the listener must stay nonblocking, since the last `accept4()` of a round normally returns EAGAIN); any other accept failure and an immediate upstream `connect()` failure (EADDRNOTAVAIL first scans the whole ephemeral port range) also end the round, while `max_conn_num` and an upstream `socket()` failure only drop that client and move on (if `accept4()` fails with anything but EAGAIN/EINTR/ECONNABORTED, e.g. EMFILE/ENFILE/ENOMEM or an LSM denial, the client stays in the backlog, so the rule's accept watcher is stopped and `clear_timer_cb()` restarts it on its next tick; an `EV_ERROR` on the accept watcher, e.g. a failed epoll re-add, is logged and retried the same way), opens a nonblocking remote socket to that rule's `remote_addr` (if `socket()` fails, e.g. EMFILE, only that client is closed) and starts a nonblocking `connect()` (an immediate failure other than EINPROGRESS, e.g. ENETUNREACH or EADDRNOTAVAIL, closes the client with a warn), creates a `tcp_pair_t`, stores both fds through `fd_manager`, then `tcp_cb()` shuttles fixed-size buffers between the two endpoints while toggling `EV_READ` / `EV_WRITE` watchers for backpressure. Both sides run with `TCP_NODELAY` unless `--disable-tcp-nodelay` is given: the TCP listener sets it once and accepted sockets inherit it, the upstream socket sets it before `connect()`. The TCP listener calls `listen()` with `listen_backlog` (65535), which the kernel caps at `net.core.somaxconn` (4096 by default since Linux 5.4, 128 before); the libc `SOMAXCONN` macro is not used because musl (and glibc before 2.31) define it as 128. TCP socket buffers are left to kernel autotuning: `SO_SNDBUF`/`SO_RCVBUF` are set only when `--sock-buf` is given (`sock_buf_explicit`), then once on the TCP listener before `listen()` (accepted sockets inherit the size and the `SOCK_*BUF_LOCK` bits, so setting it on the listener unconditionally would disable autotuning for every client) and on the upstream socket before `connect()`. Connect state: while the upstream is CONNECTING (`tcp_info_t::connected==0`) its watcher waits for `EV_READ|EV_WRITE` and nothing is sent or shut down on it; a writable-only report means connected, a readable report is checked with `getsockopt(SO_ERROR)`, and an error (refused, unreachable, or the kernel's SYN timeout ETIMEDOUT; there is no separate connect timer, only the TCP idle timeout) closes the pair with a warn. Client data read meanwhile (one buffer) is held and sent once the upstream connects, before anything is read from the upstream. Half-close: an EOF from one side (`tcp_info_t::eof`) is forwarded as `shutdown(SHUT_WR)` on the other side while the opposite direction keeps flowing; if the upstream is still connecting the shutdown waits until it connects, because `shutdown()` on a SYN_SENT socket aborts the connect. The pair is released once both sides have sent EOF, or on any recv/send/shutdown error.
- UDP flow: `udp_accept_cb()` receives the first packet from a client address on one rule's listener, creates one connected UDP socket to that rule's `remote_addr`, stores it in the rule's `conn_manager_udp`, then `udp_cb()` sends responses back to the original listener/client with `sendto()`. UDP sockets always get explicit buffers: the listener `listen_fd_buf_size` (2 MiB), each session `socket_buf_size` (1 MiB, or `--sock-buf`).
- Connection lifetime is LRU-based per rule. Each `forward_rule_t` owns `conn_manager_tcp_t`, `conn_manager_udp_t`, and their `lru_collector_t` state; `clear_timer_cb()` periodically removes inactive pairs across all rules.
- `fd_manager_t` maps OS fds to unique `fd64_t` handles to avoid fd reuse bugs. Libev watchers carry the handle in `watcher->u64` via `EV_COMMON` in `my_ev_common.h`.

## Key Directories

- `.`: Main project sources and hand-written build file.
- `libev/`: Vendored libev snapshot and compatibility files. `.gitattributes` marks this directory as vendored. Maintenance scripts live here too.
- `docker/`: Build images and `docker/build.sh`, which builds tinymapper inside Linux containers (glibc, musl, and a zig-based compile check of the release cross targets) into `build/`.
- `tests/`: Go functional test suite (own `go.mod`, standard library only) and `tests/run.sh`, which runs it inside `ubuntu:24.04` (glibc build) and `alpine:3.22` (musl build) containers.
- `bench/`: Loopback benchmark (`run.sh`), host-mode benchmark over ssh (`host.sh`), syscall counting (`syscount.sh`), perf profiling (`prof/`), the Go load tool (`fwdbench/`), and the recorded baselines (`BASELINE.md`).
- `build/` and `bench/results/`: Generated binaries and benchmark results; both are git-ignored.

## Development Commands

```sh
make all        # Native Linux build: ./tinymapper, static, -O2, -lrt
make fast       # Faster debug-style local build, no -O2/static
make debug      # Debug build with -D MY_DEBUG and -ggdb
make clean      # Remove generated binaries and git_version.h
make release    # Cross-build configured TARGETS and package tar.gz
make test       # tests/run.sh: build in containers, run the Go functional tests (glibc + musl)
make bench      # bench/run.sh: loopback benchmark + syscall counts, results in bench/results/<stamp>/
```

Container builds (any machine with Docker, including macOS):

```sh
docker/build.sh                  # build/tinymapper-glibc and build/tinymapper-musl
docker/build.sh cross            # compile check: amd64 x86 arm mips24kc_be mips24kc_le (zig, musl)
REF=4acc876 docker/build.sh      # build a commit: build/tinymapper-{glibc,musl}-4acc876
```

Run examples:

```sh
./tinymapper -l0.0.0.0:1234 -r10.222.2.1:443 -t -u
./tinymapper -l[::]:1234 -r[2001:19f0:7001:1111:00:ff:11:22]:443 -t -u
./tinymapper -c mapper.toml
```

Notes:

- `git_version.h` is generated by the `git_version` make target and included by `main.cpp`.
- Cross-compiler paths in `makefile` are hardcoded to the original author's toolchain locations; expect to override variables or use local targets.
- No `make test`, lint, format, or CI target is defined.

## Code Conventions & Common Patterns

- Style is pragmatic C-with-classes C++11: global process state, `struct` data holders, `using namespace std`, C socket APIs, `char*`/fixed buffers, and manual lifecycle management.
- Naming is mostly `snake_case`; types commonly end in `_t` (`address_t`, `tcp_pair_t`, `fd_manager_t`). Runtime forwarding state lives in `app_config.rules` and `forward_rules`; each `forward_rule_t` owns its listener fds and TCP/UDP managers.
- Keep networking nonblocking: create sockets with `SOCK_NONBLOCK|SOCK_CLOEXEC` passed to `socket()` / `accept4()` instead of a follow-up `fcntl` (`setnonblocking()`). Use `set_buf_size()` (on TCP sockets only when `sock_buf_explicit`), `close()`, and `fd_manager.fd64_close()` instead of ad-hoc fd handling.
- Logging: `mylog(level, ...)` checks the level before calling `log0()`, so arguments of filtered messages are not evaluated. `log0()` formats the whole line into a stack buffer and writes it with one `fwrite` (the timestamp and each level's `color[time][LEVEL]` prefix are formatted once per second into unlocked function-local statics, so only the event-loop thread may log: the DNS worker hands errors back through `dns_result_cb()`; the timestamp uses `localtime_r` because glibc's `localtime()` re-checks `/etc/localtime` on every call; `enable_log_color` is not part of the cache key, so it must not change once `log0()` has run: only the pre-scan at the top of `process_arg()` sets it, and the one earlier `log0()` call, the `ev_default_loop()` failure in `main()`, exits immediately). stdout is flushed per line only on a tty; otherwise it stays fully buffered (4 KiB with glibc, 1 KiB with musl) and is written when the buffer fills, by `clear_timer_cb()` every `timer_interval` (400 ms), and by `myexit()`, so lines written right before an abort, an unhandled signal, or SIGKILL can be lost.
- Addresses: connections keep the client address as `address_t` (`tcp_pair_t::addr`, `udp_pair_t::adress`) and format it only inside `mylog` arguments with `get_str()`, so filtered lines and the per-packet UDP path do no formatting. `get_str()` returns one static buffer: use it at most once per `mylog` call and only on the event-loop thread; otherwise `to_str()` into a local `char[max_addr_len]`. `to_str()` hand-formats IPv4, v4-mapped IPv6 (`::ffff:a.b.c.d`, how IPv4 clients of a dual-stack `[::]` listener appear) and the port (no `sprintf`); other IPv6 goes through `inet_ntop`. `to_str()` must not change `errno`: a `mylog` call may evaluate `get_str()` before `get_sock_error()`.
- Error handling uses `mylog(level, ...)`, `myexit()`, and `assert()` for invariants. Fatal setup errors usually log `log_fatal` then exit; runtime network errors usually log and close/erase the affected connection. `myexit()` flushes stdout and calls `_exit()`: no static destructors or `atexit` handlers run, because the detached DNS thread may still be blocked on `dns_cv` (glibc's `pthread_cond_destroy` would wait for it forever), so do not put shutdown work in destructors.
- Async work is libev-based only: `ev_io_init/start/stop`, `ev_timer`, `ev_signal`, `EV_READ`, and `EV_WRITE`. When changing watcher events, existing code stops, mutates/re-initializes, then restarts the watcher.
- Avoid introducing new allocation-heavy abstractions in hot paths. Existing TCP buffers are fixed arrays in `tcp_info_t`; UDP uses stack buffers in callbacks.
- `libev/ev_wrap.h` is generated by `libev/update_ev_wrap`; do not hand-edit generated or vendored libev files unless the change is explicitly about the embedded event loop.

## Important Files

- `main.cpp`: Entry point, CLI/config selection, protocol callbacks, event loop, per-rule runtime, connection managers.
- `config.h` / `config.cpp`: Minimal TOML subset parser for `[network]` defaults and `[[endpoints]]` forwarding rules.
- `common.h` / `common.cpp`: Shared types, `address_t` parsing/formatting, time helpers, socket helpers.
- `fd_manager.h` / `fd_manager.cpp`: Unique fd handle mapping and fd-associated connection metadata.
- `log.h` / `log.cpp`: Logging levels, color/position flags, `mylog()` / `log0()` implementation.
- `my_ev_common.h`: Embedded libev configuration (`EV_STANDALONE`, `EV_COMMON`, `EV_COMPAT3`) and the epoll-only backend selection (`EV_USE_EPOLL`/`EV_USE_EVENTFD` on, `EV_USE_POLL`/`EV_USE_SELECT` off) for both glibc and musl.
- `my_ev.h` / `my_ev.cpp`: Libev include wrapper and direct `#include "ev.c"` compilation unit.
- `makefile`: Build, cross-build, release, cleanup, and the `test` / `bench` entry points.
- `README.md`: User-facing usage examples, options, supported platforms, and performance-test reference.
- `libev/update_ev_wrap`, `libev/update_ev_c`, `libev/update_symbols`, `libev/import_libevent`: Vendored libev maintenance helpers.

## Runtime/Tooling Preferences

- Required language/toolchain: C++11 with `g++`/compatible compiler and GNU Make-style `makefile`.
- No Node, Bun, Python package manager, or dependency lockfile is used for the project build. Go (tests, `bench/fwdbench`) and Python 3 (bench summaries) use only their standard libraries.
- libev is always embedded (`my_ev.cpp` includes `ev.c`) and built with the epoll backend only; `event_loop()` logs the active backend (`event backend: epoll`) at startup.
- Linux is the only supported platform (glibc distributions and OpenWRT/musl; deployed directly on hosts). Windows/macOS/FreeBSD/Cygwin targets and code paths were removed; do not add non-Linux fallbacks. On a macOS dev machine, build and test through `docker/build.sh` / `make test`.
- Keep `libev/` treated as third-party vendored code. Prefer changing project wrapper/configuration files before modifying libev internals.

## Testing & QA

- Functional tests: `make test` (= `tests/run.sh`) builds tinymapper with `docker/build.sh`, cross-compiles the Go test binary on the host (`GOOS=linux`), and runs it in `ubuntu:24.04` against the glibc build and in `alpine:3.22` against the musl build (`--network none`, loopback only). Useful knobs: `VARIANTS=glibc`, `REF=<commit>` (test a commit's build), `TPM_NO_BUILD=1`, `TPM_SLOW=1` (adds the ~6 min TCP/UDP idle-timeout tests and the ~2 min upstream connect-timeout test, run in parallel), and test-binary flags such as `-test.run X -test.v`.
- Coverage: TCP integrity (1 B–1 GiB, 100/5000 concurrent), TCP semantics (half-close from either side, with a pending reverse backlog, and before the upstream connect completes; RST, refused/unreachable upstream, server-first; upstream connect result: client data or EOF held while connecting, a streaming upstream not starving the held request, refusal after held data or half-close, kernel SYN timeout; `TCP_NODELAY` on each side, checked with write-pause-write rounds that stall on Nagle plus delayed ACK, and its `--disable-tcp-nodelay` rollback), resource limits (`max_conn_num`, nofile exhaustion, idle timeout), accept batching (after a SIGSTOP/SIGCONT burst the first accept callback takes exactly `max_accept_per_round` clients, read from debug logs), listen backlog (the TCP listener's `sk_max_ack_backlog`, read with `NETLINK_SOCK_DIAG`, is min(65535, `somaxconn`); 2048 sequential connects while tinymapper is SIGSTOPped all land in the accept queue and are forwarded after SIGCONT), UDP sizes/session isolation/timeouts, IPv4/IPv6/4to6/6to4, client addresses in log lines (`TestLogClientAddr*`: TCP over IPv4, IPv6 and v4-mapped on a `[::]` listener, refused/unreachable upstream, and the per-packet UDP trace line carrying each sender's own address), domain refresh, roundrobin/iphash, CLI vs TOML config, invalid configs, SIGTERM exit, epoll/eventfd event backend, `O_NONBLOCK|O_CLOEXEC` on every socket kind (TCP/UDP listener, accepted client, upstream, UDP session; read from `/proc/<pid>/fdinfo`), socket buffer sizes (read with `NETLINK_SOCK_DIAG` exact lookups: by default the TCP listener keeps `tcp_rmem[1]`/`tcp_wmem[1]` and the client/upstream sockets have rcvbuf `tcp_rmem[1]` and the same sndbuf as never-configured reference sockets; with `--sock-buf` all three are locked at 2×min(N KiB, `rmem_max`/`wmem_max`) and stay there after a transfer; UDP listener 2 MiB, UDP session `--sock-buf`, default 1 MiB).
- Known defects are wrapped in `xfail(t, "<id>", ...)` with IDs from the optimization roadmap (none at present). The body asserts the correct behavior; once a fix lands the test reports XPASS and fails until the `xfail` wrapper is removed.
- Tests that edit `/etc/hosts` only run when `TPM_IN_CONTAINER=1` (set by `tests/run.sh`); never run them on a real host.
- Benchmarks: `make bench` (= `bench/run.sh`) runs the loopback benchmark and syscall counts in Docker (forwarder CPU0, client CPU2-3, backends CPU4-5) and writes `bench/results/<stamp>/`. `FWDS="tinymapper@4acc876 tinymapper" bench/run.sh` compares a commit with the working tree; `QUICK=1` is a smoke run; `bench/host.sh` runs the same workloads on real client/forwarder/server hosts over ssh. Run benchmarks with the Docker VM otherwise idle. Baselines and procedures are in `bench/BASELINE.md`.
- For source changes, at minimum run `make test`; for data-path changes also compare benchmarks and syscall counts against the baseline.
