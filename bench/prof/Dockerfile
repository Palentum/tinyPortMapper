# 剖析镜像：tinymapper-bench:1 加 strace、binutils（perf 源码行归因用 addr2line）和 perf。
# perf 优先装与 Docker VM 内核匹配的 linux-tools-<KVER>，找不到时退回 linux-tools-generic。
# 构建（bench/run.sh 自动执行）：
#   docker build --build-arg KVER="$(docker info -f '{{.KernelVersion}}')" -t tinymapper-bench-prof:1 - < bench/prof/Dockerfile
FROM tinymapper-bench:1
ARG KVER=
RUN apt-get update && apt-get install -y --no-install-recommends strace binutils \
    && (apt-get install -y --no-install-recommends "linux-tools-$KVER" \
        || apt-get install -y --no-install-recommends linux-tools-generic) \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf "$(ls -d /usr/lib/linux-tools/*/perf | head -1)" /usr/local/bin/perf
