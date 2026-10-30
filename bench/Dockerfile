# 基准工具镜像：iperf3、jq、util-linux（taskset）、procps、iproute2 与 ethtool（TOPO=veth 拓扑）、rinetd 0.73、realm 2.9.6。
# 不含 tinymapper 与 fwdbench：两者在运行时从 build/ 只读挂载，改源码不需要重建镜像。
# 构建（bench/run.sh 自动执行，无构建上下文）：docker build -t tinymapper-bench:2 - < bench/Dockerfile
# 标签随内容变化递增（:1 没有 iproute2/ethtool），bench/prof/Dockerfile 的 FROM 同步修改
# realm 的 sha256 与 GitHub release 资产摘要一致；bench/host.sh 下载 realm 时也从这里读取。
FROM ubuntu:24.04 AS fetch
ARG RINETD_SHA256=da1fa70e75c2e5906ba55bb05a71da07d1e2a1cc4de2aa9bd30b1f753d8c345a
ARG REALM_VERSION=2.9.6
ARG REALM_SHA256_aarch64=4b6c059df67a3161369df3133e5ea9e4bd266185c634ccc8990cd5bb8d271786
ARG REALM_SHA256_x86_64=b9efc8ccbab5c9f0602ab5ba0a2e00311e7b773944533a8373c00811fb6a1a6b
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends build-essential curl ca-certificates
# rinetd 0.73：release tarball，-O2
RUN mkdir /rinetd && cd /rinetd \
    && curl -fsSL -o rinetd.tar.gz https://github.com/samhocevar/rinetd/releases/download/v0.73/rinetd-0.73.tar.gz \
    && echo "$RINETD_SHA256  rinetd.tar.gz" | sha256sum -c - \
    && tar xzf rinetd.tar.gz --strip-components=1 \
    && ./configure CFLAGS="-O2" && make -j"$(nproc)"
# realm：官方 release 二进制，按架构选择
RUN a=$(uname -m) && case $a in \
      aarch64) s=$REALM_SHA256_aarch64 ;; \
      x86_64) s=$REALM_SHA256_x86_64 ;; \
      *) echo "不支持的架构：$a" >&2; exit 1 ;; \
    esac \
    && mkdir /realm && cd /realm \
    && curl -fsSL -o realm.tar.gz "https://github.com/zhboner/realm/releases/download/v$REALM_VERSION/realm-$a-unknown-linux-gnu.tar.gz" \
    && echo "$s  realm.tar.gz" | sha256sum -c - \
    && tar xzf realm.tar.gz

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends iperf3 jq util-linux procps iproute2 ethtool \
    && rm -rf /var/lib/apt/lists/*
COPY --from=fetch /rinetd/rinetd /realm/realm /usr/local/bin/
