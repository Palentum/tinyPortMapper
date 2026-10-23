#!/usr/bin/env bash
# 主机模式冒烟：3 个容器（自建 bridge 网络，不发布端口）充当客户端/转发器/后端主机，用 RSH=docker、RCP="docker cp"
# 依次跑 3 主机与 2 主机拓扑的短测，结束后删除容器与网络。只验证编排逻辑，数字没有参考价值。
# 前置：bench/run.sh 至少跑过一次（tinymapper-bench-prof:1 镜像与 build/ 下的 tinymapper）
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
NET=tpm-bench-smoke
IMG=tinymapper-bench-prof:1
cleanup() {
  docker rm -f tpm-smoke-cli tpm-smoke-fwd tpm-smoke-srv >/dev/null 2>&1 || true
  docker network rm $NET >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create $NET >/dev/null
for r in cli fwd srv; do
  priv=""; [ $r = fwd ] && priv=--privileged   # 转发器主机上要跑 perf
  docker run -d --rm --init --name tpm-smoke-$r --network $NET $priv --ulimit nofile=65536:65536 \
    --sysctl net.ipv4.tcp_tw_reuse=1 --sysctl net.ipv4.ip_local_port_range="21000 65535" $IMG sleep infinity >/dev/null
done
addr() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tpm-smoke-$1; }

export RSH=docker RCP="docker cp" REALM_BIN=${REALM_BIN:-}
export REPS=${REPS:-1} DUR=${DUR:-2} SC_DUR=${SC_DUR:-2} PROF_DUR=${PROF_DUR:-2}
export FWDS=${FWDS:-direct tinymapper realm-1c} TESTS=${TESTS:-tcp_bw_1 tcp_rr_64 tcp_crr_32 udp_pps_64 tcp_mem_5000}
export SC_FWDS=${SC_FWDS:-tinymapper} SC_TESTS=${SC_TESTS:-tcp_rr_64 tcp_crr_32 udp_pps_64}
export PROF_RUNS=${PROF_RUNS:-tinymapper:tcp_rr_64}

echo "== 3 主机"
CLI_HOST=tpm-smoke-cli FWD_HOST=tpm-smoke-fwd SRV_HOST=tpm-smoke-srv FWD_IP=$(addr fwd) SRV_IP=$(addr srv) "$ROOT/bench/host.sh"
echo "== 2 主机（客户端与后端同机）"
CLI_HOST=tpm-smoke-cli FWD_HOST=tpm-smoke-fwd SRV_HOST=tpm-smoke-cli FWD_IP=$(addr fwd) SRV_IP=$(addr cli) STAGES="bench syscount" "$ROOT/bench/host.sh"
