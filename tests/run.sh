#!/usr/bin/env bash
# 在 Linux 容器中运行功能测试（开发机可以是 macOS，容器内不需要 Go）。
#
# 用法：tests/run.sh [测试二进制参数...]      例如 tests/run.sh -test.run TCPIntegrity -test.v
# 环境变量：
#   VARIANTS="glibc musl"  要测试的构建：glibc 在 ubuntu:24.04 中运行，musl 在 alpine:3.22 中运行
#   REF=<git ref>          测试该提交的构建（build/tinymapper-<variant>-<ref>），与 docker/build.sh 一致
#   TPM_NO_BUILD=1         跳过 docker/build.sh，直接使用 build/ 中已有的二进制
#   TPM_SLOW=1             同时运行慢速用例（TCP/UDP 空闲超时，约 7 分钟）
#
# 流程：docker/build.sh 编译 tinymapper → 宿主机交叉编译测试二进制 → 每个变体一个
# `docker run --rm --network none` 容器，只读挂载 build/。任一变体失败则以非零状态退出。
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
REF=${REF:-}
SUFFIX=${REF:+-$REF}
VARIANTS=${VARIANTS:-glibc musl}

if [ "${TPM_NO_BUILD:-}" != 1 ]; then
	# shellcheck disable=SC2086
	REF="$REF" "$ROOT/docker/build.sh" $VARIANTS
fi

ARCH=$(docker version -f '{{.Server.Arch}}')
TESTBIN=tinymapper-tests.linux-$ARCH
(cd "$ROOT/tests" && GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 go test -c -o "$ROOT/build/$TESTBIN" .)

status=0
summary=()
for v in $VARIANTS; do
	case $v in
	glibc) img=ubuntu:24.04 ;;
	musl) img=alpine:3.22 ;;
	*)
		echo "未知变体：${v}（可选 glibc、musl）" >&2
		exit 2
		;;
	esac
	bin=tinymapper-$v$SUFFIX
	if [ ! -x "$ROOT/build/$bin" ]; then
		echo "缺少 build/${bin}" >&2
		exit 2
	fi
	echo "=== ${v}：build/${bin} @ ${img}"
	start=$(date +%s)
	# 20000 连接用例需要两侧各约 4 万个 fd
	if docker run --rm --network none --ulimit nofile=524288:524288 \
		-v "$ROOT/build:/build:ro" -w /tmp \
		-e TINYMAPPER_BIN="/build/$bin" -e TPM_VARIANT="$v" -e TPM_IN_CONTAINER=1 -e TPM_SLOW \
		"$img" "/build/$TESTBIN" -test.timeout=30m "$@"; then
		result=PASS
	else
		result=FAIL
		status=1
	fi
	summary+=("${v}: ${result}（$(($(date +%s) - start)) s，build/${bin}）")
done
printf '%s\n' "${summary[@]}"
exit $status
