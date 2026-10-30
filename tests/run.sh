#!/usr/bin/env bash
# 在 Linux 容器中运行功能测试（开发机可以是 macOS，容器内不需要 Go）。
#
# 用法：tests/run.sh [测试二进制参数...]      例如 tests/run.sh -test.run TCPIntegrity -test.v
# 环境变量：
#   VARIANTS="glibc-assert musl-assert"  要测试的构建（docker/build.sh 的构建类型）：glibc[-assert] 在 ubuntu:24.04 中运行，
#                          musl[-assert] 在 alpine:3.22 中运行。默认测热路径 DEBUG_ASSERT 生效的构建（T12，D20）；
#                          VARIANTS="glibc musl" 测发布构建（make all）。编译 -assert 变体时同时编译对应的发布构建，只编不测（D22）
#   REF=<git ref>          测试该提交的构建（build/tinymapper-<variant>-<ref>），与 docker/build.sh 一致
#   TPM_NO_BUILD=1         跳过 docker/build.sh，直接使用 build/ 中已有的二进制
#   TPM_SLOW=1             同时运行慢速用例（TCP/UDP 空闲超时，约 7 分钟）
#
# 流程：docker/build.sh 编译 tinymapper → 宿主机交叉编译测试二进制 → 每个变体一个
# `docker run --rm --network none --cap-add NET_ADMIN --cap-add SYS_RESOURCE --device /dev/net/tun` 容器，只读挂载 build/。任一变体失败则以非零状态退出。
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
REF=${REF:-}
SUFFIX=${REF:+-$REF}
VARIANTS=${VARIANTS:-glibc-assert musl-assert}

if [ "${TPM_NO_BUILD:-}" != 1 ]; then
	# 只在发布构建里才编译失败的写法（如 DEBUG_ASSERT 的参数是位域）在这里暴露（D22）；也让 build/ 中的发布构建与工作区一致
	builds=$VARIANTS
	for v in $VARIANTS; do
		case " $builds " in *" ${v%-assert} "*) ;; *) builds="$builds ${v%-assert}" ;; esac
	done
	# shellcheck disable=SC2086
	REF="$REF" "$ROOT/docker/build.sh" $builds
fi

ARCH=$(docker version -f '{{.Server.Arch}}')
TESTBIN=tinymapper-tests.linux-$ARCH
(cd "$ROOT/tests" && GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 go test -c -o "$ROOT/build/$TESTBIN" .)

status=0
summary=()
for v in $VARIANTS; do
	libc=${v%-assert}
	case $v in
	glibc | glibc-assert) img=ubuntu:24.04 ;;
	musl | musl-assert) img=alpine:3.22 ;;
	*)
		echo "未知变体：${v}（可选 glibc、musl、glibc-assert、musl-assert）" >&2
		exit 2
		;;
	esac
	bin=tinymapper-$v$SUFFIX
	if [ ! -x "$ROOT/build/$bin" ]; then
		echo "缺少 build/${bin}" >&2
		exit 2
	fi
	# 工作区的 -assert 构建里必须真有热路径断言（审查 F1：丢了 OPT 时会静默变成发布构建）；断言表达式字符串在 .rodata 里
	if [ "$v" != "$libc" ] && [ -z "$REF" ] && ! LC_ALL=C grep -aqF 'my_info.data_len==0&&my_info.buf==0' "$ROOT/build/$bin"; then
		echo "build/${bin} 里没有 DEBUG_ASSERT 的断言（ENABLE_DEBUG_ASSERT 没有生效？）" >&2
		exit 2
	fi
	echo "=== ${v}：build/${bin} @ ${img}"
	start=$(date +%s)
	# 20000 连接用例需要两侧各约 4 万个 fd。
	# U6：--cap-add NET_ADMIN 让容器里以 root 运行的 tinymapper 像主机上的 root（OpenWRT 等）部署一样有 CAP_NET_ADMIN，
	# UDP socket 缓冲用 SO_*BUFFORCE 设、不受 rmem_max/wmem_max 截断；没有这项能力的路径由 startMapperNoNetAdmin 覆盖
	# （去掉 CAP_NET_ADMIN 后以 root 启动 tinymapper）
	# U5：--device /dev/net/tun 供 GSO 回退用例建 tun 设备（没有 TX 校验和 offload 的出口，6.11 以前 GSO 发送返回 EIO）
	# B2：--cap-add SYS_RESOURCE 让 root 启动的 tinymapper 像主机上的 root 部署一样不受 fs.pipe-user-pages-soft 约束：容器里 uid 0 的 pipe 页数
	# 由 Docker VM 里所有 root 进程共用（测试进程的回显后端 io.Copy 走 Go 的 splice，每个 pipe 1 MiB，TestTCPMaxConn 期间约 1.9 万个；
	# 并行的另一份套件也算），用完后断言 splice 的用例拿不到 pipe
	# （needPipeQuotaExempt）；限额本身由 TestSpliceFallbackPipeQuota 以专用的非 root uid 测
	if docker run --rm --network none --ulimit nofile=524288:524288 --cap-add NET_ADMIN --cap-add SYS_RESOURCE --device /dev/net/tun \
		-v "$ROOT/build:/build:ro" -w /tmp \
		-e TINYMAPPER_BIN="/build/$bin" -e TPM_VARIANT="$libc" -e TPM_IN_CONTAINER=1 -e TPM_SLOW \
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
