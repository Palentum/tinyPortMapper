#!/usr/bin/env bash
# 在 Linux 容器里编译 tinymapper（开发机可能是 macOS），产物放在 build/。
#
# 用法：docker/build.sh [glibc] [musl] [glibc-assert] [musl-assert] [cross]      （默认 glibc musl）
#   glibc  -> build/tinymapper-glibc   在 ubuntu:24.04 中 `make all`（静态 glibc，-O2）
#   musl   -> build/tinymapper-musl    在 alpine:3.22 中 `make all`（静态 musl，与 OpenWRT 同类 libc）
#   glibc-assert / musl-assert -> build/tinymapper-{glibc,musl}-assert
#             同上，另加 -DENABLE_DEBUG_ASSERT：热路径上的 DEBUG_ASSERT 生效（T12），tests/run.sh 默认测它们；
#             不能再加 NDEBUG（common.h 会报错）
#   cross  -> build/tinymapper_<target>，发布目标（amd64 x86 arm mips24kc_be mips24kc_le）
#             用 zig 的 musl 交叉编译器编译；只做编译检查，不等同于 OpenWRT SDK。zig 在 -O2 下隐式定义 NDEBUG，
#             这里的产物不含任何 assert（SDK 的 gcc 不定义 NDEBUG）
# 环境变量：
#   REF=<git ref>  编译该提交而不是工作区；产物文件名加 "-<ref>" 后缀
#
# 产物架构与 Docker 服务端一致（`docker version -f '{{.Server.Arch}}'`）。
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
REF=${REF:-}
SUFFIX=${REF:+-$REF}
[ $# -eq 0 ] && set -- glibc musl

image() {
	local name=$1 file=$2
	docker image inspect "$name" >/dev/null 2>&1 ||
		docker build -q -t "$name" -f "$ROOT/docker/$file" "$ROOT/docker" >/dev/null
}

# 源码复制进容器再编译，并发构建不会写宿主机源码树；产物先写临时文件再 mv，正在运行的旧二进制不受影响。
# 工作区构建：保留克隆出的 .git（生成 git_version.h），再用工作区里未提交的源码覆盖。
PREP='set -e
git clone -q /src /w && cd /w
if [ -n "$REF" ]; then git checkout -q "$REF"
else cp /src/*.cpp /src/*.h /src/makefile . && rm -rf libev && cp -a /src/libev .; fi'

run() {
	local img=$1 script=$2
	mkdir -p "$ROOT/build"
	docker run --rm -e REF="$REF" -e SUFFIX="$SUFFIX" \
		-v "$ROOT:/src:ro" -v "$ROOT/build:/out" \
		-v tinymapper-zig-cache:/root/.cache/zig \
		"$img" sh -c "$PREP
$script"
}

for v in "$@"; do
	case $v in
	glibc | musl | glibc-assert | musl-assert)
		libc=${v%-assert}
		opt=""
		[ "$v" = "$libc" ] || opt=-DENABLE_DEBUG_ASSERT
		image "tinymapper-build-$libc:1" "Dockerfile.build-$libc"
		run "tinymapper-build-$libc:1" "make all OPT='$opt' >/tmp/make.log 2>&1 || { cat /tmp/make.log; exit 1; }
cp tinymapper /out/.tinymapper-$v\$SUFFIX.tmp && mv -f /out/.tinymapper-$v\$SUFFIX.tmp /out/tinymapper-$v\$SUFFIX"
		echo "已编译 build/tinymapper-$v$SUFFIX"
		;;
	cross)
		image tinymapper-build-musl:1 Dockerfile.build-musl
		run tinymapper-build-musl:1 'Z="zig c++ -Wno-date-time -target"
for t in "amd64:x86_64-linux-musl" "x86:x86-linux-musl -mcpu=pentium4" "arm:arm-linux-musleabi -mcpu=cortex_a9" \
	"mips24kc_be:mips-linux-musleabi -mcpu=mips32r2" "mips24kc_le:mipsel-linux-musleabi -mcpu=mips32r2"; do
	n=${t%%:*}
	make "$n" "cc_$n=$Z ${t#*:}" >/tmp/make.log 2>&1 || { cat /tmp/make.log; exit 1; }
	cp "tinymapper_$n" "/out/.tinymapper_$n$SUFFIX.tmp" && mv -f "/out/.tinymapper_$n$SUFFIX.tmp" "/out/tinymapper_$n$SUFFIX"
	echo "已编译 build/tinymapper_$n$SUFFIX：$(readelf -h "tinymapper_$n" | sed -n "s/^ *Machine: *//p")"
done'
		;;
	*)
		echo "未知构建类型：$v（可选 glibc、musl、glibc-assert、musl-assert、cross）" >&2
		exit 2
		;;
	esac
done
