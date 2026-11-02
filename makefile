cc_cross=/home/wangyu/Desktop/arm-2014.05/bin/arm-none-linux-gnueabi-g++
cc_local=g++
cc_mips24kc_be=/toolchains/lede-sdk-17.01.2-ar71xx-generic_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-5.4.0_musl-1.1.16/bin/mips-openwrt-linux-musl-g++
cc_mips24kc_le=/toolchains/lede-sdk-17.01.2-ramips-mt7621_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.16/bin/mipsel-openwrt-linux-musl-g++
cc_arm= /toolchains/lede-sdk-17.01.2-bcm53xx_gcc-5.4.0_musl-1.1.16_eabi.Linux-x86_64/staging_dir/toolchain-arm_cortex-a9_gcc-5.4.0_musl-1.1.16_eabi/bin/arm-openwrt-linux-c++
cc_x86=/toolchains/lede-sdk-17.01.2-x86-generic_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-i386_pentium4_gcc-5.4.0_musl-1.1.16/bin/i486-openwrt-linux-c++
cc_amd64=/toolchains/lede-sdk-17.01.2-x86-64_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-x86_64_gcc-5.4.0_musl-1.1.16/bin/x86_64-openwrt-linux-c++
#cc_bcm2708=/home/wangyu/raspberry/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/bin/arm-linux-gnueabihf-g++ 


SOURCES0=main.cpp log.cpp common.cpp config.cpp
SOURCES=${SOURCES0} my_ev.cpp -isystem libev
NAME=tinymapper


#发布构建（all 与发布目标）不定义 NDEBUG：libev 的断言在发布版里保留，漏 ev_io_stop 时中止而不是活锁（X1，D28）；-O3/LTO/PGO 评估后不采纳（D29）
FLAGS= -std=c++11   -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers ${OPT} -pthread
TARGETS=amd64 arm mips24kc_be x86  mips24kc_le

#glibc 2.34 以前 all 改为动态链接（D95）：Debian/Ubuntu 上静态链接时 libstdc++ 经弱符号调用的 pthread_cond_*、pthread_detach 不会被链进来，有域名 remote
#时启动即崩溃；NSS 另外载入的 libc.so.6 在 DNS 线程里也没有初始化，刷新时 getaddrinfo 崩溃或查不到 /etc/hosts。\043 即 #（make 4.3 前后 \# 的含义不同）
old_glibc=$(shell printf '\043include <features.h>\n\043if defined(__GLIBC__) && !__GLIBC_PREREQ(2,34)\nyes\n\043endif\n' | ${cc_local} -E -P -x c++ - 2>/dev/null)

TAR=${NAME}_binaries.tar.gz `echo ${TARGETS}|sed -r 's/([^ ]+)/${NAME}_\1/g'` version.txt

export STAGING_DIR=/tmp/    #just for supress warning of staging_dir not define

# targets for nativei (non-cross) compile 
all:git_version
	rm -f ${NAME}
	$(if ${old_glibc},@echo "glibc < 2.34: linking ${NAME} dynamically (a static build against it can crash with hostname remotes)")
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -ggdb $(if ${old_glibc},,-static) -O2

#targes for general cross compile
#cross2、cross3 静态链接 arm-2014.05 的 glibc（2.34 以前），有域名 remote 时不能用（D95），这时用 cross

cross:git_version
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -O2

cross2:git_version
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -static -lgcc_eh -O2

cross3:git_version
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} ${FLAGS} -lrt -static -O2

#targets only for debug purpose
fast: git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -ggdb -DENABLE_DEBUG_ASSERT
debug: git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -Wformat-nonliteral -D MY_DEBUG  -ggdb -DENABLE_DEBUG_ASSERT
debug2: git_version
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${FLAGS} -lrt -Wformat-nonliteral -ggdb -DENABLE_DEBUG_ASSERT

#targets only for 'make release'

mips24kc_be: git_version
	${cc_mips24kc_be}  -o ${NAME}_$@   -I. ${SOURCES} ${FLAGS} -lrt -lgcc_eh -static -O2

mips24kc_le: git_version
	${cc_mips24kc_le}  -o ${NAME}_$@   -I. ${SOURCES} ${FLAGS} -lrt -lgcc_eh -static -O2

amd64:git_version
	${cc_amd64}   -o ${NAME}_$@    -I. ${SOURCES} ${FLAGS} -lrt -static -O2 -lgcc_eh -ggdb

x86:git_version          #to build this you need 'g++-multilib' installed 
	${cc_x86}   -o ${NAME}_$@      -I. ${SOURCES} ${FLAGS} -lrt -static -O2 -lgcc_eh -ggdb
arm:git_version
	${cc_arm}   -o ${NAME}_$@      -I. ${SOURCES} ${FLAGS} -lrt -static -O2 -lgcc_eh


release: ${TARGETS}
	cp git_version.h version.txt
	tar -zcvf ${TAR}

#在 Linux 容器内编译并运行功能测试 / 基准（开发机可以是 macOS），见 tests/run.sh、bench/run.sh

test:
	tests/run.sh

bench:
	bench/run.sh

.PHONY: test bench

clean:	
	rm -f ${TAR}
	rm -f ${NAME} ${NAME}_cross
	rm -f git_version.h

git_version:
	    echo "const char *gitversion = \"$(shell git rev-parse HEAD)\";" > git_version.h
