#!/usr/bin/env bash
# 对 prof.sh 保存的 tinymapper perf.data 做源文件/源码行级归因（静态二进制含调试信息，内联代码按最内层源码位置归属）
# 在 tinymapper-bench-prof 镜像内运行，/build 需挂载录制时的同一批二进制：
#   docker run --rm -v "$PWD/build:/build:ro" -v "$PWD/bench:/bench:ro" -v "$PWD/bench/results/<时间戳>/prof:/d" \
#     -e D=/d tinymapper-bench-prof:1 bash /bench/prof/analyze.sh
set -u
. "$(dirname "$0")/../lib.sh"
D=${D:-/results/prof}
for f in "$D"/tinymapper*.perf.data; do
  pre=${f%.perf.data}
  run=${pre##*/}
  dso=$(tm_file "${run%.*}")
  # 用户态样本按源文件聚合（百分比相对于全部样本）
  perf report -i "$f" --no-children --dsos "$dso" --sort srcfile -g none --percentage absolute --percent-limit 0.05 --stdio > "$pre.srcfile.txt" 2>/dev/null
  # 用户态样本按 函数+源码行 聚合
  perf report -i "$f" --no-children --dsos "$dso" --sort sym,srcline -g none --percentage absolute --percent-limit 0.2 --stdio > "$pre.srcline.txt" 2>/dev/null
  # 全部样本的调用者视角：按含内联帧的调用链（caller 图）展开 tinymapper 的主要入口
  perf report -i "$f" --children --sort sym -g caller,0.5,callee,function,percent --percent-limit 5 --stdio > "$pre.callgraph.txt" 2>/dev/null
done
