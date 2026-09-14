#!/bin/bash
# =====================================================================
# 性能对照批量实验（指导书 6.3.2，控制变量 + 每配置重复3次）
# 因素A 丢包率 : 固定 100Mbps / 单向delay300ms / 抖动0 , loss = 0/1/3/10 %
# 因素B 时延   : 固定 100Mbps / 无丢包 / 抖动0 , 单向delay = 50/150/300ms
#               (delay300无丢包即因素A的 loss_p0，直接复用、不重复跑)
# 每次 test_congestion.py 固定 6s建连 + 60s传输 ≈ 70s，共18次 ≈ 22分钟
# 产物：perf/raw/<tag>_r<rep>/ 下保存每次的 client/server.event.trace、
#       SeqNum图和 params.txt（原始数据，可复现，禁止事后修改）
# =====================================================================
set -u
cd /vagrant/tju_tcp/test || exit 1
mkdir -p perf/raw

run_one() { # tag rate delay distro loss rep
    local tag=$1 rate=$2 delay=$3 distro=$4 loss=$5 rep=$6
    local dst=perf/raw/${tag}_r${rep}
    echo "===== [$tag rep$rep] rate=$rate delay=$delay distro=$distro loss=$loss ====="
    python3 test_congestion.py "$rate" "$delay" "$distro" "$loss"
    mkdir -p "$dst"
    cp client.event.trace "$dst/client.event.trace" 2>/dev/null
    cp server.event.trace "$dst/server.event.trace" 2>/dev/null
    cp SeqNum_VS_Time.png "$dst/SeqNum_VS_Time.png" 2>/dev/null
    echo "rate=$rate delay=$delay distro=$distro loss=$loss rep=$rep date=$(date '+%F %T')" > "$dst/params.txt"
    echo "----- saved to $dst -----"
}

REP=3
for r in $(seq 1 $REP); do
    # 因素A：丢包率（交错重复，降低时间漂移/系统负载的相关性）
    run_one loss_p0   100 300 0 0  "$r"
    run_one loss_p1   100 300 0 1  "$r"
    run_one loss_p3   100 300 0 3  "$r"
    run_one loss_p10  100 300 0 10 "$r"
    # 因素B：时延（无丢包；d300 复用 loss_p0）
    run_one delay_d50  100 50  0 0 "$r"
    run_one delay_d150 100 150 0 0 "$r"
done

echo "################ 全部 18 次实验完成，可运行: ################"
echo "# python3 perf/parse_metrics.py   # 解析 raw -> metrics.csv"
echo "# python3 perf/plot_perf.py       # 画两张对照图"
