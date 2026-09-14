# -*- coding: utf-8 -*-
# 读 perf/metrics.csv，画两张控制变量对照图（误差棒=3次重复的 min/max 极差）
# 图1 吞吐率-丢包率；图2 吞吐率-RTT（无丢包，受 rwnd 限制）
import os, csv, re, statistics
from collections import defaultdict
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
rows = list(csv.DictReader(open(os.path.join(HERE, 'metrics.csv'))))
agg = defaultdict(list)
for r in rows:
    cfg = re.sub(r'_r\d+$', '', r['tag'])   # 去掉 _r1/_r2/_r3 重复次后缀，按配置聚合
    agg[cfg].append(float(r['throughput_KBps']))


def stat(tags):
    xs, ym, lo, hi = [], [], [], []
    for tag, xv in tags:
        v = agg.get(tag)
        if not v:
            print('warn: 缺少该配置数据，跳过: %s' % tag)
            continue
        m = statistics.mean(v)
        xs.append(xv)
        ym.append(m)
        lo.append(m - min(v))
        hi.append(max(v) - m)
    return xs, ym, [lo, hi]


# 因素A：丢包率（固定 RTT=600ms）
loss_tags = [('loss_p0', 0), ('loss_p1', 1), ('loss_p3', 3), ('loss_p10', 10)]
x, y, err = stat(loss_tags)
plt.figure(figsize=(7, 5))
plt.errorbar(x, y, yerr=err, fmt='o-', color='#2563eb', capsize=5, lw=2, ms=7)
for xv, yv in zip(x, y):
    plt.annotate('%.1f' % yv, (xv, yv), textcoords='offset points', xytext=(0, 8),
                 ha='center', fontsize=9)
plt.xlabel('Packet loss rate (%)')
plt.ylabel('Throughput (KB/s)')
plt.title('Throughput vs packet loss\n(100Mbps, RTT=600ms, 60s/run, n=3, errorbar=min~max)')
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(HERE, 'throughput_vs_loss.png'), dpi=200)
plt.close()

# 因素B：RTT=2*单向delay（无丢包；d300 复用 loss_p0）
delay_tags = [('delay_d50', 100), ('delay_d150', 300), ('loss_p0', 600)]
x, y, err = stat(delay_tags)
plt.figure(figsize=(7, 5))
plt.errorbar(x, y, yerr=err, fmt='s-', color='#059669', capsize=5, lw=2, ms=7)
for xv, yv in zip(x, y):
    plt.annotate('%.1f' % yv, (xv, yv), textcoords='offset points', xytext=(0, 8),
                 ha='center', fontsize=9)
plt.xlabel('Round-trip time RTT (ms)')
plt.ylabel('Throughput (KB/s)')
plt.title('Throughput vs RTT (rwnd-limited)\n(100Mbps, no loss, rwnd=65535B, 60s/run, n=3)')
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(HERE, 'throughput_vs_rtt.png'), dpi=200)
plt.close()

print('saved: throughput_vs_loss.png , throughput_vs_rtt.png')
