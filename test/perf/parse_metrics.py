# -*- coding: utf-8 -*-
# 解析 perf/raw/ 下每次实验的 client/server.event.trace，汇总 perf/metrics.csv
# 指标全部来自真实 trace，不做任何人工填充。
# 吞吐率主口径 = 服务端收到的应用字节 / 60s 损伤传输窗口（test_congestion.py 固定 sleep60）
import os, re, glob, csv, statistics
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, 'raw')
TRACE_MSS = 1375.0     # 与 gen_graph_win.py 的段数换算口径一致
DURATION = 60.0        # 损伤网络下的固定传输时长(秒)

ev_re = re.compile(r'^\[(\d+)\] \[(\w+)\] \[(.*)\]')
seg_re = re.compile(r'seq:(\d+) ack:(-?\d+) flag:(-?\d+) length:(\d+)')
cw_re = re.compile(r'type:(\d+) size:(\d+)')


def parse_client(path):
    send_total = 0
    seqs = {}
    cw = []
    t2 = t3 = 0
    for line in open(path, errors='ignore'):
        m = ev_re.match(line)
        if not m:
            continue
        typ, body = m.group(2), m.group(3)
        if typ == 'SEND':
            mm = seg_re.search(body)
            if mm:
                flag, ln, sq = int(mm.group(3)), int(mm.group(4)), int(mm.group(1))
                if flag == 0 and ln > 0:           # 仅统计数据段
                    send_total += 1
                    seqs[sq] = seqs.get(sq, 0) + 1
        elif typ == 'CWND':
            mm = cw_re.search(body)
            if mm:
                tp = int(mm.group(1))
                cw.append(int(mm.group(2)) / TRACE_MSS)
                if tp == 2:
                    t2 += 1
                elif tp == 3:
                    t3 += 1
    unique = len(seqs)
    return dict(send_total=send_total, unique=unique, retrans=send_total - unique,
                fastrx=t2, timeout=t3,
                cwpeak=max(cw) if cw else 0.0,
                cwmean=(sum(cw) / len(cw)) if cw else 0.0)


def parse_server(path):
    nbyte = nseg = 0
    first = last = None
    for line in open(path, errors='ignore'):
        m = ev_re.match(line)
        if not m:
            continue
        if m.group(2) != 'RECV':
            continue
        mm = seg_re.search(m.group(3))
        if mm:
            flag, ln = int(mm.group(3)), int(mm.group(4))
            if flag == 0 and ln > 0:
                nbyte += ln
                nseg += 1
                ts = int(m.group(1))
                if first is None:
                    first = ts
                last = ts
    span = (last - first) / 1e6 if (first is not None and last is not None) else 0.0
    return nbyte, nseg, span


rows = []
for d in sorted(glob.glob(os.path.join(RAW, '*'))):
    if not os.path.isdir(d):
        continue
    tag = os.path.basename(d)
    cp, sp = os.path.join(d, 'client.event.trace'), os.path.join(d, 'server.event.trace')
    if not (os.path.exists(cp) and os.path.exists(sp)):
        print('skip(缺trace):', tag)
        continue
    params = {}
    pp = os.path.join(d, 'params.txt')
    if os.path.exists(pp):
        for kv in open(pp).read().split():
            if '=' in kv:
                k, v = kv.split('=', 1)
                params[k] = v
    c = parse_client(cp)
    nbyte, nseg, span = parse_server(sp)
    thr = nbyte / DURATION / 1024.0
    eff = c['unique'] / float(c['send_total']) if c['send_total'] else 0.0
    rows.append(dict(
        tag=tag, rep=params.get('rep', ''), rate=params.get('rate', ''),
        delay=params.get('delay', ''), distro=params.get('distro', ''),
        loss=params.get('loss', ''),
        recv_bytes=nbyte, recv_segs=nseg, throughput_KBps=round(thr, 2),
        active_span_s=round(span, 1), send_segs=c['send_total'],
        retrans=c['retrans'], eff_ratio=round(eff, 4),
        fastrx=c['fastrx'], timeout=c['timeout'],
        cwnd_peak=round(c['cwpeak'], 1), cwnd_mean=round(c['cwmean'], 1)))

cols = ['tag', 'rep', 'rate', 'delay', 'distro', 'loss', 'recv_bytes', 'recv_segs',
        'throughput_KBps', 'active_span_s', 'send_segs', 'retrans', 'eff_ratio',
        'fastrx', 'timeout', 'cwnd_peak', 'cwnd_mean']
out = os.path.join(HERE, 'metrics.csv')
with open(out, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    for r in rows:
        w.writerow(r)

print('wrote %s  rows=%d\n' % (out, len(rows)))
agg = defaultdict(list)
for r in rows:
    agg[r['tag']].append(r['throughput_KBps'])
print('%-10s %-3s %-10s %-10s %-10s' % ('tag', 'n', 'mean', 'min', 'max'))
for tag in sorted(agg):
    v = agg[tag]
    print('%-10s %-3d %-10.2f %-10.2f %-10.2f' %
          (tag, len(v), statistics.mean(v), min(v), max(v)))
