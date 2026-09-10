#!/bin/bash
f=/vagrant/tju_tcp/test/rdt_dbg.log
echo "=== counts ==="
echo -n "FLUSH: "; grep -c "FLUSH sent" $f
echo -n "FASTXMIT: "; grep -c "FASTXMIT" $f
echo -n "NEWACK: "; grep -c "NEWACK" $f
echo -n "RTO: "; grep -c "RTO retransmit" $f
echo -n "DUPACK: "; grep -c "DUPACK" $f
echo -n "RECV_DATA(server): "; grep -c "\[server\] RECV_DATA" $f
echo "=== FLUSH seg count distribution ==="
grep "FLUSH sent" $f | grep -o "sent [0-9]* segs" | sort | uniq -c | sort -rn | head -10
echo "=== FASTXMIT repeated bases top 10 ==="
grep "FASTXMIT" $f | grep -o "base=[0-9]*" | sort | uniq -c | sort -rn | head -10
echo "=== time span ==="
head -1 $f
tail -1 $f
