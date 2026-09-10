#!/bin/bash
rm -f /vagrant/tju_tcp/test/tc_qdisc.log
for i in $(seq 1 45); do
  echo "=== sample $i $(date +%H:%M:%S) ===" >> /vagrant/tju_tcp/test/tc_qdisc.log
  tc qdisc show >> /vagrant/tju_tcp/test/tc_qdisc.log 2>&1
  sleep 2
done
echo "DONE" >> /vagrant/tju_tcp/test/tc_qdisc.log
