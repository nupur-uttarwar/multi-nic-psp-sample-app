#!/bin/bash
killall -9 doca_psp_gateway
ldconfig  /opt/mellanox/dpdk/lib/x86_64-linux-gnu /opt/mellanox/doca/lib/x86_64-linux-gnu

nohup build/doca_psp_gateway -d ens5v0 -c /nfs/eedmunds/psp_app_input.json -a &
pid_3000=$!
sleep 5

for i in {1..100}; do
    nohup build/doca_psp_gateway -d ens5v0 -c /nfs/eedmunds/psp_app_input_2.json -a &
    pid_3001=$!
    sleep 5
    kill -9 $pid_3000

    nohup build/doca_psp_gateway -d ens5v0 -c /nfs/eedmunds/psp_app_input.json -a &
    pid_3000=$!
    sleep 5
    kill -9 $pid_3001
done
