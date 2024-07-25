#!/bin/bash
killall -9 doca_psp_gateway
ldconfig  /opt/mellanox/dpdk/lib/x86_64-linux-gnu /opt/mellanox/doca/lib/x86_64-linux-gnu
killall -9 ping

# Start DOCA processes on 3000, and move to ActivePending
echo "Starting DOCA process on 3000"
nohup build/doca_psp_gateway -d ens5v0 -c /nfs/eedmunds/psp_app_input.json -a &
pid_3000=$!
sleep 5

for i in {1..100}; do
    # Start DOCA processes on 3001, and move to Active
    nohup build/doca_psp_gateway -d ens5v0 -c /nfs/eedmunds/psp_app_input_2.json -a &
    pid_3001=$!
    sleep 5
    kill -9 $pid_3000

    nohup build/doca_psp_gateway -d ens5v0 -c /nfs/eedmunds/psp_app_input.json -a &
    pid_3000=$!
    sleep 5
    kill -9 $pid_3001
done
