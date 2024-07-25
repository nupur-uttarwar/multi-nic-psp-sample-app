#!/bin/bash
killall -9 doca_psp_gateway
ldconfig  /opt/mellanox/dpdk/lib/x86_64-linux-gnu /opt/mellanox/doca/lib/x86_64-linux-gnu
killall -9 ping

# Start DOCA processes on 3000, and move to ActivePending
echo "Starting DOCA process on 3000"
nohup build/doca_psp_gateway -d ens5v0 -c /nfs/eedmunds/psp_app_input.json -a &
pid_3000=$!
sleep 5
python3 test/grpc_test.py op_state --grpc_port 3000 --op_state ActivePending

rm ping_results.txt
# nohup ping 60.0.0.69 -i 0.01 > ping_results.txt &

# Starting point: Traffic is reaching 3000 (ActivePending) and 3001 is disconnected
for i in {1..100}; do
    # Start DOCA processes on 3001, and move to Active
    nohup build/doca_psp_gateway -d ens5v0 -c /nfs/eedmunds/psp_app_input_2.json -a &
    pid_3001=$!
    sleep 5
    echo "Passive->Active $(date '+%H:%M:%S.%6N')"
    python3 test/grpc_test.py op_state --grpc_port 3001 --op_state Active | tee -a ping_results.txt
    kill -9 $pid_3000
    echo "Active->Pending $(date '+%H:%M:%S.%6N')"
    python3 test/grpc_test.py op_state --grpc_port 3001 --op_state ActivePending | tee -a ping_results.txt

    nohup build/doca_psp_gateway -d ens5v0 -c /nfs/eedmunds/psp_app_input.json -a &
    pid_3000=$!
    sleep 5
    echo "Passive->Active $(date '+%H:%M:%S.%6N')"
    python3 test/grpc_test.py op_state --grpc_port 3000 --op_state Active | tee -a ping_results.txt
    kill -9 $pid_3001
    echo "Active->Pending $(date '+%H:%M:%S.%6N')"
    python3 test/grpc_test.py op_state --grpc_port 3000 --op_state ActivePending | tee -a ping_results.txt
done

cat ping_results.txt