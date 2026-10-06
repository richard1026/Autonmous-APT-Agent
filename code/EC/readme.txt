EC 環境重現與執行步驟】

1. 建立外部容器 (EC) Image：
   請在 EC 資料夾所在目錄（包含 Dockerfile、exploit.py、triage.py）執行以下指令：
   $ docker build -t my_ec_image ./EC



2. 執行並測試 (評分流程)：
   確保當前目錄有 /shared 資料夾與 grader.sh，然後依 Phase 啟動 IC 後執行：

----------------------------------------------------

Phase 1：

$ docker run --rm --name EC_PHASE1 -e TERM=xterm \
  -v "$(pwd)/shared:/shared" \
  -v "$(pwd)/grader.sh:/grader.sh" \
  my_ec_image /bin/bash -lc '
    chmod +x /grader.sh &&
    rm -f /tmp/bf_state.txt /tmp/offset.txt /tmp/discovery_state.txt /tmp/triage_strategy_state.txt &&
    rm -f /shared/exploit_done /shared/config.data /shared/coredump/* &&
    /grader.sh
  '

----------------------------------------------------

Phase 2：

$ docker run --rm --name EC_PHASE2 -e TERM=xterm \
  -v "$(pwd)/shared:/shared" \
  -v "$(pwd)/grader.sh:/grader.sh" \
  my_ec_image /bin/bash -lc '
    chmod +x /grader.sh &&
    rm -f /tmp/bf_state.txt /tmp/offset.txt /tmp/discovery_state.txt /tmp/triage_strategy_state.txt &&
    rm -f /shared/exploit_done /shared/config.data /shared/coredump/* &&
    /grader.sh
  '

----------------------------------------------------

Phase 3：

$ docker run --rm --name EC_PHASE3 -e TERM=xterm \
  -v "$(pwd)/shared:/shared" \
  -v "$(pwd)/grader.sh:/grader.sh" \
  my_ec_image /bin/bash -lc '
    chmod +x /grader.sh &&
    rm -f /tmp/bf_state.txt /tmp/offset.txt /tmp/discovery_state.txt /tmp/triage_strategy_state.txt &&
    rm -f /shared/exploit_done /shared/config.data /shared/coredump/* &&
    /grader.sh
  '
``