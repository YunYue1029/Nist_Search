#!/bin/bash

# 檢查是否有輸入編號
if [ -z "$1" ]; then
  echo "使用方法: ./load_chunk.sh <編號>"
  echo "範例: ./load_chunk.sh 153"
  exit 1
fi

# 將輸入的數字格式化為 5 位數（例如 153 -> 00153）
CHUNK_NUM=$(printf "%05d" $1)
FILEPATH="/app/nist_data/nvdcve-2.0-chunks/nvdcve-2.0-chunk-${CHUNK_NUM}.json"

echo "----------------------------------------------------"
echo "正在手動觸發 ETL 載入中..."
echo "目標編號: ${CHUNK_NUM}"
echo "容器路徑: ${FILEPATH}"
echo "----------------------------------------------------"

# 執行 Docker 指令
docker exec cve-api-service python3 -c "
import asyncio
import os
from etl import init_db, process_cve_file, CVE_COLLECTION

async def run():
    target = '${FILEPATH}'
    if not os.path.exists(target):
        print(f'錯誤: 找不到檔案 {target}')
        return

    try:
        client, db = await init_db()
        cve_col = db[CVE_COLLECTION]
        print(f'開始處理 {target}...')
        await process_cve_file(cve_col, target)
        client.close()
        print('處理完成。')
    except Exception as e:
        print(f'執行過程中發生錯誤: {e}')

asyncio.run(run())
"
