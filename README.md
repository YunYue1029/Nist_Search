# NIST Search

這是一個基於 FastAPI 與 MongoDB 建立的 CVE (Common Vulnerabilities and Exposures) 搜尋 API。它允許使用者透過 CPE (Common Platform Enumeration) 2.3 URI 來查詢相關的 CVE 漏洞資訊，並提供各版本 CVSS 分數的統計與詳細資料。

## 系統架構

- **FastAPI**: 提供高效能的非同步 RESTful API 服務。
- **MongoDB**: 儲存從 NIST NVD (National Vulnerability Database) 取得的 CVE 與 CPE 對應資料。
- **Docker & Docker Compose**: 容器化部署，包含 API 服務與資料庫，並設定好資料卷（Volumes）以確保資料持久化。

## 目錄結構

- `app/`: FastAPI 應用程式的主要程式碼。
  - `main.py`: API 路由與主要業務邏輯。
  - `etl.py` / `sync.py` / `download.py`: 負責從 NIST 下載資料、解析 JSON 並存入資料庫的背景服務任務。
- `docker-compose.yml`: Docker 部署設定檔，定義了資料庫與 API 的容器運作方式。
- `mongodb_data/`: MongoDB 資料庫檔案的實體儲存目錄（確保資料庫重啟不遺失）。
- `nist_data/`: 從 NIST 下載的 NVD JSON 原始資料存放目錄。
- `load_chunk.sh`: 輔助腳本，用於手動觸發並載入特定的 NVD chunk JSON 檔案到資料庫中。

## 快速開始

### 1. 啟動服務

請確認你的系統已經安裝了 Docker 與 Docker Compose。在專案的根目錄下執行以下指令來建置並啟動服務：

```bash
docker-compose up -d --build
```

這會同時啟動兩個容器：
- `cve-mongodb`: 映射至本機的 `27017` 埠。
- `cve-api-service`: 映射至本機的 `8000` 埠。

### 2. 資料庫同步 (ETL)

容器剛建立時，MongoDB 資料庫會是空的，請先載入 NIST 的漏洞資料：

- **線上同步 (從 NIST NVD 下載)**：
  發送 POST 請求，觸發背景背景程式從遠端下載並解析資料：
  ```bash
  curl -X POST http://localhost:8000/sync/online
  ```
- **本地同步 (使用已存在的本地資料)**：
  如果你已經預先將 JSON 檔案放在 `nist_data/` 內，可以觸發讀取本機資料來同步：
  ```bash
  curl -X POST http://localhost:8000/sync/local
  ```
- **手動載入特定 Chunk (開發與測試用)**：
  若想單獨測試讀取特定編號的資料檔案（例如 `nvdcve-2.0-chunk-00153.json`），可以執行腳本：
  ```bash
  ./load_chunk.sh 153
  ```

### 3. API 端點說明

服務啟動後，可前往 [http://localhost:8000/docs](http://localhost:8000/docs) 檢視與測試 Swagger UI，或者參考下方主要端點：

#### `GET /search`
- **說明**: 透過 CPE 查詢相關的 CVE 漏洞與評分統計。
- **查詢參數**:
  - `cpe` (字串, **必填**): 指定的 CPE 2.3 URI 字串 (例如 `cpe:2.3:o:microsoft:windows_10:1511:*:*:*:*:*:*:*`)。
  - `limit` (整數, 選填, 預設 `50`): 回傳的資料數量上限。
  - `offset` (整數, 選填, 預設 `0`): 分頁偏移量。
- **回傳內容**:
  回傳對應該 CPE 的 CVE 漏洞總數，包含 CVSS (v2, v3, v4) 單項的最高分數，以及相對應漏洞的列表與其獨立分數。

#### `POST /sync/online`
- **說明**: 觸發線上同步下載並載入資料庫的背景任務。

#### `POST /sync/local`
- **說明**: 觸發本地現有檔案同步至資料庫的背景任務。

## 相關設定

系統所需的環境變數（如資料庫連線字串）可直接在 `docker-compose.yml` 內調整：
- `MONGO_URI`: 設定 MongoDB 的連線網址（預設為 `mongodb://cve-mongodb:27017/`）。

## 關閉服務

若要停止並移除建立的容器服務：
```bash
docker-compose down
```
> **注意**：因為我們使用了資料卷掛載（Volume mapping），存在 `./mongodb_data` 與 `./nist_data` 的資料仍會保留在你的實體硬碟中，不會因容器刪除而遺失。
