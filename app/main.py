import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Query, HTTPException, BackgroundTasks
from motor.motor_asyncio import AsyncIOMotorClient
import logging
from sync import sync_job

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "cve_db"
COLLECTION_NAME = "cves"

mongodb_client: AsyncIOMotorClient = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global mongodb_client
    logger.info("Initializing MongoDB client...")
    mongodb_client = AsyncIOMotorClient(MONGO_URI)
    yield
    logger.info("Closing MongoDB client...")
    mongodb_client.close()

app = FastAPI(title="CVE Search API", lifespan=lifespan)

@app.get("/")
async def root():
    return {"message": "Welcome to the CVE Search API. Use /search?cpe=<CPE_URI> to query."}

@app.get("/search")
async def search_cve(
    cpe: str = Query(..., description="CPE 2.3 URI string to search for"),
    limit: int = Query(50, ge=1, le=1000, description="Number of results to return"),
    offset: int = Query(0, ge=0, description="Number of results to skip")
):
    if not mongodb_client:
        raise HTTPException(status_code=500, detail="Database connection not initialized")
        
    db = mongodb_client[DB_NAME]
    cve_collection = db[COLLECTION_NAME]
    cpematch_collection = db["cpematches"]
    
    try:
        # 1. 查找關聯的準則
        match_cursor = cpematch_collection.find({"matchedCpeNames": cpe}, {"criteria": 1, "_id": 0})
        matched_criteria = await match_cursor.to_list(length=2000)
        search_terms = list(set([cpe] + [m["criteria"] for m in matched_criteria]))
        
        query = {"cpe_list": {"$in": search_terms}}
        
        # 2. 獲取所有匹配的 CVE 分數資訊（用於統計）
        # 我們只選取必要的欄位以節省效能
        stats_cursor = cve_collection.find(
            query, 
            {"cve_id": 1, "raw_data.cve.metrics": 1, "_id": 0}
        )
        
        summary = {
            "total_count": 0,
            "cvss2_max": 0.0,
            "cvss2_max_cve": "N/A",
            "cvss3_max": 0.0,
            "cvss3_max_cve": "N/A",
            "cvss4_max": 0.0,
            "cvss4_max_cve": "N/A"
        }
        
        async for cve in stats_cursor:
            summary["total_count"] += 1
            metrics = cve.get("raw_data", {}).get("cve", {}).get("metrics", {})
            
            # CVSS 2.0
            for v2 in metrics.get("cvssMetricV2", []):
                score = v2.get("cvssData", {}).get("baseScore", 0.0)
                if score > summary["cvss2_max"]:
                    summary["cvss2_max"] = score
                    summary["cvss2_max_cve"] = cve["cve_id"]
            
            # CVSS 3.x (包含 3.0 與 3.1)
            for v3 in metrics.get("cvssMetricV31", []) + metrics.get("cvssMetricV30", []):
                score = v3.get("cvssData", {}).get("baseScore", 0.0)
                if score > summary["cvss3_max"]:
                    summary["cvss3_max"] = score
                    summary["cvss3_max_cve"] = cve["cve_id"]

            # CVSS 4.0
            for v4 in metrics.get("cvssMetricV40", []):
                score = v4.get("cvssData", {}).get("baseScore", 0.0)
                if score > summary["cvss4_max"]:
                    summary["cvss4_max"] = score
                    summary["cvss4_max_cve"] = cve["cve_id"]
        
        # 3. 獲取當前分頁的詳細資料並精簡內容
        cursor = cve_collection.find(query, {"_id": 0}).skip(offset).limit(limit)
        raw_results = await cursor.to_list(length=limit)
        
        details = []
        for item in raw_results:
            cve_id = item.get("cve_id")
            metrics = item.get("raw_data", {}).get("cve", {}).get("metrics", {})
            
            # 提取該 CVE 的各版本分數 (取該類別中的最高值)
            v2_score = 0.0
            for v2 in metrics.get("cvssMetricV2", []):
                v2_score = max(v2_score, v2.get("cvssData", {}).get("baseScore", 0.0))
                
            v3_score = 0.0
            for v3 in metrics.get("cvssMetricV31", []) + metrics.get("cvssMetricV30", []):
                v3_score = max(v3_score, v3.get("cvssData", {}).get("baseScore", 0.0))
                
            v4_score = 0.0
            for v4 in metrics.get("cvssMetricV40", []):
                v4_score = max(v4_score, v4.get("cvssData", {}).get("baseScore", 0.0))
                
            details.append({
                "cve_id": cve_id,
                "cvss_v2": v2_score,
                "cvss_v3": v3_score,
                "cvss_v4": v4_score
            })
        
        return {
            "cpe_query": cpe,
            "summary": summary,
            "details": details
        }
    except Exception as e:
        logger.error(f"Error querying database: {e}")
        raise HTTPException(status_code=500, detail="Internal server error while searching.")

@app.post("/sync/online")
async def trigger_sync_online(background_tasks: BackgroundTasks):
    """
    Trigger the download and ETL process in the background.
    """
    background_tasks.add_task(sync_job, True)
    return {"message": "Online sync job started in the background. Check server logs for progress."}

@app.post("/sync/local")
async def trigger_sync_local(background_tasks: BackgroundTasks):
    """
    Trigger the ETL process using local data in the background.
    """
    background_tasks.add_task(sync_job, False)
    return {"message": "Local sync job started in the background. Check server logs for progress."}
