import os
import time
import schedule
import logging
import asyncio

# Assuming these are available in our app context
from download import download_data
from etl import main as etl_main

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def sync_job(online: bool = True):
    mode = "online" if online else "local"
    logger.info(f"Starting sync job ({mode}): Updating MongoDB...")
    # For NVD 2.0 API, a real sync would use 'lastModStartDate' and 'lastModEndDate' params
    # to fetch only recently modified CVE records.
    try:
        if online:
            logger.info("Downloading data from online source...")
            download_data()
        else:
            logger.info("Skipping download, using local data...")
            
        asyncio.run(etl_main())
        logger.info(f"Sync job ({mode}) completed successfully.")
    except Exception as e:
        logger.error(f"Sync job ({mode}) failed: {e}")

def run_scheduler():
    logger.info("Sync Scheduler started. Job will run daily at 00:00.")
    
    schedule.every().day.at("00:00").do(sync_job)

    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    # Run once at startup
    sync_job()
    # Then start the scheduler
    run_scheduler()
