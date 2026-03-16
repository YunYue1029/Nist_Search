import os
import json
import time
import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATA_DIR = os.getenv("DATA_DIR", "./nist_data")
CVE_CHUNK_DIR = os.path.join(DATA_DIR, "nvdcve-2.0-chunks")

# NVD 2.0 API endpoint
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Optional: set NVD_API_KEY env var for higher rate limits (50 req/30s vs 5 req/30s)
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

RESULTS_PER_PAGE = 2000  # max allowed by NVD API
# Delay between requests to respect rate limits (seconds)
REQUEST_DELAY = 6.5 if not NVD_API_KEY else 1.0


def download_cve_data():
    """Download the full CVE dataset from NVD 2.0 API with pagination."""
    os.makedirs(CVE_CHUNK_DIR, exist_ok=True)

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
        logger.info("Using NVD API key for higher rate limits.")
    else:
        logger.info("No NVD_API_KEY set. Using public rate limit (5 req/30s). "
                     "Set NVD_API_KEY env var for faster downloads.")

    start_index = 0
    total_results = None
    chunk_num = 0

    while True:
        params = {
            "startIndex": start_index,
            "resultsPerPage": RESULTS_PER_PAGE,
        }

        logger.info(f"Fetching CVEs: startIndex={start_index}, "
                     f"resultsPerPage={RESULTS_PER_PAGE}...")

        try:
            response = requests.get(
                NVD_CVE_API,
                params=params,
                headers=headers,
                timeout=120
            )
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed at startIndex={start_index}: {e}")
            logger.info("Retrying in 30 seconds...")
            time.sleep(30)
            continue

        # Get total on first request
        if total_results is None:
            total_results = data.get("totalResults", 0)
            logger.info(f"Total CVEs available: {total_results}")

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            logger.info("No more vulnerabilities returned. Done.")
            break

        # Save chunk to file
        chunk_num += 1
        chunk_filename = f"nvdcve-2.0-chunk-{chunk_num:05d}.json"
        chunk_filepath = os.path.join(CVE_CHUNK_DIR, chunk_filename)

        with open(chunk_filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f)

        fetched_count = start_index + len(vulnerabilities)
        logger.info(f"Saved {chunk_filename} "
                     f"({len(vulnerabilities)} CVEs, "
                     f"{fetched_count}/{total_results} total)")

        # Check if we've fetched everything
        start_index += len(vulnerabilities)
        if start_index >= total_results:
            logger.info("All CVEs downloaded.")
            break

        # Rate limit delay
        time.sleep(REQUEST_DELAY)

    logger.info(f"Download complete. {chunk_num} chunk files saved to {CVE_CHUNK_DIR}")


def download_data():
    """Main download entry point."""
    download_cve_data()


if __name__ == "__main__":
    download_data()
