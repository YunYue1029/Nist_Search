import os
import gzip
import json
import tarfile
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import UpdateOne
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "cve_db"
CVE_COLLECTION = "cves"
CPE_COLLECTION = "cpes"
CPEMATCH_COLLECTION = "cpematches"
DATA_DIR = os.getenv("DATA_DIR", "./nist_data")
CVE_DATA_DIR = os.getenv("CVE_DATA_DIR", DATA_DIR)
CPE_DATA_DIR = os.getenv("CPE_DATA_DIR", os.path.join(DATA_DIR, "nvdcpe-2.0-chunks"))
CPEMATCH_DATA_DIR = os.getenv("CPEMATCH_DATA_DIR", os.path.join(DATA_DIR, "nvdcpematch-2.0-chunks"))

async def init_db():
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]
    cve_collection = db[CVE_COLLECTION]
    cpe_collection = db[CPE_COLLECTION]

    cpematch_collection = db[CPEMATCH_COLLECTION]

    # Create indexes
    await cve_collection.create_index("cpe_list")
    await cpe_collection.create_index("cpeName")
    await cpe_collection.create_index("cpeNameId", unique=True)
    await cpematch_collection.create_index("matchCriteriaId", unique=True)
    await cpematch_collection.create_index("criteria")
    logger.info("MongoDB indexes created.")
    return client, db

def load_json(filepath):
    """Load JSON from a file, supporting .gz compressed files."""
    if filepath.endswith('.gz'):
        with gzip.open(filepath, 'rt', encoding='utf-8') as f:
            return json.load(f)
    else:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)

def detect_format(data):
    """Detect whether the data is CVE, CPE, or CPE Match format."""
    fmt = data.get("format", "")
    if fmt == "NVD_CPEMatchString" or "matchStrings" in data:
        return "CPEMATCH"
    elif fmt == "NVD_CPE" or "products" in data:
        return "CPE"
    elif "CVE_Items" in data or "vulnerabilities" in data:
        return "CVE"
    else:
        return "UNKNOWN"

# ---------------------------------------------------------------------------
# CPE Product Processing
# ---------------------------------------------------------------------------

async def process_cpe_file(collection, filepath):
    """Process a NVD CPE product dictionary file and upsert into MongoDB."""
    logger.info(f"Processing CPE file: {filepath}...")
    try:
        data = load_json(filepath)

        if detect_format(data) != "CPE":
            logger.warning(f"Skipping {filepath}: not a CPE product file.")
            return

        products = data.get("products", [])
        if not products:
            logger.info(f"No products found in {filepath}.")
            return

        BATCH_SIZE = 5000
        total_upserted = 0

        for i in range(0, len(products), BATCH_SIZE):
            batch = products[i:i + BATCH_SIZE]
            operations = []

            for item in batch:
                cpe = item.get("cpe", {})
                cpe_name = cpe.get("cpeName")
                cpe_name_id = cpe.get("cpeNameId")

                if not cpe_name or not cpe_name_id:
                    continue

                # Extract English title if available
                title_en = ""
                for t in cpe.get("titles", []):
                    if t.get("lang") == "en":
                        title_en = t.get("title", "")
                        break

                # Parse CPE name components: cpe:2.3:part:vendor:product:version:...
                parts = cpe_name.split(":")
                document = {
                    "cpeName": cpe_name,
                    "cpeNameId": cpe_name_id,
                    "title": title_en,
                    "deprecated": cpe.get("deprecated", False),
                    "deprecatedBy": cpe.get("deprecatedBy", []),
                    "lastModified": cpe.get("lastModified", ""),
                    "created": cpe.get("created", ""),
                }
                # Add parsed fields for easier querying
                if len(parts) >= 6:
                    document["part"] = parts[2]      # a=application, o=os, h=hardware
                    document["vendor"] = parts[3]
                    document["product"] = parts[4]
                    document["version"] = parts[5]

                operations.append(
                    UpdateOne(
                        {"cpeNameId": cpe_name_id},
                        {"$set": document},
                        upsert=True
                    )
                )

            if operations:
                result = await collection.bulk_write(operations, ordered=False)
                count = result.upserted_count + result.modified_count
                total_upserted += count

        logger.info(f"CPE file {filepath} processed. Total upserted/modified: {total_upserted}")

    except Exception as e:
        logger.error(f"Error processing CPE file {filepath}: {e}")

# ---------------------------------------------------------------------------
# CVE Vulnerability Processing
# ---------------------------------------------------------------------------

async def process_cve_file(collection, filepath):
    """Process a NVD CVE vulnerability file and upsert into MongoDB."""
    logger.info(f"Processing CVE file: {filepath}...")
    try:
        data = load_json(filepath)

        if detect_format(data) != "CVE":
            logger.warning(f"Skipping {filepath}: not a CVE vulnerability file.")
            return

        # NVD 1.1 format vs 2.0 API format
        cve_items = data.get("CVE_Items", [])
        if not cve_items:
            cve_items = data.get("vulnerabilities", [])

        operations = []
        for item in cve_items:
            cve_data = item.get("cve", item)
            cve_id = ""

            # Handle NVD 2.0 format vs 1.1 format
            if "CVE" in data.get("CVE_data_type", ""):
                 cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
            elif "cve" in item:
                 cve_id = item["cve"].get("id")
            else:
                 continue

            if not cve_id:
                continue

            cpe_list = []

            # Extract CPEs - 1.1 Format
            nodes = item.get("configurations", {}).get("nodes", [])
            for node in nodes:
                children = node.get("children", [])
                cpe_matches = node.get("cpe_match", [])

                for match in cpe_matches:
                    cpe_list.append(match.get("cpe23Uri"))

                for child in children:
                    for match in child.get("cpe_match", []):
                        cpe_list.append(match.get("cpe23Uri"))

            # Extract CPEs - 2.0 Format
            configurations = item.get("cve", {}).get("configurations", [])
            for conf in configurations:
                 nodes = conf.get("nodes", [])
                 for node in nodes:
                     cpe_matches = node.get("cpeMatch", [])
                     for match in cpe_matches:
                         cpe_list.append(match.get("criteria"))

            # Clean and deduplicate
            cpe_list = list(set(filter(None, cpe_list)))

            document = {
                "cve_id": cve_id,
                "cpe_list": cpe_list,
                "raw_data": item
            }

            operations.append(
                UpdateOne(
                    {"cve_id": cve_id},
                    {"$set": document},
                    upsert=True
                )
            )

        if operations:
            result = await collection.bulk_write(operations, ordered=False)
            logger.info(f"CVE file {filepath} processed. Upserted/Modified: {result.upserted_count + result.modified_count}")
        else:
            logger.info(f"No valid CVE data to insert for {filepath}.")

    except Exception as e:
        logger.error(f"Error processing CVE file {filepath}: {e}")

# ---------------------------------------------------------------------------
# CPE Match Processing
# ---------------------------------------------------------------------------

async def process_cpematch_file(collection, filepath):
    """Process a NVD CPE Match file and upsert into MongoDB."""
    logger.info(f"Processing CPE Match file: {filepath}...")
    try:
        data = load_json(filepath)

        if detect_format(data) != "CPEMATCH":
            logger.warning(f"Skipping {filepath}: not a CPE Match file.")
            return

        match_strings = data.get("matchStrings", [])
        if not match_strings:
            logger.info(f"No matchStrings found in {filepath}.")
            return

        BATCH_SIZE = 5000
        total_upserted = 0

        for i in range(0, len(match_strings), BATCH_SIZE):
            batch = match_strings[i:i + BATCH_SIZE]
            operations = []

            for item in batch:
                ms = item.get("matchString", {})
                criteria_id = ms.get("matchCriteriaId")
                criteria = ms.get("criteria")

                if not criteria_id or not criteria:
                    continue

                # Collect matched CPE names
                matched_cpes = [
                    m.get("cpeName") for m in ms.get("matches", [])
                    if m.get("cpeName")
                ]

                document = {
                    "matchCriteriaId": criteria_id,
                    "criteria": criteria,
                    "status": ms.get("status", ""),
                    "lastModified": ms.get("lastModified", ""),
                    "created": ms.get("created", ""),
                    "matchedCpeNames": matched_cpes,
                }
                # Include version range fields if present
                for field in ["versionStartIncluding", "versionStartExcluding",
                              "versionEndIncluding", "versionEndExcluding"]:
                    if field in ms:
                        document[field] = ms[field]

                operations.append(
                    UpdateOne(
                        {"matchCriteriaId": criteria_id},
                        {"$set": document},
                        upsert=True
                    )
                )

            if operations:
                result = await collection.bulk_write(operations, ordered=False)
                count = result.upserted_count + result.modified_count
                total_upserted += count

        logger.info(f"CPE Match file {filepath} processed. Total upserted/modified: {total_upserted}")

    except Exception as e:
        logger.error(f"Error processing CPE Match file {filepath}: {e}")

# ---------------------------------------------------------------------------
# Tar.gz Extraction
# ---------------------------------------------------------------------------

def extract_tar_gz_files(data_dir):
    """Extract any .tar.gz files found in data_dir if not already extracted."""
    if not os.path.exists(data_dir):
        return

    for filename in os.listdir(data_dir):
        if not filename.endswith(".tar.gz"):
            continue

        filepath = os.path.join(data_dir, filename)
        # Determine expected extraction directory name from the tar.gz filename
        # e.g. nvdcpematch-2.0.tar.gz -> nvdcpematch-2.0-chunks
        extract_dir_name = filename.replace(".tar.gz", "-chunks")
        extract_path = os.path.join(data_dir, extract_dir_name)

        # Check if extraction directory already has content by peeking inside tar
        if os.path.exists(extract_path) and os.listdir(extract_path):
            logger.info(f"Skipping extraction of {filename}: {extract_dir_name}/ already exists.")
            continue

        logger.info(f"Extracting {filename} to {data_dir}...")
        try:
            with tarfile.open(filepath, 'r:gz') as tar:
                tar.extractall(path=data_dir)
            logger.info(f"Extracted {filename} successfully.")
        except Exception as e:
            logger.error(f"Failed to extract {filename}: {e}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    # Extract any tar.gz files before processing
    extract_tar_gz_files(DATA_DIR)

    client, db = await init_db()
    cve_collection = db[CVE_COLLECTION]
    cpe_collection = db[CPE_COLLECTION]
    cpematch_collection = db[CPEMATCH_COLLECTION]

    # Process CPE product data
    if os.path.exists(CPE_DATA_DIR):
        logger.info(f"=== Processing CPE product data from {CPE_DATA_DIR} ===")
        for root, _, files in os.walk(CPE_DATA_DIR):
            for filename in sorted(files):
                if filename.endswith(".json.gz") or filename.endswith(".json"):
                    filepath = os.path.join(root, filename)
                    await process_cpe_file(cpe_collection, filepath)
    else:
        logger.warning(f"CPE data directory {CPE_DATA_DIR} not found. Skipping.")

    # Process CPE Match data
    if os.path.exists(CPEMATCH_DATA_DIR):
        logger.info(f"=== Processing CPE Match data from {CPEMATCH_DATA_DIR} ===")
        for root, _, files in os.walk(CPEMATCH_DATA_DIR):
            for filename in sorted(files):
                if filename.endswith(".json.gz") or filename.endswith(".json"):
                    filepath = os.path.join(root, filename)
                    await process_cpematch_file(cpematch_collection, filepath)
    else:
        logger.warning(f"CPE Match data directory {CPEMATCH_DATA_DIR} not found. Skipping.")

    # Process CVE vulnerability data
    if os.path.exists(CVE_DATA_DIR):
        logger.info(f"=== Processing CVE vulnerability data from {CVE_DATA_DIR} ===")
        for root, _, files in os.walk(CVE_DATA_DIR):
            for filename in sorted(files):
                if filename.endswith(".json.gz") or filename.endswith(".json"):
                    filepath = os.path.join(root, filename)
                    data = load_json(filepath)
                    if detect_format(data) == "CVE":
                        await process_cve_file(cve_collection, filepath)
    else:
        logger.warning(f"CVE data directory {CVE_DATA_DIR} not found. Skipping.")

    client.close()
    logger.info("=== ETL complete ===")

if __name__ == "__main__":
    asyncio.run(main())
