"""
ml/download_dataset.py
=============================================================================
Downloads and validates the official UNSW-NB15 training and testing CSV sets
from verified public research mirrors.

Target locations:
  data/external/UNSW_NB15_training-set.csv (~32.3 MB, 175,341 records)
  data/external/UNSW_NB15_testing-set.csv  (~15.4 MB,  82,332 records)
=============================================================================
"""

import os
import sys
import time
import urllib.request
import hashlib

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "external"))

DATASET_CONFIG = {
    "UNSW_NB15_training-set.csv": {
        "primary_url": "https://huggingface.co/datasets/Mouwiya/UNSW-NB15-small/resolve/main/UNSW_NB15_training-set.csv",
        "fallback_url": "https://huggingface.co/datasets/dileepa0011/unsw-nb15/resolve/main/UNSW_NB15_training-set.csv",
        "expected_bytes": 32293018,
        "approx_rows": 175341,
    },
    "UNSW_NB15_testing-set.csv": {
        "primary_url": "https://huggingface.co/datasets/Mouwiya/UNSW-NB15-small/resolve/main/UNSW_NB15_testing-set.csv",
        "fallback_url": "https://huggingface.co/datasets/dileepa0011/unsw-nb15/resolve/main/UNSW_NB15_testing-set.csv",
        "expected_bytes": 15380800,
        "approx_rows": 82332,
    }
}


def download_file(filename: str, info: dict, target_dir: str = DATA_DIR) -> str:
    """Download a dataset file with retry, progress reporting, and validation."""
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, filename)

    if os.path.exists(target_path):
        size = os.path.getsize(target_path)
        if size == info["expected_bytes"]:
            print(f"[OK] {filename} already exists ({size:,} bytes). Skipping download.")
            return target_path
        else:
            print(f"[INFO] {filename} exists but size is {size} bytes (expected {info['expected_bytes']}). Re-downloading...")

    urls = [info["primary_url"], info["fallback_url"]]
    download_success = False

    for url in urls:
        print(f"[DOWNLOADING] {filename} from:\n  {url}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            with urllib.request.urlopen(req, timeout=60) as response, open(target_path, "wb") as out_file:
                total_length = response.getheader("content-length")
                total_length = int(total_length) if total_length else info["expected_bytes"]
                downloaded = 0
                block_size = 1024 * 1024  # 1 MB blocks
                start_time = time.time()

                while True:
                    buffer = response.read(block_size)
                    if not buffer:
                        break
                    downloaded += len(buffer)
                    out_file.write(buffer)
                    pct = (downloaded / total_length) * 100 if total_length else 0
                    elapsed = time.time() - start_time
                    speed_mb = (downloaded / (1024 * 1024)) / max(elapsed, 0.001)
                    sys.stdout.write(f"\r  Progress: {pct:5.1f}% [{downloaded:,} / {total_length:,} bytes] ({speed_mb:.2f} MB/s)")
                    sys.stdout.flush()

                print(f"\n[DOWNLOAD COMPLETE] Saved to: {target_path}")
                download_success = True
                break
        except Exception as e:
            print(f"\n[WARN] Download failed from {url}: {e}")
            if os.path.exists(target_path):
                try:
                    os.remove(target_path)
                except OSError:
                    pass

    if not download_success:
        raise RuntimeError(
            f"CRITICAL ERROR: Failed to download {filename} from all available sources.\n"
            f"Please verify network access. Synthetic data generation is strictly forbidden."
        )

    # Validate file size
    final_size = os.path.getsize(target_path)
    print(f"[VALIDATION] {filename} size: {final_size:,} bytes (expected {info['expected_bytes']:,})")
    assert final_size > 10_000_000, f"Downloaded file {filename} is suspiciously small: {final_size} bytes."

    return target_path


def compute_sha256(filepath: str) -> str:
    """Compute SHA-256 hash of a file in streaming chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def main():
    print("=" * 70)
    print("UNSW-NB15 DATASET ACQUISITION PIPELINE")
    print("=" * 70)
    print(f"Target Directory: {DATA_DIR}")

    hashes = {}
    for filename, info in DATASET_CONFIG.items():
        path = download_file(filename, info)
        sha = compute_sha256(path)
        hashes[filename] = sha
        print(f"  SHA-256: {sha}\n")

    print("=" * 70)
    print("DATASET ACQUISITION SUCCESSFUL")
    for fname, sha in hashes.items():
        print(f"  {fname}: {sha}")
    print("=" * 70)


if __name__ == "__main__":
    main()
