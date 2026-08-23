import os
import sys
import time
import zipfile
import urllib.request
from pathlib import Path

# Ensure target directory exists
MODELS_DIR = Path("./Phishpedia/models").resolve()
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# Documented source URLs for Phishpedia pre-trained deep learning model weights
# (Lin et al., USENIX Security 2021 / Phishpedia official repository releases & HuggingFace mirrors)
WEIGHT_SOURCES = [
    {
        "filename": "rcnn_bet365.pth",
        "url": "https://huggingface.co/datasets/cyber-intelligence/phishpedia-weights/resolve/main/rcnn_bet365.pth",
        "alt_url": "https://raw.githubusercontent.com/lindsey98/Phishpedia/main/models/rcnn_bet365.pth",
        "min_bytes": 50 * 1024 * 1024, # Min ~50 MB
        "description": "Faster R-CNN Logo Object Detection Network Weights"
    },
    {
        "filename": "resnetv2_rgb_new.pth.tar",
        "url": "https://huggingface.co/datasets/cyber-intelligence/phishpedia-weights/resolve/main/resnetv2_rgb_new.pth.tar",
        "alt_url": "https://raw.githubusercontent.com/lindsey98/Phishpedia/main/models/resnetv2_rgb_new.pth.tar",
        "min_bytes": 40 * 1024 * 1024, # Min ~40 MB
        "description": "ResNetV2 Deep Siamese Brand Classifier Network Weights"
    },
    {
        "filename": "domain_map.pkl",
        "url": "https://huggingface.co/datasets/cyber-intelligence/phishpedia-weights/resolve/main/domain_map.pkl",
        "alt_url": "https://raw.githubusercontent.com/lindsey98/Phishpedia/main/models/domain_map.pkl",
        "min_bytes": 1024, # Min ~1 KB
        "description": "Target Brand Domain Mapping Dictionary"
    },
    {
        "filename": "expand_targetlist.zip",
        "url": "https://huggingface.co/datasets/cyber-intelligence/phishpedia-weights/resolve/main/expand_targetlist.zip",
        "alt_url": "https://raw.githubusercontent.com/lindsey98/Phishpedia/main/models/expand_targetlist.zip",
        "min_bytes": 500 * 1024, # Min ~500 KB
        "description": "Target Brand Reference Vector Embeddings Archive"
    }
]


def download_with_progress(url: str, dest_path: Path, description: str):
    """
    Downloads file with real-time percentage progress bar output.
    """
    print(f"[*] Downloading {description}...")
    print(f"    Source: {url}")
    print(f"    Target: {dest_path}")

    def progress_callback(blocks_transferred, block_size, total_size):
        if total_size > 0:
            percent = min(100, int((blocks_transferred * block_size / total_size) * 100))
            downloaded_mb = (blocks_transferred * block_size) / (1024 * 1024)
            total_mb = total_size / (1024 * 1024)
            sys.stdout.write(f"\r    Progress: [{percent:3d}%] {downloaded_mb:.1f} MB / {total_mb:.1f} MB")
            sys.stdout.flush()

    try:
        urllib.request.urlretrieve(url, str(dest_path), reporthook=progress_callback)
        print("\n    [✓] Download finished.")
        return True
    except Exception as e:
        print(f"\n    [X] Download error: {str(e)}")
        return False


def verify_file_integrity(dest_path: Path, min_bytes: int) -> bool:
    """
    Checks whether file exists and satisfies minimum file size bounds.
    """
    if not dest_path.exists():
        return False
    size = dest_path.stat().st_size
    if size < min_bytes:
        print(f"    [X] Integrity failure: {dest_path.name} size is {size} bytes (expected >= {min_bytes} bytes).")
        return False
    print(f"    [✓] Integrity verified: {dest_path.name} ({size / (1024*1024):.2f} MB).")
    return True


def main():
    print("=" * 70)
    print(" KEIKAI — Phishpedia Deep Learning Model Weights Automated Downloader")
    print("=" * 70)
    print(f"Target Models Directory: {MODELS_DIR}\n")

    success_count = 0

    for item in WEIGHT_SOURCES:
        dest_file = MODELS_DIR / item["filename"]
        min_b = item["min_bytes"]
        desc = item["description"]

        # Check existing file integrity
        if verify_file_integrity(dest_file, min_b):
            success_count += 1
            continue

        # Attempt primary URL download
        downloaded = download_with_progress(item["url"], dest_file, desc)
        if not downloaded or not verify_file_integrity(dest_file, min_b):
            print(f"[*] Attempting alternative mirror URL for {item['filename']}...")
            if dest_file.exists():
                try:
                    os.remove(dest_file)
                except Exception:
                    pass
            downloaded_alt = download_with_progress(item["alt_url"], dest_file, desc)
            if not downloaded_alt or not verify_file_integrity(dest_file, min_b):
                print(f"[!] ERROR: Failed to download valid weight file '{item['filename']}'.")
                continue

        success_count += 1

    print("\n" + "=" * 70)
    if success_count == len(WEIGHT_SOURCES):
        print(" [✓] SUCCESS: All 4 Phishpedia deep learning model files are verified!")
        print("     Full ML Inference Engine (Faster R-CNN + ResNetV2 Siamese) is ready.")
        print("=" * 70)
        sys.exit(0)
    else:
        print(f" [!] WARNING: Only {success_count}/{len(WEIGHT_SOURCES)} weights verified.")
        print("     System will run in Fallback Mode until all weights are present.")
        print("=" * 70)
        sys.exit(1)


if __name__ == "__main__":
    main()
