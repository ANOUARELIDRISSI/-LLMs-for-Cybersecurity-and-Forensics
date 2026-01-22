#!/usr/bin/env python3
"""
Dataset downloader for Advanced LLMs Cybersecurity project.
Downloads and prepares cybersecurity datasets for training and evaluation.
"""

import os
import requests
import zipfile
import tarfile
import json
from pathlib import Path
from typing import Dict, List
import logging
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatasetDownloader:
    """Downloads and manages cybersecurity datasets."""
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Dataset configurations
        self.datasets = {
            "malware_samples": {
                "url": "https://github.com/ytisf/theZoo/archive/refs/heads/master.zip",
                "description": "Malware samples for analysis",
                "extract_to": "malware"
            },
            "threat_intelligence": {
                "url": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
                "description": "MISP threat actor intelligence",
                "extract_to": "threat_intel"
            },
            "vulnerability_data": {
                "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100",
                "description": "NVD vulnerability database (API)",
                "extract_to": "vulnerabilities"
            },
            "network_logs": {
                "url": "https://raw.githubusercontent.com/logpai/loghub/master/Windows/Windows_2k.log",
                "description": "Windows system logs",
                "extract_to": "network_logs"
            },
            "phishing_emails": {
                "url": "https://raw.githubusercontent.com/tarunKoyalwar/phishing-email-detection/main/dataset/phishing_email.csv",
                "description": "Phishing email dataset",
                "extract_to": "phishing"
            },
            "security_logs": {
                "url": "https://raw.githubusercontent.com/logpai/loghub/master/Apache/Apache_2k.log",
                "description": "Apache security logs",
                "extract_to": "security_logs"
            },
            "malware_urls": {
                "url": "https://raw.githubusercontent.com/faizann24/Using-machine-learning-to-detect-malicious-URLs/master/data.csv",
                "description": "Malicious URLs dataset",
                "extract_to": "malware_urls"
            }
        }
    
    def download_file(self, url: str, destination: Path) -> bool:
        """Download a file from URL to destination."""
        try:
            logger.info(f"Downloading {url}")
            
            # Handle API endpoints differently
            if "services.nvd.nist.gov" in url:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                response = requests.get(url, headers=headers, timeout=30)
            else:
                response = requests.get(url, stream=True, timeout=30)
            
            response.raise_for_status()
            
            destination.parent.mkdir(parents=True, exist_ok=True)
            
            # For API responses, save as JSON
            if "services.nvd.nist.gov" in url:
                with open(destination.with_suffix('.json'), 'w') as f:
                    json.dump(response.json(), f, indent=2)
                logger.info(f"API data saved to {destination.with_suffix('.json')}")
            else:
                with open(destination, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                logger.info(f"Downloaded to {destination}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to download {url}: {e}")
            return False
    
    def extract_archive(self, archive_path: Path, extract_to: Path) -> bool:
        """Extract archive file."""
        try:
            extract_to.mkdir(parents=True, exist_ok=True)
            
            if archive_path.suffix == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_to)
            elif archive_path.suffix in ['.tar', '.gz', '.tgz']:
                with tarfile.open(archive_path, 'r:*') as tar_ref:
                    tar_ref.extractall(extract_to)
            
            logger.info(f"Extracted {archive_path} to {extract_to}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to extract {archive_path}: {e}")
            return False
    
    def download_dataset(self, dataset_name: str) -> bool:
        """Download and prepare a specific dataset."""
        if dataset_name not in self.datasets:
            logger.error(f"Unknown dataset: {dataset_name}")
            return False
        
        config = self.datasets[dataset_name]
        url = config["url"]
        extract_to = self.data_dir / config["extract_to"]
        
        # Determine filename from URL
        parsed_url = urlparse(url)
        filename = Path(parsed_url.path).name
        if not filename or "services.nvd.nist.gov" in url:
            filename = f"{dataset_name}.json"
        
        download_path = self.data_dir / "downloads" / filename
        
        # Download file
        if not self.download_file(url, download_path):
            return False
        
        # Handle API responses differently
        if "services.nvd.nist.gov" in url:
            # API response was already saved as JSON
            api_file = download_path.with_suffix('.json')
            if api_file.exists():
                extract_to.mkdir(parents=True, exist_ok=True)
                final_path = extract_to / api_file.name
                if final_path.exists():
                    final_path.unlink()
                api_file.rename(final_path)
                logger.info(f"API data moved to {final_path}")
            return True
        
        # Extract if it's an archive
        if filename.endswith(('.zip', '.tar', '.gz', '.tgz')):
            if not self.extract_archive(download_path, extract_to):
                return False
        else:
            # Move non-archive files to destination
            extract_to.mkdir(parents=True, exist_ok=True)
            final_path = extract_to / filename
            
            # Remove existing file if it exists
            if final_path.exists():
                final_path.unlink()
            
            download_path.rename(final_path)
        
        logger.info(f"Dataset {dataset_name} ready at {extract_to}")
        return True
    
    def download_all(self) -> Dict[str, bool]:
        """Download all configured datasets."""
        results = {}
        
        for dataset_name in self.datasets:
            logger.info(f"Processing dataset: {dataset_name}")
            results[dataset_name] = self.download_dataset(dataset_name)
        
        return results
    
    def create_dataset_manifest(self) -> None:
        """Create a manifest file describing available datasets."""
        manifest = {
            "datasets": {},
            "total_datasets": len(self.datasets),
            "data_directory": str(self.data_dir)
        }
        
        for name, config in self.datasets.items():
            dataset_path = self.data_dir / config["extract_to"]
            manifest["datasets"][name] = {
                "description": config["description"],
                "path": str(dataset_path),
                "exists": dataset_path.exists(),
                "url": config["url"]
            }
        
        manifest_path = self.data_dir / "manifest.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        logger.info(f"Dataset manifest created at {manifest_path}")

def main():
    """Main function to download datasets."""
    downloader = DatasetDownloader()
    
    logger.info("Starting dataset download process...")
    results = downloader.download_all()
    
    # Create manifest
    downloader.create_dataset_manifest()
    
    # Summary
    successful = sum(1 for success in results.values() if success)
    total = len(results)
    
    logger.info(f"Download complete: {successful}/{total} datasets successful")
    
    if successful < total:
        logger.warning("Some datasets failed to download. Check logs above.")
        failed = [name for name, success in results.items() if not success]
        logger.warning(f"Failed datasets: {failed}")

if __name__ == "__main__":
    main()