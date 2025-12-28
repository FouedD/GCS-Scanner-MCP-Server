import os
import subprocess
import tempfile
import json
from typing import List, Dict, Any
from google.cloud import storage
from fastmcp import FastMCP

# Initialize MCP Server
mcp = FastMCP("GCS-Security-Scanner")

MAX_FILE_SIZE_MB = 5 
SENSITIVE_EXTENSIONS = {".js", ".env", ".json", ".txt", ".config"}

def run_gitleaks(file_path: str) -> List[Dict[str, Any]]:
    """Runs gitleaks on a specific file and returns findings."""
    try:
        result = subprocess.run(
            ["gitleaks", "detect", "--no-git", "--source", file_path, "--report-format", "json", "-r", "-"],
            capture_output=True,
            text=True
        )
        
        # Gitleaks returns exit code 1 if leaks are found
        if result.returncode == 1 and result.stdout:
            return json.loads(result.stdout)
        return []
    except Exception as e:
        return [{"error": f"Gitleaks execution failed: {str(e)}"}]

@mcp.tool()
def scan_public_bucket(bucket_name: str) -> str:
    """
    Scans files in a public GCS bucket for secrets using Gitleaks.
    Args:
        bucket_name: The name of the GCS bucket to scan.
    """
    client = storage.Client.create_anonymous_client()
    try:
        bucket = client.bucket(bucket_name)
        blobs = bucket.list_blobs()
        
        all_findings = []
        scanned_filenames = []
        files_scanned = 0

        for blob in blobs:
            # Check extension
            ext = os.path.splitext(blob.name)[1].lower()
            if ext not in SENSITIVE_EXTENSIONS:
                continue

            # Check size
            size_mb = blob.size / (1024 * 1024)
            if size_mb > MAX_FILE_SIZE_MB:
                all_findings.append({
                    "file": blob.name,
                    "status": "skipped",
                    "reason": f"File too large ({size_mb:.2f}MB)"
                })
                continue
            
            scanned_filenames.append(blob.name)

            # Scan the file
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                blob.download_to_filename(tmp.name)
                findings = run_gitleaks(tmp.name)
                
                if findings:
                    all_findings.append({
                        "file": blob.name,
                        "leaks": findings
                    })
                
                os.remove(tmp.name)
            files_scanned += 1

        summary = {
            "bucket": bucket_name,
            "files_processed_count": files_scanned,
            "scanned_files": scanned_filenames,
            "vulnerabilities": all_findings
        }
        
        return json.dumps(summary, indent=2)

    except Exception as e:
        return f"Error scanning bucket: {str(e)}"

if __name__ == "__main__":
    mcp.run()
