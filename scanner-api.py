import os
import secrets
import subprocess
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

APP_TOKEN = os.environ.get("SCANNER_API_TOKEN", "")
SOURCE_ROOT = "/www/wwwroot"
SOURCE_SCRIPT = "/opt/security-scanner/scan-source.sh"
DB_SCRIPT = "/opt/security-scanner/scan-database.sh"

app = FastAPI(title="aaPanel Read-only Scanner", version="3.0")

class SourceRequest(BaseModel):
    source_path: str = Field(min_length=1, max_length=512)

class DatabaseRequest(BaseModel):
    db_host: str = Field(default="host.docker.internal", min_length=1, max_length=255)
    db_port: int = Field(default=3306, ge=1, le=65535)
    db_user: str = Field(min_length=1, max_length=128)
    db_name: str = Field(min_length=1, max_length=128)
    db_password: str = Field(min_length=1, max_length=1024)

def auth(x_scanner_token: str | None):
    if not APP_TOKEN or not x_scanner_token or not secrets.compare_digest(x_scanner_token, APP_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")

def safe_source(path: str) -> str:
    real = os.path.realpath(path)
    root = os.path.realpath(SOURCE_ROOT)
    if real == root or not real.startswith(root + os.sep):
        raise HTTPException(status_code=400, detail="Source must be a website directory below /www/wwwroot")
    if ".." in os.path.normpath(path).split(os.sep):
        raise HTTPException(status_code=400, detail="Path traversal is not allowed")
    if not os.path.isdir(real):
        raise HTTPException(status_code=400, detail="Source directory does not exist")
    return real

def run_json(cmd, *, input_text=None, timeout=900):
    try:
        p = subprocess.run(
            cmd,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            env={k:v for k,v in os.environ.items() if k != "MYSQL_PWD"},
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Scanner timeout")
    if not p.stdout.strip():
        detail = (p.stderr or "Scanner returned no JSON")[-2000:]
        raise HTTPException(status_code=502, detail=detail)
    try:
        import json
        data = json.loads(p.stdout)
    except Exception:
        raise HTTPException(status_code=502, detail=("Invalid scanner JSON: " + p.stdout[-2000:]))
    if p.returncode not in (0,):
        data.setdefault("status", "error")
    return data

@app.get("/health")
def health():
    return {"status":"ok","mode":"read-only"}

@app.post("/scan/source")
def scan_source(req: SourceRequest, x_scanner_token: str | None = Header(default=None)):
    auth(x_scanner_token)
    path = safe_source(req.source_path)
    return run_json(["bash", SOURCE_SCRIPT, path])

@app.post("/scan/database")
def scan_database(req: DatabaseRequest, x_scanner_token: str | None = Header(default=None)):
    auth(x_scanner_token)
    # The password is supplied via stdin to the scanner, not in its argv.
    return run_json(
        ["bash", DB_SCRIPT, "--host", req.db_host, "--port", str(req.db_port),
         "--user", req.db_user, "--database", req.db_name],
        input_text=req.db_password,
        timeout=900,
    )
