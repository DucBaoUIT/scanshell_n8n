# WordPress Security Scanner

Security scanner service for detecting suspicious PHP files, webshells,
malware loaders, obfuscated payloads and persistence mechanisms in
WordPress source code.

## Components

- `scan-source.sh` - Read-only source code scanner
- `scan-database.sh` - Database security scanner
- `scanner-api.py` - Scanner API
- `Dockerfile` - Scanner container image
- `docker-compose.yml` - Deployment configuration

## Features

The source scanner checks for suspicious combinations of:

- Dynamic code execution
- `eval()` / variable function calls
- Encoded or compressed PHP payloads
- Obfuscated PHP
- HTTP/request input combined with execution
- File upload and filesystem write primitives
- Remote payload retrieval
- PHP persistence mechanisms
- `auto_prepend_file` / `auto_append_file`
- Suspicious files in WordPress persistence locations
- PHP code hidden in non-PHP files
- Webshell/backdoor-like filenames
- Encoded/compressed embedded PHP payloads

The scanner is designed to operate in **READ-ONLY mode**.

It does not modify source files or database records.

## Docker Deployment

Start the scanner API:

```bash
docker compose up -d scanner-api
```

Check the container:

```bash
docker compose ps
```

Run a source scan:

```bash
docker compose exec scanner-api \
bash /opt/security-scanner/scan-source.sh \
/www/wwwroot/example.com
```

## Security Policy

Critical findings should be manually reviewed immediately.

The scanner intentionally uses multiple signals rather than treating
generic PHP functionality such as `include`, HTTP input, filesystem access
or network requests as malware by themselves.

## CI

GitHub Actions automatically performs security checks on the repository.

The CI pipeline:

1. Validates shell scripts.
2. Checks for accidentally committed secrets.
3. Runs the source scanner against a controlled test source.
4. Generates a JSON security report.
5. Fails when critical findings are detected.
6. Uploads the report as a GitHub Actions artifact.

## Runtime Data

Runtime data is intentionally excluded from Git:

- `.env`
- `data/`
- SQLite databases
- SQLite WAL/SHM files
- runtime logs
- temporary scan results

These files must not be committed because they may contain credentials,
workflow data or runtime state.

## Repository Structure

```text
scanshell_n8n/
├── .github/
│   └── workflows/
│       └── security-scan.yml
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── README.md
├── requirements.txt
├── scan-database.sh
├── scan-source.sh
└── scanner-api.py
```

## Development

After changing the scanner:

```bash
bash -n scan-source.sh
bash -n scan-database.sh

git add .
git commit -m "Update security scanner"
git push
```

GitHub Actions will automatically run the security CI after the push.
