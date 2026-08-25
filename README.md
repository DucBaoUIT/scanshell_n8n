# aaPanel Security Shell Scanner — n8n Workflow

This repository contains the n8n workflow used to trigger the read-only aaPanel source/database security scanner and send the results to Discord.

## Security status

The original workflow contained **hard-coded sensitive values**:

- Discord webhook URL
- Scanner API token
- Database connection information

Those values have been removed from the sanitized workflow.

> **Important:** because the original workflow exposed a live Discord webhook and scanner token, rotate/revoke those values before using the workflow again.

## Files

- `Scan_shell_hardened.json` — sanitized n8n workflow.
- `scan-source.sh` — read-only source scanner.
- `scan-database.sh` — read-only database scanner.
- `scanner-api.py` — scanner API.
- `Dockerfile` — scanner container image.
- `docker-compose.yml` — container deployment.
- `requirements.txt` — Python dependencies.

## n8n workflow

The workflow is:

```text
Start Scan Form
       |
       v
Validate Inputs
       |
       +--------------------+
       |                    |
       v                    v
 Scan Source          Scan Database
       |                    |
       +---------+----------+
                 |
                 v
        Merge Scan Results
             /                   /                    v           v
 Build Discord     Build Findings
     Embed              TXT
       |                 |
       v                 v
Send Discord Report  Send Discord TXT
```

## Required n8n environment variables

The hardened workflow expects these values to be provided to the n8n process/container:

```env
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
SCANNER_API_TOKEN=replace-with-a-random-token
DB_HOST=172.18.0.1
DB_USER=shell_scanner
```

### Do NOT put these values in the workflow JSON

Do not replace the environment expressions with real secrets such as:

```text
https://discord.com/api/webhooks/...
```

or:

```text
X-Scanner-Token: real-token
```

Keep the real values in the n8n runtime environment or another secret-management mechanism.

## Enabling environment variables in n8n

If n8n is running with Docker Compose, place the secrets in the deployment environment, not in Git.

Example:

```yaml
services:
  n8n:
    environment:
      - DISCORD_WEBHOOK_URL=${DISCORD_WEBHOOK_URL}
      - SCANNER_API_TOKEN=${SCANNER_API_TOKEN}
      - DB_HOST=${DB_HOST}
      - DB_USER=${DB_USER}
```

Then keep the actual values in a local `.env` file that is excluded by `.gitignore`.

Example:

```env
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/REPLACE_ME
SCANNER_API_TOKEN=REPLACE_ME
DB_HOST=172.18.0.1
DB_USER=shell_scanner
```

**Never commit this `.env` file.**

## n8n environment-variable access

The workflow references secrets with:

```text
$env.DISCORD_WEBHOOK_URL
$env.SCANNER_API_TOKEN
$env.DB_HOST
$env.DB_USER
```

Make sure the n8n deployment permits the workflow to read the required environment variables. If your n8n version/deployment policy disables environment-variable access from expressions, use an n8n credential/secret mechanism instead of hard-coding secrets into nodes.

## Database password

The workflow currently receives the database password through the scan form and passes it to the scanner API.

This means the password can potentially exist in n8n execution data depending on the instance's execution-data retention/settings.

For a production deployment, prefer one of these designs:

1. Store the database credential in a secret/credential store and do not request it through the public form.
2. Use a dedicated low-privilege database account for scanning.
3. Disable or minimize execution-data retention where appropriate.
4. Never expose database passwords in Discord messages, logs, artifacts, Git, or workflow JSON.

## Scanner API token

Generate a new random token after rotating the previously exposed token.

For example:

```bash
openssl rand -hex 32
```

Set the same value in:

```env
SCANNER_API_TOKEN=...
```

and in the scanner API deployment.

## Discord webhook

Because the original workflow file contained a Discord webhook URL, consider that webhook **compromised**.

Create a replacement webhook and update:

```env
DISCORD_WEBHOOK_URL=...
```

Do not put the replacement URL into the workflow JSON.

## Git protection

The repository should contain a `.gitignore` similar to:

```gitignore
.env
.env.*
!.env.example

data/
*.sqlite
*.sqlite-shm
*.sqlite-wal
*.log

ci-reports/
```

Do not commit:

- `.env`
- database files
- n8n runtime data
- execution logs
- scanner reports containing sensitive information
- Discord webhook URLs
- API tokens
- database passwords

## CI security

GitHub Actions should perform at least:

1. Secret scanning.
2. Shell syntax validation.
3. Python syntax validation.
4. Scanner execution against a clean fixture.
5. A malicious fixture test proving that the scanner detects a known shell pattern.
6. Artifact upload of reports only when the report does not contain credentials or sensitive production data.

The CI must never scan the production `/www/wwwroot` directory.

## Important rotation step

The uploaded original workflow contained live-looking credentials. Before deploying the sanitized workflow:

- revoke/rotate the Discord webhook;
- rotate the scanner API token;
- review the database account password;
- check Git history to ensure the exposed values are not already committed.

If a secret was committed to Git history, simply deleting it from the latest commit is not sufficient; rotate the secret and consider rewriting repository history if necessary.

## Importing the hardened workflow

In n8n:

1. Open **Workflows**.
2. Choose **Import from File**.
3. Select `Scan_shell_hardened.json`.
4. Configure the required environment variables.
5. Verify the scanner API is reachable from the n8n container.
6. Run a test against a non-production test site first.
7. Confirm Discord receives the report and TXT attachment.
