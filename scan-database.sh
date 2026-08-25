#!/usr/bin/env bash
set -u

DB_HOST="${DB_HOST:-172.18.0.1}"
DB_PORT="${DB_PORT:-3306}"
DB_USER="${DB_USER:-shell_scanner}"

PASSWORD="${DB_PASSWORD:-}"

if [[ -z "$PASSWORD" ]]; then
    if [[ ! -t 0 ]]; then
        PASSWORD="$(cat)"
    else
        echo '{"status":"error","scanner":"scan-database.sh","error":"DB_PASSWORD is required","findings":[]}'
        exit 2
    fi
fi

mysql_cmd() {
    mysql \
        --skip-ssl \
        --batch \
        --raw \
        --skip-column-names \
        -h "$DB_HOST" \
        -P "$DB_PORT" \
        -u "$DB_USER" \
        -p"$PASSWORD" \
        "$@"
}

# Test connection.
if ! mysql_cmd -e "SELECT 1;" >/dev/null 2>&1; then
    python3 - <<'PY'
import json
print(json.dumps({
    "status": "error",
    "scanner": "scan-database.sh",
    "mode": "read-only",
    "error": "Unable to connect to MariaDB",
    "findings": []
}, ensure_ascii=False))
PY
    exit 3
fi

# System databases excluded from malware/content scanning.
DATABASES="$(
    mysql_cmd -e "SHOW DATABASES;" 2>/dev/null |
    grep -Ev '^(information_schema|performance_schema|mysql|sys)$' || true
)"

if [[ -z "$DATABASES" ]]; then
    echo '{"status":"completed","scanner":"scan-database.sh","mode":"read-only","summary":{"databases":0,"total":0,"critical":0,"high":0,"medium":0,"low":0},"databases":[],"findings":[]}'
    exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

: > "$TMP/findings.jsonl"

DB_COUNT=0

while IFS= read -r DB; do

    [[ -z "$DB" ]] && continue

    DB_COUNT=$((DB_COUNT + 1))

    # Validate database identifier before using it.
    if [[ ! "$DB" =~ ^[A-Za-z0-9_$-]+$ ]]; then
        continue
    fi

    TABLES="$(
        mysql_cmd \
            --database="$DB" \
            -e "SHOW TABLES;" 2>/dev/null || true
    )"

    while IFS= read -r TABLE; do

        [[ -z "$TABLE" ]] && continue

        if [[ ! "$TABLE" =~ ^[A-Za-z0-9_$-]+$ ]]; then
            continue
        fi

        # Discover columns.
        COLUMNS="$(
            mysql_cmd \
                --database="$DB" \
                -e "SELECT COLUMN_NAME
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA='${DB}'
                    AND TABLE_NAME='${TABLE}'
                    AND DATA_TYPE IN (
                        'char',
                        'varchar',
                        'text',
                        'tinytext',
                        'mediumtext',
                        'longtext'
                    );" 2>/dev/null || true
        )"

        [[ -z "$COLUMNS" ]] && continue

        while IFS= read -r COLUMN; do

            [[ -z "$COLUMN" ]] && continue

            if [[ ! "$COLUMN" =~ ^[A-Za-z0-9_$-]+$ ]]; then
                continue
            fi

            # Read-only content inspection.
            #
            # We deliberately look for common PHP/webshell indicators
            # inside database content. This query NEVER modifies data.
            QUERY="
                SELECT
                    CONCAT(
                        'DB=', DATABASE(),
                        '|TABLE=${TABLE}',
                        '|COLUMN=${COLUMN}',
                        '|VALUE=',
                        LEFT(
                            REPLACE(
                                REPLACE(
                                    REPLACE(
                                        CAST(\`${COLUMN}\` AS CHAR),
                                        CHAR(10), ' '
                                    ),
                                    CHAR(13), ' '
                                ),
                                CHAR(9), ' '
                            ),
                            500
                        )
                    )
                FROM \`${TABLE}\`
                WHERE
                    \`${COLUMN}\` REGEXP
                    '(eval[[:space:]]*\\(|base64_decode[[:space:]]*\\(|shell_exec[[:space:]]*\\(|passthru[[:space:]]*\\(|system[[:space:]]*\\(|assert[[:space:]]*\\(|gzinflate[[:space:]]*\\(|preg_replace[[:space:]]*\\([^)]*/e)'
                LIMIT 100;
            "

            mysql_cmd \
                --database="$DB" \
                -e "$QUERY" 2>/dev/null |
            while IFS= read -r MATCH; do

                [[ -z "$MATCH" ]] && continue

                python3 - "$DB" "$TABLE" "$COLUMN" "$MATCH" <<'PY' >> "$TMP/findings.jsonl"
import json
import sys

db = sys.argv[1]
table = sys.argv[2]
column = sys.argv[3]
match = sys.argv[4]

print(json.dumps({
    "severity": "high",
    "type": "suspicious_database_payload",
    "database": db,
    "table": table,
    "column": column,
    "reason": "Potential PHP/webshell or encoded execution pattern detected in database content",
    "match": match[:1000]
}, ensure_ascii=False))
PY

            done

        done <<< "$COLUMNS"

    done <<< "$TABLES"

done <<< "$DATABASES"

python3 - "$TMP/findings.jsonl" "$DB_COUNT" <<'PY'
import json
import sys
import datetime

findings_file = sys.argv[1]
db_count = int(sys.argv[2])

findings = []

with open(findings_file, encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue

        try:
            findings.append(json.loads(line))
        except Exception:
            pass

# Deduplicate.
unique = []
seen = set()

for item in findings:
    key = (
        item.get("database"),
        item.get("table"),
        item.get("column"),
        item.get("match")
    )

    if key not in seen:
        seen.add(key)
        unique.append(item)

findings = unique

counts = {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
}

for item in findings:
    severity = item.get("severity", "low")

    if severity not in counts:
        severity = "low"

    counts[severity] += 1

print(json.dumps({
    "status": "completed",
    "scanner": "scan-database.sh",
    "mode": "read-only",
    "scanned_at": datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat(),
    "database_user": "shell_scanner",
    "summary": {
        "databases": db_count,
        "total": len(findings),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"]
    },
    "findings": findings
}, ensure_ascii=False))
PY
