#!/usr/bin/env bash
set -u

SOURCE="${1:-}"

if [[ -z "$SOURCE" ]]; then
    echo '{"status":"error","error":"Source path is required","findings":[]}'
    exit 2
fi

if [[ ! -d "$SOURCE" ]]; then
    echo '{"status":"error","error":"Source directory does not exist","findings":[]}'
    exit 2
fi

SOURCE="$(realpath "$SOURCE")"

case "$SOURCE" in
    /www/wwwroot/*)
        ;;
    *)
        echo '{"status":"error","error":"Source must be below /www/wwwroot","findings":[]}'
        exit 2
        ;;
esac

python3 - "$SOURCE" <<'PY'
import os
import re
import sys
import json
import base64
import gzip
import zlib
import datetime

source = sys.argv[1]

VERSION = "4.1"

findings = []
critical_findings = []
files_scanned = 0

EXTENSIONS = (
    ".php",
    ".phtml",
    ".php5",
    ".php7",
    ".php8",
    ".phar",
)

SKIP_DIRS = {
    "node_modules",
    ".git",
    "vendor",
    "cache",
    "caches",
}

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def rel(path):
    try:
        return os.path.relpath(path, source)
    except Exception:
        return path


def add_finding(
    severity,
    ftype,
    path,
    line,
    reason,
    match="",
    confidence="low",
    score=0,
):
    item = {
        "severity": severity,
        "type": ftype,
        "rule": ftype,
        "confidence": confidence,
        "score": score,
        "file": path,
        "relative_file": rel(path),
        "line": line,
        "reason": reason,
        "match": match[:1000],
    }

    findings.append(item)

    if severity == "critical":
        critical_findings.append(item)


def is_sensitive_wordpress_path(path):
    p = rel(path).replace("\\", "/").lower()

    sensitive = (
        p == "wp-content/db.php",
        p == "wp-content/advanced-cache.php",
        p.startswith("wp-content/mu-plugins/"),
        p.startswith("wp-content/uploads/"),
        p.endswith("/.user.ini"),
    )

    return any(sensitive)


def looks_generated(name):
    """
    Detect very suspicious identifier style without treating it as malware
    by itself.
    """
    names = re.findall(
        r"\b[a-zA-Z_\$][a-zA-Z0-9_\$]{8,}\b",
        name
    )

    suspicious = 0

    for n in names:
        if re.search(r"[a-z]", n) and re.search(r"[0-9]", n):
            if "_" not in n and len(n) >= 10:
                suspicious += 1

    return suspicious


def decode_payload(text):
    """
    Try to identify embedded base64 -> gzip/zlib -> PHP payloads.

    This is intentionally conservative.
    """

    candidates = re.findall(
        r"[A-Za-z0-9+/]{120,}={0,2}",
        text
    )

    for candidate in candidates[:30]:
        try:
            raw = base64.b64decode(
                candidate,
                validate=False
            )
        except Exception:
            continue

        decoded = None

        # gzip
        try:
            decoded = gzip.decompress(raw)
        except Exception:
            pass

        # zlib
        if decoded is None:
            try:
                decoded = zlib.decompress(raw)
            except Exception:
                pass

        if decoded is None:
            continue

        try:
            decoded_text = decoded.decode(
                "utf-8",
                errors="ignore"
            )
        except Exception:
            continue

        if "<?php" in decoded_text or re.search(
            r"\b(eval|assert|system|exec|shell_exec|passthru|include|require)\s*\(",
            decoded_text,
            re.I
        ):
            return True, decoded_text[:3000]

    return False, None


# ----------------------------------------------------------------------
# Scan
# ----------------------------------------------------------------------

try:

    for root, dirs, files in os.walk(source):

        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS
        ]

        for filename in files:

            if not filename.lower().endswith(EXTENSIONS):
                continue

            path = os.path.join(root, filename)
            files_scanned += 1

            try:
                with open(
                    path,
                    "r",
                    encoding="utf-8",
                    errors="replace"
                ) as fh:
                    content = fh.read()

            except (PermissionError, OSError):
                continue

            if not content.strip():
                continue

            lower = content.lower()

            # ----------------------------------------------------------
            # Indicators
            # ----------------------------------------------------------

            has_eval = bool(
                re.search(
                    r"\b(eval|assert)\s*\(",
                    content,
                    re.I
                )
            )

            has_variable_function = bool(
                re.search(
                    r"\$\w+\s*\(",
                    content
                )
            )

            has_dynamic_include = bool(
                re.search(
                    r"\b(include|include_once|require|require_once)\s*\(?\s*\$",
                    content,
                    re.I
                )
            )

            has_http_input = bool(
                re.search(
                    r"\$_(GET|POST|REQUEST|COOKIE|FILES)\b",
                    content,
                    re.I
                )
            )

            has_encoding = bool(
                re.search(
                    r"\b(base64_decode|str_rot13|convert_uudecode)\s*\(",
                    content,
                    re.I
                )
            )

            has_compression = bool(
                re.search(
                    r"\b(gzinflate|gzdecode|gzuncompress)\s*\(",
                    content,
                    re.I
                )
            )

            has_command_exec = bool(
                re.search(
                    r"\b(shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(",
                    content,
                    re.I
                )
            )

            has_filesystem_write = bool(
                re.search(
                    r"\b(file_put_contents|fwrite|move_uploaded_file)\s*\(",
                    content,
                    re.I
                )
            )

            generated_count = looks_generated(content)

            payload_decoded, decoded_payload = decode_payload(content)

            sensitive = is_sensitive_wordpress_path(path)

            # ----------------------------------------------------------
            # CRITICAL RULE 1
            # Embedded compressed payload actually decodes to PHP/code
            # ----------------------------------------------------------

            if payload_decoded:

                add_finding(
                    "critical",
                    "MALWARE_LOADER",
                    path,
                    1,
                    "Obfuscated compressed PHP payload was successfully decoded from embedded data.",
                    "Base64-encoded compressed payload successfully decoded",
                    "high",
                    20
                )

                continue

            # ----------------------------------------------------------
            # CRITICAL RULE 2
            # Sensitive WordPress file + strong obfuscation
            # ----------------------------------------------------------

            if sensitive and (
                (has_encoding and has_compression and generated_count >= 5)
                or
                (has_variable_function and has_compression and generated_count >= 5)
                or
                (has_eval and has_encoding)
            ):

                score = 10

                if generated_count >= 20:
                    score += 5

                if has_http_input:
                    score += 4

                add_finding(
                    "critical",
                    "MALWARE_LOADER",
                    path,
                    1,
                    "Obfuscated executable loader detected in a sensitive WordPress path.",
                    "obfuscation + dynamic execution + compressed/encoded payload",
                    "high",
                    score
                )

                continue

            # ----------------------------------------------------------
            # CRITICAL RULE 3
            # HTTP input -> dynamic execution + obfuscation
            # ----------------------------------------------------------

            if (
                has_http_input
                and (has_eval or has_variable_function or has_dynamic_include)
                and (has_encoding or has_compression)
                and generated_count >= 2
            ):

                score = 10

                if has_eval:
                    score += 3

                if has_command_exec:
                    score += 3

                if has_filesystem_write:
                    score += 2

                add_finding(
                    "critical",
                    "MALWARE_LOADER",
                    path,
                    1,
                    "User-controlled HTTP input reaches dynamic execution with encoded/obfuscated content.",
                    "HTTP input + dynamic execution + obfuscation",
                    "high",
                    score
                )

                continue

            # ----------------------------------------------------------
            # CRITICAL RULE 4
            # Classic shell characteristics
            # ----------------------------------------------------------

            if (
                has_http_input
                and has_eval
                and generated_count >= 3
            ):

                add_finding(
                    "critical",
                    "WEBSHELL",
                    path,
                    1,
                    "HTTP-controlled input reaches eval/assert in highly obfuscated PHP.",
                    "HTTP input + eval/assert + generated identifiers",
                    "high",
                    12
                )

                continue

            # ----------------------------------------------------------
            # MEDIUM indicators
            # ----------------------------------------------------------

            if has_encoding:

                add_finding(
                    "medium",
                    "ENCODING",
                    path,
                    1,
                    "base64_decode() detected; manual review required.",
                    "base64_decode(",
                    "low",
                    1
                )

            elif has_compression:

                add_finding(
                    "medium",
                    "OBFUSCATION",
                    path,
                    1,
                    "Encoded/compressed PHP indicator detected.",
                    "compression/obfuscation",
                    "low",
                    1
                )

            elif has_command_exec:

                add_finding(
                    "medium",
                    "COMMAND_FUNCTION",
                    path,
                    1,
                    "Command execution function detected; manual review required.",
                    "command execution",
                    "low",
                    1
                )

            elif has_eval:

                add_finding(
                    "medium",
                    "DYNAMIC_EXECUTION",
                    path,
                    1,
                    "eval/assert detected; manual review required.",
                    "eval/assert",
                    "medium",
                    2
                )

except Exception as exc:

    print(json.dumps({
        "status": "error",
        "scanner": "scan-source.sh",
        "version": VERSION,
        "mode": "read-only",
        "source": source,
        "error": str(exc),
        "findings": [],
        "critical_findings": []
    }, ensure_ascii=False))

    sys.exit(3)


# ----------------------------------------------------------------------
# Deduplicate
# ----------------------------------------------------------------------

def dedupe(items):

    result = []
    seen = set()

    for item in items:

        key = (
            item["file"],
            item["type"]
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(item)

    return result


findings = dedupe(findings)
critical_findings = dedupe(critical_findings)


# ----------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------

counts = {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
}

for item in findings:

    sev = item.get("severity", "low")

    if sev not in counts:
        sev = "low"

    counts[sev] += 1


result = {
    "status": "completed",
    "scanner": "scan-source.sh",
    "version": VERSION,
    "mode": "read-only",
    "source": source,
    "scanned_at": datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat(),
    "files_scanned": files_scanned,
    "summary": {
        "total": len(findings),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"]
    },
    "critical_findings": critical_findings,
    "findings": findings
}

print(
    json.dumps(
        result,
        ensure_ascii=False
    )
)

PY
