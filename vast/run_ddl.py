#!/usr/bin/env python3
"""Run ddl.sql against Trino. Used by reset_data.sh via ephemeral container."""
import os
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import trino

conn = trino.dbapi.connect(
    host=os.environ["TRINO_HOST"],
    port=int(os.environ["TRINO_PORT"]),
    user="trino",
    catalog="vast",
    schema='"csnow-db|otel"',
    http_scheme=os.getenv("TRINO_HTTP_SCHEME", "https"),
    verify=False,
)
cur = conn.cursor()

with open("/ddl.sql") as f:
    ddl = f.read()

for stmt in ddl.split(";"):
    stmt = stmt.strip()
    if not stmt or all(
        l.strip().startswith("--") or not l.strip() for l in stmt.split("\n")
    ):
        continue
    lines = [l for l in stmt.split("\n") if l.strip() and not l.strip().startswith("--")]
    sql = "\n".join(lines)
    try:
        cur.execute(sql)
        cur.fetchall()
        first_line = sql.split("\n")[0][:70]
        print(f"  OK: {first_line}...")
    except Exception as e:
        print(f"  ERROR: {e}", file=sys.stderr)

print("VastDB tables reset complete.")
