#!/usr/bin/env bash
# Copyright (c) 2025-2026 Lexega LLC
# SPDX-License-Identifier: BUSL-1.1
# Build the seed corpus for fuzzing from existing test fixtures
# and a curated set of interesting SQL patterns.
#
# Usage: ./build_corpus.sh
#
# The generated corpus is shared across all fuzz targets via the
# `corpus/shared/` directory. Targets that need raw bytes (fuzz_dialect)
# use the SQL files directly — libfuzzer handles the dialect byte prefix.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS_DIR="$SCRIPT_DIR/corpus/shared"
SEEDS_DIR="$SCRIPT_DIR/seeds"

mkdir -p "$CORPUS_DIR"
mkdir -p "$SEEDS_DIR"

echo "=== Building fuzz seed corpus ==="

# ---------------------------------------------------------------
# 1. Copy fixture SQL files (diverse, real-world SQL)
# ---------------------------------------------------------------
FIXTURE_DIR="$SCRIPT_DIR/../tests/fixtures"
if [ -d "$FIXTURE_DIR" ]; then
    count=0
    for f in "$FIXTURE_DIR"/*.sql; do
        [ -f "$f" ] || continue
        # Skip very large files (>100KB) — they slow down fuzzing
        size=$(wc -c < "$f")
        if [ "$size" -lt 102400 ]; then
            cp "$f" "$CORPUS_DIR/fixture_$(basename "$f")"
            count=$((count + 1))
        fi
    done
    echo "  Copied $count fixture files"
else
    echo "  WARNING: No fixtures directory found at $FIXTURE_DIR"
fi

# ---------------------------------------------------------------
# 2. Write curated edge-case seeds
# ---------------------------------------------------------------
# These target patterns that are common sources of parser bugs:
# empty input, single tokens, unclosed delimiters, deep nesting,
# unusual unicode, Jinja boundaries, etc.

cat > "$SEEDS_DIR/empty.sql" << 'EOF'
EOF

cat > "$SEEDS_DIR/whitespace_only.sql" << 'EOF'
   
EOF

cat > "$SEEDS_DIR/semicolons.sql" << 'EOF'
;;;
EOF

cat > "$SEEDS_DIR/single_keyword.sql" << 'EOF'
SELECT
EOF

cat > "$SEEDS_DIR/minimal_select.sql" << 'EOF'
SELECT 1;
EOF

cat > "$SEEDS_DIR/unclosed_string.sql" << 'EOF'
SELECT 'unclosed
EOF

cat > "$SEEDS_DIR/unclosed_paren.sql" << 'EOF'
SELECT (1 + 2
EOF

cat > "$SEEDS_DIR/unclosed_block_comment.sql" << 'EOF'
/* unclosed comment
SELECT 1;
EOF

cat > "$SEEDS_DIR/nested_comments.sql" << 'EOF'
/* outer /* inner */ still in outer */ SELECT 1;
EOF

cat > "$SEEDS_DIR/deep_nesting.sql" << 'EOF'
SELECT ((((((((((1))))))))));
EOF

cat > "$SEEDS_DIR/deep_case.sql" << 'EOF'
SELECT CASE WHEN CASE WHEN CASE WHEN 1=1 THEN 2 ELSE 3 END > 0 THEN 4 ELSE 5 END = 4 THEN 'a' ELSE 'b' END;
EOF

cat > "$SEEDS_DIR/deep_subquery.sql" << 'EOF'
SELECT * FROM (SELECT * FROM (SELECT * FROM (SELECT 1 AS x) a) b) c;
EOF

cat > "$SEEDS_DIR/many_ctes.sql" << 'EOF'
WITH a AS (SELECT 1), b AS (SELECT 2), c AS (SELECT 3), d AS (SELECT 4), e AS (SELECT 5)
SELECT * FROM a JOIN b ON 1=1 JOIN c ON 1=1 JOIN d ON 1=1 JOIN e ON 1=1;
EOF

cat > "$SEEDS_DIR/jinja_expr.sql" << 'EOF'
SELECT {{ column_name }} FROM {{ ref('model') }} WHERE id = {{ var('id') }};
EOF

cat > "$SEEDS_DIR/jinja_block.sql" << 'EOF'
{% if target.name == 'prod' %}
SELECT * FROM prod_table
{% else %}
SELECT * FROM dev_table
{% endif %}
EOF

cat > "$SEEDS_DIR/jinja_unclosed.sql" << 'EOF'
SELECT {{ unclosed
EOF

cat > "$SEEDS_DIR/unicode_idents.sql" << 'EOF'
SELECT "café" AS "naïve", "日本語" FROM "schéma"."таблица";
EOF

cat > "$SEEDS_DIR/null_bytes_adjacent.sql" << 'EOF'
SELECT 1;
EOF

cat > "$SEEDS_DIR/very_long_identifier.sql" << 'EOF'
SELECT aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa FROM t;
EOF

cat > "$SEEDS_DIR/mixed_statements.sql" << 'EOF'
CREATE TABLE t (id INT);
INSERT INTO t VALUES (1), (2), (3);
UPDATE t SET id = id + 1 WHERE id > 1;
DELETE FROM t WHERE id = 4;
SELECT * FROM t;
DROP TABLE t;
EOF

cat > "$SEEDS_DIR/window_functions.sql" << 'EOF'
SELECT id, ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS rn FROM emp;
EOF

cat > "$SEEDS_DIR/complex_merge.sql" << 'EOF'
MERGE INTO target t USING source s ON t.id = s.id
WHEN MATCHED AND s.deleted = true THEN DELETE
WHEN MATCHED THEN UPDATE SET t.name = s.name, t.updated = CURRENT_TIMESTAMP()
WHEN NOT MATCHED THEN INSERT (id, name) VALUES (s.id, s.name);
EOF

cat > "$SEEDS_DIR/create_masking_policy.sql" << 'EOF'
CREATE MASKING POLICY email_mask AS (val STRING) RETURNS STRING ->
  CASE WHEN CURRENT_ROLE() IN ('ADMIN') THEN val ELSE '***MASKED***' END;
EOF

cat > "$SEEDS_DIR/grant_revoke.sql" << 'EOF'
GRANT SELECT ON ALL TABLES IN SCHEMA mydb.myschema TO ROLE analyst;
REVOKE ALL PRIVILEGES ON DATABASE mydb FROM ROLE intern;
EOF

cat > "$SEEDS_DIR/scripting_block.sql" << 'EOF'
BEGIN
  LET x := 1;
  IF (x > 0) THEN
    RETURN x;
  ELSE
    RETURN 0;
  END IF;
END;
EOF

cat > "$SEEDS_DIR/dollar_quoted_pg.sql" << 'EOF'
CREATE FUNCTION add(a INT, b INT) RETURNS INT AS $$
BEGIN
  RETURN a + b;
END;
$$ LANGUAGE plpgsql;
EOF

cat > "$SEEDS_DIR/backtick_bq.sql" << 'EOF'
SELECT `project.dataset.table`.col FROM `project.dataset.table` WHERE `col` = 1;
EOF

cat > "$SEEDS_DIR/bracket_ident_mssql.sql" << 'EOF'
SELECT [Column Name] FROM [dbo].[My Table] WHERE [ID] = 1;
EOF

cat > "$SEEDS_DIR/operators_stress.sql" << 'EOF'
SELECT 1+2-3*4/5%6, a||b, c::INT, d->>'key', e IS NOT NULL, f BETWEEN 1 AND 10, g IN (1,2,3), h LIKE '%test%', i ILIKE 'pat', j RLIKE '\\d+';
EOF

cat > "$SEEDS_DIR/lateral_flatten.sql" << 'EOF'
SELECT f.value::STRING AS tag FROM my_table, LATERAL FLATTEN(input => tags) f;
EOF

cat > "$SEEDS_DIR/pivot_unpivot.sql" << 'EOF'
SELECT * FROM sales PIVOT (SUM(amount) FOR quarter IN ('Q1', 'Q2', 'Q3', 'Q4')) AS p;
SELECT * FROM quarterly UNPIVOT (amount FOR quarter IN (q1, q2, q3, q4));
EOF

cat > "$SEEDS_DIR/copy_into.sql" << 'EOF'
COPY INTO my_table FROM @my_stage FILE_FORMAT = (TYPE = 'CSV' SKIP_HEADER = 1) ON_ERROR = 'CONTINUE';
EOF

cat > "$SEEDS_DIR/create_task.sql" << 'EOF'
CREATE TASK my_task WAREHOUSE = compute_wh SCHEDULE = 'USING CRON 0 * * * * UTC' AS INSERT INTO log SELECT CURRENT_TIMESTAMP();
EOF

cat > "$SEEDS_DIR/alter_stage.sql" << 'EOF'
ALTER STAGE my_stage SET ENCRYPTION = (TYPE = 'NONE');
ALTER STAGE my_stage SET URL = 's3://bucket/path/' CREDENTIALS = (AWS_KEY_ID = 'key' AWS_SECRET_KEY = 'secret');
EOF

# Copy seeds to corpus
for f in "$SEEDS_DIR"/*.sql; do
    [ -f "$f" ] || continue
    cp "$f" "$CORPUS_DIR/seed_$(basename "$f")"
done
seed_count=$(ls "$SEEDS_DIR"/*.sql 2>/dev/null | wc -l)
echo "  Created $seed_count curated seed files"

total=$(ls "$CORPUS_DIR"/* 2>/dev/null | wc -l)
echo ""
echo "=== Corpus ready: $total total files in $CORPUS_DIR ==="
echo ""
echo "Run a fuzz target with:"
echo "  cargo +nightly fuzz run fuzz_tokenize corpus/shared/ -- -max_len=16384"
echo "  cargo +nightly fuzz run fuzz_parse corpus/shared/ -- -max_len=16384"
echo "  cargo +nightly fuzz run fuzz_format corpus/shared/ -- -max_len=16384"
echo "  cargo +nightly fuzz run fuzz_format_roundtrip corpus/shared/ -- -max_len=16384"
echo "  cargo +nightly fuzz run fuzz_dialect corpus/shared/ -- -max_len=16384"
