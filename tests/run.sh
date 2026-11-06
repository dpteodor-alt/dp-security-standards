#!/usr/bin/env bash
# Self-test for dp-security-standards.
#
#   1. Runs PHPCS (phpcs/ruleset.xml) and Semgrep (semgrep/dp-sec.yml) on tests/fixtures and
#      checks that every bad.php fires exactly where marked and every good.php stays silent.
#   2. Tests the CI gate (bin/dp-gate.py): no baseline -> fail, baseline -> pass,
#      moved code -> still pass, a new finding -> fail.
#
# Tools: PHPCS from vendor/bin (composer install) or $PHPCS; Semgrep from PATH or $SEMGREP.
# Portable: bash 3.2 (macOS) and GNU/Linux.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHPCS="${PHPCS:-$ROOT/vendor/bin/phpcs}"
SEMGREP="${SEMGREP:-semgrep}"
PYTHON="${PYTHON:-python3}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# shellcheck source=/dev/null
source "$ROOT/tools.env"

echo "== Tools"
"$PHPCS" --version
"$PHPCS" -i
SEMGREP_FOUND="$("$SEMGREP" --version 2>/dev/null | tail -n1)"
echo "Semgrep ${SEMGREP_FOUND} (pinned: ${SEMGREP_VERSION})"
if [ "$SEMGREP_FOUND" != "$SEMGREP_VERSION" ]; then
	echo "WARNING: Semgrep version differs from tools.env" >&2
fi

run_phpcs() { # $1 = output file, rest = targets. PHPCS exits non-zero when it finds something.
	local out="$1"; shift
	"$PHPCS" --standard="$ROOT/phpcs/ruleset.xml" --report=json -q "$@" > "$out" || true
	"$PYTHON" -c 'import json,sys; json.load(open(sys.argv[1]))' "$out" \
		|| { echo "PHPCS did not produce a JSON report:"; cat "$out"; exit 2; }
}

run_semgrep() { # $1 = output file, rest = targets.
	local out="$1"; shift
	"$SEMGREP" scan --config "$ROOT/semgrep/dp-sec.yml" --metrics=off --disable-version-check \
		--json --quiet --output "$out" "$@"
}

echo
echo "== 1. Fixtures"
cd "$ROOT"
FIXTURES=()
while IFS= read -r file; do FIXTURES+=("$file"); done < <(find tests/fixtures -name '*.php' | sort)
run_phpcs "$WORK/phpcs.json" "${FIXTURES[@]}"
run_semgrep "$WORK/semgrep.json" "${FIXTURES[@]}"
"$PYTHON" "$ROOT/tests/check-fixtures.py" --root "$ROOT" --phpcs "$WORK/phpcs.json" --semgrep "$WORK/semgrep.json"

echo
echo "== 2. Gate"
CONSUMER="$WORK/consumer"
mkdir -p "$CONSUMER/src"
cp tests/fixtures/DP-SEC-001/bad.php "$CONSUMER/src/routes.php"
cp tests/fixtures/DP-SEC-009/bad.php "$CONSUMER/src/db.php"
cd "$CONSUMER"

gate() { # $1 = expected exit code, rest = extra gate args
	local expected="$1"; shift
	run_phpcs "$WORK/c-phpcs.json" src
	run_semgrep "$WORK/c-semgrep.json" src
	set +e
	# Run the gate as it runs locally: no GitHub annotations or step summary from the self-test.
	env -u GITHUB_ACTIONS -u GITHUB_STEP_SUMMARY \
		"$PYTHON" "$ROOT/bin/dp-gate.py" check --root . --phpcs "$WORK/c-phpcs.json" --semgrep "$WORK/c-semgrep.json" \
		--baseline .dp-security/baseline.json "$@" > "$WORK/gate.out" 2>&1
	local code=$?
	set -e
	if [ "$code" -ne "$expected" ]; then
		cat "$WORK/gate.out"
		echo "FAIL: gate exited $code, expected $expected"
		exit 1
	fi
	grep -E '^\*\*Result' "$WORK/gate.out"
}

echo "-- a) no baseline: existing findings block"
gate 1

echo "-- b) baseline created: same code passes"
run_phpcs "$WORK/c-phpcs.json" src
run_semgrep "$WORK/c-semgrep.json" src
env -u GITHUB_ACTIONS -u GITHUB_STEP_SUMMARY \
	"$PYTHON" "$ROOT/bin/dp-gate.py" baseline --root . --phpcs "$WORK/c-phpcs.json" --semgrep "$WORK/c-semgrep.json" \
	--baseline .dp-security/baseline.json
gate 0

echo "-- c) code moved down by 3 lines: still passes"
{ head -n 1 src/db.php; printf '\n\n\n'; tail -n +2 src/db.php; } > "$WORK/db.php" && mv "$WORK/db.php" src/db.php
gate 0

echo "-- d) a new vulnerable line: fails"
cat >> src/db.php <<'PHP'

function dp_new_query( $id ) {
	global $wpdb;
	return $wpdb->get_row( "SELECT * FROM {$wpdb->posts} WHERE ID = $id" );
}
PHP
gate 1
if ! grep -qx '| New | 1 | 0 |' "$WORK/gate.out" \
	|| ! grep -q 'src/db.php:39: \[ERROR\] phpcs WordPress.DB.PreparedSQL.InterpolatedNotPrepared' "$WORK/gate.out"; then
	cat "$WORK/gate.out"
	echo "FAIL: expected exactly one new finding (src/db.php:39)"
	exit 1
fi

echo "-- e) a new warning only: passes, fails with --fail-on-warnings"
"$PYTHON" -c 'import sys; p = sys.argv[1]; l = open(p).read().splitlines(True); open(p, "w").writelines(l[:-5])' src/db.php
cat >> src/routes.php <<'PHP'

register_rest_route( 'dp/v1', '/news', array( 'methods' => 'GET', 'callback' => 'dp_news', 'permission_callback' => '__return_true' ) );
PHP
gate 0
gate 1 --fail-on-warnings

echo
echo "All self-tests passed."
