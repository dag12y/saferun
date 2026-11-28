#!/usr/bin/env bash
set -euo pipefail

action_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.github/actions/saferun" && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT

export GITHUB_WORKSPACE="$test_dir/workspace"
export GITHUB_OUTPUT="$test_dir/output"
export SAFERUN_BIN="$test_dir/saferun"
export SAFERUN_SARIF_FILE="reports/safe run.sarif"
export SAFERUN_PACKAGES=""
export EXPECTED_ARGS="$test_dir/expected"
export STUB_STATUS=0 STUB_REPORT=valid
mkdir -p -- "$GITHUB_WORKSPACE/reports"
report="$GITHUB_WORKSPACE/$SAFERUN_SARIF_FILE"

cat > "$SAFERUN_BIN" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -ge 3 && $1 == npm && $2 == install && ${!#} == --format=sarif ]]
shift 2
diff -u "$EXPECTED_ARGS" <(for arg in "${@:1:$#-1}"; do printf '%s\n' "$arg"; done)
if [[ $STUB_REPORT == valid ]]; then
    echo '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"SafeRun"}},"results":[]}]}'
else
    echo 'report unavailable'
fi
exit "$STUB_STATUS"
STUB
chmod +x -- "$SAFERUN_BIN"

check_failure() {
    : > "$GITHUB_OUTPUT"
    if bash "$action_root/analyze.sh" 2>"$test_dir/error"; then
        echo "Expected the action analysis to fail." >&2
        exit 1
    fi
    [[ ! -s "$GITHUB_OUTPUT" ]]
    grep -Fq -- "$1" "$test_dir/error"
}

: > "$EXPECTED_ARGS"
bash "$action_root/analyze.sh"
grep -Fxq 'sarif-file=reports/safe run.sarif' "$GITHUB_OUTPUT"
grep -Fxq 'blocked=false' "$GITHUB_OUTPUT"
jq -e '.version == "2.1.0"' "$report" >/dev/null

touch -- "$GITHUB_WORKSPACE/example@1"
printf '%s\n' '@scope/pkg@^1.2.3' 'example@*' > "$EXPECTED_ARGS"
SAFERUN_PACKAGES=$'@scope/pkg@^1.2.3\nexample@*'
STUB_STATUS=3
: > "$GITHUB_OUTPUT"
bash "$action_root/analyze.sh"
grep -Fxq 'blocked=true' "$GITHUB_OUTPUT"
grep -Fxq 'sarif-file=reports/safe run.sarif' "$GITHUB_OUTPUT"

cp -- "$report" "$test_dir/previous-report"
STUB_STATUS=1
check_failure 'analysis failed (exit 1)'
cmp -- "$report" "$test_dir/previous-report"

STUB_STATUS=0
STUB_REPORT=invalid
check_failure 'did not produce a valid SARIF report'
cmp -- "$report" "$test_dir/previous-report"

STUB_STATUS=3
check_failure 'did not produce a valid SARIF report'

SAFERUN_PACKAGES='--dry-run'
check_failure 'accepts npm package specs only'

ln -s -- "$test_dir" "$GITHUB_WORKSPACE/linked-directory"
SAFERUN_SARIF_FILE='linked-directory/outside.sarif'
check_failure 'must be a regular file inside the workspace'
[[ ! -e "$test_dir/outside.sarif" ]]

ln -s -- "$test_dir/previous-report" "$GITHUB_WORKSPACE/linked-file"
SAFERUN_SARIF_FILE=linked-file
check_failure 'must be a regular file inside the workspace'

unusual_directory="$GITHUB_WORKSPACE/"$'reports\nextra'
mkdir -- "$unusual_directory"
ln -s -- "$unusual_directory" "$GITHUB_WORKSPACE/linked-reports"
SAFERUN_SARIF_FILE=linked-reports/new.sarif
check_failure 'must be a regular file inside the workspace'
