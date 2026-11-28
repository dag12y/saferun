#!/usr/bin/env bash
set -euo pipefail

IFS= read -r -d '' workspace < <(realpath -ez -- "$GITHUB_WORKSPACE")
cd "$workspace"

report=$SAFERUN_SARIF_FILE
case "$report" in
    ""|/*|*/|*$'\n'*|*$'\r'*)
        echo "The SARIF output must be a workspace-relative file path." >&2
        exit 1
        ;;
esac

if ! IFS= read -r -d '' report_dir < <(realpath -ez -- "$(dirname -- "$report")"); then
    echo "The SARIF output requires an existing parent directory." >&2
    exit 1
fi
report_name=$(basename -- "$report")
destination="$report_dir/$report_name"
if [[ ( "$report_dir" != "$workspace" && "$report_dir" != "$workspace/"* ) ||
      "$destination" == *$'\n'* || "$destination" == *$'\r'* ||
      ! -d "$report_dir" || -L "$destination" || ( -e "$destination" && ! -f "$destination" ) ]]; then
    echo "The SARIF output must be a regular file inside the workspace with an existing parent directory." >&2
    exit 1
fi

package_specs=${SAFERUN_PACKAGES//$'\n'/ }
package_specs=${package_specs//$'\r'/ }
read -r -a packages <<< "$package_specs"
for package in "${packages[@]}"; do
    if [[ "$package" == -* ]]; then
        echo "The packages input accepts npm package specs only." >&2
        exit 1
    fi
done

temporary_report=$(mktemp -- "$report_dir/.saferun-sarif.XXXXXXXX")
trap 'rm -f -- "$temporary_report"' EXIT

status=0
"$SAFERUN_BIN" npm install "${packages[@]}" --format=sarif > "$temporary_report" || status=$?
case "$status" in
    0) blocked=false ;;
    3) blocked=true ;;
    *)
        printf 'SafeRun analysis failed (exit %s).\n' "$status" >&2
        exit 1
        ;;
esac

if ! jq -e -s 'length == 1 and (.[0] | .version == "2.1.0" and (.runs | type == "array" and length > 0 and all(.tool.driver.name == "SafeRun" and (.results | type == "array"))))' "$temporary_report" >/dev/null; then
    echo "SafeRun did not produce a valid SARIF report." >&2
    exit 1
fi

mv -fT -- "$temporary_report" "$destination"
printf 'sarif-file=%s\nblocked=%s\n' "${destination#"$workspace/"}" "$blocked" >> "$GITHUB_OUTPUT"
