#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
cd "$repo"
go build -o "$scratch/saferun" ./cmd/saferun
"$scratch/saferun" setup
mkdir "$scratch/project" "$scratch/fixture-home"
cat > "$scratch/saferun-fixture" <<'WRAPPER'
#!/usr/bin/env bash
set -eu
fixture_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
exec env HOME="$fixture_dir/fixture-home" "$fixture_dir/saferun" "$@"
WRAPPER
chmod +x "$scratch/saferun-fixture"
cp tests/fixtures/npm-project/{package.json,package-lock.json} "$scratch/project/"
cd "$scratch/project"
export SAFERUN_CONFIG="$scratch/saferun.json"
printf '%s\n' '{"osv":{"enabled":false}}' > "$SAFERUN_CONFIG"

# A frozen tree has the same manifest and lockfile throughout a project scan.
cp package-lock.json "$scratch/empty-lock.json"
"$scratch/saferun-fixture" npm install --format=sarif > "$scratch/empty.sarif"
node -e 'if (JSON.parse(require("node:fs").readFileSync(process.argv[1])).version !== "2.1.0") process.exit(1)' "$scratch/empty.sarif"
cmp "$scratch/empty-lock.json" package-lock.json

# Use the real npm resolver and Docker image. The root hook's marker stays in Docker.
node - <<'JS'
const fs = require('node:fs');
const project = JSON.parse(fs.readFileSync('package.json'));
project.scripts ??= {};
project.overrides = { 'is-number': '6.0.0' };
project.scripts.postinstall = 'node -e "require(\'node:fs\').writeFileSync(\'host-hook-marker\', \'fixture\')"';
fs.writeFileSync('package.json', JSON.stringify(project, null, 2) + '\n');
JS
printf 'y\n' | "$scratch/saferun-fixture" npm install is-odd@3.0.1 --save-exact
test ! -e host-hook-marker
node - <<'JS'
const assert = require('node:assert/strict');
const lock = require('./package-lock.json');
const actual = require('./node_modules/.package-lock.json');
const installed = require('./node_modules/is-number/package.json');
assert.equal(installed.version, '6.0.0');
assert.equal(lock.packages['node_modules/is-number'].integrity, actual.packages['node_modules/is-number'].integrity);
assert.equal(require('./package.json').dependencies['is-odd'], '3.0.1');
assert.equal(actual.packages['node_modules/is-odd'].version, '3.0.1');
JS

# Inject a host rebuild failure after publication to exercise full rollback through the CLI.
cp package.json "$scratch/saved-package.json"
cp package-lock.json "$scratch/saved-lock.json"
real_npm=$(command -v npm)
mkdir "$scratch/bin"
printf '#!/usr/bin/env bash\nreal_npm=%q\n' "$real_npm" > "$scratch/bin/npm"
cat >> "$scratch/bin/npm" <<'WRAPPER'
if [[ "$1" == rebuild ]]; then
    printf '%s\n' 'changed existing dependency' > node_modules/is-number/package.json
    exit 42
fi
exec "$real_npm" "$@"
WRAPPER
chmod +x "$scratch/bin/npm"
set +e
printf 'y\ny\n' | env PATH="$scratch/bin:$PATH" "$scratch/saferun-fixture" npm install is-odd@3.0.1 --allow-host-scripts > "$scratch/rollback.log" 2>&1
status=$?
set -e
if [[ "$status" != 1 ]] || ! grep -q 'Project restored successfully' "$scratch/rollback.log"; then
    cat "$scratch/rollback.log" >&2
    exit 1
fi
cmp "$scratch/saved-package.json" package.json
cmp "$scratch/saved-lock.json" package-lock.json
node -e 'if (require("./node_modules/is-number/package.json").version !== "6.0.0") process.exit(1)'

# The action's wrapper is exercised with the real CLI for both success and policy block.
run_action() {
    env GITHUB_WORKSPACE="$PWD" GITHUB_OUTPUT="$scratch/action-output" \
        SAFERUN_BIN="$scratch/saferun-fixture" SAFERUN_PACKAGES= SAFERUN_SARIF_FILE=scan.sarif \
        bash "$repo/.github/actions/saferun/analyze.sh"
}
run_action
grep -q '^blocked=false$' "$scratch/action-output"
node - <<'JS'
const fs = require('node:fs');
const project = JSON.parse(fs.readFileSync('package.json'));
project.scripts ??= {};
project.scripts.postinstall = 'node -e "require(\'node:fs\').writeFileSync(\'.env.saferun-fixture\', \'fixture\')"';
fs.writeFileSync('package.json', JSON.stringify(project, null, 2) + '\n');
JS
: > "$scratch/action-output"
run_action
grep -q '^blocked=true$' "$scratch/action-output"
test ! -e .env.saferun-fixture
