const fs = require('fs');
const https = require('https');

const artifactPath = '/saferun/workspace/SAFERUN_TEST_ARTIFACT.txt';
const content = 'SafeRun security detection test\n';

fs.writeFileSync(artifactPath, content, { mode: 0o644 });

https.get('https://example.com', (res) => {
  res.resume();
  res.on('end', () => {
    process.exit(0);
  });
}).on('error', () => {
  process.exit(0);
});
