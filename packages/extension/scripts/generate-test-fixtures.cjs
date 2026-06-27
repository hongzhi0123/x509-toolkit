const path = require('path');
const fs = require('fs');
const { createSelfSignedP12 } = require(path.resolve(__dirname, '../../core/dist'));

const FIXTURES_DIR = path.resolve(__dirname, '../test-fixtures');

async function main() {
  fs.mkdirSync(FIXTURES_DIR, { recursive: true });

  const p12Buffer = await createSelfSignedP12('test-rsa-2048.example', 3650, 'test-passphrase');
  fs.writeFileSync(path.join(FIXTURES_DIR, 'test-rsa-2048.p12'), p12Buffer);

  fs.writeFileSync(path.join(FIXTURES_DIR, 'dummy.txt'), 'placeholder for VS Code explorer rendering');

  console.log('Generated test-fixtures/test-rsa-2048.p12');
  console.log('  CN:   test-rsa-2048.example');
  console.log('  Days: 3650');
  console.log('  Pass: test-passphrase');
  console.log('Generated test-fixtures/dummy.txt');
}

main().catch(err => {
  console.error('Failed to generate fixtures:', err);
  process.exit(1);
});
