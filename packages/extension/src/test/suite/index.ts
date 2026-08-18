import * as path from 'path';
import * as fs from 'fs';

export async function run(): Promise<void> {
  const { default: Mocha } = await import('mocha');
  const mocha = new Mocha({
    ui: 'tdd',
    color: true,
    timeout: 15_000,
  });

  const testsRoot = __dirname;
  const testFiles = collectTestFiles(testsRoot);
  for (const file of testFiles) {
    mocha.addFile(path.resolve(testsRoot, file));
  }

  return new Promise((resolve, reject) => {
    mocha.run((failures: number) => {
      if (failures > 0) {
        reject(new Error(`${failures} tests failed.`));
      } else {
        resolve();
      }
    });
  });
}

function collectTestFiles(dir: string): string[] {
  const files: string[] = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory() && entry.name !== 'node_modules') {
      files.push(...collectTestFiles(path.join(dir, entry.name)).map(f => path.join(entry.name, f)));
    } else if (entry.name.endsWith('.test.js')) {
      files.push(entry.name);
    }
  }
  return files;
}
