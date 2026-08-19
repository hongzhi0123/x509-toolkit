import { runTests } from '@vscode/test-electron';
import * as path from 'path';

async function main(): Promise<void> {
  try {
    const extensionDevelopmentPath = path.resolve(__dirname, '../../..');
    const extensionTestsPath = path.resolve(__dirname, './suite/index');
    const version = process.env.VSCODE_TEST_VERSION ?? '1.126.0';
    const cachePath = process.env.VSCODE_TEST_CACHE_PATH
      ?? (process.env.LOCALAPPDATA
        ? path.join(process.env.LOCALAPPDATA, 'vscode-test-cache', 'x509-toolkit')
        : path.resolve(extensionDevelopmentPath, '.vscode-test'));

    await runTests({
      version,
      cachePath,
      extensionDevelopmentPath,
      extensionTestsPath,
      launchArgs: ['--disable-extensions', '--headless'],
    });
  } catch (err) {
    process.exit(1);
  }
}

main();
