import * as vscode from 'vscode';
import { openCreateCertPanel } from './panels/createCertPanel';
import { showFromSelection } from './commands/showFromSelection';
import { openFile } from './commands/openFile';
import { openFromExplorer } from './commands/openFromExplorer';
import { inspectTlsServer } from './commands/inspectTlsServer';

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('x509toolkit.showFromSelection', showFromSelection(context)),
    vscode.commands.registerCommand('x509toolkit.openFile', openFile(context)),
    vscode.commands.registerCommand('x509toolkit.createCertificate', openCreateCertPanel(context)),
    vscode.commands.registerCommand('x509toolkit.openFromExplorer', openFromExplorer(context)),
    vscode.commands.registerCommand('x509toolkit.inspectTlsServer', inspectTlsServer(context))
  );
}

export function deactivate(): void {
  // Nothing to clean up
}

