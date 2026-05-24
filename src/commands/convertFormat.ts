import * as vscode from 'vscode';
import { openConvertPanel } from '../panels/convertPanel';

export function convertFormat(context: vscode.ExtensionContext): () => void {
  return () => openConvertPanel(context);
}
