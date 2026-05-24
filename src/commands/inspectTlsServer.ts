import * as vscode from 'vscode';
import * as tls from 'tls';
import { getOrCreatePanel, sendLoading, sendCertificates, sendError } from '../panels/panelManager';
import { parseCertificate } from '../parsers/certificateParser';
import type { CertificateData, ExtToWebviewMsg, TlsConnectionInfo } from '../types/types';

/**
 * Parse a "host", "host:port" or "[ipv6]:port" string into host + port.
 * Defaults to port 443 when no port is specified.
 */
function parseHostPort(input: string): { host: string; port: number } {
  const trimmed = input.trim();

  // IPv6 with port: [::1]:443
  const ipv6Match = trimmed.match(/^\[([^\]]+)\]:(\d+)$/);
  if (ipv6Match) {
    return { host: ipv6Match[1], port: parseInt(ipv6Match[2], 10) };
  }

  // host:port — only treat as host:port when the part after the last colon
  // is entirely numeric (avoids treating "example.com" or plain IPv6 as host:port)
  const lastColon = trimmed.lastIndexOf(':');
  if (lastColon > 0) {
    const portStr = trimmed.slice(lastColon + 1);
    const port = parseInt(portStr, 10);
    if (!isNaN(port) && port > 0 && port <= 65535 && portStr === String(port)) {
      return { host: trimmed.slice(0, lastColon), port };
    }
  }

  return { host: trimmed, port: 443 };
}

/**
 * Walk the certificate chain returned by getPeerCertificate(true).
 * Node.js sets issuerCertificate to the same object for self-signed roots to
 * prevent infinite loops — we use object-identity to detect that.
 */
function walkCertChain(leaf: tls.DetailedPeerCertificate): Buffer[] {
  const chain: Buffer[] = [];
  const seen = new Set<object>();
  let current: tls.DetailedPeerCertificate = leaf;

  while (true) {
    if (seen.has(current)) break;
    seen.add(current);
    if (current.raw) {
      chain.push(current.raw);
    }
    if (!current.issuerCertificate || current.issuerCertificate === (current as object)) break;
    current = current.issuerCertificate;
  }

  return chain;
}

function connectAndInspect(
  panel: vscode.WebviewPanel,
  host: string,
  port: number
): Promise<void> {
  return new Promise((resolve, reject) => {
    const steps: string[] = [];

    const postProgress = (step: string): void => {
      steps.push(step);
      const msg: ExtToWebviewMsg = { type: 'tlsProgress', step };
      panel.webview.postMessage(msg);
    };

    let settled = false;
    const done = (err?: Error): void => {
      if (settled) return;
      settled = true;
      if (err) { reject(err); } else { resolve(); }
    };

    const t0 = Date.now();
    const elapsed = (): string => `${Date.now() - t0}ms`;

    steps.push(`Connecting to ${host}:${port}…`);
    postProgress(`Connecting to ${host}:${port}…`);

    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false, timeout: 15_000 },
      async () => {
        const proto = socket.getProtocol() ?? 'TLS';
        const cipher = socket.getCipher()?.name ?? 'unknown';
        const ip = socket.remoteAddress ?? host;

        postProgress(`TLS handshake complete (${proto}) · Parsing chain…`);

        let chain: CertificateData[];
        try {
          const rawChain = walkCertChain(socket.getPeerCertificate(true));
          if (rawChain.length === 0) {
            throw new Error('No certificates received from server');
          }
          chain = await Promise.all(rawChain.map(buf => parseCertificate(buf)));
        } catch (e) {
          socket.destroy();
          done(e as Error);
          return;
        }

        socket.destroy();

        steps.push(`Chain parsed: ${chain.length} certificate${chain.length !== 1 ? 's' : ''}`);
        const tlsSource: TlsConnectionInfo = { host, port, ip, protocol: proto, cipher, steps };
        sendCertificates(panel, chain, 0, tlsSource);
        done();
      }
    );

    socket.on('lookup', (_err: Error | null, address: string) => {
      const resolved = address ?? host;
      postProgress(`Resolved ${host} → ${resolved} (${elapsed()})`);
    });

    socket.on('connect', () => {
      postProgress(`TCP connected (${elapsed()}) · TLS handshake…`);
    });

    socket.on('error', (err: Error) => {
      socket.destroy();
      done(err);
    });

    socket.on('timeout', () => {
      socket.destroy();
      done(new Error(`Connection to ${host}:${port} timed out`));
    });
  });
}

export function inspectTlsServer(context: vscode.ExtensionContext): () => Promise<void> {
  return async () => {
    // Pre-fill the input box from the current editor selection if it looks like a hostname
    let defaultValue = '';
    const editor = vscode.window.activeTextEditor;
    if (editor && !editor.selection.isEmpty) {
      const selected = editor.document.getText(editor.selection).trim();
      if (/^[a-zA-Z0-9._\-:[\]]+$/.test(selected) && selected.length < 256) {
        defaultValue = selected;
      }
    }

    const input = await vscode.window.showInputBox({
      prompt: 'Enter hostname or host:port to inspect TLS certificate',
      placeHolder: 'example.com  or  example.com:8443',
      value: defaultValue,
      validateInput: (val) => val.trim() ? null : 'Please enter a hostname',
    });

    if (!input) return;

    const { host, port } = parseHostPort(input);
    const panel = getOrCreatePanel(context.extensionUri, context);
    sendLoading(panel, `Resolving ${host}…`);

    try {
      await connectAndInspect(panel, host, port);
    } catch (err: unknown) {
      sendError(panel, `Failed to connect to ${host}:${port}: ${(err as Error).message ?? String(err)}`);
    }
  };
}
