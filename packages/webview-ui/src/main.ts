import App from './App.svelte';
import CreateCertPanel from './lib/CreateCertPanel.svelte';
import ConvertHub from './lib/ConvertHub.svelte';
import KeyViewer from './lib/KeyViewer.svelte';
import KeyGenPanel from './lib/KeyGenPanel.svelte';
import CrlView from './lib/CrlView.svelte';

const appEl = document.getElementById('app')!;
const view  = (appEl as HTMLElement).dataset.view;

if (view === 'createCert') {
  new CreateCertPanel({ target: appEl });
} else if (view === 'convertHub') {
  new ConvertHub({ target: appEl });
} else if (view === 'keyViewer') {
  new KeyViewer({ target: appEl });
} else if (view === 'keyGen') {
  new KeyGenPanel({ target: appEl });
} else if (view === 'crlViewer') {
  new CrlView({ target: appEl });
} else {
  new App({ target: appEl });
}
