import App from './panels/App.svelte';
import CreateCertPanel from './panels/CreateCertPanel.svelte';
import ConvertHub from './panels/ConvertHub.svelte';
import KeyViewer from './panels/KeyViewer.svelte';
import KeyGenPanel from './panels/KeyGenPanel.svelte';
import CrlView from './panels/CrlView.svelte';

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
