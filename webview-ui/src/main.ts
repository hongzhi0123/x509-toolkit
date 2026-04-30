import App from './App.svelte';
import CreateCertPanel from './lib/CreateCertPanel.svelte';

const appEl = document.getElementById('app')!;
const view  = (appEl as HTMLElement).dataset.view;

if (view === 'createCert') {
  new CreateCertPanel({ target: appEl });
} else {
  new App({ target: appEl });
}
