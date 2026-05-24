import App from './App.svelte';
import CreateCertPanel from './lib/CreateCertPanel.svelte';
import ConvertHub from './lib/ConvertHub.svelte';

const appEl = document.getElementById('app')!;
const view  = (appEl as HTMLElement).dataset.view;

if (view === 'createCert') {
  new CreateCertPanel({ target: appEl });
} else if (view === 'convertHub') {
  new ConvertHub({ target: appEl });
} else {
  new App({ target: appEl });
}
