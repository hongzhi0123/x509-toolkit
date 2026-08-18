const appEl = document.getElementById('app')!;
const view  = (appEl as HTMLElement).dataset.view;

const loadPanel = (view?: string) => {
  switch (view) {
    case 'createCert': return import('./panels/CreateCertPanel.svelte');
    case 'convertHub': return import('./panels/ConvertHub.svelte');
    case 'keyViewer':  return import('./panels/KeyViewer.svelte');
    case 'keyGen':     return import('./panels/KeyGenPanel.svelte');
    case 'crlViewer':  return import('./panels/CrlView.svelte');
    default:           return import('./panels/App.svelte');
  }
};

loadPanel(view).then(mod => new mod.default({ target: appEl }));
