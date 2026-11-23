import './styles/shared.css';

const appEl = document.getElementById('app')!;
const view  = (appEl as HTMLElement).dataset.view;

const loadPanel = (view?: string) => {
  switch (view) {
    case 'createCert': return import('./panels/CreateCertPanel.svelte');
    case 'convertHub': return import('./panels/ConvertHub.svelte');
    case 'keyViewer':
    case 'keyViewerCustomEditor': return import('./panels/KeyViewer.svelte');
    case 'keyGen':     return import('./panels/KeyGenPanel.svelte');
    case 'crlViewer':
    case 'crlViewerCustomEditor': return import('./panels/CrlView.svelte');
    default:           return import('./panels/App.svelte');
  }
};

loadPanel(view).then(mod => new mod.default({
  target: appEl,
  props: { showTextEditorButton: view === 'customEditor' || view === 'keyViewerCustomEditor' || view === 'crlViewerCustomEditor' },
}));
