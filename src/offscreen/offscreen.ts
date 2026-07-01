import { loadAllModels, runAllInference, getModelStatus } from '../ml-inference/index';
import { ExtensionMessage, DOMScanResult, MLPrediction } from '../types/index';

// Tracked so inference requests can await model readiness before running.
let _loadingPromise: Promise<void> | null = (async () => {
  try {
    await loadAllModels();
  } catch (err) {
    console.error('[CyberINTEL-AI/offscreen] loadAllModels error:', err);
  }
  const status = getModelStatus();
  chrome.storage.local.set({ modelStatus: status });
  chrome.runtime.sendMessage({ type: 'MODELS_LOADED', payload: status } as ExtensionMessage).catch(() => {});
  _loadingPromise = null;
})();

chrome.runtime.onMessage.addListener((msg: ExtensionMessage, _sender, sendResponse) => {
  if (msg.type === 'OFFSCREEN_ML_REQUEST') {
    (async () => {
      // If models are still loading, wait for them before running inference.
      if (_loadingPromise) await _loadingPromise;
      const { url, dom } = msg.payload as { url: string; dom: DOMScanResult };
      try {
        const preds: MLPrediction[] = await runAllInference(url, dom);
        sendResponse({ type: 'OFFSCREEN_ML_RESULT', payload: preds });
      } catch (err) {
        sendResponse({ type: 'OFFSCREEN_ML_RESULT', error: String(err), payload: [] });
      }
    })();
    return true;
  }
  return false;
});
