// Client logic for AI Assistant modal
(function () {
  const api = window.QuantumShieldApiClient;

  function el(id) { return document.getElementById(id); }

  document.addEventListener('DOMContentLoaded', function () {
    const openBtn = el('openAiAssistantBtn');
    const modal = el('aiAssistantModal');
    const closeBtn = el('aiAssistantModalClose');
    const sendBtn = el('aiSendBtn');
    const queryInput = el('aiQueryInput');
    const responseHost = el('aiResponse');
    const statusEl = el('aiAssistantStatus');

    if (!openBtn || !modal) return;

    openBtn.addEventListener('click', function () {
      modal.classList.add('open');
      statusEl.textContent = '';
      responseHost.textContent = '';
      queryInput.focus();
    });

    closeBtn && closeBtn.addEventListener('click', function () {
      modal.classList.remove('open');
    });

    sendBtn && sendBtn.addEventListener('click', async function () {
      const q = (queryInput.value || '').trim();
      const assetEl = el('aiAssetId');
      const assetId = assetEl ? (assetEl.value || '').trim() : '';
      if (!q) {
        responseHost.textContent = 'Please enter a question.';
        return;
      }
      sendBtn.disabled = true;
      statusEl.textContent = 'Thinking…';
      responseHost.textContent = '';

      // Try SSE streaming endpoint first; if it fails, fall back to regular POST
      const qs = api.buildQuery({ query: q, asset_id: assetId });
      const streamUrl = `${api.baseUrl}/ai/cbom-query/stream?${qs}`;
      let evtSource;
      let streaming = false;
      try {
        evtSource = new EventSource(streamUrl);
        streaming = true;
      } catch (e) {
        streaming = false;
      }

      if (streaming && evtSource) {
        evtSource.onmessage = function (e) {
          // Append incremental data
          responseHost.textContent += e.data;
        };
        evtSource.addEventListener('done', function (e) {
          statusEl.textContent = '';
          sendBtn.disabled = false;
          try { evtSource.close(); } catch (err) {}
        });
        evtSource.onerror = async function (e) {
          // If streaming is not supported or fails, close and fallback
          try { evtSource.close(); } catch (err) {}
          // Fallback to fetch-based request
          try {
            const res = await api.fetch('/ai/cbom-query', { method: 'POST', body: { query: q, asset_id: assetId } });
            if (res && res.answer) {
              responseHost.innerText = res.answer;
            } else if (res && res.message) {
              responseHost.innerText = 'No answer: ' + (res.message || 'Unknown');
            } else {
              responseHost.innerText = 'No response from assistant.';
            }
          } catch (err) {
            responseHost.innerText = 'Error: ' + (err.message || err);
          } finally {
            sendBtn.disabled = false;
            statusEl.textContent = '';
          }
        };
      } else {
        // No streaming support; regular POST
        try {
          const res = await api.fetch('/ai/cbom-query', { method: 'POST', body: { query: q, asset_id: assetId } });
          if (res && res.answer) {
            responseHost.innerText = res.answer;
          } else if (res && res.message) {
            responseHost.innerText = 'No answer: ' + (res.message || 'Unknown');
          } else {
            responseHost.innerText = 'No response from assistant.';
          }
        } catch (err) {
          responseHost.innerText = 'Error: ' + (err.message || err);
        } finally {
          sendBtn.disabled = false;
          statusEl.textContent = '';
        }
      }
    });
  });
})();
