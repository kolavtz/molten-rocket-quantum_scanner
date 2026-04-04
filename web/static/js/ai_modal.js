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
      if (!q) {
        responseHost.textContent = 'Please enter a question.';
        return;
      }
      sendBtn.disabled = true;
      statusEl.textContent = 'Thinking…';
      responseHost.textContent = '';
      try {
        const res = await api.fetch('/ai/cbom-query', { method: 'POST', body: { query: q } });
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
    });
  });
})();
