/* AI Assistant widget script with persistent chat history and Zendesk UI interactions */
(function(){
  'use strict';
  
  function el(id){ return document.getElementById(id); }
  
  function createEl(tag, cls, html){
    const d = document.createElement(tag);
    if(cls) d.className = cls;
    if(html) d.innerHTML = html;
    return d;
  }
  
  function safeScroll(container){
    try { container.scrollTop = container.scrollHeight; } catch(e){}
  }

  function getHistory() {
    try {
      return JSON.parse(sessionStorage.getItem('qs_chat_history')) || [];
    } catch(e) {
      return [];
    }
  }

  function saveHistory(history) {
    try {
      sessionStorage.setItem('qs_chat_history', JSON.stringify(history));
    } catch(e) {}
  }

  document.addEventListener('DOMContentLoaded', function(){
    const toggle = el('ai-toggle');
    const panel = el('ai-panel');
    const closeBtn = el('ai-close');
    const sendBtn = el('ai-send');
    const input = el('ai-input');
    const msgs = el('ai-messages');
    const attachBtn = el('ai-attach-scan');

    if (!panel || !msgs) return;

    // Toggle panel
    if (toggle) {
      toggle.addEventListener('click', function(e){
        e.preventDefault();
        panel.classList.toggle('open');
        safeScroll(msgs);
      });
    }

    if (closeBtn) {
      closeBtn.addEventListener('click', function(e){
        e.preventDefault();
        panel.classList.remove('open');
      });
    }

    // Append a message to UI and history
    function appendMessage(role, text, skipSave = false) {
      const msgGroup = createEl('div', 'ai-msg-group ' + role);
      const name = role === 'user' ? 'You' : 'Zea (AI agent)';
      msgGroup.appendChild(createEl('span', 'ai-sender-name', name));
      
      const bubble = createEl('div', 'ai-msg ' + role, text.replace(/\n/g, '<br>'));
      msgGroup.appendChild(bubble);
      msgs.appendChild(msgGroup);
      safeScroll(msgs);

      if (!skipSave) {
        const history = getHistory();
        history.push({ role, text });
        saveHistory(history);
      }
    }

    // Render option pills
    function appendOptions() {
      const optionsContainer = createEl('div', 'ai-options-container');
      const options = [
        { label: 'Start a Scan', msg: 'Run a Post-Quantum scan' },
        { label: 'PQC Mitigations', msg: 'What are the key PQC features?' },
        { label: 'CBOM Export Help', msg: 'Show me a CBOM export demo' },
        { label: 'Learn about PQC', msg: 'What is Post-Quantum Cryptography?' },
        { label: 'Check System Posture', msg: 'Show my scan metrics summary' }
      ];

      options.forEach(opt => {
        const btn = createEl('button', 'ai-option-btn', opt.label);
        btn.addEventListener('click', function(e){
          e.preventDefault();
          optionsContainer.remove();
          sendMessage(opt.msg);
        });
        optionsContainer.appendChild(btn);
      });
      msgs.appendChild(optionsContainer);
      safeScroll(msgs);
    }

    // Send a message
    async function sendMessage(text) {
      const msgText = text || (input.value || '').trim();
      if (!msgText) return;
      
      if (!text) {
        input.value = '';
      }

      appendMessage('user', msgText);

      // Loading/typing indicator
      const loading = createEl('div', 'ai-msg-group assistant');
      loading.appendChild(createEl('span', 'ai-sender-name', 'Zea (AI agent)'));
      const bubble = createEl('div', 'ai-msg assistant');
      bubble.innerHTML = '<div class="ai-loading-dots"><span></span><span></span><span></span></div>';
      loading.appendChild(bubble);
      msgs.appendChild(loading);
      safeScroll(msgs);

      try {
        const history = getHistory().map(h => ({
          role: h.role,
          content: h.text
        }));

        const resp = await fetch('/api/ai/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: msgText, history: history })
        });
        const data = await resp.json();
        
        loading.remove();
        
        let reply = data && data.reply;
        if (!reply && data && data.raw) {
          try { reply = typeof data.raw === 'string' ? data.raw : JSON.stringify(data.raw); } catch(e) { reply = String(data.raw); }
        }
        if (!reply) reply = 'No response from AI.';

        appendMessage('assistant', reply);
        // Show option pills again after response to guide the user
        appendOptions();
      } catch(err) {
        loading.remove();
        appendMessage('assistant', 'Error calling AI: ' + (err.message || String(err)));
      }
    }

    // Initialize/restore chat window
    function initChat() {
      msgs.innerHTML = '';
      
      // Render Zendesk Privacy Notice
      const notice = createEl('div', 'ai-notice', 'This chat is recorded using a cloud service and is subject to the terms of our <a href="#" onclick="event.preventDefault()">Privacy Notice</a>.');
      msgs.appendChild(notice);

      // Render Timestamp
      const now = new Date();
      const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
      const timestamp = createEl('div', 'ai-timestamp', timeStr);
      msgs.appendChild(timestamp);

      const history = getHistory();
      if (history.length > 0) {
        history.forEach(h => {
          appendMessage(h.role, h.text, true);
        });
        // append option pills at the end of session resumption
        appendOptions();
      } else {
        // Welcome messages
        appendMessage('assistant', "Hi there, I'm Zea, your QuantumShield AI agent. I'm here to help you secure your systems.");
        appendMessage('assistant', 'Ask me a question or choose an option below.');
        appendOptions();
      }
    }

    // Attach event listeners
    if (sendBtn) {
      sendBtn.addEventListener('click', () => sendMessage());
    }
    if (input) {
      input.addEventListener('keydown', function(e){
        if (e.key === 'Enter') {
          e.preventDefault();
          sendMessage();
        }
      });
    }

    if (attachBtn) {
      attachBtn.addEventListener('click', async function(e){
        e.preventDefault();
        const scanId = window.CURRENT_SCAN_ID || window.SCAN_ID || null;
        if (!scanId) {
          appendMessage('assistant', 'No active scan context to attach. Open a scan page first.');
          return;
        }
        appendMessage('assistant', 'Fetching scan summary…');
        try {
          const r = await fetch(`/api/scans/${encodeURIComponent(scanId)}/result`);
          const j = await r.json();
          if (!j || j.status !== 'success' || !j.data) {
            appendMessage('assistant', 'Could not fetch scan data.');
            return;
          }
          const report = j.data || {};
          const ov = report.overview || {};
          const summary = `Scan ${scanId} (${report.target || 'target'}): assets=${ov.total_assets||0}, pqc_safe=${ov.quantum_safe||0}, vulnerable=${ov.quantum_vulnerable||0}, compliance=${ov.average_compliance_score||0}%`;
          input.value = (input.value ? input.value + "\n\n" : "") + "Scan summary:\n" + summary + "\n\nPlease analyze and suggest next steps.";
          input.focus();
        } catch(e) {
          appendMessage('assistant', 'Failed to attach scan: ' + (e.message || String(e)));
        }
      });
    }

    // Boot
    initChat();
  });
})();
