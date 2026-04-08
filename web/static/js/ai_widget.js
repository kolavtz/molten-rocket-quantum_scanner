/* AI widget with agentic RAG behaviors */
(function(){
  const SCAN_ID_RE = /\b[0-9a-f]{7,40}\b/i;
  function el(id){return document.getElementById(id);} 
  function createEl(tag, cls, html){const d=document.createElement(tag); if(cls) d.className=cls; if(html) d.innerHTML=html; return d;}
  function safeScroll(container){ try{ container.scrollTop = container.scrollHeight; }catch(e){} }
  function truncate(s, n){ if(!s) return ''; if(s.length <= n) return s; return s.slice(0,n-1) + '\n... (truncated)'; }

  async function fetchJsonOrText(path){
    try{
      const r = await fetch(path);
      return await qsParseJsonResponse(r);
    }catch(e){
      try{ const r2 = await fetch(path); return { error: 'fetch failed' }; }catch(_) { return null; }
    }
  }

  function analyzeMessageForData(msg){
    const out = [];
    const lower = (msg || '').toLowerCase();
    const hasScanWord = /\b(scan|result|findings|cbom|certificate|certificate|cert|asset|vulnerab)/i.test(lower);
    const wantsMetrics = /\b(metric|metrics|dashboard|summary|overview|counts)\b/i.test(lower);
    const wantsCerts = /\b(cert|certificate|tls|chain)\b/i.test(lower);
    const wantsCbom = /\b(cbom|component|sbom)\b/i.test(lower);

    if(hasScanWord){
      const m = SCAN_ID_RE.exec(msg);
      if(m){ out.push({type:'scan', scanId: m[0]}); }
      else if(window.CURRENT_SCAN_ID) { out.push({type:'scan', scanId: window.CURRENT_SCAN_ID}); }
    }
    if(wantsMetrics) out.push({type:'metrics'});
    if(wantsCerts){
      const sid = (SCAN_ID_RE.exec(msg) || [window.CURRENT_SCAN_ID || null])[0];
      if(sid) out.push({type:'certs', scanId: sid});
    }
    if(wantsCbom){
      const sid = (SCAN_ID_RE.exec(msg) || [window.CURRENT_SCAN_ID || null])[0];
      if(sid) out.push({type:'cbom', scanId: sid});
    }
    // dedupe by type+scanId
    const seen = new Set();
    return out.filter(a=>{ const k = a.type + '::' + (a.scanId||''); if(seen.has(k)) return false; seen.add(k); return true; });
  }

  async function performAutoFetch(actions){
    const parts = [];
    for(const act of actions){
      try{
        if(act.type === 'scan' && act.scanId){
          const p = `/api/scans/${encodeURIComponent(act.scanId)}/result`;
          const j = await fetchJsonOrText(p);
          if(j && j.status === 'success' && j.data){
            const report = j.data;
            const ov = report.overview || {};
            const tls = report.tls_results || [];
            const topServices = (report.discovered_services||[]).slice(0,6).map(s=>`${s.host || s.endpoint || ''}:${s.port||''} (${s.service||''})`).join(', ');
            const summary = `SCAN_SUMMARY (${act.scanId})\nTarget: ${report.target||'n/a'}\nGenerated: ${report.generated_at||report.scanned_at||'n/a'}\nStatus: ${report.status||'n/a'}\nAssets: ${ov.total_assets||0}, PQC_SAFE: ${ov.quantum_safe||0}, VULN: ${ov.quantum_vulnerable||0}, Compliance: ${ov.average_compliance_score||'n/a'}%\nTop Services: ${topServices || 'none'}\nCertificates: ${tls.length} (expired: ${(report.cert_summary && report.cert_summary.expired) || 0}, expiring<=30d: ${(report.cert_summary && report.cert_summary.expiring) || 0})\nCBOM components: ${((report.cbom && report.cbom.components && report.cbom.components.length) || report.cbom_components || (ov.cbom_components)) || 0}`;
            parts.push(summary);
          } else {
            parts.push(`SCAN_SUMMARY (${act.scanId}): Not available`);
          }
        } else if(act.type === 'metrics'){
          const j = await fetchJsonOrText('/api/scans/metrics');
          if(j){ parts.push('METRICS: ' + truncate(JSON.stringify(j), 2000)); } else parts.push('METRICS: unavailable');
        } else if(act.type === 'certs' && act.scanId){
          const path = `/api/scans/${encodeURIComponent(act.scanId)}/certificates?page=1&page_size=12&sort=valid_until&order=asc`;
          const j = await fetchJsonOrText(path);
          if(j && j.status === 'success'){
            const certs = j.data || [];
            const soon = certs.slice(0,5).map(c => `${c.host||''}:${c.port||''} exp:${c.valid_to||c.valid_until||'n/a'}` ).join('; ');
            parts.push(`CERTS (${act.scanId}): total=${(certs.length||0)}; soon=${soon}`);
          } else {
            parts.push(`CERTS (${act.scanId}): unavailable`);
          }
        } else if(act.type === 'cbom' && act.scanId){
          const p = `/api/scans/${encodeURIComponent(act.scanId)}/result`;
          const j = await fetchJsonOrText(p);
          if(j && j.status === 'success' && j.data){
            const cb = (j.data.cbom && j.data.cbom.components) || [];
            const csum = cb.slice(0,6).map(c=>`${c.name||c.component||c.purl||'comp'}`).join(', ');
            parts.push(`CBOM (${act.scanId}): components=${cb.length||0}; sample: ${csum}`);
          } else parts.push(`CBOM (${act.scanId}): unavailable`);
        }
      }catch(e){ parts.push(`${act.type.toUpperCase()}: fetch error`); }
    }
    return parts.join('\n\n');
  }

  document.addEventListener('DOMContentLoaded', function(){
    const toggle = el('ai-toggle');
    const panel = el('ai-panel');
    const closeBtn = el('ai-close');
    const sendBtn = el('ai-send');
    const input = el('ai-input');
    const msgs = el('ai-messages');
    const attachBtn = el('ai-attach-scan');
    const agentToggle = el('ai-agent-toggle');

    let AGENT_MODE = localStorage.getItem('qs_agent_mode') === '1';
    function setAgentToggleState(){ if(agentToggle){ agentToggle.classList.toggle('on', AGENT_MODE); agentToggle.setAttribute('aria-pressed', AGENT_MODE? 'true':'false'); agentToggle.textContent = AGENT_MODE? 'AGENT ON' : 'AGENT'; }}
    setAgentToggleState();
    if(agentToggle){ agentToggle.addEventListener('click', function(){ AGENT_MODE = !AGENT_MODE; localStorage.setItem('qs_agent_mode', AGENT_MODE? '1':'0'); setAgentToggleState(); }); }

    async function openPanelAndFetch(){
      try{
        panel.classList.add('open');
        // If agent mode is enabled, proactively fetch context (scan + metrics) for RAG
        if(AGENT_MODE){
          appendMessage('assistant', 'Agentic mode active — fetching context…');
          const actions = [];
          if(window.CURRENT_SCAN_ID) actions.push({type:'scan', scanId: window.CURRENT_SCAN_ID});
          // default: fetch global metrics as helpful context
          actions.push({type:'metrics'});
          const ctx = await performAutoFetch(actions);
          if(ctx){
            // keep attached data for next send, and show brief summary to user
            window.__ai_last_attached_data = ctx;
            appendMessage('assistant', 'Attached data (auto):<br>' + truncate(ctx, 2000));
          } else {
            appendMessage('assistant', 'Agent: no contextual data available.');
          }
        }
      }catch(e){
        appendMessage('assistant', 'Agent prefetch error: ' + (e && e.message ? e.message : String(e)));
      }
    }
    function closePanel(){ panel.classList.remove('open'); }
    toggle && toggle.addEventListener('click', function(e){ e.preventDefault(); if(panel.classList.contains('open')) closePanel(); else openPanelAndFetch(); });
    closeBtn && closeBtn.addEventListener('click', function(){ closePanel(); });
    // mini toggle (always-on-top small logo)
    const miniToggle = el('ai-mini-toggle');
    if(miniToggle){ miniToggle.addEventListener('click', function(e){ e.preventDefault(); if(panel.classList.contains('open')) closePanel(); else openPanelAndFetch(); }); }

    function appendMessage(role, text){
      const m = createEl('div', 'ai-msg ' + (role==='user'?'user':'assistant'), text.replace(/\n/g, '<br>'));
      msgs.appendChild(m);
      safeScroll(msgs);
    }

    async function sendMessage(){
      const text = (input.value || '').trim();
      if(!text) return;
      appendMessage('user', text);
      input.value = '';
      const loading = createEl('div', 'ai-msg assistant', 'Assistant is typing…'); loading.classList.add('ai-loading'); msgs.appendChild(loading);
      safeScroll(msgs);

      try{
        // Prepare history and include any pre-attached auto-fetched data (from open)
        let history = [];
        if(AGENT_MODE && window.__ai_last_attached_data){
          history.push({role:'system', content: 'Attached Data:\n' + window.__ai_last_attached_data});
          // consume it so it is not reused unintentionally
          window.__ai_last_attached_data = null;
        }
        // agentic prefetch based on user's message (additional on-demand fetches)
        const actions = AGENT_MODE ? analyzeMessageForData(text) : [];
        if(actions && actions.length){
          appendMessage('assistant', 'Agent fetching required data…');
          const ctx = await performAutoFetch(actions);
          if(ctx){ history.push({role:'system', content: 'Attached Data:\n' + ctx}); }
        }

        const resp = await fetch('/api/ai/chat', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ message: text, history: history }) });
        const data = await qsParseJsonResponse(resp);
        loading.remove();
        let reply = null;
        if(data && data.reply) reply = data.reply;
        else if (data && data.raw){ try { reply = JSON.stringify(data.raw); }catch(e){ reply = String(data.raw); } }
        else if (data && data.ok && data.raw) { reply = JSON.stringify(data.raw); }
        if(!reply) reply = 'No response from AI.';
        appendMessage('assistant', reply);
      }catch(err){
        loading.remove();
        appendMessage('assistant', 'Error calling AI: ' + (err && err.message ? err.message : String(err)));
      }
    }

    if(sendBtn){ sendBtn.addEventListener('click', sendMessage); }
    if(input){ input.addEventListener('keydown', function(e){ if((e.ctrlKey || e.metaKey) && e.key === 'Enter'){ e.preventDefault(); sendMessage(); } }); }

    if(attachBtn){ attachBtn.addEventListener('click', async function(){
      const scanId = window.CURRENT_SCAN_ID || window.SCAN_ID || null;
      if(!scanId){ appendMessage('assistant', 'No active scan context to attach. Open a scan page first.'); return; }
      appendMessage('assistant', 'Fetching scan summary…');
      try{
        const r = await fetch(`/api/scans/${encodeURIComponent(scanId)}/result`);
        const j = await qsParseJsonResponse(r);
        if(!j || j.status !== 'success' || !j.data){ appendMessage('assistant', 'Could not fetch scan data.'); return; }
        const report = j.data || {};
        const ov = report.overview || {};
        const summary = `Scan ${scanId} (${report.target || 'target'}): assets=${ov.total_assets||0}, pqc_safe=${ov.quantum_safe||0}, vulnerable=${ov.quantum_vulnerable||0}, compliance=${ov.average_compliance_score||0}%`;
        input.value = (input.value ? input.value + "\n\n" : "") + "Scan summary:\n" + summary + "\n\nPlease analyze and suggest next steps.";
        input.focus();
      }catch(e){ appendMessage('assistant', 'Failed to attach scan: ' + (e && e.message? e.message : String(e))); }
    }); }

  });
})();
