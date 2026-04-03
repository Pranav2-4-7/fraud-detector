/**
 * FraudShield v2.0 — Popup Controller
 * Handles page scanning, heuristic analysis, tab navigation, and UI rendering.
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  // ========================================================
  // CONSTANTS & CONFIG
  // ========================================================
  const API_URL = 'http://127.0.0.1:8000';
  const RING_CIRCUMFERENCE = 2 * Math.PI * 52; // ~326.73

  // ========================================================
  // DOM REFERENCES
  // ========================================================
  const dom = {
    // Header
    statusDot: document.querySelector('.status-dot'),
    statusText: document.getElementById('status-text'),
    trustScore: document.getElementById('trust-score'),
    ringProgress: document.getElementById('ring-progress'),
    siteDomain: document.getElementById('site-domain'),
    siteVerdict: document.getElementById('site-verdict'),

    // Tabs
    tabBtns: document.querySelectorAll('.tab-btn'),
    tabPanes: document.querySelectorAll('.tab-pane'),
    txnBadge: document.getElementById('txn-badge'),

    // Safety
    sslValue: document.getElementById('ssl-value'),
    sslIcon: document.getElementById('ssl-icon'),
    cardSsl: document.getElementById('card-ssl'),
    domainValue: document.getElementById('domain-value'),
    iframeValue: document.getElementById('iframe-value'),
    cardIframes: document.getElementById('card-iframes'),
    extformsValue: document.getElementById('extforms-value'),
    cardForms: document.getElementById('card-forms'),
    inputsValue: document.getElementById('inputs-value'),
    cardInputs: document.getElementById('card-inputs'),
    linksValue: document.getElementById('links-value'),
    alertsList: document.getElementById('alerts-list'),

    // Transactions
    txnEmpty: document.getElementById('txn-empty'),
    txnContent: document.getElementById('txn-content'),
    amountsList: document.getElementById('amounts-list'),
    methodsList: document.getElementById('methods-list'),
    formsList: document.getElementById('forms-list'),
    manualForm: document.getElementById('manual-form'),
    manualAmount: document.getElementById('manual-amount'),
    manualCard: document.getElementById('manual-card'),
    manualFrequency: document.getElementById('manual-frequency'),
    btnManualCheck: document.getElementById('btn-manual-check'),
    manualResult: document.getElementById('manual-result'),

    // Analysis
    riskFactors: document.getElementById('risk-factors'),
    recList: document.getElementById('rec-list'),
    scanTime: document.getElementById('scan-time'),
    btnRescan: document.getElementById('btn-rescan'),
    
    // Network
    netNodes: document.getElementById('net-nodes-count'),
    netSiblings: document.getElementById('net-siblings-count'),
    netAlert: document.getElementById('network-alert'),
    netGraph: document.getElementById('network-graph')
  };

  // State
  let currentScan = null;
  let backendAvailable = false;

  // ========================================================
  // TAB NAVIGATION
  // ========================================================

  dom.tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;

      dom.tabBtns.forEach(b => b.classList.remove('active'));
      dom.tabPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      document.getElementById(`pane-${tab}`).classList.add('active');
    });
  });

  // ========================================================
  // TRUST SCORE RING ANIMATION
  // ========================================================

  function animateRing(score, level) {
    const offset = RING_CIRCUMFERENCE - (score / 100) * RING_CIRCUMFERENCE;

    dom.ringProgress.style.strokeDashoffset = offset;
    dom.ringProgress.classList.remove('caution', 'danger');
    if (level === 'caution') dom.ringProgress.classList.add('caution');
    if (level === 'danger') dom.ringProgress.classList.add('danger');

    // Animate score counter
    let current = 0;
    const target = score;
    const increment = Math.max(1, Math.floor(target / 30));
    const timer = setInterval(() => {
      current = Math.min(current + increment, target);
      dom.trustScore.textContent = current;
      if (current >= target) {
        dom.trustScore.textContent = target;
        clearInterval(timer);
      }
    }, 30);
  }

  // ========================================================
  // COMPUTE TRUST SCORE (CLIENT-SIDE HEURISTIC)
  // ========================================================

  function computeTrustScore(scanData) {
    if (!scanData || !scanData.security) return { score: 50, level: 'caution' };

    const sec = scanData.security;
    let score = 100;

    // SSL penalty
    if (!sec.isHTTPS) score -= 30;

    // Phishing patterns
    score -= Math.min(sec.phishingScore * 0.5, 30);

    // Hidden iframes
    score -= Math.min(sec.hiddenIframes * 12, 24);

    // External forms
    score -= Math.min(sec.externalForms * 10, 20);

    // Suspicious patterns
    score -= Math.min(sec.suspiciousPatterns.length * 6, 18);

    // Sensitive inputs on non-HTTPS
    if (!sec.isHTTPS && sec.sensitiveInputCount > 0) score -= 12;

    // Content signals
    if (scanData.content) {
      if (!scanData.content.hasFavicon) score -= 3;
      if (!scanData.content.metaDescription) score -= 2;
    }

    // Bonus for analytics (legitimate sites usually have them)
    if (scanData.content && scanData.content.hasGoogleAnalytics) score += 3;

    score = Math.max(0, Math.min(100, Math.round(score)));

    let level = 'safe';
    if (score < 40) level = 'danger';
    else if (score < 70) level = 'caution';

    return { score, level };
  }

  // ========================================================
  // RENDER FUNCTIONS
  // ========================================================

  function setStatus(text, scanning = false) {
    dom.statusText.textContent = text;
    if (scanning) {
      dom.statusDot.classList.add('scanning');
    } else {
      dom.statusDot.classList.remove('scanning');
    }
  }

  function renderSafety(scanData) {
    const sec = scanData.security;

    // SSL
    if (sec.isHTTPS) {
      dom.sslValue.textContent = 'Secured';
      dom.sslValue.className = 'card-value text-green';
      dom.sslIcon.textContent = '🔒';
      dom.cardSsl.className = 'info-card safe';
    } else {
      dom.sslValue.textContent = 'Not Secure';
      dom.sslValue.className = 'card-value text-red';
      dom.sslIcon.textContent = '🔓';
      dom.cardSsl.className = 'info-card danger';
    }

    // Domain
    dom.domainValue.textContent = sec.domain;
    dom.domainValue.title = sec.domain;

    // Hidden iframes
    dom.iframeValue.textContent = sec.hiddenIframes;
    dom.cardIframes.className = sec.hiddenIframes > 0 ? 'info-card danger' : 'info-card';

    // External forms
    dom.extformsValue.textContent = sec.externalForms;
    dom.cardForms.className = sec.externalForms > 0 ? 'info-card caution' : 'info-card';

    // Sensitive inputs
    dom.inputsValue.textContent = sec.sensitiveInputCount;
    dom.cardInputs.className = sec.sensitiveInputCount > 3 ? 'info-card caution' : 'info-card';

    // Links
    const content = scanData.content;
    dom.linksValue.textContent = `${content.externalLinks} / ${content.totalLinks}`;

    // Alerts
    if (sec.suspiciousPatterns.length > 0) {
      dom.alertsList.innerHTML = sec.suspiciousPatterns.map((pattern, i) => {
        const severity = pattern.toLowerCase().includes('phishing') || pattern.toLowerCase().includes('impersonation')
          ? 'danger' : 'warning';
        return `
          <div class="alert-item ${severity}" style="animation-delay: ${i * 0.1}s">
            <span>${severity === 'danger' ? '🚨' : '⚠️'}</span>
            <span>${escapeHtml(pattern)}</span>
          </div>
        `;
      }).join('');
    } else {
      // Check for positive signals
      let positiveAlerts = '';
      if (sec.isHTTPS) {
        positiveAlerts += `<div class="alert-item info"><span>✅</span><span>Connection is encrypted (HTTPS)</span></div>`;
      }
      if (content.hasGoogleAnalytics) {
        positiveAlerts += `<div class="alert-item info"><span>✅</span><span>Google Analytics detected (legitimate site signal)</span></div>`;
      }
      if (content.hasFavicon) {
        positiveAlerts += `<div class="alert-item info"><span>✅</span><span>Favicon present</span></div>`;
      }
      dom.alertsList.innerHTML = positiveAlerts || '<div class="alert-placeholder">No threats detected — site looks clean 🎉</div>';
    }
  }

  function renderTransactions(scanData) {
    const txn = scanData.transactions;
    const hasData = txn.amounts.length > 0 || txn.paymentMethods.length > 0 || txn.paymentForms.length > 0;

    if (hasData) {
      dom.txnEmpty.classList.add('hidden');
      dom.txnContent.classList.remove('hidden');

      // Badge
      const totalItems = txn.amounts.length + txn.paymentMethods.length;
      if (totalItems > 0) {
        dom.txnBadge.textContent = totalItems;
        dom.txnBadge.classList.remove('hidden');
      }

      // Amounts
      if (txn.amounts.length > 0) {
        document.getElementById('amounts-section').classList.remove('hidden');
        dom.amountsList.innerHTML = txn.amounts.map(a => `
          <div class="amount-item">
            <span class="amount-value">$${a.value.toLocaleString('en-US', { minimumFractionDigits: 2 })}</span>
            <span class="amount-context">${escapeHtml(a.context)}</span>
          </div>
        `).join('');
      } else {
        document.getElementById('amounts-section').classList.add('hidden');
      }

      // Payment Methods
      if (txn.paymentMethods.length > 0) {
        document.getElementById('methods-section').classList.remove('hidden');
        const methodIcons = {
          visa: '💳', mastercard: '💳', amex: '💳', discover: '💳',
          rupay: '💳', upi: '📱', paypal: '🅿️', stripe: '⚡',
          card_form_detected: '📝'
        };
        dom.methodsList.innerHTML = txn.paymentMethods.map(m => `
          <span class="method-chip">
            <span class="chip-icon">${methodIcons[m] || '💳'}</span>
            ${m === 'card_form_detected' ? 'Card Form' : m.charAt(0).toUpperCase() + m.slice(1)}
          </span>
        `).join('');
      } else {
        document.getElementById('methods-section').classList.add('hidden');
      }

      // Payment Forms
      if (txn.paymentForms.length > 0) {
        document.getElementById('forms-section').classList.remove('hidden');
        dom.formsList.innerHTML = txn.paymentForms.map((f, i) => `
          <div class="form-item">
            <strong>Form #${i + 1}</strong> — ${f.fieldCount} fields
            ${f.hasCardField ? ' • Card Input' : ''} ${f.hasCVV ? ' • CVV' : ''}
            <div class="form-detail">Method: ${f.method.toUpperCase()} | Action: ${f.action === 'none' ? 'Current page' : escapeHtml(truncate(f.action, 40))}</div>
          </div>
        `).join('');
      } else {
        document.getElementById('forms-section').classList.add('hidden');
      }
    } else {
      dom.txnEmpty.classList.remove('hidden');
      dom.txnContent.classList.add('hidden');
    }
  }

  function renderAnalysis(scanData, trustResult) {
    const sec = scanData.security;
    const content = scanData.content;

    // Risk Factors
    const factors = [
      {
        name: 'SSL Encryption',
        icon: sec.isHTTPS ? '🔒' : '🔓',
        score: sec.isHTTPS ? 100 : 10,
        color: sec.isHTTPS ? 'green' : 'red'
      },
      {
        name: 'Phishing Detection',
        icon: '🎣',
        score: Math.max(0, 100 - sec.phishingScore),
        color: sec.phishingScore < 20 ? 'green' : sec.phishingScore < 50 ? 'yellow' : 'red'
      },
      {
        name: 'Hidden Elements',
        icon: '👁️',
        score: sec.hiddenIframes === 0 ? 100 : Math.max(0, 100 - sec.hiddenIframes * 25),
        color: sec.hiddenIframes === 0 ? 'green' : 'red'
      },
      {
        name: 'Form Security',
        icon: '📋',
        score: sec.externalForms === 0 ? 100 : Math.max(0, 100 - sec.externalForms * 30),
        color: sec.externalForms === 0 ? 'green' : sec.externalForms === 1 ? 'yellow' : 'red'
      },
      {
        name: 'Domain Reputation',
        icon: '🌐',
        score: sec.suspiciousPatterns.length === 0 ? 95 : Math.max(0, 100 - sec.suspiciousPatterns.length * 20),
        color: sec.suspiciousPatterns.length === 0 ? 'green' : 'red'
      },
      {
        name: 'Content Integrity',
        icon: '📄',
        score: Math.min(100, (content.hasFavicon ? 30 : 0) + (content.metaDescription ? 30 : 0) + (content.hasGoogleAnalytics ? 40 : 20)),
        color: content.hasFavicon && content.metaDescription ? 'green' : 'yellow'
      }
    ];

    dom.riskFactors.innerHTML = factors.map((f, i) => `
      <div class="risk-factor" style="animation-delay: ${i * 0.08}s">
        <span class="rf-icon">${f.icon}</span>
        <div class="rf-body">
          <div class="rf-name">${f.name}</div>
          <div class="rf-bar">
            <div class="rf-fill ${f.color}" style="width: ${f.score}%"></div>
          </div>
        </div>
        <span class="rf-score">${f.score}%</span>
      </div>
    `).join('');

    // Recommendations
    const recommendations = [];

    if (!sec.isHTTPS) {
      recommendations.push({ icon: '🔴', text: 'This site is NOT encrypted. Avoid entering passwords or payment info.', warn: true });
    }
    if (sec.hiddenIframes > 0) {
      recommendations.push({ icon: '🔴', text: `${sec.hiddenIframes} hidden iframe(s) detected — possible clickjacking attempt.`, warn: true });
    }
    if (sec.externalForms > 0) {
      recommendations.push({ icon: '🟡', text: 'Forms submit data to external domains. Verify before entering info.', warn: true });
    }
    if (sec.suspiciousPatterns.length > 0) {
      recommendations.push({ icon: '🔴', text: 'Suspicious patterns found. This site may be impersonating another brand.', warn: true });
    }
    if (sec.isHTTPS && sec.suspiciousPatterns.length === 0 && sec.hiddenIframes === 0) {
      recommendations.push({ icon: '✅', text: 'Site appears safe. Standard security measures are in place.' });
    }
    if (scanData.transactions.amounts.length > 0) {
      recommendations.push({ icon: '💡', text: 'Transaction amounts detected. Review them in the Transactions tab.' });
    }

    dom.recList.innerHTML = recommendations.map(r => `
      <div class="rec-item ${r.warn ? 'warn' : ''}">
        <span class="rec-icon">${r.icon}</span>
        <span>${r.text}</span>
      </div>
    `).join('');

    // Scan time
    dom.scanTime.textContent = `Scanned: ${new Date().toLocaleTimeString()}`;
  }

  function renderVerdict(trustResult) {
    const { score, level } = trustResult;

    dom.siteVerdict.className = `site-verdict ${level}`;

    if (level === 'safe') {
      dom.siteVerdict.textContent = '✅ Site appears safe — no threats detected';
    } else if (level === 'caution') {
      dom.siteVerdict.textContent = '⚠️ Proceed with caution — some risks found';
    } else {
      dom.siteVerdict.textContent = '🚨 High risk detected — avoid sensitive actions';
    }
  }

  // ========================================================
  // MANUAL FRAUD CHECK (with API fallback)
  // ========================================================

  function heuristicFraudCheck(amount, cardType, frequency) {
    // Client-side heuristic scoring when backend is unavailable
    let probability = 0.02;

    // High amounts are riskier
    if (amount > 5000) probability += 0.15;
    else if (amount > 2000) probability += 0.08;
    else if (amount > 500) probability += 0.03;

    // Small payments in high frequency are suspicious
    if (frequency >= 3 && amount < 100) probability += 0.25;
    else if (frequency >= 5) probability += 0.20;
    else if (frequency >= 2) probability += 0.05;

    // Round amounts are slightly suspicious
    if (amount % 100 === 0 && amount > 100) probability += 0.02;

    // Card type influence
    if (cardType === 'amex') probability += 0.01;

    // Site safety influence
    if (currentScan) {
      const sec = currentScan.security;
      if (!sec.isHTTPS) probability += 0.15;
      if (sec.hiddenIframes > 0) probability += 0.10;
      if (sec.externalForms > 0) probability += 0.08;
      if (sec.suspiciousPatterns.length > 0) probability += 0.12;
    }

    probability = Math.min(probability, 0.99);

    let risk = 'LOW';
    if (probability > 0.15) risk = 'HIGH';
    else if (probability > 0.06) risk = 'MEDIUM';

    return {
      fraud_probability: probability,
      is_fraud: probability > 0.15 ? 1 : 0,
      risk_level: risk
    };
  }

  async function runFraudCheck(amount, cardType, frequency) {
    // Collect behavioral data from currentScan if available
    let behavior = { time_on_page_s: 0, mouse_speed_px_s: 0, typing_speed_cpm: 0 };
    if (currentScan && currentScan.behavior) {
      behavior = currentScan.behavior;
    }

    // Try backend first, fallback to heuristic
    if (backendAvailable) {
      try {
        const payload = {
            transaction_amount: amount,
            card_type: cardType,
            user_location: 'US',
            transaction_frequency: frequency,
            device_type: 'desktop',
            time_on_page_s: behavior.time_on_page_s,
            mouse_speed_px_s: behavior.mouse_speed_px_s,
            typing_speed_cpm: behavior.typing_speed_cpm
        };
        const response = await fetch(`${API_URL}/predict`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (response.ok) {
          return await response.json();
        }
      } catch (e) {
        console.log('Backend unavailable, using heuristic');
      }
    }
    return heuristicFraudCheck(amount, cardType, frequency);
  }

  function renderFraudResult(result) {
    const { fraud_probability, is_fraud, risk_level, xai_explanations, network_graph } = result;
    const level = risk_level === 'HIGH' ? 'danger' : risk_level === 'MEDIUM' ? 'caution' : 'safe';
    const badgeClass = risk_level === 'HIGH' ? 'high' : risk_level === 'MEDIUM' ? 'medium' : 'low';

    dom.manualResult.className = `manual-result ${level}`;
    dom.manualResult.classList.remove('hidden');
    dom.manualResult.innerHTML = `
      <div class="result-header">
        <span class="result-verdict">${is_fraud ? '❌ FLAGGED' : '✅ CLEARED'}</span>
        <span class="result-badge ${badgeClass}">${risk_level} RISK</span>
      </div>
      <div class="result-details">
        <div class="result-row">
          <span class="label">Fraud Probability</span>
          <span class="value">${(fraud_probability * 100).toFixed(2)}%</span>
        </div>
        <div class="result-row">
          <span class="label">Decision</span>
          <span class="value">${is_fraud ? 'Transaction Blocked' : 'Transaction Safe'}</span>
        </div>
        <div class="result-row">
          <span class="label">Engine</span>
          <span class="value">${backendAvailable ? 'XGBoost ML' : 'Heuristic'}</span>
        </div>
      </div>
    `;

    // Render XAI if available
    if (xai_explanations && xai_explanations.length > 0) {
      const xaiHtml = xai_explanations.map((x, i) => `
        <div class="risk-factor" style="animation-delay: ${i * 0.08}s">
          <span class="rf-icon">${x.type === 'danger' ? '🚨' : x.type === 'warning' ? '⚠️' : '✅'}</span>
          <div class="rf-body">
            <div class="rf-name">${x.feature}</div>
          </div>
          <span class="rf-score" style="color: ${x.type === 'danger' ? '#f87171' : x.type === 'warning' ? '#fbbf24' : '#34d399'}">${x.impact}</span>
        </div>
      `).join('');
      // Prepend to risk factors in analysis tab
      dom.riskFactors.innerHTML = xaiHtml + '<div style="margin: 10px 0; border-top: 1px solid rgba(255,255,255,0.1);"></div>' + dom.riskFactors.innerHTML;
      
      // Auto-switch to Analysis Tab to show AI logic (User preference may vary, but helpful for UX)
      document.getElementById('tab-analysis').click();
    }

    // Render Network Graph if available
    if (network_graph) {
      dom.netNodes.textContent = network_graph.node_count;
      dom.netSiblings.textContent = network_graph.connected_siblings;
      
      if (network_graph.ring_detected) {
        dom.netAlert.classList.remove('hidden');
      } else {
        dom.netAlert.classList.add('hidden');
      }

      // Draw mock nodes
      let graphNodesHtml = '';
      for(let i=0; i<network_graph.node_count; i++) {
        // Random placement for visual effect
        let left = 20 + Math.random() * 60;
        let top = 20 + Math.random() * 60;
        const color = network_graph.ring_detected ? '#ef4444' : '#3b82f6';
        graphNodesHtml += `<div style="position:absolute; width:12px; height:12px; background:${color}; border-radius:50%; box-shadow: 0 0 10px ${color}; left:${left}%; top:${top}%;"></div>`;
        if (i > 0) {
           // Draw a string line connecting to center node roughly
           graphNodesHtml += `<div style="position:absolute; width:20%; height:1px; background:rgba(255,255,255,0.2); left:50%; top:50%; transform: rotate(${Math.random()*360}deg); transform-origin: 0 0;"></div>`;
        }
      }
      dom.netGraph.innerHTML = `<div style="position:relative; width: 100%; height: 150px; background: rgba(0,0,0,0.2); border-radius: 8px; margin-top: 10px; overflow: hidden;">
        <div style="position:absolute; width:16px; height:16px; background:#fff; border-radius:50%; left:50%; top:50%; transform:translate(-50%, -50%); z-index:10; box-shadow: 0 0 10px #fff;"></div>
        ${graphNodesHtml}
      </div>`;
    }
  }

  // ========================================================
  // MAIN SCAN LOGIC
  // ========================================================

  async function scanCurrentPage() {
    setStatus('Scanning...', true);

    try {
      // Get active tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) {
        setStatus('No tab', false);
        return;
      }

      dom.siteDomain.textContent = new URL(tab.url).hostname || 'Unknown';

      // Check for restricted pages
      if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('about:')) {
        setStatus('Restricted', false);
        dom.trustScore.textContent = '--';
        dom.siteVerdict.textContent = 'Cannot scan browser internal pages';
        dom.siteVerdict.className = 'site-verdict';
        return;
      }

      // Inject content script if needed and request scan
      let scanResult;
      try {
        const response = await chrome.tabs.sendMessage(tab.id, { action: 'scanPage' });
        if (response && response.success) {
          scanResult = response.data;
        }
      } catch (e) {
        // Content script may not be loaded yet, try injecting
        try {
          await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ['content.js']
          });
          // Wait a bit then retry
          await new Promise(r => setTimeout(r, 300));
          const response = await chrome.tabs.sendMessage(tab.id, { action: 'scanPage' });
          if (response && response.success) {
            scanResult = response.data;
          }
        } catch (injectError) {
          console.error('Cannot inject content script:', injectError);
        }
      }

      if (!scanResult) {
        // Fallback: basic analysis from tab info alone
        scanResult = {
          timestamp: Date.now(),
          url: tab.url,
          domain: new URL(tab.url).hostname,
          security: {
            isHTTPS: tab.url.startsWith('https://'),
            domain: new URL(tab.url).hostname,
            fullUrl: tab.url,
            hasLoginForm: false,
            sensitiveInputCount: 0,
            hiddenIframes: 0,
            externalForms: 0,
            suspiciousPatterns: [],
            phishingScore: 0
          },
          transactions: { amounts: [], paymentMethods: [], paymentForms: [] },
          content: { title: tab.title, metaDescription: '', externalScripts: 0, totalLinks: 0, externalLinks: 0, hasGoogleAnalytics: false, hasFavicon: false }
        };
      }

      currentScan = scanResult;

      // Compute trust
      const trustResult = computeTrustScore(scanResult);

      // Render everything
      animateRing(trustResult.score, trustResult.level);
      renderVerdict(trustResult);
      renderSafety(scanResult);
      renderTransactions(scanResult);
      renderAnalysis(scanResult, trustResult);

      setStatus('Complete', false);

    } catch (error) {
      console.error('Scan error:', error);
      setStatus('Error', false);
      dom.siteVerdict.textContent = `Error: ${error.message}`;
      dom.siteVerdict.className = 'site-verdict danger';
    }
  }

  // ========================================================
  // CHECK BACKEND AVAILABILITY
  // ========================================================

  async function checkBackend() {
    try {
      const response = await fetch(`${API_URL}/docs`, { method: 'HEAD', signal: AbortSignal.timeout(2000) });
      backendAvailable = response.ok;
    } catch (e) {
      backendAvailable = false;
    }
  }

  // ========================================================
  // EVENT HANDLERS
  // ========================================================

  // Manual form
  dom.manualForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const amount = parseFloat(dom.manualAmount.value);
    const card = dom.manualCard.value;
    const frequency = parseInt(dom.manualFrequency.value, 10) || 1;

    if (isNaN(amount) || amount <= 0) return;

    dom.btnManualCheck.textContent = 'Analyzing...';
    dom.btnManualCheck.classList.add('loading');
    dom.btnManualCheck.disabled = true;

    const result = await runFraudCheck(amount, card, frequency);
    renderFraudResult(result);

    dom.btnManualCheck.textContent = 'Run Fraud Analysis';
    dom.btnManualCheck.classList.remove('loading');
    dom.btnManualCheck.disabled = false;
  });

  // Rescan
  dom.btnRescan.addEventListener('click', () => {
    scanCurrentPage();
  });

  // ========================================================
  // UTILITIES
  // ========================================================

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function truncate(str, len) {
    return str.length > len ? str.substring(0, len) + '...' : str;
  }

  // ========================================================
  // INIT
  // ========================================================

  checkBackend();
  scanCurrentPage();
});
