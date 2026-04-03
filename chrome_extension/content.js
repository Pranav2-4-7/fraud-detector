/**
 * FraudShield Content Script
 * Injected into every page to scan for:
 * - Payment forms and transaction amounts
 * - Phishing indicators and suspicious patterns
 * - SSL/security signals
 * - Hidden iframes and suspicious redirects
 */

(() => {
  'use strict';

  // ========================================================
  // 1. TRANSACTION DETECTION
  // ========================================================

  function detectTransactionAmounts() {
    const amounts = [];
    const currencyRegex = /(?:[\$\£\€\₹]|USD|EUR|GBP|INR|Rs\.?)\s*[\d,]+\.?\d{0,2}/gi;
    const amountLabelRegex = /(?:total|amount|price|cost|pay|checkout|subtotal|grand\s*total|order\s*total)\s*[:\-]?\s*(?:[\$\£\€\₹]|USD|EUR|GBP|INR|Rs\.?)\s*([\d,]+\.?\d{0,2})/gi;

    // Search visible text nodes
    const walker = document.createTreeWalker(
      document.body, NodeFilter.SHOW_TEXT, null
    );

    const seenAmounts = new Set();
    while (walker.nextNode()) {
      const text = walker.currentNode.textContent.trim();
      if (!text) continue;

      // Priority: labeled amounts (e.g., "Total: $150.00")
      let match;
      while ((match = amountLabelRegex.exec(text)) !== null) {
        const val = parseFloat(match[1].replace(/,/g, ''));
        if (!isNaN(val) && val > 0 && !seenAmounts.has(val)) {
          seenAmounts.add(val);
          amounts.push({ value: val, context: match[0].trim(), type: 'labeled' });
        }
      }

      // Secondary: any currency value
      while ((match = currencyRegex.exec(text)) !== null) {
        const numStr = match[0].replace(/[^\d.,]/g, '').replace(/,/g, '');
        const val = parseFloat(numStr);
        if (!isNaN(val) && val > 0 && !seenAmounts.has(val)) {
          seenAmounts.add(val);
          amounts.push({ value: val, context: match[0].trim(), type: 'currency' });
        }
      }
    }

    // Also check input fields with amount-like names
    const inputs = document.querySelectorAll('input[type="number"], input[name*="amount"], input[name*="price"], input[name*="total"], input[id*="amount"], input[id*="price"]');
    inputs.forEach(inp => {
      const val = parseFloat(inp.value);
      if (!isNaN(val) && val > 0 && !seenAmounts.has(val)) {
        seenAmounts.add(val);
        amounts.push({ value: val, context: `Input: ${inp.name || inp.id || 'unnamed'}`, type: 'input' });
      }
    });

    return amounts.sort((a, b) => b.value - a.value).slice(0, 10);
  }

  function detectPaymentMethods() {
    const methods = [];
    const bodyText = document.body.innerText.toLowerCase();
    const html = document.body.innerHTML.toLowerCase();

    const cards = [
      { name: 'visa', patterns: ['visa', 'visa card'] },
      { name: 'mastercard', patterns: ['mastercard', 'master card', 'master-card'] },
      { name: 'amex', patterns: ['amex', 'american express'] },
      { name: 'discover', patterns: ['discover card', 'discover'] },
      { name: 'rupay', patterns: ['rupay'] },
      { name: 'upi', patterns: ['upi', 'google pay', 'phonepe', 'paytm'] },
      { name: 'paypal', patterns: ['paypal'] },
      { name: 'stripe', patterns: ['stripe'] }
    ];

    cards.forEach(card => {
      if (card.patterns.some(p => bodyText.includes(p) || html.includes(p))) {
        methods.push(card.name);
      }
    });

    // Check for credit card input fields
    const ccInputs = document.querySelectorAll(
      'input[name*="card"], input[name*="cc"], input[autocomplete*="cc-number"], input[name*="credit"], input[id*="card-number"], input[placeholder*="card number"]'
    );
    if (ccInputs.length > 0) {
      methods.push('card_form_detected');
    }

    return [...new Set(methods)];
  }

  function detectPaymentForms() {
    const forms = document.querySelectorAll('form');
    const paymentForms = [];

    forms.forEach((form, idx) => {
      const formHtml = form.innerHTML.toLowerCase();
      const formAction = (form.action || '').toLowerCase();
      const isPayment =
        formHtml.includes('card') ||
        formHtml.includes('payment') ||
        formHtml.includes('checkout') ||
        formHtml.includes('billing') ||
        formHtml.includes('cvv') ||
        formHtml.includes('expir') ||
        formAction.includes('pay') ||
        formAction.includes('checkout') ||
        formAction.includes('order');

      if (isPayment) {
        const fields = form.querySelectorAll('input, select');
        paymentForms.push({
          index: idx,
          action: form.action || 'none',
          method: form.method || 'get',
          fieldCount: fields.length,
          hasCardField: formHtml.includes('card') || formHtml.includes('cc-number'),
          hasCVV: formHtml.includes('cvv') || formHtml.includes('cvc') || formHtml.includes('security code')
        });
      }
    });

    return paymentForms;
  }

  // ========================================================
  // 2. PHISHING & SECURITY ANALYSIS
  // ========================================================

  function analyzeSecuritySignals() {
    const signals = {
      isHTTPS: window.location.protocol === 'https:',
      domain: window.location.hostname,
      fullUrl: window.location.href,
      hasLoginForm: false,
      sensitiveInputCount: 0,
      hiddenIframes: 0,
      externalForms: 0,
      suspiciousPatterns: [],
      phishingScore: 0
    };

    // Check for login/credential forms
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    const emailInputs = document.querySelectorAll('input[type="email"], input[name*="email"], input[name*="user"], input[autocomplete*="username"]');
    signals.hasLoginForm = passwordInputs.length > 0;
    signals.sensitiveInputCount = passwordInputs.length + emailInputs.length;

    // Count sensitive data fields
    const ssnInputs = document.querySelectorAll('input[name*="ssn"], input[name*="social"], input[name*="aadhar"], input[name*="pan"]');
    signals.sensitiveInputCount += ssnInputs.length;

    // Hidden iframes (common phishing technique)
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach(iframe => {
      const style = window.getComputedStyle(iframe);
      if (style.display === 'none' || style.visibility === 'hidden' ||
        style.opacity === '0' || iframe.width === '0' || iframe.height === '0' ||
        parseInt(style.width) <= 1 || parseInt(style.height) <= 1) {
        signals.hiddenIframes++;
      }
    });

    // External form actions (submitting data to different domains)
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
      if (form.action) {
        try {
          const formDomain = new URL(form.action, window.location.href).hostname;
          if (formDomain !== window.location.hostname) {
            signals.externalForms++;
          }
        } catch (e) { /* ignore invalid URLs */ }
      }
    });

    // Suspicious patterns
    const domain = window.location.hostname.toLowerCase();

    // Homoglyph detection (e.g., paypa1.com, g00gle.com)
    const knownBrands = ['google', 'paypal', 'amazon', 'apple', 'microsoft', 'facebook', 'instagram', 'netflix', 'bank', 'chase', 'wells', 'citi'];
    knownBrands.forEach(brand => {
      const homoglyphs = domain.replace(/1/g, 'l').replace(/0/g, 'o').replace(/rn/g, 'm');
      if (homoglyphs.includes(brand) && !domain.includes(brand)) {
        signals.suspiciousPatterns.push(`Possible ${brand} impersonation (homoglyph)`);
      }
    });

    // Excessive subdomains
    const subdomainCount = domain.split('.').length - 2;
    if (subdomainCount > 2) {
      signals.suspiciousPatterns.push(`Excessive subdomains (${subdomainCount})`);
    }

    // IP-based URL
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
      signals.suspiciousPatterns.push('IP-based URL (no domain name)');
    }

    // Very long domain
    if (domain.length > 40) {
      signals.suspiciousPatterns.push('Unusually long domain name');
    }

    // Known suspicious TLDs
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.buzz', '.rest'];
    if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
      signals.suspiciousPatterns.push('Suspicious top-level domain');
    }

    // Check for urgent/alarming language (common in phishing)
    const bodyText = document.body.innerText.toLowerCase();
    const urgentPhrases = [
      'your account has been compromised',
      'verify your identity immediately',
      'your account will be suspended',
      'urgent action required',
      'click here to verify',
      'confirm your password',
      'unusual activity detected',
      'your payment was declined',
      'update your payment information immediately'
    ];
    urgentPhrases.forEach(phrase => {
      if (bodyText.includes(phrase)) {
        signals.suspiciousPatterns.push(`Urgent language: "${phrase}"`);
      }
    });

    // Compute phishing score (0-100)
    let score = 0;
    if (!signals.isHTTPS) score += 25;
    if (signals.hiddenIframes > 0) score += 15 * signals.hiddenIframes;
    if (signals.externalForms > 0) score += 15;
    if (signals.suspiciousPatterns.length > 0) score += 10 * signals.suspiciousPatterns.length;
    if (signals.sensitiveInputCount > 3) score += 10;
    if (signals.hasLoginForm && !signals.isHTTPS) score += 20;
    signals.phishingScore = Math.min(score, 100);

    return signals;
  }

  function analyzePageContent() {
    const content = {
      title: document.title,
      metaDescription: '',
      externalScripts: 0,
      totalLinks: 0,
      externalLinks: 0,
      hasGoogleAnalytics: false,
      hasFavicon: false
    };

    // Meta description
    const metaDesc = document.querySelector('meta[name="description"]');
    content.metaDescription = metaDesc ? metaDesc.content : '';

    // Script analysis
    const scripts = document.querySelectorAll('script[src]');
    scripts.forEach(s => {
      try {
        const scriptDomain = new URL(s.src, window.location.href).hostname;
        if (scriptDomain !== window.location.hostname) {
          content.externalScripts++;
        }
        if (s.src.includes('google-analytics') || s.src.includes('gtag') || s.src.includes('googletagmanager')) {
          content.hasGoogleAnalytics = true;
        }
      } catch (e) { /* ignore */ }
    });

    // Link analysis
    const links = document.querySelectorAll('a[href]');
    content.totalLinks = links.length;
    links.forEach(link => {
      try {
        const linkDomain = new URL(link.href, window.location.href).hostname;
        if (linkDomain !== window.location.hostname) {
          content.externalLinks++;
        }
      } catch (e) { /* ignore */ }
    });

    // Favicon
    content.hasFavicon = !!document.querySelector('link[rel*="icon"]');

    return content;
  }

  // ========================================================
  // 3. FULL PAGE SCAN
  // ========================================================

  function performFullScan() {
    return {
      timestamp: Date.now(),
      url: window.location.href,
      domain: window.location.hostname,
      security: analyzeSecuritySignals(),
      transactions: {
        amounts: detectTransactionAmounts(),
        paymentMethods: detectPaymentMethods(),
        paymentForms: detectPaymentForms()
      },
      content: analyzePageContent()
    };
  }

  // ========================================================
  // 4. MESSAGE HANDLER
  // ========================================================

  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'scanPage') {
      try {
        const scanResult = performFullScan();
        sendResponse({ success: true, data: scanResult });
      } catch (error) {
        sendResponse({ success: false, error: error.message });
      }
    }
    return true; // Keep message channel open for async response
  });

  // Auto-scan on load and notify background
  try {
    const autoScan = performFullScan();
    chrome.runtime.sendMessage({
      action: 'autoScanResult',
      data: autoScan
    });
  } catch (e) {
    // Extension context may not be available
  }

})();
