/**
 * FraudShield Background Service Worker
 * Manages badge updates, scan history, and coordinates between content scripts and popup.
 */

// Session storage for scan history
const scanHistory = new Map();
const MAX_HISTORY = 50;

// Badge color map
const BADGE_COLORS = {
  safe: '#10b981',
  caution: '#f59e0b',
  danger: '#ef4444',
  unknown: '#64748b'
};

/**
 * Compute a trust level from a scan result
 */
function computeTrustLevel(scanData) {
  if (!scanData || !scanData.security) return { level: 'unknown', score: 50 };

  const sec = scanData.security;
  let score = 100;

  // SSL
  if (!sec.isHTTPS) score -= 30;

  // Phishing patterns
  score -= Math.min(sec.phishingScore, 50);

  // Hidden iframes
  score -= sec.hiddenIframes * 10;

  // External forms
  score -= sec.externalForms * 8;

  // Suspicious patterns
  score -= sec.suspiciousPatterns.length * 5;

  // Sensitive inputs on non-HTTPS
  if (!sec.isHTTPS && sec.sensitiveInputCount > 0) score -= 15;

  score = Math.max(0, Math.min(100, score));

  let level = 'safe';
  if (score < 40) level = 'danger';
  else if (score < 70) level = 'caution';

  return { level, score };
}

/**
 * Update the extension badge for a tab
 */
function updateBadge(tabId, trustLevel) {
  const { level, score } = trustLevel;

  chrome.action.setBadgeText({ text: score.toString(), tabId });
  chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS[level] || BADGE_COLORS.unknown, tabId });
}

/**
 * Handle auto-scan results from content scripts
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'autoScanResult' && sender.tab) {
    const tabId = sender.tab.id;
    const scanData = message.data;

    // Store in history
    const domain = scanData.domain || 'unknown';
    scanHistory.set(domain, {
      ...scanData,
      tabId,
      scannedAt: Date.now()
    });

    // Trim history
    if (scanHistory.size > MAX_HISTORY) {
      const oldest = scanHistory.keys().next().value;
      scanHistory.delete(oldest);
    }

    // Update badge
    const trustLevel = computeTrustLevel(scanData);
    updateBadge(tabId, trustLevel);

    // Store for popup access
    chrome.storage.session.set({
      [`scan_${tabId}`]: { scanData, trustLevel }
    }).catch(() => {
      // session storage might not be available
    });
  }

  if (message.action === 'getScanHistory') {
    sendResponse({ history: Object.fromEntries(scanHistory) });
  }

  if (message.action === 'getTabScan') {
    const tabId = message.tabId;
    chrome.storage.session.get([`scan_${tabId}`]).then(result => {
      sendResponse(result[`scan_${tabId}`] || null);
    }).catch(() => {
      sendResponse(null);
    });
    return true;
  }

  return true;
});

// Update badge when tab changes
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const result = await chrome.storage.session.get([`scan_${activeInfo.tabId}`]);
    const data = result[`scan_${activeInfo.tabId}`];
    if (data) {
      updateBadge(activeInfo.tabId, data.trustLevel);
    }
  } catch (e) { /* ignore */ }
});

// Clear scan data when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([`scan_${tabId}`]).catch(() => {});
});
