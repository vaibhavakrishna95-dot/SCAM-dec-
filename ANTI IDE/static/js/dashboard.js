/**
 * SCAMSHIELD — Dashboard Interactive Engine
 * Handles message input, category selection, sample loading,
 * API dispatch, radar loading state, dynamic result rendering,
 * and session scan history.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const messageInput = document.getElementById('messageInput');
  const charCount = document.getElementById('charCount');
  const wordCount = document.getElementById('wordCount');
  const categoryPills = document.querySelectorAll('.category-pill');
  const sampleButtons = document.querySelectorAll('.sample-btn');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const clearBtn = document.getElementById('clearBtn');
  const clearHistoryBtn = document.getElementById('clearHistoryBtn');
  const inputErrorFeedback = document.getElementById('inputErrorFeedback');
  const errorMsgText = document.getElementById('errorMsgText');

  // Result Panel States
  const resultsPlaceholder = document.getElementById('resultsPlaceholder');
  const resultsLoading = document.getElementById('resultsLoading');
  const resultsCard = document.getElementById('resultsCard');

  // Result Fields
  const resVerdict = document.getElementById('resVerdict');
  const resRiskBadge = document.getElementById('resRiskBadge');
  const resRiskLevel = document.getElementById('resRiskLevel');
  const resRiskScore = document.getElementById('resRiskScore');
  const resRiskMeterFill = document.getElementById('resRiskMeterFill');
  const resModelProb = document.getElementById('resModelProb');
  const resModelInterpretation = document.getElementById('resModelInterpretation');
  const resFlagsCount = document.getElementById('resFlagsCount');
  const resFlagsList = document.getElementById('resFlagsList');
  const resUrlSection = document.getElementById('resUrlSection');
  const resUrlList = document.getElementById('resUrlList');
  const resExplanation = document.getElementById('resExplanation');
  const resRecommendations = document.getElementById('resRecommendations');
  const historyList = document.getElementById('historyList');

  let currentCategory = 'sms';

  // Representative Sample Messages
  const samples = {
    prize: {
      category: 'sms',
      text: 'URGENT: Congratulations! You have won £1,000,000 cash prize in our international lottery reward draw! Call 09061743811 immediately or visit claim-prize.xyz to claim your reward.'
    },
    otp: {
      category: 'email',
      text: 'Dear customer, your bank account has been suspended due to suspicious activity. Please verify your OTP 849201 immediately and enter your password at http://192.168.1.55/login to restore access.'
    },
    url: {
      category: 'url',
      text: 'Your FedEx delivery parcel #US98214 is on hold due to unpaid customs fee of $2.50. Complete address and payment verification now at http://fedx-customs-verify.top/track'
    },
    job: {
      category: 'other',
      text: 'Work from home part-time opportunity! Earn $400 to $900 per day by liking 5 YouTube videos. No experience required. Daily payout. Contact hiring manager on Telegram @WorkFastNow'
    },
    ham1: {
      category: 'sms',
      text: 'Your Amazon order #402-88219 has been dispatched. Expected delivery by tomorrow 6 PM. Track your package in the official Amazon app.'
    },
    ham2: {
      category: 'other',
      text: 'Hey Sarah, are we still meeting in conference room B at 2 PM to review the quarterly marketing slides? Let me know.'
    }
  };

  // 1. Text Area Input Counter
  function updateCounters() {
    const val = messageInput.value;
    charCount.textContent = val.length;
    const words = val.trim() ? val.trim().split(/\s+/).length : 0;
    wordCount.textContent = words;
  }

  messageInput.addEventListener('input', () => {
    updateCounters();
    hideError();
  });

  // 2. Category Selector
  categoryPills.forEach(pill => {
    pill.addEventListener('click', () => {
      categoryPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentCategory = pill.getAttribute('data-category');
    });
  });

  function setCategory(cat) {
    currentCategory = cat;
    categoryPills.forEach(p => {
      if (p.getAttribute('data-category') === cat) {
        p.classList.add('active');
      } else {
        p.classList.remove('active');
      }
    });
  }

  // 3. Load Samples
  sampleButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const sampleKey = btn.getAttribute('data-sample');
      if (samples[sampleKey]) {
        messageInput.value = samples[sampleKey].text;
        setCategory(samples[sampleKey].category);
        updateCounters();
        hideError();
      }
    });
  });

  // 4. Clear Button
  clearBtn.addEventListener('click', () => {
    messageInput.value = '';
    updateCounters();
    hideError();
    showPlaceholderState();
  });

  // Error messaging
  function showError(msg) {
    errorMsgText.textContent = msg;
    inputErrorFeedback.classList.remove('d-none');
    messageInput.focus();
  }

  function hideError() {
    inputErrorFeedback.classList.add('d-none');
    errorMsgText.textContent = '';
  }

  function showPlaceholderState() {
    resultsPlaceholder.classList.remove('d-none');
    resultsLoading.classList.add('d-none');
    resultsCard.classList.add('d-none');
  }

  function showLoadingState() {
    resultsPlaceholder.classList.add('d-none');
    resultsLoading.classList.remove('d-none');
    resultsCard.classList.add('d-none');
  }

  function showResultsState() {
    resultsPlaceholder.classList.add('d-none');
    resultsLoading.classList.add('d-none');
    resultsCard.classList.remove('d-none');
  }

  // 5. Analyze Action
  analyzeBtn.addEventListener('click', async () => {
    const text = messageInput.value.trim();
    if (!text) {
      showError('Please paste or type a message or URL to analyze.');
      return;
    }

    if (text.length > 15000) {
      showError('Message exceeds maximum limit of 15,000 characters.');
      return;
    }

    hideError();
    showLoadingState();

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          text: text,
          category: currentCategory
        })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Failed to analyze text.');
      }

      // Render Results
      renderAnalysisResult(data);
      saveToSessionHistory(text, data);
      showResultsState();

    } catch (err) {
      console.error('[-] Analysis error:', err);
      showError(err.message || 'Network error occurred while connecting to detection engine.');
      showPlaceholderState();
    }
  });

  // 6. Render Results into UI
  function renderAnalysisResult(res) {
    // Verdict & Risk Level
    resVerdict.textContent = res.verdict;
    resRiskLevel.textContent = `${res.risk_level} Risk`;

    // Reset risk badge classes
    resRiskBadge.className = 'risk-badge';
    resRiskMeterFill.className = 'risk-meter-fill';

    if (res.risk_level === 'High') {
      resRiskBadge.classList.add('risk-badge-high');
      resRiskMeterFill.classList.add('high');
      resRiskBadge.querySelector('i').className = 'bi bi-exclamation-octagon-fill';
    } else if (res.risk_level === 'Medium') {
      resRiskBadge.classList.add('risk-badge-medium');
      resRiskMeterFill.classList.add('medium');
      resRiskBadge.querySelector('i').className = 'bi bi-exclamation-triangle-fill';
    } else {
      resRiskBadge.classList.add('risk-badge-low');
      resRiskMeterFill.classList.add('low');
      resRiskBadge.querySelector('i').className = 'bi bi-shield-check';
    }

    // Score & Meter Fill
    resRiskScore.textContent = `${res.risk_score} / 100`;
    resRiskMeterFill.style.width = `${Math.max(5, res.risk_score)}%`;

    // Model Confidence
    if (res.model_confidence && res.model_confidence.available) {
      const probPct = (res.model_confidence.spam_probability * 100).toFixed(1);
      resModelProb.textContent = `${probPct}%`;
      resModelInterpretation.textContent = res.model_confidence.interpretation;
    } else {
      resModelProb.textContent = 'Heuristic Mode';
      resModelInterpretation.textContent = 'Rule-based threat analysis active.';
    }

    // Warning Flags
    resFlagsCount.textContent = `${res.warning_signs_count} Flag${res.warning_signs_count === 1 ? '' : 's'}`;
    resFlagsList.innerHTML = '';

    if (res.warning_signs && res.warning_signs.length > 0) {
      res.warning_signs.forEach(sign => {
        const item = document.createElement('div');
        item.className = 'p-3 rounded-3';
        const sevClass = sign.severity === 'high' ? 'severity-high' : (sign.severity === 'medium' ? 'severity-medium' : 'severity-low');
        const borderStyle = sign.severity === 'high' ? 'var(--risk-high)' : (sign.severity === 'medium' ? 'var(--risk-medium)' : 'var(--accent-cyan)');

        item.style.background = 'rgba(0,0,0,0.25)';
        item.style.borderLeft = `3px solid ${borderStyle}`;
        item.style.borderTop = '1px solid var(--border-card)';
        item.style.borderRight = '1px solid var(--border-card)';
        item.style.borderBottom = '1px solid var(--border-card)';

        const triggersHtml = sign.triggers && sign.triggers.length > 0
          ? `<div class="mt-2 small text-dim font-mono">Matched: <span class="text-white">${sign.triggers.map(t => `"${t}"`).join(', ')}</span></div>`
          : '';

        item.innerHTML = `
          <div class="d-flex justify-content-between align-items-center mb-1">
            <span class="small fw-bold text-white">${sign.title}</span>
            <span class="severity-tag ${sevClass}">${sign.severity}</span>
          </div>
          <p class="small text-muted mb-0">${sign.description}</p>
          ${triggersHtml}
        `;
        resFlagsList.appendChild(item);
      });
    } else {
      resFlagsList.innerHTML = `
        <div class="p-3 rounded-3 text-center" style="background: rgba(16, 185, 129, 0.05); border: 1px dashed var(--risk-low-border);">
          <span class="small text-success"><i class="bi bi-shield-check me-1"></i> No aggressive threat keywords or high-risk rules triggered.</span>
        </div>
      `;
    }

    // URL Inspection
    if (res.url_inspection && res.url_inspection.has_urls && res.url_inspection.urls_inspected.length > 0) {
      resUrlSection.classList.remove('d-none');
      resUrlList.innerHTML = '';
      res.url_inspection.urls_inspected.forEach(urlObj => {
        const urlItem = document.createElement('div');
        urlItem.className = 'small';
        
        const flagsHtml = urlObj.flags && urlObj.flags.length > 0
          ? urlObj.flags.map(f => `<div class="text-danger small mt-1"><i class="bi bi-exclamation-circle-fill me-1"></i> ${f.detail}</div>`).join('')
          : '<div class="text-success small mt-1"><i class="bi bi-check-circle me-1"></i> No direct IP or known shortener signatures flagged.</div>';

        urlItem.innerHTML = `
          <div class="font-mono text-warning fw-semibold text-break">${urlObj.raw_url}</div>
          <div class="text-dim small">Domain: <strong class="text-white">${urlObj.domain || 'N/A'}</strong></div>
          ${flagsHtml}
        `;
        resUrlList.appendChild(urlItem);
      });
    } else {
      resUrlSection.classList.add('d-none');
      resUrlList.innerHTML = '';
    }

    // Plain Explanation
    resExplanation.textContent = res.explanation;

    // Recommendations
    resRecommendations.innerHTML = '';
    if (res.recommendations && res.recommendations.length > 0) {
      res.recommendations.forEach(rec => {
        const li = document.createElement('li');
        li.className = 'd-flex align-items-start gap-2';
        li.innerHTML = `<i class="bi bi-check-circle-fill text-info mt-1 flex-shrink-0"></i> <span>${rec}</span>`;
        resRecommendations.appendChild(li);
      });
    }
  }

  // 7. Session History (Stored in sessionStorage)
  function getSessionHistory() {
    try {
      const stored = sessionStorage.getItem('scamshield_history');
      return stored ? JSON.parse(stored) : [];
    } catch {
      return [];
    }
  }

  function saveToSessionHistory(rawText, res) {
    try {
      const history = getSessionHistory();
      const newEntry = {
        id: Date.now(),
        text: rawText,
        snippet: rawText.length > 70 ? rawText.substring(0, 70) + '...' : rawText,
        category: res.input_category || 'sms',
        verdict: res.verdict,
        risk_level: res.risk_level,
        risk_score: res.risk_score,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      history.unshift(newEntry);
      // Keep last 15 scans
      sessionStorage.setItem('scamshield_history', JSON.stringify(history.slice(0, 15)));
      renderHistory();
    } catch (err) {
      console.warn('[-] Could not save history to sessionStorage:', err);
    }
  }

  function renderHistory() {
    const history = getSessionHistory();
    if (!history || history.length === 0) {
      historyList.innerHTML = `
        <div class="text-center py-4 text-dim small" id="emptyHistoryMsg">
          <i class="bi bi-inbox fs-3 d-block mb-1 opacity-50"></i>
          No previous scans in this session yet. Your analyzed messages will appear here.
        </div>
      `;
      return;
    }

    historyList.innerHTML = '';
    history.forEach(item => {
      const el = document.createElement('div');
      el.className = 'history-item';
      
      const badgeClass = item.risk_level === 'High' ? 'text-danger border-danger-subtle bg-danger-subtle' : 
                         (item.risk_level === 'Medium' ? 'text-warning border-warning-subtle bg-warning-subtle' : 'text-success border-success-subtle bg-success-subtle');

      el.innerHTML = `
        <div class="d-flex justify-content-between align-items-center mb-1">
          <span class="badge border font-mono small ${badgeClass}">${item.risk_level} Risk</span>
          <span class="text-dim small font-mono">${item.timestamp}</span>
        </div>
        <p class="small text-muted font-mono mb-1 text-truncate">${item.snippet}</p>
        <div class="d-flex justify-content-between align-items-center">
          <span class="small text-dim text-uppercase font-mono">${item.category}</span>
          <span class="small text-info"><i class="bi bi-arrow-repeat me-1"></i>Reload</span>
        </div>
      `;

      el.addEventListener('click', () => {
        messageInput.value = item.text;
        setCategory(item.category);
        updateCounters();
        hideError();
        messageInput.focus();
      });

      historyList.appendChild(el);
    });
  }

  clearHistoryBtn.addEventListener('click', () => {
    sessionStorage.removeItem('scamshield_history');
    renderHistory();
  });

  // Initial history render
  renderHistory();
});
