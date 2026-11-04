/**
 * SCAMSHIELD — ML Insights & DBSCAN Visualizer
 * Fetches metrics from /api/metrics and renders interactive 2D DBSCAN
 * scatter plot from /api/dbscan-sample on HTML5 Canvas.
 */

document.addEventListener('DOMContentLoaded', () => {
  loadMetrics();
  initDbscanCanvas();
});

// 1. Fetch & Populate Supervised Evaluation Metrics
async function loadMetrics() {
  try {
    const res = await fetch('/api/metrics');
    if (!res.ok) return;
    const json = await res.json();
    if (!json.success || !json.data) return;

    const data = json.data;
    const nb = data.models['Multinomial Naive Bayes'];
    const lr = data.models['Logistic Regression'];

    if (nb) {
      document.getElementById('nbAcc').textContent = `${(nb.accuracy * 100).toFixed(2)}%`;
      document.getElementById('nbPrec').textContent = `${(nb.precision * 100).toFixed(2)}%`;
      document.getElementById('nbRec').textContent = `${(nb.recall * 100).toFixed(2)}%`;
      document.getElementById('nbF1').textContent = `${(nb.f1 * 100).toFixed(2)}%`;

      if (nb.confusion_matrix) {
        document.getElementById('cmTn').textContent = nb.confusion_matrix.tn;
        document.getElementById('cmFp').textContent = nb.confusion_matrix.fp;
        document.getElementById('cmFn').textContent = nb.confusion_matrix.fn;
        document.getElementById('cmTp').textContent = nb.confusion_matrix.tp;
      }
    }

    if (lr) {
      document.getElementById('lrAcc').textContent = `${(lr.accuracy * 100).toFixed(2)}%`;
      document.getElementById('lrPrec').textContent = `${(lr.precision * 100).toFixed(2)}%`;
      document.getElementById('lrRec').textContent = `${(lr.recall * 100).toFixed(2)}%`;
      document.getElementById('lrF1').textContent = `${(lr.f1 * 100).toFixed(2)}%`;
    }

    if (data.dataset) {
      document.getElementById('statTotalRecs').textContent = `${data.dataset.total_records.toLocaleString()} messages`;
      const hamPct = ((data.dataset.ham_count / data.dataset.total_records) * 100).toFixed(1);
      const spamPct = ((data.dataset.spam_count / data.dataset.total_records) * 100).toFixed(1);
      document.getElementById('statHamCount').textContent = `${data.dataset.ham_count.toLocaleString()} (${hamPct}%)`;
      document.getElementById('statSpamCount').textContent = `${data.dataset.spam_count.toLocaleString()} (${spamPct}%)`;
    }
  } catch (err) {
    console.warn('[-] Failed to load metrics:', err);
  }
}

// 2. Interactive DBSCAN Canvas Visualizer
let rawPoints = [];
let activeFilter = 'all';
let hoveredPoint = null;

function initDbscanCanvas() {
  const canvas = document.getElementById('dbscanCanvas');
  const wrapper = document.getElementById('canvasWrapper');
  const tooltip = document.getElementById('dbscanTooltip');
  const loader = document.getElementById('canvasLoader');
  const filterBtns = document.querySelectorAll('#dbscanFilterGroup button');

  if (!canvas || !wrapper) return;
  const ctx = canvas.getContext('2d');

  function resizeCanvas() {
    const dpr = window.devicePixelRatio || 1;
    const rect = wrapper.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    renderPlot();
  }

  window.addEventListener('resize', resizeCanvas);

  // Filter Buttons
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeFilter = btn.getAttribute('data-filter');
      renderPlot();
    });
  });

  // Color Palette for Clusters
  const clusterColors = {
    '-1': '#f43f5e', // Outlier / Noise (Crimson)
    '0': '#06b6d4',  // Electric Cyan
    '1': '#a855f7',  // Violet
    '2': '#10b981',  // Emerald Green
    '3': '#f59e0b',  // Amber
    '4': '#3b82f6',  // Blue
    '5': '#ec4899'   // Pink
  };

  function getClusterColor(clusterId) {
    const idStr = String(clusterId);
    return clusterColors[idStr] || '#38bdf8';
  }

  // Fetch DBSCAN Sample Data
  fetch('/api/dbscan-sample')
    .then(r => r.json())
    .then(json => {
      if (loader) loader.classList.add('d-none');
      if (!json.success || !json.data) return;

      const data = json.data;
      rawPoints = data.points || [];

      // Update Header Stats
      document.getElementById('statClusters').textContent = data.n_clusters;
      document.getElementById('statNoise').textContent = `${data.n_noise} (${(data.noise_ratio * 100).toFixed(1)}%)`;
      document.getElementById('statSamples').textContent = data.n_samples;

      resizeCanvas();
    })
    .catch(err => {
      if (loader) loader.innerHTML = `<span class="text-danger small">Failed loading cluster data.</span>`;
      console.error('[-] DBSCAN load error:', err);
    });

  // Coordinate Normalization & Projection
  function getRenderablePoints() {
    if (!rawPoints || rawPoints.length === 0) return [];

    let filtered = rawPoints;
    if (activeFilter === 'noise') {
      filtered = rawPoints.filter(p => p.is_noise || p.cluster === -1);
    } else if (activeFilter === 'spam') {
      filtered = rawPoints.filter(p => p.true_label === 'spam');
    } else if (activeFilter === 'ham') {
      filtered = rawPoints.filter(p => p.true_label === 'ham');
    }

    if (filtered.length === 0) return [];

    // Find min and max bounds
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    rawPoints.forEach(p => {
      if (p.x < minX) minX = p.x;
      if (p.x > maxX) maxX = p.x;
      if (p.y < minY) minY = p.y;
      if (p.y > maxY) maxY = p.y;
    });

    const rect = wrapper.getBoundingClientRect();
    const pad = 45;
    const w = rect.width - pad * 2;
    const h = rect.height - pad * 2;

    const spanX = (maxX - minX) || 1;
    const spanY = (maxY - minY) || 1;

    return filtered.map(p => {
      const cx = pad + ((p.x - minX) / spanX) * w;
      const cy = rect.height - (pad + ((p.y - minY) / spanY) * h); // invert Y
      return { ...p, cx, cy };
    });
  }

  // Render Canvas
  function renderPlot() {
    const rect = wrapper.getBoundingClientRect();
    ctx.clearRect(0, 0, rect.width, rect.height);

    // Draw grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
    ctx.lineWidth = 1;
    const gridStep = 50;
    for (let x = 0; x < rect.width; x += gridStep) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, rect.height);
      ctx.stroke();
    }
    for (let y = 0; y < rect.height; y += gridStep) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(rect.width, y);
      ctx.stroke();
    }

    const points = getRenderablePoints();

    // Draw Points
    points.forEach(p => {
      const isNoise = p.cluster === -1;
      const color = getClusterColor(p.cluster);

      ctx.beginPath();
      if (isNoise) {
        // Draw Outlier as Distinct Hex / Cross
        ctx.arc(p.cx, p.cy, 5, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.strokeStyle = '#fff';
        ctx.lineWidth = 1;
        ctx.stroke();
      } else {
        // Regular Cluster Point
        ctx.arc(p.cx, p.cy, 3.8, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
      }
    });

    // Highlight hovered point
    if (hoveredPoint) {
      ctx.beginPath();
      ctx.arc(hoveredPoint.cx, hoveredPoint.cy, 9, 0, Math.PI * 2);
      ctx.strokeStyle = '#38bdf8';
      ctx.lineWidth = 2;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(hoveredPoint.cx, hoveredPoint.cy, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#fff';
      ctx.fill();
    }
  }

  // Mouse Interactivity (Hover Tooltip)
  canvas.addEventListener('mousemove', e => {
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    const points = getRenderablePoints();
    let closest = null;
    let minDist = 12; // threshold in pixels

    points.forEach(p => {
      const dist = Math.hypot(p.cx - mouseX, p.cy - mouseY);
      if (dist < minDist) {
        minDist = dist;
        closest = p;
      }
    });

    if (closest) {
      hoveredPoint = closest;
      renderPlot();

      const isNoise = closest.cluster === -1;
      const clusterBadge = isNoise
        ? `<span class="badge bg-danger-subtle text-danger border border-danger-subtle font-mono">Noise / Anomaly (-1)</span>`
        : `<span class="badge bg-info-subtle text-info border border-info-subtle font-mono">Cluster #${closest.cluster}</span>`;

      const labelBadge = closest.true_label === 'spam'
        ? `<span class="badge bg-warning-subtle text-warning border border-warning-subtle font-mono">True: SPAM</span>`
        : `<span class="badge bg-success-subtle text-success border border-success-subtle font-mono">True: HAM</span>`;

      tooltip.innerHTML = `
        <div class="d-flex justify-content-between align-items-center gap-2 mb-2">
          ${clusterBadge}
          ${labelBadge}
        </div>
        <p class="small text-muted font-mono mb-1" style="line-height:1.4;">"${closest.snippet}"</p>
        <div class="text-dim small font-mono" style="font-size:0.7rem;">SVD Coordinates: (${closest.x}, ${closest.y})</div>
      `;

      // Position Tooltip
      tooltip.style.display = 'block';
      let tooltipX = mouseX + 15;
      let tooltipY = mouseY - 15;

      if (tooltipX + 280 > rect.width) {
        tooltipX = mouseX - 290;
      }
      if (tooltipY + 120 > rect.height) {
        tooltipY = mouseY - 110;
      }

      tooltip.style.left = `${tooltipX}px`;
      tooltip.style.top = `${tooltipY}px`;

    } else {
      if (hoveredPoint) {
        hoveredPoint = null;
        renderPlot();
      }
      tooltip.style.display = 'none';
    }
  });

  canvas.addEventListener('mouseleave', () => {
    hoveredPoint = null;
    renderPlot();
    tooltip.style.display = 'none';
  });
}
