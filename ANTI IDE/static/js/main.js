/**
 * SCAMSHIELD — Global Main JavaScript
 * Handles global navbar status, tooltips, and API health checks.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Check API health in background
  checkApiHealth();
});

async function checkApiHealth() {
  try {
    const res = await fetch('/api/health');
    if (res.ok) {
      const data = await res.json();
      console.log('[*] ScamShield API Health:', data);
    }
  } catch (err) {
    console.warn('[-] API Health Check failed:', err);
  }
}
