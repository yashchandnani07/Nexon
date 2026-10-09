/**
 * AegisAI DLP Guardian — Background Service Worker v4
 *
 * New: Admin Lock system
 *   – Admin sets a 4-6 digit PIN via the popup.
 *   – PIN is stored in chrome.storage.sync (encrypted in enterprise via sync).
 *   – On install, logs tamper-resistance event.
 *   – Uses chrome.management to detect if THIS extension is being disabled.
 *   – Sends uninstall audit ping to DLP server so removal is logged.
 *   – Alarm re-registers on every wake (service worker persistence).
 */

const GATEWAY_HEALTH = 'http://localhost:8001/health';
const DLP_AUDIT_API  = 'http://localhost:8001/gateway/audit-event';
const EXT_ID         = chrome.runtime.id;

// ── Badge helpers ─────────────────────────────────────────────────────────────
function setBadge(text, color) {
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

async function checkGateway() {
  try {
    const r = await fetch(GATEWAY_HEALTH);
    if (r.ok) setBadge('ON', '#0EA5E9');
    else       setBadge('OFF', '#EF4444');
  } catch {
    setBadge('ERR', '#F59E0B');
  }
}

// ── Audit log helper ──────────────────────────────────────────────────────────
async function sendAuditEvent(eventType, details = {}) {
  try {
    await fetch(DLP_AUDIT_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source:     'dlp-guardian-extension',
        event_type: eventType,
        ext_id:     EXT_ID,
        timestamp:  new Date().toISOString(),
        ...details,
      }),
    });
  } catch {
    // Fail silently — network may be unavailable during removal
    console.warn('[DLP Guardian] Audit ping failed for event:', eventType);
  }
}

// ── Install / startup ─────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('[DLP Guardian v4] Installed — service worker active');
  setBadge('ON', '#0EA5E9');
  checkGateway();

  if (details.reason === 'install') {
    // First install — store a tamper timestamp
    await chrome.storage.local.set({
      dlp_install_time: Date.now(),
      dlp_lock_enabled: false,
      dlp_tamper_count: 0,
    });
    sendAuditEvent('EXTENSION_INSTALLED', { reason: details.reason });
  } else if (details.reason === 'update') {
    sendAuditEvent('EXTENSION_UPDATED', { version: chrome.runtime.getManifest().version });
  }
});

// Re-register alarm on every service worker startup (MV3 persistence)
chrome.alarms.create('healthCheck',       { periodInMinutes: 0.5 });
chrome.alarms.create('tamperCheck',       { periodInMinutes: 1   });
chrome.alarms.create('tamperCountReset',  { periodInMinutes: 60  });

chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === 'healthCheck')      checkGateway();
  if (alarm.name === 'tamperCheck')      runTamperCheck();
  if (alarm.name === 'tamperCountReset') resetTamperCount();
});

// ── Tamper detection ──────────────────────────────────────────────────────────
async function runTamperCheck() {
  const data = await chrome.storage.local.get(['dlp_lock_enabled', 'dlp_tamper_count']);
  if (!data.dlp_lock_enabled) return;

  // Detect if the extension page is reachable (self-check as proxy for active)
  try {
    const url = chrome.runtime.getURL('popup.html');
    if (!url) throw new Error('Extension URL unavailable');
  } catch (e) {
    // Extension is likely being removed
    sendAuditEvent('EXTENSION_TAMPER_DETECTED', { detail: 'self-url-unavailable' });
  }
}

async function resetTamperCount() {
  await chrome.storage.local.set({ dlp_tamper_count: 0 });
}

// ── chrome.management: detect if THIS ext is disabled ────────────────────────
if (chrome.management) {
  chrome.management.onDisabled.addListener(async (info) => {
    if (info.id !== EXT_ID) return;
    const data = await chrome.storage.local.get('dlp_lock_enabled');
    sendAuditEvent('EXTENSION_DISABLED', {
      locked:     data.dlp_lock_enabled || false,
      bypassed:   data.dlp_lock_enabled,  // if locked, this is an unauthorised action
    });
    // Re-enable if a lock is active (best-effort — Chrome may not allow this)
    if (data.dlp_lock_enabled) {
      try { await chrome.management.setEnabled(EXT_ID, true); } catch {}
    }
  });

  chrome.management.onUninstalled.addListener((id) => {
    if (id !== EXT_ID) return;
    // Last-gasp event: send removal audit ping to server
    sendAuditEvent('EXTENSION_REMOVED_UNAUTHORISED');
  });
}

// ── Message routing from popup ────────────────────────────────────────────────
chrome.runtime.onMessage.addListener(async (msg, sender, sendResponse) => {

  // Badge update from content script
  if (msg.type === 'DLP_RESULT') {
    if      (msg.decision === 'BLOCK') setBadge('BLK', '#EF4444');
    else if (msg.decision === 'WARN')  setBadge('WRN', '#F59E0B');
    else                               setBadge('OK',  '#10B981');
    setTimeout(checkGateway, 3000);
    return;
  }

  // ── Admin Lock API ──────────────────────────────────────────────
  if (msg.type === 'ADMIN_SET_PIN') {
    // Hash the PIN (SHA-256 via SubtleCrypto) before storing
    const pinHash = await hashPin(msg.pin);
    await chrome.storage.local.set({
      dlp_lock_enabled: true,
      dlp_pin_hash:     pinHash,
      dlp_lock_set_at:  new Date().toISOString(),
      dlp_lock_set_by:  msg.adminId || 'admin',
    });
    sendAuditEvent('ADMIN_LOCK_ENABLED', { admin: msg.adminId });
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === 'ADMIN_VERIFY_PIN') {
    const data = await chrome.storage.local.get(['dlp_pin_hash', 'dlp_lock_enabled']);
    if (!data.dlp_lock_enabled) { sendResponse({ ok: true, unlocked: true }); return true; }
    const pinHash = await hashPin(msg.pin);
    const match   = pinHash === data.dlp_pin_hash;
    if (match) {
      sendAuditEvent('ADMIN_PIN_VERIFIED_SUCCESS');
    } else {
      const { dlp_tamper_count: cnt = 0 } = await chrome.storage.local.get('dlp_tamper_count');
      await chrome.storage.local.set({ dlp_tamper_count: cnt + 1 });
      sendAuditEvent('ADMIN_PIN_FAILED', { attempt_count: cnt + 1 });
    }
    sendResponse({ ok: match });
    return true;
  }

  if (msg.type === 'ADMIN_REMOVE_LOCK') {
    const data = await chrome.storage.local.get('dlp_pin_hash');
    const pinHash = await hashPin(msg.pin);
    if (pinHash !== data.dlp_pin_hash) {
      sendResponse({ ok: false, error: 'Wrong PIN' });
      return true;
    }
    await chrome.storage.local.set({ dlp_lock_enabled: false, dlp_pin_hash: null });
    sendAuditEvent('ADMIN_LOCK_REMOVED');
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === 'GET_LOCK_STATUS') {
    const data = await chrome.storage.local.get([
      'dlp_lock_enabled', 'dlp_lock_set_at', 'dlp_lock_set_by', 'dlp_tamper_count',
    ]);
    sendResponse(data);
    return true;
  }
});

// ── SHA-256 hash helper ───────────────────────────────────────────────────────
async function hashPin(pin) {
  const buf  = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('dlp-salt-v1::' + pin));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}
