/**
 * TraceZ — Options Page Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  const apiUrl = document.getElementById('apiUrl');
  const notificationsToggle = document.getElementById('notificationsToggle');
  const lastSynced = document.getElementById('lastSynced');
  const syncBtn = document.getElementById('syncBtn');
  const syncStatus = document.getElementById('syncStatus');
  const trustedList = document.getElementById('trustedList');
  const trustedInput = document.getElementById('trustedInput');
  const addTrustedBtn = document.getElementById('addTrustedBtn');
  const saveBtn = document.getElementById('saveBtn');
  const saveStatus = document.getElementById('saveStatus');

  // Load current settings
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'getSettings' });
    if (resp && resp.settings) {
      const s = resp.settings;
      apiUrl.value = s.apiUrl || 'http://localhost:8000';
      notificationsToggle.checked = s.notifications !== false;
      const levelRadio = document.querySelector(`input[name="level"][value="${s.level || 'balanced'}"]`);
      if (levelRadio) levelRadio.checked = true;
    }
  } catch (e) { /* defaults */ }

  // Load trusted sites
  try {
    const data = await chrome.storage.local.get(['tracez_trusted']);
    if (data.tracez_trusted) {
      const trusted = JSON.parse(data.tracez_trusted);
      renderTrustedList(trusted);
    }
  } catch (e) { /* empty */ }

  // Load last synced
  try {
    const data = await chrome.storage.local.get(['tracez_last_synced']);
    if (data.tracez_last_synced) {
      lastSynced.textContent = new Date(data.tracez_last_synced).toLocaleString();
    }
  } catch (e) { /* never */ }

  // Save button
  saveBtn.addEventListener('click', async () => {
    const level = document.querySelector('input[name="level"]:checked')?.value || 'balanced';
    const settings = {
      enabled: true,
      apiUrl: apiUrl.value.trim() || 'http://localhost:8000',
      level,
      notifications: notificationsToggle.checked,
    };

    try {
      await chrome.runtime.sendMessage({ type: 'updateSettings', settings });
      saveStatus.textContent = '✓ Settings saved';
      saveStatus.style.color = '#10B981';
      setTimeout(() => { saveStatus.textContent = ''; }, 3000);
    } catch (e) {
      saveStatus.textContent = '✗ Failed to save';
      saveStatus.style.color = '#EF4444';
    }
  });

  // Sync button
  syncBtn.addEventListener('click', async () => {
    syncStatus.textContent = 'Syncing...';
    syncStatus.style.color = '#6B7280';
    try {
      const resp = await chrome.runtime.sendMessage({ type: 'forceSyncBlocklist' });
      if (resp && resp.success) {
        syncStatus.textContent = '✓ Synced successfully';
        syncStatus.style.color = '#10B981';
        lastSynced.textContent = new Date().toLocaleString();
      } else {
        syncStatus.textContent = '✗ Sync failed — is the backend running?';
        syncStatus.style.color = '#EF4444';
      }
    } catch (e) {
      syncStatus.textContent = '✗ Sync failed';
      syncStatus.style.color = '#EF4444';
    }
    setTimeout(() => { syncStatus.textContent = ''; }, 5000);
  });

  // Add trusted site
  addTrustedBtn.addEventListener('click', async () => {
    const domain = trustedInput.value.trim().toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/.*$/, '');
    if (!domain) return;

    try {
      await chrome.runtime.sendMessage({ type: 'trustSite', domain });
      trustedInput.value = '';

      // Reload list
      const data = await chrome.storage.local.get(['tracez_trusted']);
      if (data.tracez_trusted) {
        renderTrustedList(JSON.parse(data.tracez_trusted));
      }
    } catch (e) { /* silent */ }
  });

  function renderTrustedList(domains) {
    trustedList.textContent = '';
    if (domains.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'No trusted sites yet';
      trustedList.appendChild(empty);
      return;
    }

    for (const domain of domains) {
      const item = document.createElement('div');
      item.className = 'trusted-item';

      const name = document.createElement('span');
      name.textContent = domain;

      const removeBtn = document.createElement('button');
      removeBtn.className = 'trusted-remove';
      removeBtn.textContent = '✕';
      removeBtn.addEventListener('click', async () => {
        // Remove from storage
        const data = await chrome.storage.local.get(['tracez_trusted']);
        let list = data.tracez_trusted ? JSON.parse(data.tracez_trusted) : [];
        list = list.filter(d => d !== domain);
        await chrome.storage.local.set({ tracez_trusted: JSON.stringify(list) });
        renderTrustedList(list);
      });

      item.appendChild(name);
      item.appendChild(removeBtn);
      trustedList.appendChild(item);
    }
  }
});
