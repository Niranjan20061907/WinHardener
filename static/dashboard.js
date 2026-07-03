/* CIS Hardening Dashboard — UI interactions */

(function () {
  'use strict';

  /* ── Gauge animation ─────────────────────────────────── */

  function initGauge() {
    const fill = document.querySelector('.gauge-fill');
    if (!fill) return;

    const score = parseFloat(fill.dataset.score || 0);
    const circumference = 314; // 2π × r(50)

    // Start at empty, animate to score after paint
    fill.style.strokeDashoffset = circumference;

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        const offset = circumference - (score / 100) * circumference;
        fill.style.strokeDashoffset = offset;
      });
    });
  }

  /* ── Edit dialogs ─────────────────────────────────────── */

  function openEditDrawer(id) {
    const drawer = document.getElementById(id);
    if (!drawer) return;
    document.querySelectorAll('.edit-drawer[open]').forEach(openDrawer => {
      if (openDrawer !== drawer) openDrawer.close();
    });
    drawer.show();
    drawer.classList.add('is-open');
  }

  function closeEditDrawer(drawer) {
    if (!drawer) return;
    drawer.classList.remove('is-open');
    drawer.close();
  }

  function initEditButtons() {
    document.querySelectorAll('.edit-btn').forEach(btn => {
      btn.addEventListener('click', event => {
        event.stopPropagation();
        openEditDrawer(btn.dataset.modal);
      });
    });

    document.querySelectorAll('.policy-row[data-modal]').forEach(row => {
      row.addEventListener('click', event => {
        if (event.target.closest('button, a, input, select, label')) return;
        openEditDrawer(row.dataset.modal);
      });
      row.addEventListener('keydown', event => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        openEditDrawer(row.dataset.modal);
      });
    });

    document.querySelectorAll('.close-dialog-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        closeEditDrawer(btn.closest('dialog'));
      });
    });

    document.querySelectorAll('.edit-dialog').forEach(dialog => {
      dialog.addEventListener('cancel', e => {
        e.preventDefault();
        closeEditDrawer(dialog);
      });
    });
  }

  /* ── Confirm dialog ───────────────────────────────────── */

  const confirmDialog = document.getElementById('confirm-dialog');
  const confirmTitle  = document.getElementById('confirm-title');
  const confirmBody   = document.getElementById('confirm-body');
  const confirmOk     = document.getElementById('confirm-ok');
  const confirmCancel = document.getElementById('confirm-cancel');

  let pendingSubmit = null;

  function showConfirm(message, onConfirm) {
    if (!confirmDialog) { onConfirm(); return; }
    confirmBody.textContent = message;
    confirmDialog.showModal();
    pendingSubmit = onConfirm;
  }

  if (confirmCancel) {
    confirmCancel.addEventListener('click', () => {
      confirmDialog.close();
      pendingSubmit = null;
    });
  }

  if (confirmOk) {
    confirmOk.addEventListener('click', () => {
      confirmDialog.close();
      if (pendingSubmit) { pendingSubmit(); pendingSubmit = null; }
    });
  }

  if (confirmDialog) {
    confirmDialog.addEventListener('click', e => {
      if (e.target === confirmDialog) {
        confirmDialog.close();
        pendingSubmit = null;
      }
    });
  }

  /* ── Operation forms: loading + confirm ───────────────── */

  const overlay     = document.getElementById('loading-overlay');
  const loadingText = document.getElementById('loading-text');

  function setLoading(submitter, message) {
    if (submitter) {
      submitter.disabled = true;
      submitter.classList.add('is-loading');
    }
    if (overlay) {
      if (loadingText && message) loadingText.textContent = message;
      overlay.classList.add('visible');
    }
  }

  function getLoadingMessage(form) {
    const action = form.action || '';
    if (action.includes('reset-all') || action.includes('reset_all')) return 'Restoring default configuration…';
    if (action.includes('reset'))   return 'Resetting policy to default…';
    if (action.includes('apply'))   return 'Applying security configuration…';
    if (action.includes('customize')) return 'Saving custom value…';
    if (action.includes('login'))   return 'Signing in…';
    return 'Processing…';
  }

  document.querySelectorAll('.operation-form').forEach(form => {
    form.addEventListener('submit', e => {
      if (e.defaultPrevented) return;
      if (!form.checkValidity()) return;

      const submitter = e.submitter;
      const confirmMsg = submitter && submitter.dataset.confirm;

      if (confirmMsg) {
        e.preventDefault();
        showConfirm(confirmMsg, () => {
          setLoading(submitter, getLoadingMessage(form));
          form.submit();
        });
        return;
      }

      setLoading(submitter, getLoadingMessage(form));
    });
  });

  /* ── Toast auto-dismiss ───────────────────────────────── */

  function initToasts() {
    document.querySelectorAll('.toast-close').forEach(btn => {
      btn.addEventListener('click', () => {
        const toast = btn.closest('.toast');
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.2s';
        setTimeout(() => toast.remove(), 200);
      });
    });

    // Auto-dismiss after 6s
    document.querySelectorAll('.toast').forEach((toast, i) => {
      setTimeout(() => {
        if (!document.contains(toast)) return;
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.4s';
        setTimeout(() => toast.remove(), 400);
      }, 5000 + i * 300);
    });
  }

  /* ── Sidebar smooth scroll for anchor links ───────────── */

  function initSidebarLinks() {
    document.querySelectorAll('.sidebar-link[href^="#"]').forEach(link => {
      link.addEventListener('click', e => {
        e.preventDefault();
        const target = document.getElementById(link.getAttribute('href').slice(1));
        if (target) {
          target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      });
    });
  }

  /* ── Init ─────────────────────────────────────────────── */

  initGauge();
  initEditButtons();
  initToasts();
  initSidebarLinks();

})();
