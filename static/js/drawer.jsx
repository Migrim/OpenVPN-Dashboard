// Peer detail drawer + logs panel + port check + data budget

const { useState: _useState, useEffect: _useEffect, useRef: _useRef, useMemo: _useMemo } = React;

// ============================================================
// PingBars — thin bar chart with Y-axis, newest bar on the left
// ============================================================
function PingBars({ data, height = 68, color = 'var(--accent-2)', labels }) {
  const containerRef = _useRef(null);
  const [cw, setCw] = _useState(500);
  const [hover, setHover] = _useState(null); // { i, y }

  _useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    setCw(Math.round(el.getBoundingClientRect().width) || 500);
    const ro = new ResizeObserver(entries => {
      const w = entries[0]?.contentRect.width;
      if (w > 0) setCw(Math.round(w));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const PL = 40, PR = 8, PT = 8, PB = 14;
  const iw = cw - PL - PR;
  const ih = height - PT - PB;
  const n = data.length;

  const maxRaw = Math.max(...data, 10);
  const mag = Math.pow(10, Math.floor(Math.log10(maxRaw)));
  const norm = maxRaw / mag;
  const niceMax = norm <= 1 ? mag : norm <= 2 ? 2 * mag : norm <= 5 ? 5 * mag : 10 * mag;

  const ticks = [0, Math.round(niceMax / 2), niceMax];
  const yAt = v => PT + ih - (v / niceMax) * ih;
  const gap = 2;
  const barW = Math.max(2, (iw - gap * (n - 1)) / n);
  const fmt = v => v === 0 ? '0' : v >= 1000 ? `${(v / 1000).toFixed(v % 1000 === 0 ? 0 : 1)}s` : `${v}ms`;
  const fmtExact = v => v == null || v <= 0 ? 'no data'
    : v >= 1000 ? `${(v / 1000).toFixed(2)} s`
    : `${v >= 100 ? Math.round(v) : Number(v.toFixed(1))} ms`;

  const barX = i => PL + i * (barW + gap);

  const onMove = (e) => {
    const el = containerRef.current;
    if (!el || n === 0) return;
    const rect = el.getBoundingClientRect();
    const x = e.clientX - rect.left;
    if (x < PL || x > cw - PR) { setHover(null); return; }
    const i = Math.min(n - 1, Math.max(0, Math.floor((x - PL) / (barW + gap))));
    setHover({ i, y: e.clientY - rect.top });
  };

  return (
    <div
      ref={containerRef}
      style={{ width: '100%', position: 'relative', cursor: 'crosshair' }}
      onMouseMove={onMove}
      onMouseLeave={() => setHover(null)}
    >
      <svg viewBox={`0 0 ${cw} ${height}`} preserveAspectRatio="none" style={{ width: '100%', height, display: 'block' }}>
        {ticks.map((t, i) => {
          const y = yAt(t);
          return (
            <g key={i}>
              <line x1={PL} x2={cw - PR} y1={y} y2={y} stroke="var(--border)" strokeWidth="1"
                strokeDasharray={t === 0 ? '' : '2 3'} opacity="0.6" />
              <text x={PL - 5} y={y + 3.5} textAnchor="end" fontSize="9" fill="var(--muted)" fontFamily="var(--mono)">{fmt(t)}</text>
            </g>
          );
        })}
        {hover && (
          <rect x={barX(hover.i) - gap / 2} y={PT} width={barW + gap} height={ih}
            fill="var(--ink)" opacity="0.07" rx="2" />
        )}
        {data.map((v, i) => {
          const x = barX(i);
          const bh = (v / niceMax) * ih;
          return <rect key={i} x={x} y={yAt(v)} width={barW} height={bh}
            fill={color} opacity={hover && hover.i === i ? 1 : 0.2 + 0.8 * (i / Math.max(n - 1, 1))} rx="1" />;
        })}
      </svg>
      {hover && (
        <div
          className="pingbar-tip"
          style={{
            left: Math.max(PL + 20, Math.min(cw - PR - 20, barX(hover.i) + barW / 2)),
            top: Math.max(14, hover.y - 12),
          }}
        >
          <span className="pingbar-tip-val">{fmtExact(data[hover.i])}</span>
          {labels && labels[hover.i] != null && <span className="pingbar-tip-lbl">{labels[hover.i]}</span>}
        </div>
      )}
    </div>
  );
}

// ============================================================
// DnsActivity — opt-in "top visited domains (24h)" tab body
// ============================================================
function DnsActivity({ peer, onPeerUpdated }) {
  const [data, setData] = _useState(null);
  const [loading, setLoading] = _useState(true);
  const [busy, setBusy] = _useState(false);
  const enabled = data ? !!data.enabled : !!peer.monitorDns;

  const load = async () => {
    try {
      const r = await window.WG.apiCall('/api/users/' + encodeURIComponent(peer.name) + '/dns', { silent: true });
      setData(r);
    } catch (_) {
      // leave previous data in place on a transient error
    } finally {
      setLoading(false);
    }
  };

  _useEffect(() => {
    let cancelled = false;
    setLoading(true);
    const tick = async () => { if (!cancelled) await load(); };
    tick();
    const id = setInterval(tick, 10000);
    return () => { cancelled = true; clearInterval(id); };
  }, [peer && peer.name]);

  const toggle = async () => {
    const next = !enabled;
    setBusy(true);
    const t = window.WG.toast?.loading?.(next ? 'Enabling domain monitoring…' : 'Disabling…');
    try {
      await window.WG.apiCall('/api/users/' + encodeURIComponent(peer.name) + '/settings', {
        silent: true, method: 'PATCH', body: JSON.stringify({ monitor_dns: next }),
      });
      setData(d => ({ ...(d || {}), enabled: next, domains: next ? (d?.domains || []) : [], total: next ? (d?.total || 0) : 0, unique: next ? (d?.unique || 0) : 0 }));
      if (onPeerUpdated) onPeerUpdated();
      t?.success?.(next ? 'Monitoring on' : 'Monitoring off',
        next ? `Now recording domains for "${peer.name}"` : `Cleared captured history for "${peer.name}"`);
      load();
    } catch (e) {
      t?.error?.('Could not update', e.message || 'API error');
    } finally {
      setBusy(false);
    }
  };

  const domains = (data && data.domains) || [];
  const maxCount = domains.reduce((m, d) => Math.max(m, d.count), 0) || 1;
  const capturing = data && data.capturing;
  const unavailable = data && data.available === false;
  const err = data && data.error;

  return (
    <>
      <section className="drawer-section">
        <div className="setting-row" style={{ borderTop: 'none', paddingTop: 0 }}>
          <div>
            <div className="setting-label">Monitor visited domains</div>
            <div className="setting-desc">
              Records the top domains this peer looks up, kept for {(data && data.retention_hours) || 24}h.
            </div>
          </div>
          <div className="setting-control">
            <button className={`toggle ${enabled ? 'on' : ''}`} onClick={toggle} disabled={busy || unavailable} aria-pressed={enabled}>
              <span className="toggle-knob" />
            </button>
          </div>
        </div>
        <div className="dns-privacy">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3l7 4v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V7l7-4z"/></svg>
          <span>
            Only <strong>domain names</strong> are visible from the server (via DNS) — full page URLs are
            encrypted by HTTPS and are never captured. This is browsing activity for whoever uses this peer.
          </span>
        </div>
      </section>

      {unavailable && (
        <section className="drawer-section">
          <div className="dns-note dns-note-warn">
            <code>tcpdump</code> is not installed on the server, so monitoring can't run. Install it with
            {' '}<code>apt install tcpdump</code> and reload the dashboard.
          </div>
        </section>
      )}

      {enabled && !unavailable && (
        <section className="drawer-section">
          <div className="section-head">
            <span className="section-label">TOP DOMAINS · LAST {(data && data.retention_hours) || 24}H</span>
            <span className="section-meta">
              <span className={`dns-dot ${capturing ? 'on' : ''}`} />
              {capturing ? 'capturing' : 'idle'}
            </span>
          </div>

          {err ? (
            <div className="dns-note dns-note-warn" style={{ marginBottom: 10 }}>{err}</div>
          ) : null}

          {domains.length > 0 ? (
            <>
              <div className="dns-summary">
                <span><strong>{data.total.toLocaleString()}</strong> lookups</span>
                <span><strong>{data.unique.toLocaleString()}</strong> unique domains</span>
              </div>
              <ol className="dns-list">
                {domains.map((d, i) => (
                  <li key={d.domain} className="dns-item">
                    <span className="dns-rank">{i + 1}</span>
                    <span className="dns-name" title={d.domain}>{d.domain}</span>
                    <span className="dns-bar-wrap">
                      <span className="dns-bar" style={{ width: `${Math.max(4, (d.count / maxCount) * 100)}%` }} />
                    </span>
                    <span className="dns-count">{d.count.toLocaleString()}</span>
                  </li>
                ))}
              </ol>
            </>
          ) : loading ? (
            <div aria-hidden="true">
              <div className="dns-summary">
                <span className="skel" style={{ width: 88 }} />
                <span className="skel" style={{ width: 118 }} />
              </div>
              <ol className="dns-list">
                {[0, 1, 2, 3, 4].map(i => (
                  <li key={i} className="dns-item">
                    <span className="dns-rank"><span className="skel" style={{ width: 12, height: 9 }} /></span>
                    <span className="dns-name"><span className="skel" style={{ width: `${76 - ((i * 23) % 42)}%` }} /></span>
                    <span className="dns-bar-wrap"><span className="skel" style={{ display: 'block', width: `${Math.max(10, 85 - i * 17)}%`, height: 6, borderRadius: 99 }} /></span>
                    <span className="dns-count"><span className="skel" style={{ width: 26, height: 9 }} /></span>
                  </li>
                ))}
              </ol>
            </div>
          ) : (
            <div className="empty-chart" style={{ height: 90 }}>
              No DNS queries captured yet — activity appears once this peer browses.
            </div>
          )}
        </section>
      )}

      {!enabled && !unavailable && (
        <section className="drawer-section">
          <div className="empty-chart" style={{ height: 90, lineHeight: 1.5, padding: '0 16px', textAlign: 'center' }}>
            Monitoring is off. Turn on the toggle above to start recording the most visited domains for this peer.
          </div>
        </section>
      )}
    </>
  );
}

// ============================================================
// PeerQrModal — scannable provisioning QR for the live config
// ============================================================
function PeerQrModal({ peer, onClose }) {
  const [qr, setQr] = _useState({ loading: true, url: '', error: '' });
  const [shown, setShown] = _useState(false); // set once the QR image has decoded
  const closeRef = _useRef(null);

  _useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    closeRef.current?.focus({ preventScroll: true });
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  _useEffect(() => {
    let cancelled = false;
    setQr({ loading: true, url: '', error: '' });
    setShown(false);
    (async () => {
      try {
        const profile = await window.WG.fetchPeerConfig(peer.name);
        if (cancelled) return;
        // level L keeps the module count low enough to stay scannable at 240px
        const url = new window.QRious({ value: profile, size: 240, level: 'L' }).toDataURL();
        setQr({ loading: false, url, error: '' });
      } catch (e) {
        if (!cancelled) setQr({ loading: false, url: '', error: e.message || 'Could not build the config' });
      }
    })();
    return () => { cancelled = true; };
  }, [peer.name]);

  // A portal still bubbles events up the React tree, so clicks must be contained
  // or the peer row hosting this modal treats them as "open the drawer".
  const contain = (e) => e.stopPropagation();

  return ReactDOM.createPortal(
    <>
      <div className="qr-modal-scrim" onClick={(e) => { contain(e); onClose(); }} />
      <div className="qr-modal" role="dialog" aria-modal="true" aria-label={`Provisioning QR code for ${peer.name}`}
        onClick={contain} onContextMenu={(e) => { e.preventDefault(); contain(e); }}>
        <header className="qr-modal-head">
          <div>
            <div className="qr-modal-title">Provision a device</div>
            <div className="qr-modal-sub mono">{peer.name}</div>
          </div>
          <button ref={closeRef} className="icon-btn-sm" onClick={onClose} aria-label="Close">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M18 6L6 18M6 6l12 12"/></svg>
          </button>
        </header>
        <div className="qr-modal-body">
          <div className="qr-modal-stage">
            {qr.error ? (
              <div className="qr-modal-err">{qr.error}</div>
            ) : (
              <>
                <div className={`skel qr-modal-skel${shown ? ' is-gone' : ''}`} aria-hidden="true" />
                {/* 260 = 240px QR + the 10px padding ap-qr-img adds on each side (border-box) */}
                {qr.url && (
                  <img
                    src={qr.url}
                    width={260}
                    height={260}
                    alt={`WireGuard config QR code for ${peer.name}`}
                    className={`ap-qr-img qr-modal-img${shown ? ' is-shown' : ''}`}
                    onLoad={() => setShown(true)}
                  />
                )}
              </>
            )}
          </div>
          <div className="qr-modal-cap">Scan in the WireGuard app to import this tunnel</div>
          <div className="qr-modal-note">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" aria-hidden="true"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/></svg>
            Contains the private key
          </div>
        </div>
      </div>
    </>,
    document.body
  );
}

// ============================================================
// PeerDrawer — slide-out detail with charts + controls
// ============================================================
function PeerDrawer({ peer, onClose, throughputBuffers, peerPingHistory = {}, onRevoke, onPeerUpdated, tweaks = {} }) {
  const [qrOpen, setQrOpen] = _useState(false);
  const [copied, setCopied] = _useState('');
  const [downloading, setDownloading] = _useState(false);
  const [revoking, setRevoking] = _useState(false);
  const [pendingAction, setPendingAction] = _useState(null); // 'pause' | 'resume' | null
  const [tab, setTab] = _useState('overview');
  const [settingsDirty, setSettingsDirty] = _useState(() => {
    try { return !!localStorage.getItem('WG_PEER_DRAFT_' + peer?.name); } catch { return false; }
  });
  const [diag, setDiag] = _useState({ loading: true, pingMs: null, pingStatus: '', location: null, endpointIp: '', pingIp: '' });
  const pingHistory = peerPingHistory[peer?.name] || new Array(24).fill(0);
  const latestPing = pingHistory[pingHistory.length - 1] > 0 ? pingHistory[pingHistory.length - 1] : null;

  _useEffect(() => {
    // The QR modal owns Escape while it is open, otherwise one press closes both
    const onKey = (e) => { if (e.key === 'Escape' && !qrOpen) onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose, qrOpen]);

  _useEffect(() => {
    if (!peer) return;
    let cancelled = false;
    const fetchDiag = async () => {
      try {
        const r = await window.WG.apiCall('/api/users/' + encodeURIComponent(peer.name) + '/diag', { silent: true });
        if (cancelled) return;
        setDiag({
          loading: false,
          pingMs: r.ping_ms,
          pingStatus: r.ping_status || '',
          location: r.location || null,
          endpointIp: r.endpoint_ip || '',
          pingIp: r.ping_ip || '',
        });
      } catch (_) {
        if (!cancelled) setDiag(d => ({ ...d, loading: false, pingMs: null, pingStatus: 'error' }));
      }
    };
    setDiag({ loading: true, pingMs: null, pingStatus: '', location: null, endpointIp: '', pingIp: '' });
    fetchDiag();
    const id = setInterval(fetchDiag, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, [peer && peer.name]);

  if (!peer) return null;

  const thr = throughputBuffers[peer.id] || { rx: [], tx: [] };
  const thrSamples = _useMemo(() => {
    const { rx, tx } = thr;
    const n = Math.min(rx.length, tx.length);
    const now = Date.now();
    return Array.from({ length: n }, (_, i) => ({
      ts: now - (n - 1 - i) * 3000,
      rx: rx[i] || 0,
      tx: tx[i] || 0,
    }));
  }, [thr]);
  const pingLabel = diag.pingMs != null ? `${diag.pingMs} ms` : (diag.pingStatus || 'timeout');
  const locationLabel = (diag.location && diag.location.label) || peer.country || '—';

  const copy = (val, key) => {
    navigator.clipboard?.writeText(val);
    setCopied(key);
    setTimeout(() => setCopied(''), 1500);
  };

  const downloadConfig = async () => {
    setDownloading(true);
    try {
      await window.WG.downloadPeerConfig(peer.name);
      window.WG.toast?.success?.('Config downloaded', `${peer.name}.conf`);
    } catch (e) {
      window.WG.toast?.error?.('Download failed', e.message || 'API error');
    } finally {
      setDownloading(false);
    }
  };

  const revokePeer = () => {
    window.WG.toast?.confirm?.(
      'Revoke this peer?',
      `"${peer.name}" will be permanently removed and disconnected.`,
      {
        confirmLabel: 'Revoke',
        onConfirm: async () => {
          setRevoking(true);
          const t = window.WG.toast?.loading?.(`Revoking "${peer.name}"…`);
          try {
            await window.WG.revokePeer(peer.name);
            t?.success?.('Peer revoked', `"${peer.name}" has been removed`);
            onClose();
            if (onRevoke) onRevoke();
          } catch (e) {
            t?.error?.('Revoke failed', e.message || 'API error');
          } finally {
            setRevoking(false);
          }
        },
      }
    );
  };

  const togglePause = async () => {
    const wasPaused = peer.paused;
    const action = wasPaused ? 'resume' : 'pause';
    setPendingAction(action);
    const t = window.WG.toast?.loading?.(wasPaused ? `Resuming "${peer.name}"…` : `Pausing "${peer.name}"…`);
    try {
      await window.WG.setPeerPaused(peer.name, !wasPaused);
      if (onPeerUpdated) onPeerUpdated();
      if (wasPaused) {
        t?.success?.('Peer resumed', `"${peer.name}" is active again`);
      } else {
        t?.update?.({ type: 'pause', title: 'Peer paused', desc: `"${peer.name}" is now blocked`, duration: 4000 });
      }
    } catch (e) {
      t?.error?.(`Failed to ${action} peer`, e.message || 'API error');
    } finally {
      setPendingAction(null);
    }
  };

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={`Peer ${peer.name}`}>
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: peer.status === 'connected' ? 'var(--avatar-bg)' : 'var(--border-strong)' }}>
              {peer.name.split('-').map(s => s[0]).join('').slice(0, 2).toUpperCase()}
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h2 className="drawer-title">{peer.name}</h2>
                <span className={`status-pill status-${peer.status}`}>
                  {peer.status}
                </span>
              </div>
              <div className="drawer-sub">{peer.device} · {peer.addr}</div>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M6 6l12 12M18 6L6 18"/></svg>
          </button>
        </header>

        <div className="drawer-tabs">
          <button className={`drawer-tab ${tab === 'overview' ? 'on' : ''}`} onClick={() => setTab('overview')}>Overview</button>
          <button className={`drawer-tab ${tab === 'activity' ? 'on' : ''}`} onClick={() => setTab('activity')}>
            Activity
            {peer.monitorDns && <span className="drawer-tab-dot drawer-tab-dot-live" title="Domain monitoring is on" />}
          </button>
          <button className={`drawer-tab ${tab === 'settings' ? 'on' : ''}`} onClick={() => setTab('settings')}>
            Settings
            {settingsDirty && <span className="drawer-tab-dot" title="Unsaved config changes" />}
          </button>
        </div>

        {tab === 'settings' ? (
          <div className="drawer-body">
            <window.PeerSettings peer={peer} onDirtyChange={setSettingsDirty} onPeerUpdated={onPeerUpdated} />
          </div>
        ) : tab === 'activity' ? (
          <div className="drawer-body">
            <DnsActivity peer={peer} onPeerUpdated={onPeerUpdated} />
          </div>
        ) : (
        <div className="drawer-body">
          <section className="drawer-section">
            <div className="section-head">
              <span className="section-label">LIVE THROUGHPUT</span>
              <span className="section-meta">
                <span className="legend-dot" style={{ background: 'var(--accent)' }} /> rx&nbsp;
                <span className="legend-dot" style={{ background: 'var(--accent-2)' }} /> tx
              </span>
            </div>
            <div className="drawer-chart">
              {thrSamples.some(s => s.rx > 0 || s.tx > 0) ? (
                <ThroughputChart samples={thrSamples} height={180} range="1m" spline={tweaks.splineChart} splineTension={tweaks.splineTension ?? 1} smoothScroll={tweaks.smoothThroughput} smoothScale={tweaks.smoothScale} />
              ) : (
                <div className="empty-chart">No recent activity</div>
              )}
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head">
              <span className="section-label">PING LATENCY</span>
              <span className="section-meta">{latestPing != null ? `${latestPing} ms` : '—'}</span>
            </div>
            <div className="drawer-chart">
              {pingHistory.some(v => v > 0) ? (
                <PingBars data={pingHistory} height={68} color="var(--accent-2)" />
              ) : (
                <div className="empty-chart" style={{ height: 68 }}>No recent activity</div>
              )}
            </div>
          </section>

          <section className="drawer-section">
            <div className="stats-grid">
              <div className="stat-cell">
                <div className="stat-label">BYTES IN</div>
                <div className="stat-val">{window.WG.formatBytes(peer.bytesIn)}</div>
              </div>
              <div className="stat-cell">
                <div className="stat-label">BYTES OUT</div>
                <div className="stat-val">{window.WG.formatBytes(peer.bytesOut)}</div>
              </div>
              <div className="stat-cell">
                <div className="stat-label">PING</div>
                <div className="stat-val">
                  {diag.loading
                    ? <span className="pc-spinner" style={{ width: 16, height: 16, display: 'block', margin: '5px auto 0' }} />
                    : <span className="ping-val-in">{pingLabel}</span>}
                </div>
              </div>
              <div className="stat-cell">
                <div className="stat-label">HANDSHAKE</div>
                <div className="stat-val">{window.WG.formatRelTime(peer.lastHs)}</div>
              </div>
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head">
              <span className="section-label">CONNECTION</span>
            </div>
            <dl className="kv">
              <dt>Endpoint</dt>
              <dd className="mono">{peer.endpoint}</dd>
              <dt>Endpoint IP</dt>
              <dd className="mono">{diag.endpointIp || '—'}</dd>
              <dt>Location</dt>
              <dd>{locationLabel}</dd>
              <dt>Ping target</dt>
              <dd className="mono">{diag.pingIp || peer.allowedIps || peer.addr || '—'}</dd>
              <dt>Allowed IPs</dt>
              <dd className="mono">{peer.allowedIps || peer.addr}</dd>
              {peer.pubKey && (
                <>
                  <dt>Public key</dt>
                  <dd className="mono key-val">
                    <span className="truncate">{peer.pubKey}</span>
                    <button className="mini-btn mini-btn-icon" title="Copy public key" onClick={() => copy(peer.pubKey, 'pk')}>
                      {copied === 'pk'
                        ? <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6L9 17l-5-5"/></svg>
                        : <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>}
                    </button>
                  </dd>
                </>
              )}
            </dl>
          </section>

          <section className="drawer-section">
            <div className="section-head">
              <span className="section-label">NOTES</span>
              <button className="mini-btn" onClick={() => setTab('settings')}>edit →</button>
            </div>
            <div className="notes-block">
              {(peer.note || peer.longNote) ? (
                <>
                  {peer.note && <div className="notes-short">{peer.note}</div>}
                  {peer.longNote && <div className="notes-long">{peer.longNote}</div>}
                </>
              ) : (
                <span className="notes-empty">No notes</span>
              )}
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head">
              <span className="section-label">ACTIONS</span>
            </div>
            <div className="action-row">
              <button className="btn btn-primary" onClick={downloadConfig} disabled={downloading}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>
                {downloading ? 'Downloading…' : 'Download config'}
              </button>
              <button className="btn btn-ghost" onClick={() => setQrOpen(true)} title="Show a QR code to import this config on a phone">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3M21 14v3M14 17v4h3M17 21h4"/></svg>
                Show QR
              </button>
              {(() => {
                // Use pendingAction to determine display so background status polls
                // can't flip the icon/text mid-operation.
                const showAsResuming = pendingAction === 'resume' || (!pendingAction && peer.paused);
                return (
                  <button className="btn btn-ghost" onClick={togglePause} disabled={!!pendingAction}
                    title={showAsResuming ? 'Re-enable this peer on the server' : 'Block this peer server-side without revoking it'}>
                    {showAsResuming ? (
                      <>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M5 3l14 9-14 9V3z"/></svg>
                        {pendingAction === 'resume' ? 'Resuming…' : 'Resume'}
                      </>
                    ) : (
                      <>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>
                        {pendingAction === 'pause' ? 'Pausing…' : 'Pause'}
                      </>
                    )}
                  </button>
                );
              })()}
              <button className="btn btn-danger" onClick={revokePeer} disabled={revoking}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2m3 0v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6"/></svg>
                {revoking ? 'Revoking…' : 'Revoke'}
              </button>
            </div>
            {peer.paused && (
              <div style={{ marginTop: 8, padding: '6px 10px', borderRadius: 6, background: 'color-mix(in oklch, var(--warn) 12%, transparent)', color: 'var(--warn)', fontFamily: 'var(--mono)', fontSize: 11 }}>
                Peer is paused — traffic is blocked server-side. The device tunnel may still show as connected.
              </div>
            )}
          </section>
        </div>
        )}
      </aside>
      {qrOpen && <PeerQrModal peer={peer} onClose={() => setQrOpen(false)} />}
    </>
  );
}

// ============================================================
// LogsPanel — live streaming logs with alerts callout
// ============================================================
function NotifIcon({ level }) {
  if (level === 'error') return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><path d="M12 8v5M12 16h.01"/></svg>;
  if (level === 'warn') return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0zM12 9v4M12 17h.01"/></svg>;
  if (level === 'success') return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><path d="M8 12l2.5 2.5L16 9"/></svg>;
  if (level === 'update') return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 2v11m0 0l-4-4m4 4l4-4M4 18h16"/></svg>;
  return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><path d="M12 11v5M12 8h.01"/></svg>;
}

function LogsPanel({ logs, notifications = [], onExpand, onDismiss = () => {}, serviceActive = false, ifaceName = 'wg0' }) {
  const scrollRef = _useRef(null);
  const [idx, setIdx] = _useState(0);
  const [leaving, setLeaving] = _useState(false);
  const [notifsCollapsed, setNotifsCollapsed] = _useState(
    () => localStorage.getItem('WG_NOTIFS_COLLAPSED') === 'true'
  );

  _useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [logs.length]);

  const visible = notifications;
  const safeIdx = visible.length ? idx % visible.length : 0;
  const current = visible[safeIdx];

  _useEffect(() => {
    if (visible.length <= 1) return;
    let swapT;
    const id = setInterval(() => {
      setLeaving(true);
      swapT = setTimeout(() => {
        setIdx(i => (i + 1) % visible.length);
        setLeaving(false);
      }, 550);
    }, 7000);
    return () => { clearInterval(id); clearTimeout(swapT); };
  }, [visible.length]);

  const toggleNotifs = (e) => {
    e.stopPropagation();
    const next = !notifsCollapsed;
    setNotifsCollapsed(next);
    localStorage.setItem('WG_NOTIFS_COLLAPSED', String(next));
  };

  return (
    <div className="logs-card logs-card-clickable" onClick={onExpand} role="button" tabIndex={0}>
      <div className="logs-split">
        <div className="notif-panel" onClick={e => e.stopPropagation()}>
          <div className="notif-head" onClick={toggleNotifs} role="button" tabIndex={0} title={notifsCollapsed ? 'Show notifications' : 'Hide notifications'}>
            <span className="section-label">NOTIFICATIONS</span>
            <div className="notif-head-end">
              {visible.length > 0 && <span className="notif-count">{visible.length}</span>}
              {(() => {
                const lvl = visible.some(n => n.level === 'error') ? 'error'
                  : visible.some(n => n.level === 'warn') ? 'warn'
                  : visible.length > 0 ? 'info' : null;
                return lvl && <span className={`notif-indicator notif-indicator-${lvl}`} />;
              })()}
              <svg className={`notif-arrow${notifsCollapsed ? ' is-collapsed' : ''}`} width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M18 15l-6-6-6 6"/>
              </svg>
            </div>
          </div>
          <div className={`notif-col${notifsCollapsed ? ' is-collapsed' : ''}`}>
            <div className="notif-col-inner">
              <div className="notif-body">
                {current ? (
                  <div className={`notif-item notif-${current.level}${leaving ? ' is-leaving' : ''}`}>
                    <span className="notif-icon"><NotifIcon level={current.level} /></span>
                    <div className="notif-text">
                      <div className="notif-title">{current.title}</div>
                      <div className="notif-desc">{current.desc}</div>
                    </div>
                    <button
                      className="notif-dismiss"
                      aria-label="Dismiss notification"
                      onClick={e => { e.stopPropagation(); onDismiss(current.key); }}
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
                    </button>
                  </div>
                ) : (
                  <div className="notif-empty">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.5"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/><line x1="1" y1="1" x2="23" y2="23" stroke="currentColor" strokeWidth="1.5"/></svg>
                    No notifications
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="logs-col">
          <div className="logs-head">
            <span className="section-label">LIVE LOGS</span>
            <div className="log-meta">
              <span className={serviceActive ? 'pulse-dot' : 'pulse-dot pulse-dot-off'} /> {ifaceName}
              <span className="log-expand-hint">expand <svg className="log-expand-chev" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4"><path d="M9 18l6-6-6-6"/></svg></span>
            </div>
          </div>
          <div className={`logs-stream${logs.length === 0 ? ' is-empty' : ''}`} ref={scrollRef}>
            {logs.length === 0 ? (
              <div className="logs-empty logs-empty-mini">
                <span className="logs-empty-icon">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M8 6h13M8 12h13M8 18h9"/><path d="M3 6h.01M3 12h.01M3 18h.01"/></svg>
                </span>
                <div className="logs-empty-title">No log entries</div>
                <div className="logs-empty-desc">New lines appear here as the service runs.</div>
              </div>
            ) : logs.map((l, i) => (
              <div key={i} className={`log-line log-${l.level}`}>
                <span className="log-time">{new Date(l.t).toTimeString().slice(0, 8)}</span>
                <span className="log-level">{l.level}</span>
                <span className="log-msg">{l.msg}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================
// StepperInput — typeable value between the − / + stepper buttons.
// Commits on blur/Enter, reverts on Escape.
// ============================================================
function StepperInput({ value, unit, min = 1, max = 100000, disabled, onCommit }) {
  const [draft, setDraft] = _useState(null);
  const cancelRef = _useRef(false);
  const shown = draft != null ? draft : String(value);
  const commit = (raw) => {
    setDraft(null);
    if (cancelRef.current) { cancelRef.current = false; return; }
    const n = parseInt(raw, 10);
    if (isNaN(n)) return;
    const clamped = Math.max(min, Math.min(max, n));
    if (clamped !== value) onCommit(clamped);
  };
  return (
    <span className="stepper-val">
      <input
        className="mono"
        type="number"
        inputMode="numeric"
        min={min}
        max={max}
        disabled={disabled}
        value={shown}
        style={{ width: `${Math.max(2, String(shown).length + 0.5)}ch` }}
        onFocus={e => e.target.select()}
        onChange={e => setDraft(e.target.value)}
        onBlur={e => commit(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'Enter') e.currentTarget.blur();
          else if (e.key === 'Escape') { cancelRef.current = true; e.currentTarget.blur(); }
        }}
        aria-label={unit ? `Value in ${unit}` : 'Value'}
      />
      {unit && <span className="stepper-unit">{unit}</span>}
    </span>
  );
}

// ============================================================
// DataBudgetDrawer
// ============================================================
function DataBudgetDrawer({ total, budget, enabled = true, alerts, resetTime, peers, peerBudgets = {}, setPeerBudget, enforcement = { action: 'none', throttle_mbps: 5 }, budgetUsage, updateBudgetSettings, onClose }) {
  const [saving, setSaving] = _useState(false);
  const [msg, setMsg] = _useState('');

  _useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const cap = budget * 1024 * 1024 * 1024;
  const pct = Math.min(100, (total / cap) * 100);
  const remaining = Math.max(0, cap - total);

  const enforceState = budgetUsage?.enforce_state || {};
  const throttledCount = Object.values(enforceState).filter(s => s === 'throttled').length;
  const pausedCount = Object.values(enforceState).filter(s => s === 'paused').length;
  const enfAction = enforcement.action || 'none';
  const enfLabel = enfAction === 'pause' ? 'pause at 100%'
    : enfAction === 'throttle' ? `throttle to ${enforcement.throttle_mbps || 5} Mbps at 100%`
    : enfAction === 'combined' ? `throttle to ${enforcement.throttle_mbps || 5} Mbps at 80% · pause at 100%`
    : '';

  const peerByName = new Map(peers.map(p => [p.name, p]));
  const peerBreakdown = (budgetUsage?.peers || []).map(row => {
    const p = peerByName.get(row.name) || {};
    return { ...p, id: row.name, name: row.name, total: row.bytes || 0 };
  });
  const maxPeerTotal = Math.max(...peerBreakdown.map(p => p.total), 1);

  const saveSettings = async (patch) => {
    setSaving(true);
    setMsg('');
    try {
      return await updateBudgetSettings(patch);
    } catch (e) {
      setMsg('Error: ' + (e.message || 'save failed'));
    } finally {
      setSaving(false);
    }
  };

  const exportCsv = async () => {
    setSaving(true);
    setMsg('');
    try {
      const r = await window.WG.apiCall('/api/data-budget/export', { silent: true, method: 'POST', body: JSON.stringify({}) });
      const blob = new Blob([r.csv || ''], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = r.filename || 'data-budget.csv';
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        a.remove();
        URL.revokeObjectURL(url);
      }, 0);
      setMsg('Exported CSV');
      setTimeout(() => setMsg(''), 2000);
    } catch (e) {
      setMsg('Error: ' + (e.message || 'export failed'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Data budget">
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: 'var(--avatar-bg)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M3 3v18h18"/><path d="M7 14l4-4 4 4 5-5"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">Data budget</h2>
              <div className="drawer-sub">Usage since {budgetUsage?.period_start_iso ? new Date(budgetUsage.period_start_iso).toLocaleString() : 'current reset'} · resets at {resetTime} local time</div>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M6 6l12 12M18 6L6 18"/></svg>
          </button>
        </header>

        <div className="drawer-body">
          <section className="drawer-section">
            <div className="budget-hero">
              <div className="budget-hero-nums">
                <div className="budget-used">
                  <div className="budget-big">{window.WG.formatBytes(total).split(' ')[0]}<span className="budget-unit">{window.WG.formatBytes(total).split(' ')[1]}</span></div>
                  <div className="budget-lbl">{enabled ? 'used' : 'used today'}</div>
                </div>
                {enabled && <div className="budget-divider" />}
                {enabled && (
                  <div className="budget-used">
                    <div className="budget-big">{window.WG.formatBytes(remaining).split(' ')[0]}<span className="budget-unit">{window.WG.formatBytes(remaining).split(' ')[1]}</span></div>
                    <div className="budget-lbl">remaining</div>
                  </div>
                )}
                {!enabled && (
                  <div className="budget-track">
                    <button className="btn" disabled={saving} onClick={() => saveSettings({ enabled: true })}>Enable budget</button>
                  </div>
                )}
              </div>
              {!enabled && <BudgetComposition rows={peerBreakdown} />}
              {enabled && (
                <div className="budget-bar-wrap">
                  <div className="budget-bar">
                    <div className="budget-bar-fill" style={{ width: `${pct}%`, background: pct > 90 ? 'var(--danger)' : pct > 70 ? 'var(--warn)' : 'var(--accent)' }} />
                    {[70, 90].map(t => (
                      <div key={t} className="budget-marker" style={{ left: `${t}%` }} title={`${t}% threshold`} />
                    ))}
                  </div>
                  <div className="budget-bar-labels">
                    <span>0</span>
                    <span className="mono">{pct.toFixed(1)}%</span>
                    <span>{budget} GB</span>
                  </div>
                </div>
              )}
              {enabled && enfAction !== 'none' && (
                <div className="budget-enf">
                  <span>{enfLabel}</span>
                  <span className="budget-enf-counts">
                    {throttledCount > 0 && <span className="pb-badge pb-badge-throttled">{throttledCount} throttled</span>}
                    {pausedCount > 0 && <span className="pb-badge pb-badge-paused">{pausedCount} paused</span>}
                    {throttledCount === 0 && pausedCount === 0 && <span>no peers limited</span>}
                  </span>
                </div>
              )}
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head">
              <span className="section-label">{enabled ? 'BUDGET BY PEER' : 'USAGE BY PEER'}</span>
              <span className="section-meta">{peerBreakdown.length} peers · {enabled ? 'daily' : 'today'}</span>
            </div>
            <div className="peer-budget-list">
              {peerBreakdown.map(p => {
                const b = peerBudgets[p.id] != null ? peerBudgets[p.id] : 'inf';
                const isInf = !enabled || b === 'inf';
                const pcap = isInf ? 0 : b * 1024 * 1024 * 1024;
                const ppct = isInf ? 0 : Math.min(100, (p.total / pcap) * 100);
                const over = !isInf && p.total > pcap;
                const fillColor = over ? 'var(--danger)' : ppct > 80 ? 'var(--warn)' : 'var(--accent)';
                const enf = enforceState[p.id] || 'none';
                return (
                  <div key={p.id} className={`pb-row${isInf ? ' is-inf' : ''}`}>
                    <div className="pb-top">
                      <div className="pb-id">
                        <span className="pb-name">
                          {p.name}
                          {enf === 'throttled' && <span className="pb-badge pb-badge-throttled">throttled</span>}
                          {enf === 'paused' && <span className="pb-badge pb-badge-paused">paused</span>}
                        </span>
                        <span className="pb-device">{p.device || ''}</span>
                      </div>
                      {enabled && (
                        <div className="pb-ctrl">
                          {!isInf && (
                            <div className="stepper stepper-sm">
                              <button onClick={() => setPeerBudget(p.id, Math.max(1, b - 1))}>−</button>
                              <StepperInput value={b} unit="GB" onCommit={v => setPeerBudget(p.id, v)} />
                              <button onClick={() => setPeerBudget(p.id, b + 1)}>+</button>
                            </div>
                          )}
                          <button
                            className={`pb-inf-btn${isInf ? ' on' : ''}`}
                            onClick={() => setPeerBudget(p.id, isInf ? 5 : 'inf')}
                            title={isInf ? 'Set a daily limit' : 'Remove limit'}
                          ><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M18.178 8c5.096 0 5.096 8 0 8-5.095 0-7.133-8-12.739-8-4.585 0-4.585 8 0 8 5.606 0 7.644-8 12.74-8z"/></svg></button>
                        </div>
                      )}
                    </div>
                    <div className={`pb-bar${isInf ? ' inf' : ''}`}>
                      {isInf
                        ? <div className="pb-bar-fill" style={{ width: `${(p.total / maxPeerTotal) * 100}%`, background: 'var(--muted)' }} />
                        : <div className="pb-bar-fill" style={{ width: `${ppct}%`, background: fillColor }} />}
                    </div>
                    <div className="pb-foot">
                      <span className="pb-used mono">{window.WG.formatBytes(p.total)} <span className="pb-used-lbl">today</span></span>
                      {!enabled
                        ? null
                        : isInf
                          ? <span className="pb-status mono pb-status-inf">∞ no limit</span>
                          : <span className={`pb-status mono${over ? ' pb-status-over' : ''}`}>{over ? `over by ${window.WG.formatBytes(p.total - pcap)}` : `${ppct.toFixed(0)}% of ${b} GB`}</span>}
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head">
              <span className="section-label">SETTINGS</span>
            </div>
            <div className="settings-list">
              <div className="setting-row">
                <div>
                  <div className="setting-title">Daily budget</div>
                  <div className="setting-desc">{enabled ? 'Track usage against a daily data limit' : 'Off — only data used today is shown'}</div>
                </div>
                <div className="setting-control">
                  <button className={`toggle ${enabled ? 'on' : ''}`} disabled={saving} onClick={() => saveSettings({ enabled: !enabled })} aria-pressed={enabled}>
                    <span className="toggle-knob" />
                  </button>
                  {msg && <span style={{ display: 'block', marginTop: 3, color: msg.startsWith('Error') ? 'var(--danger)' : 'var(--accent-2)', fontFamily: 'var(--mono)', fontSize: 10 }}>{msg}</span>}
                </div>
              </div>
              {enabled && (
                <div className="setting-row">
                  <div>
                    <div className="setting-title">Daily limit</div>
                    <div className="setting-desc">Data allowance shared across all peers — click the number to type</div>
                  </div>
                  <div className="setting-control">
                    <div className="stepper">
                      <button disabled={saving} onClick={() => saveSettings({ budget_gb: Math.max(1, budget - 5) })}>−</button>
                      <StepperInput value={budget} unit="GB" disabled={saving} onCommit={v => saveSettings({ budget_gb: v })} />
                      <button disabled={saving} onClick={() => saveSettings({ budget_gb: budget + 5 })}>+</button>
                    </div>
                  </div>
                </div>
              )}
              <div className="setting-row">
                <div>
                  <div className="setting-title">Reset time</div>
                  <div className="setting-desc">When the daily counter rolls over</div>
                </div>
                <div className="setting-control">
                  <select className="select-input" value={resetTime} disabled={saving} onChange={e => saveSettings({ reset_time: e.target.value })}>
                    <option value="00:00">00:00</option>
                    <option value="04:00">04:00</option>
                    <option value="06:00">06:00</option>
                    <option value="12:00">12:00</option>
                  </select>
                </div>
              </div>
              {enabled && (
                <div className="setting-row">
                  <div>
                    <div className="setting-title">Alerts at 70% / 90% / 100%</div>
                    <div className="setting-desc">Notification + log entry when approaching or exceeding budget limit</div>
                  </div>
                  <div className="setting-control">
                    <button className={`toggle ${alerts ? 'on' : ''}`} disabled={saving} onClick={() => saveSettings({ alerts: !alerts })} aria-pressed={alerts}>
                      <span className="toggle-knob" />
                    </button>
                  </div>
                </div>
              )}
              {enabled && (
                <div className="setting-row">
                  <div>
                    <div className="setting-title">When budget exceeded</div>
                    <div className="setting-desc">Action applied per peer once their limit is hit</div>
                  </div>
                  <div className="setting-control">
                    <select
                      className="select-input"
                      value={enforcement.action}
                      disabled={saving}
                      onChange={e => saveSettings({ enforcement: { ...enforcement, action: e.target.value } })}
                    >
                      <option value="none">No action</option>
                      <option value="throttle">Reduce speed</option>
                      <option value="pause">Pause connection</option>
                      <option value="combined">Combined — slow at 80%, pause at 100%</option>
                    </select>
                  </div>
                </div>
              )}
              {enabled && (enforcement.action === 'throttle' || enforcement.action === 'combined') && (
                <div className="setting-row">
                  <div>
                    <div className="setting-title">Reduced speed</div>
                    <div className="setting-desc">Speed cap applied when peer exceeds their budget</div>
                  </div>
                  <div className="setting-control">
                    <div className="stepper">
                      <button disabled={saving} onClick={() => saveSettings({ enforcement: { ...enforcement, throttle_mbps: Math.max(1, (enforcement.throttle_mbps || 5) - 1) } })}>−</button>
                      <StepperInput value={enforcement.throttle_mbps || 5} unit="Mbps" max={1000} disabled={saving} onCommit={v => saveSettings({ enforcement: { ...enforcement, throttle_mbps: v } })} />
                      <button disabled={saving} onClick={() => saveSettings({ enforcement: { ...enforcement, throttle_mbps: (enforcement.throttle_mbps || 5) + 1 } })}>+</button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </section>

          <section className="drawer-section">
            <div className="action-row">
              <button className="btn btn-primary" onClick={exportCsv} disabled={saving}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>
                {saving ? 'Working…' : 'Export CSV'}
              </button>
            </div>
          </section>
        </div>
      </aside>
    </>
  );
}

// ============================================================
// buildLogsPdf — dependency-free PDF export of log lines, colored
// by level to match the dashboard (info blue, warn amber, error red)
// ============================================================
function buildLogsPdf(entries, meta = {}) {
  const W = 595.28, H = 841.89, M = 44;              // A4 portrait
  const FS = 7.2, LH = 11.4, CW = FS * 0.6;          // Courier metrics
  const maxCols = Math.floor((W - 2 * M) / CW);
  const headerH = 64, footerH = 34;

  const esc = s => s.replace(/[\\()]/g, m => '\\' + m);
  const UMAP = { '—': 151, '–': 150, '‘': 145, '’': 146, '“': 147, '”': 148, '•': 149, '…': 133 };
  const enc = s => Array.from(String(s)).map(ch => {
    const c = ch.codePointAt(0);
    if (c < 128) return ch;
    if (ch === '→') return '->';
    if (UMAP[ch]) return String.fromCharCode(UMAP[ch]);
    return c <= 255 ? ch : '?';
  }).join('');

  const C = {
    title: '0.10 0.12 0.16',
    sub: '0.46 0.48 0.53',
    time: '0.52 0.55 0.60',
    rule: '0.86 0.87 0.89',
    foot: '0.58 0.60 0.64',
    level: { info: '0.20 0.44 0.83', warn: '0.72 0.42 0.02', error: '0.79 0.15 0.15' },
    chip:  { info: '0.89 0.93 0.99', warn: '0.99 0.94 0.85', error: '0.99 0.91 0.91' },
    msg:   { info: '0.16 0.18 0.22', warn: '0.54 0.36 0.05', error: '0.63 0.13 0.13' },
  };

  const pad2 = n => String(n).padStart(2, '0');
  const fmtTs = t => {
    const d = new Date(t);
    return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  };

  // Column layout in character units: date+time | level chip | message
  const lvlX = 20.5;
  const msgX = lvlX + 8;
  const msgCols = Math.max(20, Math.floor(maxCols - msgX));

  // Flatten entries into rows of colored segments; wrap with hanging indent.
  const rows = [];
  entries.forEach(l => {
    const lv = C.level[l.level] ? l.level : 'info';
    let rest = enc(l.msg || '');
    let first = true;
    do {
      let chunk = rest.slice(0, msgCols);
      if (rest.length > msgCols) {
        const sp = chunk.lastIndexOf(' ');
        if (sp > msgCols * 0.6) chunk = chunk.slice(0, sp);
      }
      rest = rest.slice(chunk.length).replace(/^ +/, '');
      if (first) {
        rows.push({
          chip: lv,
          segs: [
            { x: 0, text: fmtTs(l.t), color: C.time },
            { x: lvlX + 0.6, text: lv.toUpperCase(), color: C.level[lv] },
            { x: msgX, text: chunk, color: C.msg[lv] },
          ],
        });
        first = false;
      } else {
        rows.push({ segs: [{ x: msgX, text: chunk, color: C.msg[lv] }] });
      }
    } while (rest.length);
  });

  const capFirst = Math.floor((H - M - headerH - footerH) / LH);
  const capRest = Math.floor((H - M - footerH - M + 6) / LH);
  const pages = [];
  let cur = [];
  rows.forEach(r => {
    if (cur.length >= (pages.length === 0 ? capFirst : capRest)) { pages.push(cur); cur = []; }
    cur.push(r);
  });
  pages.push(cur);

  const nPages = pages.length;
  const footLeft = enc(`${meta.title || 'WireGuard logs'} · ${fmtTs(Date.now()).slice(0, 10)}`);
  const streams = pages.map((pageRows, pi) => {
    let s = '';
    let y;
    if (pi === 0) {
      s += `BT /F2 14 Tf ${C.title} rg 1 0 0 1 ${M} ${(H - M - 10).toFixed(2)} Tm (${esc(enc(meta.title || 'WireGuard logs'))}) Tj ET\n`;
      if (meta.sub) s += `BT /F1 7.5 Tf ${C.sub} rg 1 0 0 1 ${M} ${(H - M - 25).toFixed(2)} Tm (${esc(enc(meta.sub))}) Tj ET\n`;
      s += `${C.rule} rg ${M} ${(H - M - 36).toFixed(2)} ${(W - 2 * M).toFixed(2)} 0.8 re f\n`;
      y = H - M - headerH;
    } else {
      y = H - M;
    }
    pageRows.forEach(r => {
      if (r.chip) {
        const label = r.chip.toUpperCase();
        const rx = M + lvlX * CW;
        const rw = (label.length + 1.2) * CW;
        s += `${C.chip[r.chip]} rg ${rx.toFixed(2)} ${(y - 2.2).toFixed(2)} ${rw.toFixed(2)} ${(FS + 3.6).toFixed(2)} re f\n`;
      }
      s += `BT /F1 ${FS} Tf\n`;
      r.segs.forEach(seg => {
        s += `1 0 0 1 ${(M + seg.x * CW).toFixed(2)} ${y.toFixed(2)} Tm ${seg.color} rg (${esc(seg.text)}) Tj\n`;
      });
      s += 'ET\n';
      y -= LH;
    });
    const pageLbl = `Page ${pi + 1} of ${nPages}`;
    s += `${C.rule} rg ${M} ${(footerH - 4).toFixed(2)} ${(W - 2 * M).toFixed(2)} 0.6 re f\n`;
    s += `BT /F1 7 Tf ${C.foot} rg 1 0 0 1 ${M} ${(footerH - 14).toFixed(2)} Tm (${esc(footLeft)}) Tj ET\n`;
    s += `BT /F1 7 Tf ${C.foot} rg 1 0 0 1 ${(W - M - pageLbl.length * 7 * 0.6).toFixed(2)} ${(footerH - 14).toFixed(2)} Tm (${esc(pageLbl)}) Tj ET\n`;
    return s;
  });

  const objs = [];
  objs[1] = '<< /Type /Catalog /Pages 2 0 R >>';
  objs[2] = `<< /Type /Pages /Kids [${pages.map((_, i) => `${5 + i * 2} 0 R`).join(' ')}] /Count ${nPages} >>`;
  objs[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>';
  objs[4] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>';
  pages.forEach((_, i) => {
    const pn = 5 + i * 2;
    objs[pn] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${W} ${H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${pn + 1} 0 R >>`;
    objs[pn + 1] = `<< /Length ${streams[i].length} >>\nstream\n${streams[i]}\nendstream`;
  });

  let pdf = '%PDF-1.4\n';
  const offsets = [];
  for (let i = 1; i < objs.length; i++) {
    offsets[i] = pdf.length;
    pdf += `${i} 0 obj\n${objs[i]}\nendobj\n`;
  }
  const xref = pdf.length;
  pdf += `xref\n0 ${objs.length}\n0000000000 65535 f \n`;
  for (let i = 1; i < objs.length; i++) pdf += offsets[i].toString().padStart(10, '0') + ' 00000 n \n';
  pdf += `trailer\n<< /Size ${objs.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;

  return Uint8Array.from(pdf, ch => ch.charCodeAt(0) & 0xFF);
}

// ============================================================
// LogsDrawer — full log history, own polling, verbose, retention, download
// ============================================================
function LogsDrawer({ alerts, onClose, verbose, setVerbose, onDismiss }) {
  const [levelFilter, setLevelFilter] = _useState('all');
  const [search, setSearch] = _useState('');
  const [autoScroll, setAutoScroll] = _useState(true);
  const [retention, setRetention] = _useState('forever');
  const [retentionSaving, setRetentionSaving] = _useState(false);
  const [localLogs, setLocalLogs] = _useState([]);
  const [loading, setLoading] = _useState(true);
  const streamRef = _useRef(null);
  const wasAtBottom = _useRef(true);
  const logSearchRef = _useRef(null);

  // Keyboard close
  _useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  // Own fast polling — restarts when verbose changes
  _useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const n = verbose ? 1000 : 300;
        const j = await window.WG.apiCall(`/api/logs?n=${n}&verbose=${verbose ? 1 : 0}`, { silent: true });
        if (cancelled) return;
        if (j.lines) setLocalLogs(window.WG.parseLogLines(j.lines, verbose));
        setLoading(false);
      } catch (_) {}
    };
    poll();
    const id = setInterval(poll, 3000);
    return () => { cancelled = true; clearInterval(id); };
  }, [verbose]);

  // Auto-scroll — only if user was already at the bottom
  _useEffect(() => {
    const el = streamRef.current;
    if (!el) return;
    if (autoScroll && wasAtBottom.current) {
      el.scrollTop = el.scrollHeight;
    }
  }, [localLogs.length, autoScroll]);

  const onScroll = () => {
    const el = streamRef.current;
    if (!el) return;
    wasAtBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  };

  // Load persisted retention setting
  _useEffect(() => {
    window.WG.apiCall('/api/logs/retention', { silent: true })
      .then(r => { if (r.retention) setRetention(r.retention); })
      .catch(() => {});
  }, []);

  const saveRetention = async (val) => {
    const prev = retention;
    setRetention(val);
    setRetentionSaving(true);
    try {
      const r = await window.WG.apiCall('/api/logs/retention', { silent: true, method: 'POST', body: JSON.stringify({ retention: val }) });
      if (val === 'forever') window.WG.toast?.success?.('Retention saved', 'Journal entries are kept forever');
      else if (r.ok) window.WG.toast?.success?.('Retention saved', `Journal vacuumed — kept last ${val}, re-applied every 6 h`);
      else window.WG.toast?.error?.('Vacuum failed', 'Setting saved, but journalctl vacuum failed — check server logs');
    } catch (e) {
      setRetention(prev);
      window.WG.toast?.error?.('Retention not saved', e.message || 'API unreachable');
    } finally {
      setRetentionSaving(false);
    }
  };

  const downloadLogs = () => {
    const rows = localLogs.map(l => {
      const ts = new Date(l.t).toISOString();
      return `${ts} [${l.level.toUpperCase().padEnd(5)}] ${l.msg}`;
    }).join('\n');
    const blob = new Blob([rows], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `wg0-logs-${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
  };

  const downloadPdfLogs = () => {
    const bytes = buildLogsPdf(localLogs, {
      title: 'WireGuard logs',
      sub: `exported ${new Date().toLocaleString()} · ${localLogs.length} lines${verbose ? ' · verbose' : ''}`,
    });
    const blob = new Blob([bytes], { type: 'application/pdf' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `wg0-logs-${new Date().toISOString().slice(0, 10)}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
  };

  const clearLogs = () => {
    window.WG.toast?.confirm?.(
      'Clear the log view?',
      `${localLogs.length} lines will be hidden from this panel. The system journal itself is not deleted.`,
      {
        confirmLabel: 'Clear',
        onConfirm: async () => {
          const t = window.WG.toast?.loading?.('Clearing logs…');
          try {
            await window.WG.apiCall('/api/logs/clear', { silent: true, method: 'POST' });
            setLocalLogs([]);
            t?.success?.('Logs cleared', 'Older entries are hidden from the panel');
          } catch (e) {
            t?.error?.('Could not clear logs', e.message || 'API unreachable');
          }
        },
      },
    );
  };

  const filtered = localLogs.filter(l => {
    if (levelFilter !== 'all' && l.level !== levelFilter) return false;
    if (search && !l.msg.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });
  const isFiltered = levelFilter !== 'all' || !!search;

  const counts = {
    info:  localLogs.filter(l => l.level === 'info').length,
    warn:  localLogs.filter(l => l.level === 'warn').length,
    error: localLogs.filter(l => l.level === 'error').length,
  };

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer drawer-wide" role="dialog" aria-label="Logs">
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: 'var(--avatar-bg)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">Logs</h2>
              <div className="drawer-sub">
                {verbose && <span style={{ marginLeft: 6, color: 'var(--accent)', fontFamily: 'var(--mono)', fontSize: 10 }}>VERBOSE</span>}
              </div>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M6 6l12 12M18 6L6 18"/></svg>
          </button>
        </header>

        <div className="drawer-body">
          {alerts.length > 0 && (
            <section className="drawer-section">
              <div className="section-head"><span className="section-label">WARNINGS</span></div>
              <div className="alerts-block" style={{ padding: 0 }}>
                {alerts.map((a, i) => (
                  <div key={i} className={`alert alert-${a.level}`}>
                    <span className="alert-icon">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0zM12 9v4M12 17h.01"/></svg>
                    </span>
                    <div className="alert-body">
                      <div className="alert-title">{a.title}</div>
                      <div className="alert-desc">{a.desc}</div>
                    </div>
                    {onDismiss && (
                      <button className="alert-dismiss" onClick={() => onDismiss(a.key)} aria-label="Dismiss">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 6l12 12M18 6L6 18"/></svg>
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </section>
          )}

          <section className="drawer-section">
            <div className="log-stats">
              <div className="log-stat"><div className="log-stat-val" style={{ color: 'var(--accent-2)' }}>{counts.info}</div><div className="log-stat-lbl">info</div></div>
              <div className="log-stat"><div className="log-stat-val" style={{ color: 'var(--warn)' }}>{counts.warn}</div><div className="log-stat-lbl">warn</div></div>
              <div className="log-stat"><div className="log-stat-val" style={{ color: 'var(--danger)' }}>{counts.error}</div><div className="log-stat-lbl">error</div></div>
              <div className="log-stat"><div className="log-stat-val">{localLogs.length}</div><div className="log-stat-lbl">total</div></div>
            </div>
          </section>

          <section className="drawer-section">
            <div className="log-toolbar">
              <div className="search" style={{ flex: 1, height: 32 }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
                <input ref={logSearchRef} type="text" placeholder="Search logs…" value={search} onChange={e => setSearch(e.target.value)} />
                {search && (
                  <button className="search-clear" onClick={() => { setSearch(''); logSearchRef.current?.focus(); }} aria-label="Clear search">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
                  </button>
                )}
              </div>
              <div className="peers-filters">
                {['all', 'info', 'warn', 'error'].map(s => (
                  <button key={s} className={`filter-pill ${levelFilter === s ? 'active' : ''}`} onClick={() => setLevelFilter(s)}>{s}</button>
                ))}
              </div>
            </div>
          </section>

          <section className="drawer-section">
            <div className="logs-stream logs-stream-tall" ref={streamRef} onScroll={onScroll}>
              {loading ? (
                [0, 1, 2, 3, 4, 5, 6, 7].map(i => (
                  <div key={i} className={`log-line${verbose ? ' no-ts' : ''}`} aria-hidden="true">
                    {!verbose && <span className="log-time"><span className="skel" style={{ width: 52, height: 9 }} /></span>}
                    <span style={{ alignSelf: 'center' }}><span className="skel" style={{ width: 34, height: 9 }} /></span>
                    <span className="log-msg"><span className="skel" style={{ width: 170 + ((i * 67) % 250), height: 9 }} /></span>
                  </div>
                ))
              ) : filtered.length === 0 ? (
                <div className="logs-empty">
                  <span className="logs-empty-icon">
                    {isFiltered ? (
                      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
                    ) : (
                      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M8 6h13M8 12h13M8 18h9"/><path d="M3 6h.01M3 12h.01M3 18h.01"/></svg>
                    )}
                  </span>
                  <div className="logs-empty-title">{isFiltered ? 'No matching logs' : 'No log entries'}</div>
                  <div className="logs-empty-desc">
                    {isFiltered
                      ? 'No lines match the current search and level filter.'
                      : 'Nothing has been logged yet. New entries appear here as the service runs.'}
                  </div>
                  {isFiltered && (
                    <button className="btn logs-empty-btn" onClick={() => { setSearch(''); setLevelFilter('all'); }}>
                      Reset filters
                    </button>
                  )}
                </div>
              ) : filtered.map((l, i) => (
                <div key={i} className={`log-line log-${l.level}${verbose ? ' no-ts' : ''}`}>
                  {!verbose && <span className="log-time">{new Date(l.t).toTimeString().slice(0, 8)}</span>}
                  <span className="log-level">{l.level}</span>
                  <span className="log-msg">{l.msg}</span>
                </div>
              ))}
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head"><span className="section-label">SETTINGS</span></div>
            <div className="settings-list">
              <div className="setting-row">
                <div>
                  <div className="setting-title">Auto-scroll</div>
                  <div className="setting-desc">Follow new log lines as they arrive</div>
                </div>
                <div className="setting-control">
                  <button className={`toggle ${autoScroll ? 'on' : ''}`} onClick={() => setAutoScroll(v => !v)}>
                    <span className="toggle-knob" />
                  </button>
                </div>
              </div>
              <div className="setting-row">
                <div>
                  <div className="setting-title">Verbose logging</div>
                  <div className="setting-desc">Fetch 1000 lines with microsecond timestamps (journalctl short-precise)</div>
                </div>
                <div className="setting-control">
                  <button className={`toggle ${verbose ? 'on' : ''}`} onClick={() => setVerbose(v => !v)}>
                    <span className="toggle-knob" />
                  </button>
                </div>
              </div>
              <div className="setting-row">
                <div>
                  <div className="setting-title">Retention</div>
                  <div className="setting-desc">Removes journal entries older than the selected period — applied now and re-applied periodically</div>
                </div>
                <div className="setting-control">
                  <select className="select-input" value={retention} disabled={retentionSaving} onChange={e => saveRetention(e.target.value)}>
                    <option value="1d">1 day</option>
                    <option value="7d">7 days</option>
                    <option value="30d">30 days</option>
                    <option value="forever">Forever</option>
                  </select>
                </div>
              </div>
            </div>
          </section>

          <section className="drawer-section">
            <div className="action-row logs-action-row">
              <button className="btn btn-primary" onClick={downloadLogs} disabled={localLogs.length === 0}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>
                Download logs ({localLogs.length} lines)
              </button>
              <button className="btn" onClick={downloadPdfLogs} disabled={localLogs.length === 0}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M14 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V9z"/><path d="M14 3v6h6"/></svg>
                Download PDF
              </button>
              <button className="btn btn-danger" onClick={clearLogs} disabled={localLogs.length === 0}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M3 6h18M8 6V4a1 1 0 011-1h6a1 1 0 011 1v2M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>
                Clear logs
              </button>
            </div>
          </section>
        </div>
      </aside>
    </>
  );
}

// ============================================================
// PortCheckDrawer — animated diagnostic using real API
// ============================================================
function PortCheckDrawer({ peers, onClose }) {
  const steps = [
    { id: 'iface',     label: 'Interface wg0 present',       detail: 'Check link state and systemd unit' },
    { id: 'listen',    label: 'Listening on UDP 51820',       detail: 'Verify port is bound' },
    { id: 'fw-in',     label: 'Firewall accepts inbound',     detail: 'UFW / iptables INPUT rule' },
    { id: 'fw-fwd',    label: 'Forwarding enabled',           detail: 'net.ipv4.ip_forward = 1' },
    { id: 'nat',       label: 'NAT / MASQUERADE rule',        detail: 'PostUp POSTROUTING rule present' },
    { id: 'dns',       label: 'External connectivity',        detail: 'Ping 1.1.1.1 from server' },
    { id: 'handshake', label: 'Peer handshakes verified',     detail: `${peers.filter(p => p.status === 'connected').length} online · ${peers.filter(p => p.status === 'offline').length} offline` },
  ];

  const [current, setCurrent] = _useState(-1);
  const [results, setResults] = _useState({});
  const [done, setDone] = _useState(false);
  const [running, setRunning] = _useState(false);
  const [apiError, setApiError] = _useState(null);
  const [hidden, setHidden] = _useState(false);
  const bgToastRef     = _useRef(null);
  const closedRef      = _useRef(false);
  const runningRef     = _useRef(false);
  const cleanupTimerRef = _useRef(null);

  const handleClose = () => {
    if (runningRef.current) {
      closedRef.current = true;
      setHidden(true);
      bgToastRef.current = window.WG.toast?.loading('Port check in progress…');
    } else {
      onClose();
    }
  };

  _useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') handleClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const run = async () => {
    // Reset background-run state so re-runs behave like a fresh open
    closedRef.current = false;
    clearTimeout(cleanupTimerRef.current);
    bgToastRef.current?.dismiss();
    bgToastRef.current = null;

    runningRef.current = true;
    setRunning(true);
    setDone(false);
    setResults({});
    setCurrent(0);
    setApiError(null);

    let stepResults = {};
    try {
      // Fetch all diagnostic data in parallel
      const [status, diag, health] = await Promise.all([
        window.WG.apiCall('/api/status', { silent: true }).catch(() => null),
        window.WG.apiCall('/api/diag/vpn', { silent: true }).catch(() => null),
        window.WG.apiCall('/api/health', { silent: true }).catch(() => null),
      ]);

      const port = (status && status.network && status.network.port) || 51820;
      const portStatus = await window.WG.apiCall('/api/ports?proto=udp&port=' + port, { silent: true }).catch(() => null);

      const connectedPeers = peers.filter(p => p.status === 'connected').length;

      stepResults = {
        'iface':     (status && status.service && status.service.active) ? 'ok' : 'fail',
        'listen':    (portStatus && portStatus.listening) ? 'ok' : 'fail',
        'fw-in':     (portStatus && portStatus.ufw_allowed) ? 'ok' : 'warn',
        'fw-fwd':    (diag && diag.ip_forward) ? 'ok' : 'fail',
        'nat':       (diag && diag.has_postup) ? 'ok' : 'warn',
        'dns':       (health && health.ping_ok) ? 'ok' : 'warn',
        'handshake': connectedPeers > 0 ? 'ok' : (peers.length > 0 ? 'warn' : 'ok'),
      };

      // Reveal one by one with animation (skip if hidden in background)
      if (!closedRef.current) {
        for (let i = 0; i < steps.length; i++) {
          setCurrent(i);
          await new Promise(r => setTimeout(r, 350 + Math.random() * 300));
          setResults(prev => ({ ...prev, [steps[i].id]: stepResults[steps[i].id] }));
        }
      }
    } catch (e) {
      setApiError(e.message || 'API unreachable');
      steps.forEach(s => { stepResults[s.id] = 'fail'; });
    }

    runningRef.current = false;
    setRunning(false);
    setDone(true);
    setCurrent(-1);
    window.WG.apiCall('/api/diag/refresh', { method: 'POST', silent: true }).catch(() => {});

    if (closedRef.current && bgToastRef.current) {
      const vals = Object.values(stepResults);
      const f = vals.filter(v => v === 'fail').length;
      const w = vals.filter(v => v === 'warn').length;
      const p = vals.filter(v => v === 'ok').length;

      const DURATION = 8000;
      const stats = [
        f > 0 && { color: 'var(--danger)', count: f, label: f === 1 ? 'failed'  : 'failed'  },
        w > 0 && { color: 'var(--warn)',   count: w, label: w === 1 ? 'warning' : 'warnings' },
        p > 0 && { color: 'var(--success)',count: p, label: p === 1 ? 'passed'  : 'passed'  },
      ].filter(Boolean);

      const viewResultsIcon = <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>;

      bgToastRef.current.update({
        type: f > 0 ? 'error' : w > 0 ? 'warning' : 'success',
        title: 'Port check complete',
        stats,
        action: {
          label: 'View results',
          icon: viewResultsIcon,
          onClick: () => {
            clearTimeout(cleanupTimerRef.current);
            setHidden(false);
          },
        },
        duration: DURATION,
      });

      cleanupTimerRef.current = setTimeout(onClose, DURATION + 300);
    }
  };

  _useEffect(() => {
    run();
    return () => { clearTimeout(cleanupTimerRef.current); bgToastRef.current?.dismiss(); };
  }, []);

  const passed = Object.values(results).filter(v => v === 'ok').length;
  const warned = Object.values(results).filter(v => v === 'warn').length;
  const failed = Object.values(results).filter(v => v === 'fail').length;
  const progress = current === -1 && done ? 1 : current === -1 ? 0 : (current + 0.5) / steps.length;

  if (hidden) return null;

  return (
    <>
      <div className="drawer-scrim" onClick={handleClose} />
      <aside className="drawer" role="dialog" aria-label="Port check">
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: 'var(--avatar-bg)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3v18M3 12h18"/><circle cx="12" cy="12" r="9"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">Port check</h2>
              <div className="drawer-sub">
                {running ? 'Running diagnostics…' : done ? `Completed · ${passed} passed, ${warned} warnings, ${failed} failed` : 'Idle'}
              </div>
            </div>
          </div>
          <button className="icon-btn" onClick={handleClose} aria-label="Close">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M6 6l12 12M18 6L6 18"/></svg>
          </button>
        </header>

        <div className="drawer-body">
          <section className="drawer-section">
            <div className="pc-hero">
              <div className="pc-hero-head">
                <span className="section-label">DIAGNOSTIC</span>
                <span className="mono" style={{ color: 'var(--muted)' }}>
                  {done ? `${steps.length}/${steps.length}` : current === -1 ? `0/${steps.length}` : `${current}/${steps.length}`}
                </span>
              </div>
              <div className="pc-progress">
                <div className="pc-progress-fill" style={{ width: `${progress * 100}%` }} />
                {running && <div className="pc-progress-glow" style={{ left: `${progress * 100}%` }} />}
              </div>
              <div className="pc-summary">
                <span className="pc-stat pc-ok"><span className="pc-dot" /> {passed} passed</span>
                <span className="pc-stat pc-warn"><span className="pc-dot" /> {warned} warnings</span>
                <span className="pc-stat pc-fail"><span className="pc-dot" /> {failed} failed</span>
              </div>
            </div>
          </section>

          <section className="drawer-section">
            <div className="pc-steps">
              <div className="pc-line" />
              <div className="pc-line-fill" style={{ height: `${progress * 100}%` }} />
              {steps.map((s, i) => {
                const result = results[s.id];
                const isActive = current === i;
                const isDone = result !== undefined;
                return (
                  <div key={s.id} className={`pc-step ${isActive ? 'active' : ''} ${isDone ? 'done' : ''} ${result ? `result-${result}` : ''}`}>
                    <div className="pc-marker">
                      {isDone ? (
                        result === 'ok' ? (
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="M5 12l5 5L20 7"/></svg>
                        ) : result === 'warn' ? (
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>
                        ) : (
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="M6 6l12 12M18 6L6 18"/></svg>
                        )
                      ) : isActive ? (
                        <span className="pc-spinner" />
                      ) : (
                        <span className="pc-idle-dot" />
                      )}
                    </div>
                    <div className="pc-step-body">
                      <div className="pc-step-title">{s.label}</div>
                      <div className="pc-step-detail">
                        {s.detail}
                        {isActive && <span className="pc-typing">...</span>}
                      </div>
                      {isDone && (
                        <div className={`pc-badge pc-badge-${result}`}>
                          {result === 'ok' ? 'OK' : result === 'warn' ? 'WARNING' : 'FAILED'}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          {done && (() => {
            if (apiError) {
              return (
                <section className="drawer-section">
                  <div className="pc-tip">
                    <div className="pc-tip-icon">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v5M12 16h.01"/></svg>
                    </div>
                    <div className="pc-tip-body">
                      <div className="pc-tip-title">API unreachable</div>
                      <div className="pc-tip-desc">{apiError}</div>
                    </div>
                  </div>
                </section>
              );
            }
            const firstIssue = steps.find(s => results[s.id] === 'warn' || results[s.id] === 'fail');
            if (!firstIssue) {
              return (
                <section className="drawer-section">
                  <div className="pc-tip pc-tip-ok">
                    <div className="pc-tip-icon">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M5 12l5 5L20 7"/></svg>
                    </div>
                    <div className="pc-tip-body">
                      <div className="pc-tip-title">All checks passed</div>
                      <div className="pc-tip-desc">Your tunnel is configured correctly and reachable from the internet. No action required.</div>
                    </div>
                  </div>
                </section>
              );
            }
            const tips = {
              iface:     { title: 'Interface wg0 missing or down',     desc: 'The WireGuard service is not active. Start it and verify the config file.', cmd: 'sudo systemctl start wg-quick@wg0\nsudo wg show wg0' },
              listen:    { title: 'Port 51820 is not bound',            desc: 'Nothing is listening on the WireGuard UDP port. Check ListenPort in the config, then restart.', cmd: 'sudo ss -ulnp | grep 51820\nsudo systemctl restart wg-quick@wg0' },
              'fw-in':   { title: 'Inbound UDP not in UFW rules',       desc: 'Add an accept rule for UDP 51820 on your WAN interface.', cmd: 'sudo ufw allow 51820/udp\nsudo ufw reload' },
              'fw-fwd':  { title: 'IP forwarding disabled',             desc: 'Packets from peers cannot be routed. Enable forwarding in the kernel.', cmd: 'sudo sysctl -w net.ipv4.ip_forward=1\necho "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-wg.conf' },
              nat:       { title: 'NAT / PostUp rule missing',          desc: 'Outbound traffic from peers is not being masqueraded. Use the "Fix Issues" button or add the rule manually.', cmd: 'sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE' },
              dns:       { title: 'No internet connectivity from server', desc: 'The server cannot reach 1.1.1.1. Check your routing table and default gateway.', cmd: 'ping -c3 1.1.1.1\nip route show' },
              handshake: { title: 'No peers have connected recently',   desc: 'Verify peer configs are correct, PersistentKeepalive is set, and their endpoint points to this server.', cmd: 'sudo wg show wg0 latest-handshakes' },
            };
            const tip = tips[firstIssue.id];
            return (
              <section className="drawer-section">
                <div className="section-head"><span className="section-label">HOW TO RESOLVE</span></div>
                <div className="pc-tip">
                  <div className="pc-tip-icon">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2a7 7 0 00-4 12.7V17a2 2 0 002 2h4a2 2 0 002-2v-2.3A7 7 0 0012 2zM9 22h6"/></svg>
                  </div>
                  <div className="pc-tip-body">
                    <div className="pc-tip-title">{tip.title}</div>
                    <div className="pc-tip-desc">{tip.desc}</div>
                    <div className="pc-tip-cmd">
                      <button className="cmd-copy" onClick={() => navigator.clipboard?.writeText(tip.cmd)}>COPY</button>
                      {tip.cmd.split('\n').map((line, i) => (
                        <div key={i}>
                          <span className="cmd-prompt">{line.startsWith('#') ? '' : '$ '}</span>{line}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </section>
            );
          })()}

          <section className="drawer-section">
            <div className="action-row">
              <button className="btn btn-primary" onClick={run} disabled={running}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 12a9 9 0 11-9-9c2.5 0 4.7 1 6.4 2.6L21 3v6h-6"/></svg>
                {running ? 'Running…' : 'Re-run check'}
              </button>
            </div>
          </section>
        </div>
      </aside>
    </>
  );
}

// ============================================================
// SettingsDrawer — accent color, server info, software update
// ============================================================
const UPDATE_STAGES = [
  { id: 'fetch',   label: 'Fetching updates',  detail: 'checking origin/main' },
  { id: 'pull',    label: 'Pulling changes',    detail: 'merging commits' },
  { id: 'restart', label: 'Restarting service', detail: 'wg-dashboard' },
];

const UPD_COOLDOWN_MS = 30_000;
const UPD_COOLDOWN_KEY = 'WG_UPDATE_COOLDOWN_END';

function CountdownRing({ remaining }) {
  const secs = Math.ceil(remaining / 1000);
  const digits = String(secs).split('');
  return (
    <span style={{ fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--muted)', flexShrink: 0 }}>
      {digits.map((d, i) => (
        <span key={`${i}_${d}`} style={{ display: 'inline-block', animation: 'numFlyUp 0.3s cubic-bezier(0.2, 0.9, 0.25, 1) both' }}>{d}</span>
      ))}s
    </span>
  );
}

function ChangePasswordSection() {
  return (
    <section className="drawer-section">
      <div className="section-head"><span className="section-label">SECURITY</span></div>
      <div className="settings-list">
        <div className="setting-row">
          <div>
            <div className="setting-title">Dashboard password</div>
            <div className="setting-desc">Change the password used to log in to this dashboard</div>
          </div>
          <div className="setting-control">
            <button className="btn btn-primary" onClick={() => window.location.href = '/change-password'}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
              Change
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}

function SettingsDrawer({ tweaks, setTweaks, onClose, onUpdateAvailable }) {
  const accent = tweaks.accent || 'terracotta';
  const [version, setVersion] = _useState('…');
  const [newVersion, setNewVersion] = _useState('');
  const [phase, setPhase] = _useState('loading');
  const [sysInfo, setSysInfo] = _useState(null);
  const [avatarState, setAvatarState] = _useState('loading');
  const [stageIdx, setStageIdx] = _useState(-1);
  const [stageDetails, setStageDetails] = _useState({});
  const [updateError, setUpdateError] = _useState('');
  const rafRef = _useRef(null);
  const fillRef = _useRef(null);
  const glowRef = _useRef(null);
  const pctRef = _useRef(null);
  const progressRef = _useRef(0);

  const paint = (p) => {
    progressRef.current = p;
    if (fillRef.current) fillRef.current.style.width = p + '%';
    if (glowRef.current) glowRef.current.style.left = p + '%';
    if (pctRef.current) pctRef.current.textContent = Math.round(p) + '%';
  };

  const animateTo = (target, dur, onDone) => {
    dur = dur || 500;
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    const from = progressRef.current;
    const start = performance.now();
    const step = (now) => {
      const t = Math.min(1, (now - start) / dur);
      const eased = t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
      paint(from + (target - from) * eased);
      if (t < 1) {
        rafRef.current = requestAnimationFrame(step);
      } else if (onDone) {
        onDone();
      }
    };
    rafRef.current = requestAnimationFrame(step);
  };

  const [checking, setChecking] = _useState(false);
  const [cooldownEnd, setCooldownEnd] = _useState(() => {
    try { const v = Number(localStorage.getItem(UPD_COOLDOWN_KEY)); return (v && v > Date.now()) ? v : null; } catch { return null; }
  });
  const [remaining, setRemaining] = _useState(() => {
    try { const v = Number(localStorage.getItem(UPD_COOLDOWN_KEY)); return (v && v > Date.now()) ? v - Date.now() : 0; } catch { return 0; }
  });
  const onCooldown = remaining > 0;
  const [advancedOpen, setAdvancedOpen] = _useState(false);
  const [chartFineOpen, setChartFineOpen] = _useState(false);
  const [softColorsFineOpen, setSoftColorsFineOpen] = _useState(false);
  const devUpdatesRef = _useRef(tweaks.devUpdates);
  devUpdatesRef.current = tweaks.devUpdates;
  const prevDevUpdatesRef = _useRef(tweaks.devUpdates);

  const checkForUpdates = (manual) => {
    const devParam = devUpdatesRef.current ? '?dev=1' : '';
    if (manual) setChecking(true);
    Promise.all([
      fetch(`/api/update/check${devParam}`).then(r => r.json()),
      fetch('/api/system/info').then(r => r.json()),
      manual ? new Promise(r => setTimeout(r, 2000)) : Promise.resolve(),
    ]).then(([upd, sys]) => {
      setVersion(upd.local || 'unknown');
      setNewVersion(upd.remote || '');
      setPhase(upd.available ? 'available' : 'idle');
      setSysInfo(sys);
      if (upd.available && onUpdateAvailable) onUpdateAvailable(true);
    }).catch(() => { setVersion('unknown'); setPhase('idle'); })
      .finally(() => {
        if (!manual) return;
        setChecking(false);
        const end = Date.now() + UPD_COOLDOWN_MS;
        setCooldownEnd(end);
        try { localStorage.setItem(UPD_COOLDOWN_KEY, String(end)); } catch {}
      });
  };

  _useEffect(() => {
    if (!cooldownEnd) { setRemaining(0); return; }
    const tick = () => {
      const r = Math.max(0, cooldownEnd - Date.now());
      setRemaining(r);
      if (r === 0) {
        setCooldownEnd(null);
        try { localStorage.removeItem(UPD_COOLDOWN_KEY); } catch {}
      }
    };
    tick();
    const id = setInterval(tick, 100);
    return () => clearInterval(id);
  }, [cooldownEnd]);

  _useEffect(() => {
    checkForUpdates(false);
    const id = setInterval(() => checkForUpdates(false), 10 * 60 * 1000);
    return () => clearInterval(id);
  }, []);

  _useEffect(() => {
    if (prevDevUpdatesRef.current === tweaks.devUpdates) return;
    prevDevUpdatesRef.current = tweaks.devUpdates;
    checkForUpdates(false);
  }, [tweaks.devUpdates]);

  _useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape' && phase !== 'updating') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose, phase]);

  _useEffect(() => () => {
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
  }, []);

  const setAccent = (id) => {
    setTweaks({ ...tweaks, accent: id });
  };

  const runUpdate = () => {
    setPhase('updating');
    setStageIdx(0);
    setStageDetails({});
    setUpdateError('');
    paint(0);

    fetch(`/api/update/apply${tweaks.devUpdates ? '?dev=1' : ''}`, { method: 'POST' })
      .then(res => {
        if (!res.ok || !res.body) throw new Error('Request failed');
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';
        const read = () => reader.read().then(({ done, value }) => {
          if (done) return;
          buf += decoder.decode(value, { stream: true });
          const parts = buf.split('\n\n');
          buf = parts.pop();
          parts.forEach(part => {
            const line = part.trim();
            if (!line.startsWith('data: ')) return;
            try {
              const evt = JSON.parse(line.slice(6));
              if (evt.event === 'stage') {
                const idx = UPDATE_STAGES.findIndex(s => s.id === evt.id);
                if (idx >= 0) setStageIdx(idx);
                if (evt.detail) setStageDetails(prev => {
                  const existing = prev[evt.id] || [];
                  const last = existing[existing.length - 1];
                  return last === evt.detail ? prev : { ...prev, [evt.id]: [...existing, evt.detail] };
                });
                animateTo(evt.progress || 0);
              } else if (evt.event === 'done') {
                animateTo(100, 600, () => {
                  setStageIdx(UPDATE_STAGES.length);
                  if (evt.version) setVersion(evt.version);
                  setPhase('done');
                });
              } else if (evt.event === 'error') {
                setUpdateError(evt.detail || 'Unknown error');
                setPhase('error');
              }
            } catch (_) {}
          });
          read();
        }).catch(err => {
          setUpdateError('Stream error: ' + (err.message || 'closed'));
          setPhase('error');
        });
        read();
      })
      .catch(err => {
        setUpdateError('Connection failed: ' + (err.message || ''));
        setPhase('error');
      });
  };

  const SI = sysInfo || {};
  const stats = [
    { label: 'Version',      value: version !== '…' ? version : null,               skelW: 72,  mono: true,  highlight: phase === 'done' },
    { label: 'Platform',     value: SI.platform   || null,                           skelW: 110, mono: false },
    { label: 'Kernel',       value: SI.kernel     || null,                           skelW: 150, mono: true  },
    { label: 'Uptime',       value: SI.uptime     || null,                           skelW: 120, mono: false },
    { label: 'Interface',    value: SI.interface  || null,                           skelW: 36,  mono: true  },
    { label: 'Service',      value: SI.service    || null,                           skelW: 100, mono: true  },
  ];

  const accents = [
    { id: 'terracotta', c: 'oklch(59% 0.15 33)',  name: 'Terracotta' },
    { id: 'forest',     c: 'oklch(55% 0.11 150)', name: 'Forest' },
    { id: 'blue',       c: 'oklch(55% 0.22 235)', name: 'Iris'  },
    { id: 'plum',       c: 'oklch(48% 0.12 330)', name: 'Plum' },
    { id: 'ink',        c: 'oklch(52% 0.20 20)',  name: 'Ember' },
  ];

  return (
    <>
      <div className="drawer-scrim" onClick={() => phase !== 'updating' && onClose()} />
      <aside className="drawer" role="dialog" aria-label="Dashboard settings">
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: 'var(--avatar-bg)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 11-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 110-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 114 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 110 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">Dashboard settings</h2>
              <div className="drawer-sub" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                {SI.service ? SI.service : <span className="skel skel-sub" style={{ width: 100 }} />}
                {' · '}
                {SI.service_enabled != null ? (SI.service_enabled ? 'enabled' : 'disabled') : <span className="skel skel-sub" style={{ width: 52 }} />}
              </div>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close" disabled={phase === 'updating'}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M6 6l12 12M18 6L6 18"/></svg>
          </button>
        </header>

        <div className="drawer-body">
          <section className="drawer-section">
            <div className="section-head"><span className="section-label">ACCENT COLOR</span></div>
            <div className="set-accent-grid">
              {accents.map(a => (
                <button key={a.id} className={`set-accent ${accent === a.id ? 'on' : ''}`} onClick={() => setAccent(a.id)}>
                  <span className="set-accent-dot" style={{ background: a.c }}>
                    {accent === a.id && (
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3.2"><path d="M5 12l5 5L20 7"/></svg>
                    )}
                  </span>
                  <span className="set-accent-name">{a.name}</span>
                </button>
              ))}
            </div>
            <div className="settings-list" style={{ marginTop: '10px' }}>
              <div className="setting-row">
                <div className="setting-row-main">
                  <span className="soft-preview" aria-hidden="true">
                    <span className="soft-preview-swatch soft-preview-before" />
                    <span className="soft-preview-swatch soft-preview-after" />
                  </span>
                  <div>
                    <div className="setting-title">Soft colors</div>
                    <div className="setting-desc">Warm cream / charcoal surfaces instead of plain white</div>
                  </div>
                </div>
                <div className="setting-control" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <button
                    className="chart-fine-toggle"
                    onClick={() => setSoftColorsFineOpen(v => !v)}
                    aria-expanded={softColorsFineOpen}
                    title="Fine-tune accent tinting"
                  >
                    Customize
                    <svg style={{ transform: softColorsFineOpen ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }} width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 9l6 6 6-6"/></svg>
                  </button>
                  <button
                    className={`toggle ${tweaks.softColors ? 'on' : ''}`}
                    onClick={() => setTweaks({ ...tweaks, softColors: !tweaks.softColors })}
                    aria-pressed={!!tweaks.softColors}
                  >
                    <span className="toggle-knob" />
                  </button>
                </div>
              </div>

              {/* Accent tint — independent of soft colors, so it works on plain
                  surfaces or warm ones, in light or dark mode. Collapsed by
                  default, opened via the Customize toggle above. */}
              <div className={`collapse-rows${softColorsFineOpen ? ' open' : ''}`}>
                <div>
                  <div className="chart-fine-list">
                    <div className="setting-row">
                      <div>
                        <div className="setting-title">Accent tint</div>
                        <div className="setting-desc">Text, numbers and icons pick up shades of your accent color, in both light and dark mode. Backgrounds, containers and input fields stay neutral.</div>
                      </div>
                      <div className="setting-control">
                        <button
                          className={`toggle ${tweaks.accentTint ? 'on' : ''}`}
                          onClick={() => setTweaks({ ...tweaks, accentTint: !tweaks.accentTint })}
                          aria-pressed={!!tweaks.accentTint}
                        >
                          <span className="toggle-knob" />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {(() => {
            const chartsAllOn = tweaks.splineChart && tweaks.smoothThroughput && tweaks.smoothScale;
            const chartsAnyOn = tweaks.splineChart || tweaks.smoothThroughput || tweaks.smoothScale;
            return (
          <section className="drawer-section">
            <div className="section-head"><span className="section-label">CHARTS</span></div>
            <div className="settings-list">
              {/* Master switch — flips all three chart-smoothing settings at once. */}
              <div className="setting-row">
                <div>
                  <div className="setting-title">Smooth charts</div>
                  <div className="setting-desc">Spline lines, continuous scroll and animated Y-axis scaling</div>
                </div>
                <div className="setting-control" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <button
                    className="chart-fine-toggle"
                    onClick={() => setChartFineOpen(v => !v)}
                    aria-expanded={chartFineOpen}
                    title="Fine-tune individual chart settings"
                  >
                    Customize
                    <svg style={{ transform: chartFineOpen ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }} width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 9l6 6 6-6"/></svg>
                  </button>
                  <button
                    className={`toggle ${chartsAnyOn ? 'on' : ''} ${chartsAnyOn && !chartsAllOn ? 'mixed' : ''}`}
                    onClick={() => setTweaks({ ...tweaks, splineChart: !chartsAllOn, smoothThroughput: !chartsAllOn, smoothScale: !chartsAllOn })}
                    aria-pressed={chartsAllOn}
                    title={chartsAllOn ? 'Turn all chart smoothing off' : 'Turn all chart smoothing on'}
                  >
                    <span className="toggle-knob" />
                  </button>
                </div>
              </div>

              {/* Fine controls — collapsed by default, animates open via grid-rows. */}
              <div className={`collapse-rows${chartFineOpen ? ' open' : ''}`}>
                <div>
                  <div className="chart-fine-list">
                    <div className="setting-row">
                      <div>
                        <div className="setting-title">Smooth lines</div>
                        <div className="setting-desc">Use spline interpolation on the live throughput chart</div>
                      </div>
                      <div className="setting-control" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div className={`tension-slider-wrap${tweaks.splineChart ? ' visible' : ''}`}>
                          <span style={{ fontSize: 10, color: 'var(--muted)', fontFamily: 'var(--mono)', minWidth: 26, textAlign: 'right' }}>
                            {(tweaks.splineTension ?? 1).toFixed(1)}
                          </span>
                          <input
                            type="range" min="0" max="3" step="0.1"
                            value={tweaks.splineTension ?? 1}
                            onChange={e => setTweaks({ ...tweaks, splineTension: parseFloat(e.target.value) })}
                            className="tension-slider"
                            style={{ background: `linear-gradient(to right, var(--accent) ${((tweaks.splineTension ?? 1) / 3) * 100}%, var(--border) ${((tweaks.splineTension ?? 1) / 3) * 100}%)` }}
                          />
                        </div>
                        <button
                          className={`toggle ${tweaks.splineChart ? 'on' : ''}`}
                          onClick={() => setTweaks({ ...tweaks, splineChart: !tweaks.splineChart })}
                          aria-pressed={tweaks.splineChart}
                        >
                          <span className="toggle-knob" />
                        </button>
                      </div>
                    </div>
                    <div className="setting-row">
                      <div>
                        <div className="setting-title">Continuous scroll</div>
                        <div className="setting-desc">Scrolls the chart between poll updates instead of jumping at each interval</div>
                      </div>
                      <div className="setting-control">
                        <button
                          className={`toggle ${tweaks.smoothThroughput ? 'on' : ''}`}
                          onClick={() => setTweaks({ ...tweaks, smoothThroughput: !tweaks.smoothThroughput })}
                          aria-pressed={tweaks.smoothThroughput}
                        >
                          <span className="toggle-knob" />
                        </button>
                      </div>
                    </div>
                    <div className="setting-row">
                      <div>
                        <div className="setting-title">Smooth Y-axis scaling</div>
                        <div className="setting-desc">Animates the Y-axis when throughput crosses unit boundaries instead of snapping</div>
                      </div>
                      <div className="setting-control">
                        <button
                          className={`toggle ${tweaks.smoothScale ? 'on' : ''}`}
                          onClick={() => setTweaks({ ...tweaks, smoothScale: !tweaks.smoothScale })}
                          aria-pressed={tweaks.smoothScale}
                        >
                          <span className="toggle-knob" />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>
            );
          })()}

          <section className="drawer-section">
            <div className="section-head"><span className="section-label">SERVER</span></div>
            <div className="set-stats">
              {stats.map((s, i) => (
                <div className="set-stat" key={s.label}>
                  <div className="set-stat-label">{s.label}</div>
                  <div className={`set-stat-val ${s.mono ? 'mono' : ''} ${s.highlight ? 'is-new' : ''}`}>
                    {s.value != null
                      ? <span className="set-stat-in">{s.value}</span>
                      : <span className="skel skel-stat" style={{ width: s.skelW, animationDelay: `${i * -110}ms` }} />}
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head"><span className="section-label">SOFTWARE UPDATE</span></div>

            {phase === 'loading' && (
              <div className="upd-card" style={{display:'flex',alignItems:'center',gap:'8px',color:'var(--text-2)',fontSize:'13px'}}>
                <span className="pc-spinner" style={{width:'14px',height:'14px',flexShrink:0}} />
                Fetching updates…
              </div>
            )}

            {phase === 'idle' && (
              <div className="upd-card upd-idle-card">
                <div className={`upd-idle-content${checking ? ' is-blurring' : ''}`}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2.2" style={{flexShrink:0}}><path d="M5 12l5 5L20 7"/></svg>
                  <span style={{color:'var(--text-2)',fontSize:'13px',flex:1}}>Up to date · <span className="mono">{version}</span></span>
                  {onCooldown && <CountdownRing remaining={remaining} />}
                  <button className="icon-btn" onClick={() => checkForUpdates(true)} aria-label="Check for updates" title={onCooldown ? 'Check again in a moment' : 'Check for updates'} disabled={checking || onCooldown}>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12a9 9 0 11-9-9c2.5 0 4.7 1 6.4 2.6L21 3v6h-6"/></svg>
                  </button>
                </div>
                <div className={`upd-fetch-overlay${checking ? ' is-active' : ''}`}>
                  <span className="pc-spinner" style={{width:'12px',height:'12px',flexShrink:0}} />
                  <span className="upd-fetch-text">Fetching updates</span>
                </div>
              </div>
            )}

            {phase === 'available' && (
              <div className="upd-card upd-available">
                <div className="upd-badge-row">
                  <span className="upd-pill">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>
                    Update available
                  </span>
                </div>
                <div className="upd-ver-flow">
                  <span className="upd-ver upd-ver-old mono">{version}</span>
                  <svg className="upd-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14m-6-6l6 6-6 6"/></svg>
                  <span className="upd-ver upd-ver-new mono">{newVersion}</span>
                </div>
                <div className="upd-notes">New version available on GitHub. The service will be restarted to apply the update.</div>
                <button className="btn btn-primary upd-btn" onClick={runUpdate}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 12a9 9 0 11-9-9c2.5 0 4.7 1 6.4 2.6L21 3v6h-6"/></svg>
                  Install update
                </button>
              </div>
            )}

            {phase === 'updating' && (
              <div className="upd-card">
                <div className="upd-progress-head">
                  <span className="upd-stage-name">{UPDATE_STAGES[Math.min(stageIdx, UPDATE_STAGES.length - 1)]?.label}<span className="pc-typing">…</span></span>
                  <span className="upd-pct mono" ref={pctRef}>0%</span>
                </div>
                <div className="upd-progress">
                  <div className="upd-progress-fill" ref={fillRef} />
                  <div className="upd-progress-glow" ref={glowRef} />
                </div>
                <div className="upd-steplist">
                  {UPDATE_STAGES.map((s, i) => {
                    const done = i < stageIdx;
                    const active = i === stageIdx;
                    const details = stageDetails[s.id] || [s.detail];
                    return (
                      <div key={s.id} className={`upd-step ${done ? 'done' : ''} ${active ? 'active' : ''}`}>
                        <span className="upd-step-marker">
                          {done ? (
                            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="M5 12l5 5L20 7"/></svg>
                          ) : active ? (
                            <span className="pc-spinner" />
                          ) : (
                            <span className="pc-idle-dot" />
                          )}
                        </span>
                        <span className="upd-step-body">
                          <span className="upd-step-label">{s.label}</span>
                          {(active || done) && details.map((d, di) => (
                            <span key={di} className="upd-step-detail mono">{d}</span>
                          ))}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {phase === 'error' && (
              <div className="upd-card" style={{borderColor:'oklch(72% 0.16 25)',background:'oklch(99% 0.01 25)'}}>
                <div style={{display:'flex',gap:'8px',alignItems:'flex-start'}}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="oklch(55% 0.18 25)" strokeWidth="2" style={{marginTop:'1px',flexShrink:0}}><circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/></svg>
                  <div>
                    <div style={{fontWeight:'600',fontSize:'13px',color:'oklch(45% 0.15 25)'}}>Update failed</div>
                    <div style={{fontSize:'12px',color:'var(--text-2)',marginTop:'3px',fontFamily:'var(--font-mono)',wordBreak:'break-all'}}>{updateError}</div>
                  </div>
                </div>
                <button className="btn btn-primary upd-btn" onClick={runUpdate} style={{marginTop:'12px'}}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 12a9 9 0 11-9-9c2.5 0 4.7 1 6.4 2.6L21 3v6h-6"/></svg>
                  Retry
                </button>
              </div>
            )}

            {phase === 'done' && (
              <div className="upd-card upd-done">
                <div className="upd-done-check">
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.6"><path d="M5 12l5 5L20 7"/></svg>
                </div>
                <div className="upd-done-title">Update installed</div>
                <div className="upd-done-desc">Now running <span className="mono">{version}</span>. Reload the dashboard to apply the changes.</div>
                <button className="btn btn-primary upd-refresh-btn" onClick={() => window.location.reload()}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9"><path d="M21 12a9 9 0 11-9-9c2.5 0 4.7 1 6.4 2.6L21 3v6h-6"/></svg>
                  Refresh dashboard
                </button>
              </div>
            )}

            <div style={{ marginBottom: '12px' }} />

          <ChangePasswordSection />

            <div className="settings-list" style={{ marginTop: '10px' }}>
              <button
                className="setting-row"
                onClick={() => setAdvancedOpen(v => !v)}
                style={{ width: '100%', textAlign: 'left', cursor: 'pointer', background: 'none', border: 'none', color: 'inherit' }}
              >
                <span style={{ fontSize: '12px', color: 'var(--muted)', fontWeight: '500' }}>Advanced settings</span>
                <svg style={{ transform: advancedOpen ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s', color: 'var(--muted)', flexShrink: 0 }} width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 9l6 6 6-6"/></svg>
              </button>
              <div className={`collapse-rows${advancedOpen ? ' open' : ''}`}>
                <div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-title">Throughput refresh rate</div>
                      <div className="setting-desc">How often the live throughput chart polls for new data</div>
                    </div>
                    <div className="setting-control" style={{ flexDirection: 'column', alignItems: 'flex-end' }}>
                      <div className="seg" style={{ width: 'fit-content' }}>
                        {[{ v: 10, label: '10ms' }, { v: 500, label: '500ms' }, { v: 1000, label: '1s' }, { v: 2000, label: '2s' }, { v: 5000, label: '5s' }].map(({ v, label }) => (
                          <button
                            key={v}
                            className={tweaks.refreshInterval === v ? 'on' : ''}
                            onClick={() => setTweaks({ ...tweaks, refreshInterval: v })}
                          >{label}</button>
                        ))}
                      </div>
                      <div style={{
                        display: 'flex', alignItems: 'center', gap: 4,
                        maxHeight: tweaks.refreshInterval <= 500 ? '20px' : '0',
                        opacity: tweaks.refreshInterval <= 500 ? 1 : 0,
                        marginTop: tweaks.refreshInterval <= 500 ? '5px' : '0',
                        overflow: 'hidden',
                        transition: 'max-height 0.22s ease, opacity 0.18s ease, margin-top 0.22s ease',
                      }}>
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0zM12 9v4M12 17h.01"/></svg>
                        <span style={{ fontSize: '10px', color: 'var(--muted)' }}>High server load</span>
                      </div>
                    </div>
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-title">Developer updates</div>
                      <div className="setting-desc">Opt in to pre-release builds — may be unstable or contain bugs</div>
                    </div>
                    <div className="setting-control">
                      <button
                        className={`toggle ${tweaks.devUpdates ? 'on' : ''}`}
                        onClick={() => setTweaks({ ...tweaks, devUpdates: !tweaks.devUpdates })}
                        aria-pressed={tweaks.devUpdates}
                      >
                        <span className="toggle-knob" />
                      </button>
                    </div>
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-title">Traffic mode <span style={{ fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--muted)', marginLeft: 4 }}>experimental</span></div>
                      <div className="setting-desc">Show per-peer live traffic breakdown — not fully implemented yet</div>
                    </div>
                    <div className="setting-control">
                      <button
                        className={`toggle ${tweaks.trafficMode ? 'on' : ''}`}
                        onClick={() => setTweaks({ ...tweaks, trafficMode: !tweaks.trafficMode })}
                        aria-pressed={!!tweaks.trafficMode}
                      >
                        <span className="toggle-knob" />
                      </button>
                    </div>
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-title">Welcome tour</div>
                      <div className="setting-desc">Re-open the setup walkthrough from the beginning</div>
                    </div>
                    <div className="setting-control">
                      <button
                        className="btn"
                        onClick={() => window.location.href = '/welcome'}
                      >Show</button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head"><span className="section-label">ABOUT</span></div>
            <a
              className="gh-profile"
              href="https://github.com/Migrim/Wireguard-Quick"
              target="_blank"
              rel="noopener noreferrer"
            >
              <span className={`gh-avatar-wrap ${avatarState === 'ready' ? 'is-ready' : ''}`}>
                {avatarState === 'loading' && <span className="skel gh-avatar-skel" />}
                {avatarState === 'error' && (
                  <span className="gh-avatar-fallback" aria-hidden="true">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                  </span>
                )}
                <img
                  className="gh-avatar"
                  src="https://github.com/Migrim.png?size=160"
                  srcSet="https://github.com/Migrim.png?size=80 1x, https://github.com/Migrim.png?size=160 2x"
                  alt="Migrim"
                  width="40"
                  height="40"
                  decoding="async"
                  onLoad={() => setAvatarState('ready')}
                  onError={() => setAvatarState('error')}
                />
              </span>
              <div className="gh-meta">
                <div className="gh-user">Migrim</div>
                <div className="gh-repo">Wireguard-Quick</div>
              </div>
              <span className="gh-open" aria-hidden="true" title="Open on GitHub">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/></svg>
              </span>
            </a>
          </section>
        </div>
      </aside>
    </>
  );
}

// ============================================================
// UptimeDrawer — service availability history + downtime log
// ============================================================
const UPTIME_RANGES = ['24h', '7d', '30d', '90d'];

function _fmtLiveDur(ms) {
  if (!ms || ms <= 0) return '—';
  let s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400); s -= d * 86400;
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${String(s).padStart(2, '0')}s`;
  return `${m}m ${String(s).padStart(2, '0')}s`;
}

function _fmtDurS(sec) {
  if (sec == null) return '—';
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
  if (d > 0) return `${d}d ${h % 24}h`;
  if (h > 0) return `${h}h ${m % 60}m`;
  return `${m}m ${sec % 60}s`;
}

function _fmtPct(pct) {
  if (pct == null) return '—';
  if (pct >= 100) return '100%';
  return `${pct.toFixed(pct >= 99 ? 2 : 1)}%`;
}

// European (DD.MM.YYYY HH:MM) formatting for the downtime/outage log.
function _fmtEuTime(ms) {
  if (!ms) return '—';
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
function _fmtEuRange(startMs, endMs) {
  if (!endMs) return _fmtEuTime(startMs);
  const s = new Date(startMs), e = new Date(endMs);
  const p = (n) => String(n).padStart(2, '0');
  // Collapse to a single date when the outage starts and ends the same day.
  const endStr = s.toDateString() === e.toDateString() ? `${p(e.getHours())}:${p(e.getMinutes())}` : _fmtEuTime(endMs);
  return `${_fmtEuTime(startMs)} → ${endStr}`;
}

const INCIDENTS_PAGE = 5;
const LAT_BARS = 96; // fixed latency-chart bar count (matches backend downsample cap)

const UPTIME_TARGET_NAMES = { '1.1.1.1': 'Cloudflare', '1.0.0.1': 'Cloudflare', '8.8.8.8': 'Google', '8.8.4.4': 'Google' };
const _pingTargetLabel = (ip) => ip ? `${ip}${UPTIME_TARGET_NAMES[ip] ? ` (${UPTIME_TARGET_NAMES[ip]})` : ''}` : '—';

function UpAvailabilitySection({ stats, loaded }) {
  const cells = [
    { key: '24h', label: 'LAST 24 HOURS' },
    { key: '7d',  label: 'LAST 7 DAYS' },
    { key: '30d', label: 'LAST 30 DAYS' },
  ].map(({ key, label }) => {
    const s = (stats || {})[key] || {};
    const pct = s.uptime_pct;
    const color = pct == null ? 'var(--muted)'
      : pct < 95 ? 'var(--danger)'
      : pct < 99.5 ? 'var(--warn)'
      : 'var(--ink)';
    const sub = s.down_s > 0 ? `${_fmtDurS(s.down_s)} down` : pct == null ? 'no data yet' : 'no downtime';
    const subExtra = s.down_s > 0 ? `${s.incidents} incident${s.incidents === 1 ? '' : 's'}` : '';
    return { key, label, pct, color, sub, subExtra };
  });
  return (
    <section className="drawer-section">
      <div className="section-head">
        <span className="section-label">AVAILABILITY</span>
        <span className="section-meta">excluding monitoring gaps</span>
      </div>
      <div className="stats-grid">
        {cells.map(c => (
          <div className="stat-cell" key={c.key}>
            <div className="stat-label">{c.label}</div>
            <div className="stat-val" style={{ color: c.color }}>
              {loaded ? _fmtPct(c.pct) : <span className="skel" style={{ width: 64 }} />}
            </div>
            <div className="up-stat-sub mono">{loaded ? c.sub : <span className="skel skel-sub" style={{ width: 80 }} />}</div>
            {loaded && c.subExtra && <div className="up-stat-sub mono">{c.subExtra}</div>}
          </div>
        ))}
      </div>
    </section>
  );
}

function UpTimelineSection({ timeline, range, setRange, loaded, ariaLabel }) {
  const buckets = timeline?.buckets || [];
  const [hover, setHover] = _useState(null); // { i }
  const n = buckets.length;

  const tickText = (b) => {
    if (b.state === 'unknown') return 'no data';
    if (b.state === 'up') return 'up';
    if (b.state === 'down') return `down · ${_fmtDurS(b.down_s)}`;
    return `up ${b.up_pct != null ? b.up_pct.toFixed(1) : '—'}% · down ${_fmtDurS(b.down_s)}`;
  };
  const tickRange = (b) => {
    const bs = (timeline?.bucket_s || 0) * 1000;
    const st = new Date(b.ts_ms);
    const en = new Date(Math.min(b.ts_ms + bs, timeline?.end_ms || b.ts_ms + bs));
    const dOpts = { month: 'short', day: 'numeric' };
    const tOpts = { hour: '2-digit', minute: '2-digit' };
    const sameDay = st.toDateString() === en.toDateString();
    return `${st.toLocaleString([], { ...dOpts, ...tOpts })} – ${en.toLocaleString([], sameDay ? tOpts : { ...dOpts, ...tOpts })}`;
  };
  const onMove = (e) => {
    if (!n) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const i = Math.max(0, Math.min(n - 1, Math.floor((e.clientX - rect.left) / (rect.width || 1) * n)));
    setHover({ i });
  };
  const hv = hover && buckets[hover.i] ? { i: hover.i, b: buckets[hover.i] } : null;

  const rangeStartLabel = timeline?.start_ms
    ? new Date(timeline.start_ms).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    : '';
  return (
    <section className="drawer-section">
      <div className="section-head">
        <span className="section-label">TIMELINE</span>
        <div className="seg">
          {UPTIME_RANGES.map(r => (
            <button key={r} className={range === r ? 'on' : ''} onClick={() => setRange(r)}>{r}</button>
          ))}
        </div>
      </div>
      <div className="up-strip-card">
        {loaded ? (
          <>
            <div
              className="up-strip-wrap"
              onMouseMove={onMove}
              onMouseLeave={() => setHover(null)}
            >
              <div className="up-strip" role="img" aria-label={`${ariaLabel}, last ${range}`}>
                {buckets.map((b, i) => (
                  <span key={i} className={`up-tick up-tick-${b.state}${hv && hv.i === i ? ' is-hover' : ''}`} />
                ))}
              </div>
              {hv && (
                <div
                  className="pingbar-tip"
                  style={{ left: `clamp(70px, ${(((hv.i + 0.5) / n) * 100).toFixed(2)}%, calc(100% - 70px))`, top: -6 }}
                >
                  <span className="pingbar-tip-val up-tip-val">
                    <i className={`up-dot up-tick-${hv.b.state}`} />
                    {tickText(hv.b)}
                  </span>
                  <span className="pingbar-tip-lbl">{tickRange(hv.b)}</span>
                </div>
              )}
            </div>
            <div className="up-strip-labels mono">
              <span>{rangeStartLabel}</span>
              <span>now</span>
            </div>
            <div className="up-legend mono">
              <span><i className="up-dot up-tick-up" /> up</span>
              <span><i className="up-dot up-tick-partial" /> partial</span>
              <span><i className="up-dot up-tick-down" /> down</span>
              <span><i className="up-dot up-tick-unknown" /> no data</span>
            </div>
          </>
        ) : (
          <div className="up-strip">
            {Array.from({ length: 48 }).map((_, i) => <span key={i} className="up-tick up-tick-unknown" style={{ opacity: 0.4 }} />)}
          </div>
        )}
      </div>
    </section>
  );
}

function UpIncidentsSection({ incidents, loaded, now, sectionLabel, downTitle, emptyLabel, monitorSince }) {
  incidents = incidents || [];
  const [shown, setShown] = _useState(INCIDENTS_PAGE);
  const visible = incidents.slice(0, shown);
  const remaining = incidents.length - visible.length;
  return (
    <section className="drawer-section">
      <div className="section-head">
        <span className="section-label">{sectionLabel}</span>
        {loaded && incidents.length > 0 && (
          <span className="section-meta">{incidents.length} event{incidents.length === 1 ? '' : 's'} · last 90 days</span>
        )}
      </div>
      {!loaded ? (
        <div className="up-events">
          {[0, 1].map(i => (
            <div className="up-event" key={i}>
              <span className="up-event-dot" style={{ background: 'var(--border)' }} />
              <div className="up-event-main">
                <div><span className="skel" style={{ width: 120 }} /></div>
                <div style={{ marginTop: 4 }}><span className="skel skel-sub" style={{ width: 200 }} /></div>
              </div>
            </div>
          ))}
        </div>
      ) : incidents.length === 0 ? (
        <div className="up-empty">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--success)" strokeWidth="2.2"><path d="M5 12l5 5L20 7"/></svg>
          <span>{emptyLabel}{monitorSince ? ` since ${_fmtEuTime(monitorSince)}` : ''}</span>
        </div>
      ) : (
        <div className="up-events">
          {visible.map((ev, i) => {
            const isDown = ev.state === 'down';
            const dur = ev.ongoing ? Math.floor((now - ev.start_ms) / 1000) : ev.duration_s;
            return (
              <div key={`${ev.start_ms}-${i}`} className={`up-event ${isDown ? 'is-down' : 'is-gap'}`}>
                <span className="up-event-dot" />
                <div className="up-event-main">
                  <div className="up-event-title">
                    {isDown ? downTitle : 'Monitoring gap'}
                    {ev.ongoing && <span className="up-event-ongoing">ongoing</span>}
                  </div>
                  <div className="up-event-sub mono">
                    {ev.ongoing ? _fmtEuTime(ev.start_ms) : _fmtEuRange(ev.start_ms, ev.end_ms)}
                  </div>
                </div>
                <span className="up-event-dur mono">{_fmtDurS(dur)}</span>
              </div>
            );
          })}
          {remaining > 0 && (
            <button className="up-loadmore" onClick={() => setShown(s => s + INCIDENTS_PAGE)}>
              Load more ({remaining})
            </button>
          )}
        </div>
      )}
      <div className="up-footnote mono">
        {monitorSince
          ? `Monitoring since ${_fmtEuTime(monitorSince)} · history kept for 90 days`
          : 'Monitoring starts with the first sample · history kept for 90 days'}
      </div>
    </section>
  );
}

function UptimeDrawer({ unit, onClose }) {
  const [tab, setTab] = _useState('service');
  const [data, setData] = _useState(null);
  const [range, setRange] = _useState(() => {
    const saved = localStorage.getItem('WG_UPTIME_RANGE');
    return UPTIME_RANGES.includes(saved) ? saved : '24h';
  });
  const [now, setNow] = _useState(Date.now());

  _useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  _useEffect(() => {
    localStorage.setItem('WG_UPTIME_RANGE', range);
    let cancelled = false;
    const load = () => window.WG.apiCall(`/api/uptime?range=${range}`, { silent: true })
      .then(j => { if (!cancelled) setData(j); })
      .catch(() => {});
    load();
    const id = setInterval(load, 15000);
    return () => { cancelled = true; clearInterval(id); };
  }, [range]);

  // Tick the session counter every second while the drawer is open
  _useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const loaded = !!data;
  const cur = data?.current;
  const active = !!cur?.active;
  const sinceMs = cur?.since_ms || 0;
  const sessionMs = sinceMs ? Math.max(0, now - sinceMs) : 0;
  const monitorSince = data?.monitor?.since_ms || 0;
  const intervalS = data?.monitor?.interval_s || 30;

  const net = data?.net;
  const netCur = net?.current;
  const netState = netCur?.state || 'unknown';
  const netUp = netState === 'up';
  const netSinceMs = netCur?.since_ms || 0;
  const netTarget = _pingTargetLabel(netCur?.target || net?.monitor?.targets?.[0]);
  const netLatency = net?.latency || {};
  // Pad to a fixed bar count (matches the backend's 96-point downsample cap) so the
  // chart keeps a stable shape instead of a few fat bars on first boot. Real samples
  // stay right-aligned (newest at the far right); empty slots render as no-data gaps.
  const latRaw = netLatency.series || [];
  const latPad = Math.max(0, LAT_BARS - latRaw.length);
  const latSeries = [...Array(latPad).fill(null), ...latRaw.map(s => s.ms)];
  const latLabels = [...Array(latPad).fill(''), ...latRaw.map(s =>
    new Date(s.ts_ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))];
  const latMeta = netLatency.avg_ms != null
    ? `avg ${netLatency.avg_ms} ms · min ${netLatency.min_ms} · max ${netLatency.max_ms} · last 24h`
    : 'last 24h';

  const sub = tab === 'service'
    ? `${unit || data?.unit || 'wg-quick'} · sampled every ${intervalS}s`
    : `pinging ${netTarget} every ${intervalS}s`;

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Uptime">
        <header className="drawer-head">
          <div className="drawer-head-left">
            <div className="peer-avatar" style={{ background: 'var(--avatar-bg)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
            </div>
            <div>
              <h2 className="drawer-title">Uptime</h2>
              <div className="drawer-sub">{sub}</div>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M6 6l12 12M18 6L6 18"/></svg>
          </button>
        </header>

        <div className="drawer-tabs">
          <button className={`drawer-tab ${tab === 'service' ? 'on' : ''}`} onClick={() => setTab('service')}>Service uptime</button>
          <button className={`drawer-tab ${tab === 'net' ? 'on' : ''}`} onClick={() => setTab('net')}>
            Internet connectivity
            {loaded && !netUp && netState !== 'unknown' && <span className="drawer-tab-dot" title="Internet is unreachable" />}
          </button>
        </div>

        {tab === 'service' && (
        <div className="drawer-body">
          <section className="drawer-section">
            <div className={`up-hero ${loaded ? (active ? 'is-up' : 'is-down') : ''}`}>
              <div className="up-hero-status">
                {loaded ? (
                  <span className={`kpi-badge ${active ? 'badge-ok' : 'badge-down'}`}>
                    <span className={`pulse-dot ${active ? '' : 'pulse-dot-down'}`} />
                    {active ? 'running' : 'stopped'}
                  </span>
                ) : <span className="skel" style={{ width: 60 }} />}
                <span className="up-hero-since mono">
                  {loaded
                    ? (sinceMs ? `since ${window.WG.formatAbsTime(sinceMs)}` : '')
                    : <span className="skel skel-sub" style={{ width: 140 }} />}
                </span>
              </div>
              <div className="up-hero-clock">
                {loaded
                  ? (sinceMs ? _fmtLiveDur(sessionMs) : (active ? '—' : 'stopped'))
                  : <span className="skel" style={{ width: 150, height: 28 }} />}
              </div>
              <div className="up-hero-lbl">{active || !loaded ? 'current session uptime' : 'down for'}</div>
            </div>
          </section>

          <UpAvailabilitySection stats={data?.stats} loaded={loaded} />
          <UpTimelineSection timeline={data?.timeline} range={range} setRange={setRange} loaded={loaded} ariaLabel="Service uptime timeline" />
          <UpIncidentsSection
            incidents={data?.incidents} loaded={loaded} now={now}
            sectionLabel="DOWNTIME LOG" downTitle="Service down"
            emptyLabel="No downtime recorded" monitorSince={monitorSince}
          />
        </div>
        )}

        {tab === 'net' && (
        <div className="drawer-body">
          <section className="drawer-section">
            <div className={`up-hero ${loaded ? (netUp ? 'is-up' : netState === 'down' ? 'is-down' : '') : ''}`}>
              <div className="up-hero-status">
                {loaded ? (
                  <span className={`kpi-badge ${netUp ? 'badge-ok' : netState === 'down' ? 'badge-down' : ''}`}>
                    <span className={`pulse-dot ${netUp ? '' : netState === 'down' ? 'pulse-dot-down' : 'pulse-dot-off'}`} />
                    {netUp ? 'online' : netState === 'down' ? 'offline' : 'no data'}
                  </span>
                ) : <span className="skel" style={{ width: 60 }} />}
                <span className="up-hero-since mono">
                  {loaded
                    ? (netSinceMs ? `since ${window.WG.formatAbsTime(netSinceMs)}` : '')
                    : <span className="skel skel-sub" style={{ width: 140 }} />}
                </span>
              </div>
              <div className="up-hero-clock">
                {loaded
                  ? (netUp
                      ? (netCur?.latency_ms != null ? `${netCur.latency_ms >= 100 ? Math.round(netCur.latency_ms) : netCur.latency_ms.toFixed(1)} ms` : '—')
                      : netState === 'down'
                        ? (netSinceMs ? _fmtLiveDur(Math.max(0, now - netSinceMs)) : 'offline')
                        : '—')
                  : <span className="skel" style={{ width: 150, height: 28 }} />}
              </div>
              <div className="up-hero-lbl">
                {!loaded || netUp ? `current ping · ${netTarget}` : netState === 'down' ? 'offline for' : 'waiting for first sample'}
              </div>
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-head">
              <span className="section-label">LATENCY</span>
              <span className="section-meta">{latMeta}</span>
            </div>
            <div className="drawer-chart">
              {loaded && latRaw.length > 0 ? (
                <PingBars data={latSeries} labels={latLabels} height={72} color="var(--accent-2)" />
              ) : (
                <div className="empty-chart" style={{ height: 72 }}>{loaded ? 'no latency data yet' : 'loading…'}</div>
              )}
            </div>
          </section>

          <UpAvailabilitySection stats={net?.stats} loaded={loaded} />
          <UpTimelineSection timeline={net?.timeline} range={range} setRange={setRange} loaded={loaded} ariaLabel="Internet connectivity timeline" />
          <UpIncidentsSection
            incidents={net?.incidents} loaded={loaded} now={now}
            sectionLabel="OUTAGE LOG" downTitle="Internet down"
            emptyLabel="No outages recorded" monitorSince={net?.monitor?.since_ms || 0}
          />
        </div>
        )}
      </aside>
    </>
  );
}

// ============================================================
Object.assign(window, { PeerDrawer, PeerQrModal, LogsPanel, DataBudgetDrawer, LogsDrawer, PortCheckDrawer, SettingsDrawer, NotifIcon, UptimeDrawer });
