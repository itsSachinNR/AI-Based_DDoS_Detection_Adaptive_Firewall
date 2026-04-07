(() => {
  const initial = window.DDOS_INITIAL || {};

  function currentTheme(status) {
    const isAttack = status === "DDoS Detected";
    return {
      statusClass: isAttack ? "danger" : "normal",
      icon: isAttack ? "⚠" : "🛡"
    };
  }

  function clampPercent(value) {
    const n = Number(value || 0);
    return Math.max(0, Math.min(100, n));
  }

  function safeArray(v, fallback = []) {
    return Array.isArray(v) && v.length ? v : fallback;
  }

  function renderReasons(reasons) {
    const wrap = document.getElementById("reasonList");
    const cardWrap = document.getElementById("reasonListCard");

    const html = (reasons && reasons.length)
      ? reasons.map(r => `<div class="reason-chip">${r}</div>`).join("")
      : `<div class="reason-chip">No strong indicators</div>`;

    if (wrap) wrap.innerHTML = html;
    if (cardWrap) cardWrap.innerHTML = html;
  }

  function renderBlockedIps(blockedIps) {
    const box = document.getElementById("blockedIpsList");
    if (!box) return;

    if (!blockedIps || !blockedIps.length) {
      box.innerHTML = `<div class="empty">No blocked IPs right now.</div>`;
      return;
    }

    box.innerHTML = blockedIps.map(ip => `<span class="blocked-chip">${ip}</span>`).join("");
  }

  function renderAlerts(alerts) {
    const list = document.getElementById("alertsList");
    if (!list) return;

    if (!alerts || !alerts.length) {
      list.innerHTML = `<div class="empty">No alerts yet.</div>`;
      return;
    }

    list.innerHTML = alerts.map(alert => `
      <div class="alert-item warning">
        <div class="alert-title">${alert.message}</div>
        <div class="alert-meta">
          <span>${alert.time}</span>
          <span>Count: ${alert.count}</span>
        </div>
      </div>
    `).join("");
  }

  function renderAttackLogs(logs) {
    const box = document.getElementById("attackLogs");
    if (!box) return;

    if (!logs || !logs.length) {
      box.innerHTML = `<div class="empty">No attacks detected yet.</div>`;
      return;
    }

    box.innerHTML = logs.map(log => `
      <div class="log-item">
        <div class="log-time">${log.time}</div>
        <div class="log-main">
          <div class="log-ip">${log.ip}</div>
          <div class="log-sub">
            ${log.packet_rate} req/s • ${log.confidence}% confidence
            ${log.reasons && log.reasons.length ? ` • ${log.reasons[0]}` : ""}
          </div>
        </div>
        <span class="tag ${log.action === "Blocked" ? "danger" : "warning"}">${log.action}</span>
      </div>
    `).join("");
  }

  function renderRequests(reqs) {
    const table = document.getElementById("requestsTable");
    if (!table) return;

    if (!reqs || !reqs.length) {
      table.innerHTML = `<div class="empty">No requests yet.</div>`;
      return;
    }

    table.innerHTML = reqs.map(req => `
      <div class="request-row">
        <span>${req.time || "-"}</span>
        <span>${req.ip || "-"}</span>
        <span class="method-${(req.method || "GET").toLowerCase()}">${req.method || "GET"}</span>
        <span>${req.path || "-"}</span>
        <span>${req.status ?? "-"}</span>
        <span class="tag ${req.flag === "suspicious" ? "danger" : "success"}">${req.flag || "clean"}</span>
      </div>
    `).join("");
  }

  function renderTopIps(data) {
    const list = document.getElementById("topIpsList");
    if (!list) return;

    const labels = safeArray(data.top_ips_labels, ["Demo traffic"]);
    const values = safeArray(data.top_ips_values, [1]);

    const maxValue = Math.max(...values, 1);

    list.innerHTML = labels.map((ip, idx) => {
      const value = Number(values[idx] || 0);
      const percent = clampPercent((value / maxValue) * 100);
      return `
        <div class="ip-row">
          <div class="ip-row-main">
            <div class="ip-row-ip">${ip}</div>
            <div class="ip-row-sub">Requests: ${value}</div>
          </div>
          <div class="ip-row-bar">
            <div class="ip-row-fill" style="width:${percent}%"></div>
          </div>
        </div>
      `;
    }).join("");
  }

  function renderStatus(data) {
    const theme = currentTheme(data.status);

    const banner = document.getElementById("statusBanner");
    if (banner) {
      banner.classList.remove("normal", "danger");
      banner.classList.add(theme.statusClass);
    }

    const badge = document.getElementById("statusBadge");
    if (badge) {
      badge.className = `status-badge ${theme.statusClass}`;
      badge.textContent = data.status ?? "Normal Traffic";
    }

    const statusIcon = document.getElementById("statusIcon");
    if (statusIcon) {
      statusIcon.textContent = theme.icon;
    }

    const conf = data.confidence ?? 0;

    const confidenceBar = document.getElementById("confidenceBar");
    if (confidenceBar) {
      confidenceBar.style.width = `${clampPercent(conf)}%`;
    }

    const snapshotConfidence = document.getElementById("snapshotConfidence");
    if (snapshotConfidence) snapshotConfidence.textContent = conf;

    const confidence = document.getElementById("confidence");
    if (confidence) confidence.textContent = conf;

    const totalRequests = document.getElementById("totalRequests");
    const uniqueIps = document.getElementById("uniqueIps");
    const topIpCount = document.getElementById("topIpCount");
    const topIpCountText = document.getElementById("topIpCountText");
    const topIp = document.getElementById("topIp");
    const lastUpdated = document.getElementById("lastUpdated");
    const attackProbability = document.getElementById("attackProbability");
    const modelName = document.getElementById("modelName");
    const miniModelName = document.getElementById("miniModelName");
    const rfProb = document.getElementById("rfProb");
    const anomalyProb = document.getElementById("anomalyProb");

    if (totalRequests) totalRequests.textContent = data.total_requests ?? 0;
    if (uniqueIps) uniqueIps.textContent = data.unique_ips ?? 0;
    if (topIpCount) topIpCount.textContent = data.top_ip_count ?? 0;
    if (topIpCountText) topIpCountText.textContent = data.top_ip_count ?? 0;
    if (topIp) topIp.textContent = data.top_ip ?? "-";
    if (lastUpdated) lastUpdated.textContent = data.timestamp ?? "--:--:--";
    if (attackProbability) attackProbability.textContent = `${conf}%`;
    if (modelName) modelName.textContent = data.model_name ?? "Hybrid ML";
    if (miniModelName) miniModelName.textContent = data.model_name ?? "Hybrid ML";
    if (rfProb) rfProb.textContent = data.rf_attack_probability ?? 0;
    if (anomalyProb) anomalyProb.textContent = data.anomaly_attack_probability ?? 0;

    renderReasons(data.reasons || []);
    renderBlockedIps(data.blocked_ips || []);
    renderAlerts(data.alerts || []);
    renderAttackLogs(data.attack_logs || []);
    renderRequests(data.recent_requests || []);
    renderTopIps(data);
  }

  async function refresh() {
    try {
      const res = await fetch("/api/metrics", {
        cache: "no-store",
        headers: {
          "X-Dashboard-Internal": "1"
        }
      });
      const data = await res.json();

      renderStatus(data);
    } catch (err) {
      console.error("Refresh failed:", err);
    }
  }

  function init() {
    renderStatus(initial);

    const refreshBtn = document.getElementById("refreshBtn");
    const simulateBtn = document.getElementById("simulateBtn");

    if (refreshBtn) refreshBtn.addEventListener("click", refresh);
    if (simulateBtn) simulateBtn.addEventListener("click", refresh);

    setInterval(refresh, 2000);
  }

  init();
})();
