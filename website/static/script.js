(() => {
  const initial = window.DDOS_INITIAL || {};

  let ipChart = null;
  let trafficChart = null;
  const threshold = 50;

  function currentTheme(status) {
    const isAttack = status === "DDoS Detected";
    return {
      statusClass: isAttack ? "danger" : "normal",
      icon: isAttack ? "⚠" : "🛡",
      line: isAttack ? "#ef4444" : "#22c55e",
      fill: isAttack ? "rgba(239,68,68,0.18)" : "rgba(34,197,94,0.18)"
    };
  }

  function clampPercent(value) {
    const n = Number(value || 0);
    return Math.max(0, Math.min(100, n));
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
    const confidence = document.getElementById("confidence");
    const snapshotConfidence = document.getElementById("snapshotConfidence");
    const confidenceBar = document.getElementById("confidenceBar");
    const topIpBar = document.getElementById("topIpBar");

    if (confidence) confidence.textContent = conf;
    if (snapshotConfidence) snapshotConfidence.textContent = conf;
    if (confidenceBar) confidenceBar.style.width = `${clampPercent(conf)}%`;
    if (topIpBar) topIpBar.style.width = `${clampPercent(conf)}%`;

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
  }

  function createThresholdPlugin(thresholdValue) {
    return {
      id: "thresholdLine",
      afterDraw(chart) {
        const { ctx, chartArea, scales } = chart;
        if (!chartArea || !scales?.y) return;

        const y = scales.y.getPixelForValue(thresholdValue);

        ctx.save();
        ctx.strokeStyle = "rgba(250,204,21,0.95)";
        ctx.lineWidth = 2;
        ctx.setLineDash([6, 6]);
        ctx.beginPath();
        ctx.moveTo(chartArea.left, y);
        ctx.lineTo(chartArea.right, y);
        ctx.stroke();
        ctx.setLineDash([]);

        ctx.fillStyle = "rgba(250,204,21,0.95)";
        ctx.font = "12px Arial";
        ctx.fillText("Threshold", chartArea.left + 8, y - 8);
        ctx.restore();
      }
    };
  }

  function createIpChart(data) {
    const canvas = document.getElementById("ipChart");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    const labels = data.top_ips_labels?.length ? data.top_ips_labels : ["No traffic"];
    const values = data.top_ips_values?.length ? data.top_ips_values : [0];

    ipChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [{
          data: values,
          borderWidth: 0,
          borderRadius: 12,
          barThickness: 18,
          backgroundColor: values.map((_, idx) => idx === 0 ? "rgba(239,68,68,0.95)" : "rgba(34,211,238,0.9)")
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: "y",
        animation: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { color: "rgba(148,163,184,0.10)" },
            ticks: { color: "#94a3b8" }
          },
          y: {
            grid: { display: false },
            ticks: { color: "#cbd5e1" }
          }
        }
      }
    });
  }

  function createTrafficChart(data) {
    const canvas = document.getElementById("trafficChart");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    const theme = currentTheme(data.status);

    const labels = data.time_labels?.length ? data.time_labels : ["--"];
    const values = data.rate_history?.length ? data.rate_history : [0];

    trafficChart = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [{
          label: "Packet Rate",
          data: values,
          borderColor: theme.line,
          backgroundColor: theme.fill,
          borderWidth: 3,
          tension: 0.35,
          fill: true,
          pointRadius: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: "#94a3b8" }
          },
          y: {
            beginAtZero: true,
            grid: { color: "rgba(148,163,184,0.10)" },
            ticks: { color: "#94a3b8" }
          }
        }
      },
      plugins: [createThresholdPlugin(threshold)]
    });
  }

  function updateIpChart(data) {
    if (!ipChart) return;

    const labels = data.top_ips_labels?.length ? data.top_ips_labels : ["No traffic"];
    const values = data.top_ips_values?.length ? data.top_ips_values : [0];

    ipChart.data.labels = labels;
    ipChart.data.datasets[0].data = values;
    ipChart.data.datasets[0].backgroundColor = values.map((_, idx) => idx === 0 ? "rgba(239,68,68,0.95)" : "rgba(34,211,238,0.9)");
    ipChart.update();
  }

  function updateTrafficChart(data) {
    if (!trafficChart) return;

    const theme = currentTheme(data.status);
    trafficChart.data.labels = data.time_labels?.length ? data.time_labels : ["--"];
    trafficChart.data.datasets[0].data = data.rate_history?.length ? data.rate_history : [0];
    trafficChart.data.datasets[0].borderColor = theme.line;
    trafficChart.data.datasets[0].backgroundColor = theme.fill;
    trafficChart.update();
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

  async function refresh() {
    try {
      const res = await fetch("/api/metrics");
      const data = await res.json();

      renderStatus(data);
      updateIpChart(data);
      updateTrafficChart(data);
      renderAlerts(data.alerts || []);
      renderAttackLogs(data.attack_logs || []);
      renderRequests(data.recent_requests || []);
    } catch (err) {
      console.error("Refresh failed:", err);
    }
  }

  function init() {
    renderStatus(initial);
    createIpChart(initial);
    createTrafficChart(initial);
    renderAlerts(initial.alerts || []);
    renderAttackLogs(initial.attack_logs || []);
    renderRequests(initial.recent_requests || []);

    const refreshBtn = document.getElementById("refreshBtn");
    const simulateBtn = document.getElementById("simulateBtn");

    if (refreshBtn) refreshBtn.addEventListener("click", refresh);
    if (simulateBtn) simulateBtn.addEventListener("click", refresh);

    setInterval(refresh, 2000);
  }

  init();
})();
