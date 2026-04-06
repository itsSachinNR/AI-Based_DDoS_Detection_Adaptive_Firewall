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

  // 🔥 Smooth values (IMPORTANT FIX)
  function smoothValues(oldArr, newArr, factor = 0.6) {
    return newArr.map((val, i) => {
      const old = oldArr[i] ?? val;
      return (old * factor) + (val * (1 - factor));
    });
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

    const confidenceBar = document.getElementById("confidenceBar");
    if (confidenceBar) {
      confidenceBar.style.width = `${clampPercent(conf)}%`;
    }

    document.getElementById("confidence").textContent = conf;
    document.getElementById("snapshotConfidence").textContent = conf;

    document.getElementById("totalRequests").textContent = data.total_requests ?? 0;
    document.getElementById("uniqueIps").textContent = data.unique_ips ?? 0;
    document.getElementById("topIp").textContent = data.top_ip ?? "-";
    document.getElementById("topIpCount").textContent = data.top_ip_count ?? 0;
    document.getElementById("topIpCountText").textContent = data.top_ip_count ?? 0;

    document.getElementById("lastUpdated").textContent = data.timestamp ?? "--:--:--";
    document.getElementById("attackProbability").textContent = `${conf}%`;

    document.getElementById("modelName").textContent = data.model_name ?? "Hybrid ML";
    document.getElementById("miniModelName").textContent = data.model_name ?? "Hybrid ML";

    document.getElementById("rfProb").textContent = data.rf_attack_probability ?? 0;
    document.getElementById("anomalyProb").textContent = data.anomaly_attack_probability ?? 0;

    renderReasons(data.reasons || []);
    renderBlockedIps(data.blocked_ips || []);
  }

  function createIpChart(data) {
    const ctx = document.getElementById("ipChart").getContext("2d");

    ipChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: data.top_ips_labels,
        datasets: [{
          data: data.top_ips_values,
          borderRadius: 12,
          backgroundColor: "rgba(34,211,238,0.9)"
        }]
      },
      options: {
        indexAxis: "y",
        animation: { duration: 300 },
        plugins: { legend: { display: false } }
      }
    });
  }

  function createTrafficChart(data) {
    const ctx = document.getElementById("trafficChart").getContext("2d");

    trafficChart = new Chart(ctx, {
      type: "line",
      data: {
        labels: data.time_labels,
        datasets: [{
          data: data.rate_history,
          borderWidth: 3,
          tension: 0.4,
          fill: true
        }]
      },
      options: {
        animation: { duration: 300 },
        plugins: { legend: { display: false } }
      }
    });
  }

  function updateIpChart(data) {
    if (!ipChart) return;

    const smoothed = smoothValues(ipChart.data.datasets[0].data, data.top_ips_values);

    ipChart.data.labels = data.top_ips_labels;
    ipChart.data.datasets[0].data = smoothed;
    ipChart.update();
  }

  function updateTrafficChart(data) {
    if (!trafficChart) return;

    const smoothed = smoothValues(trafficChart.data.datasets[0].data, data.rate_history);

    trafficChart.data.labels = data.time_labels;
    trafficChart.data.datasets[0].data = smoothed;
    trafficChart.update();
  }

  async function refresh() {
    try {
      const res = await fetch("/api/metrics");
      const data = await res.json();

      renderStatus(data);
      updateIpChart(data);
      updateTrafficChart(data);
    } catch (err) {
      console.error(err);
    }
  }

  function init() {
    renderStatus(initial);
    createIpChart(initial);
    createTrafficChart(initial);

    setInterval(refresh, 2000);
  }

  init();
})();
