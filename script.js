/* ===================== Achtergrond canvas (subtiel grid/particles) ===================== */

(function initBgCanvas() {
  const canvas = document.getElementById("bgCanvas");
  const ctx = canvas.getContext("2d");
  let w, h, particles;

  function resize() {
    w = canvas.width = window.innerWidth;
    h = canvas.height = window.innerHeight;
  }

  function makeParticles() {
    const count = Math.min(70, Math.floor((w * h) / 22000));
    particles = Array.from({ length: count }, () => ({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.25,
      vy: (Math.random() - 0.5) * 0.25,
    }));
  }

  function tick() {
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = "rgba(78, 230, 166, 0.5)";
    for (const p of particles) {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > w) p.vx *= -1;
      if (p.y < 0 || p.y > h) p.vy *= -1;
      ctx.beginPath();
      ctx.arc(p.x, p.y, 1.3, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.strokeStyle = "rgba(78, 230, 166, 0.08)";
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const a = particles[i], b = particles[j];
        const dist = Math.hypot(a.x - b.x, a.y - b.y);
        if (dist < 130) {
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(tick);
  }

  window.addEventListener("resize", () => { resize(); makeParticles(); });
  resize();
  makeParticles();
  tick();
})();

/* ===================== Globe (roterend punten-netwerk) ===================== */

const Globe = (function initGlobe() {
  const canvas = document.getElementById("globeCanvas");
  const ctx = canvas.getContext("2d");
  let w, h, points, rotation = 0;
  let pulseTargets = []; // hosts die net "live" gevonden zijn, geven een flits

  function resize() {
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;
    w = canvas.width;
    h = canvas.height;
    buildPoints();
  }

  function buildPoints() {
    points = [];
    const latSteps = 10;
    const lonSteps = 16;
    for (let i = 0; i <= latSteps; i++) {
      const lat = (Math.PI * i) / latSteps - Math.PI / 2;
      for (let j = 0; j < lonSteps; j++) {
        const lon = (2 * Math.PI * j) / lonSteps;
        points.push({ lat, lon, pulse: 0 });
      }
    }
  }

  function project(lat, lon, rot, radius, cx, cy) {
    const x3 = Math.cos(lat) * Math.cos(lon + rot);
    const y3 = Math.sin(lat);
    const z3 = Math.cos(lat) * Math.sin(lon + rot);
    const scale = (z3 + 2) / 3;
    return {
      x: cx + x3 * radius * scale,
      y: cy + y3 * radius * scale,
      depth: z3,
      scale,
    };
  }

  function tick() {
    ctx.clearRect(0, 0, w, h);
    const cx = w / 2, cy = h / 2;
    const radius = Math.min(w, h) * 0.36;

    rotation += 0.0022;

    for (const p of points) {
      const proj = project(p.lat, p.lon, rotation, radius, cx, cy);
      const alpha = 0.15 + Math.max(0, proj.depth) * 0.35;
      const size = 0.8 + proj.scale * 1.1 + p.pulse * 2.5;

      if (p.pulse > 0) p.pulse *= 0.92;

      ctx.beginPath();
      ctx.fillStyle = p.pulse > 0.05
        ? `rgba(78, 230, 166, ${Math.min(1, alpha + p.pulse)})`
        : `rgba(78, 205, 230, ${alpha})`;
      ctx.arc(proj.x, proj.y, size, 0, Math.PI * 2);
      ctx.fill();
    }

    requestAnimationFrame(tick);
  }

  window.addEventListener("resize", resize);
  resize();
  tick();

  return {
    pulse() {
      // laat een paar willekeurige punten oplichten bij een nieuw scanresultaat
      if (!points || !points.length) return;
      for (let i = 0; i < 3; i++) {
        const p = points[Math.floor(Math.random() * points.length)];
        p.pulse = 1;
      }
    },
  };
})();

/* ===================== Scanner UI-logica ===================== */

const domainInput = document.getElementById("domain");
const bruteforceToggle = document.getElementById("bruteforce");
const portsToggle = document.getElementById("ports");
const takeoverToggle = document.getElementById("takeover");
const wordlistInput = document.getElementById("wordlist");
const scanBtn = document.getElementById("scanBtn");
const stopBtn = document.getElementById("stopBtn");
const exportBtn = document.getElementById("exportBtn");
const statusLine = document.getElementById("statusLine");
const progressWrap = document.getElementById("progressWrap");
const progressFill = document.getElementById("progressFill");
const progressText = document.getElementById("progressText");
const resultsBody = document.getElementById("resultsBody");
const countBadge = document.getElementById("countBadge");
const globalStatus = document.getElementById("globalStatus");
const globalStatusText = document.getElementById("globalStatusText");

const statLive = document.getElementById("statLive");
const statChecked = document.getElementById("statChecked");
const statTakeover = document.getElementById("statTakeover");
const statWildcard = document.getElementById("statWildcard");

let eventSource = null;
let allResults = [];

function resetTable() {
  resultsBody.innerHTML = "";
  allResults = [];
  countBadge.textContent = "0";
  statLive.textContent = "0";
  statChecked.textContent = "0";
  statTakeover.textContent = "0";
  statWildcard.textContent = "—";
}

function statusClassForCode(code) {
  if (code >= 200 && code < 300) return "http-2xx";
  if (code >= 300 && code < 400) return "http-3xx";
  return code >= 500 ? "http-5xx" : "http-4xx";
}

function renderRow(entry) {
  const tr = document.createElement("tr");
  if (entry.takeover && entry.takeover.vulnerable) tr.classList.add("row-takeover");
  if (entry.wildcard_match) tr.classList.add("row-wildcard");

  const hostTd = document.createElement("td");
  hostTd.className = "host-cell";
  hostTd.textContent = entry.host;
  if (entry.wildcard_match) {
    const tag = document.createElement("span");
    tag.className = "wildcard-tag";
    tag.textContent = "wildcard-match (mogelijk ruis)";
    hostTd.appendChild(tag);
  }
  tr.appendChild(hostTd);

  const ipTd = document.createElement("td");
  ipTd.className = "ip-cell";
  ipTd.textContent = entry.ips.join(", ");
  tr.appendChild(ipTd);

  const httpTd = document.createElement("td");
  if (entry.http && entry.http.length) {
    entry.http.forEach(h => {
      const badge = document.createElement("span");
      badge.className = "http-badge " + statusClassForCode(h.status_code);
      badge.textContent = `${h.scheme.toUpperCase()} ${h.status_code}`;
      httpTd.appendChild(badge);
    });
  } else {
    httpTd.innerHTML = '<span class="ip-cell">geen HTTP</span>';
  }
  tr.appendChild(httpTd);

  const metaTd = document.createElement("td");
  metaTd.className = "meta-cell";
  if (entry.http && entry.http.length) {
    const first = entry.http[0];
    if (first.title) {
      const titleSpan = document.createElement("span");
      titleSpan.className = "title-line";
      titleSpan.textContent = first.title;
      metaTd.appendChild(titleSpan);
    }
    if (first.server) {
      metaTd.appendChild(document.createTextNode(`Server: ${first.server}`));
    }
  }
  tr.appendChild(metaTd);

  const portsTd = document.createElement("td");
  if (entry.open_ports && entry.open_ports.length) {
    entry.open_ports.forEach(p => {
      const chip = document.createElement("span");
      chip.className = "port-chip";
      chip.textContent = p;
      portsTd.appendChild(chip);
    });
  } else {
    portsTd.innerHTML = '<span class="ip-cell">—</span>';
  }
  tr.appendChild(portsTd);

  const takeoverTd = document.createElement("td");
  takeoverTd.className = "takeover-cell";
  if (entry.takeover) {
    const badge = document.createElement("span");
    if (entry.takeover.vulnerable === true) {
      badge.className = "takeover-badge vuln";
      badge.textContent = `KWETSBAAR — ${entry.takeover.service}`;
    } else {
      badge.className = "takeover-badge maybe";
      badge.textContent = `CHECK — ${entry.takeover.service}`;
    }
    takeoverTd.appendChild(badge);
    const reason = document.createElement("span");
    reason.className = "takeover-reason";
    reason.textContent = entry.takeover.reason;
    takeoverTd.appendChild(reason);
  } else {
    takeoverTd.innerHTML = '<span class="ip-cell">—</span>';
  }
  tr.appendChild(takeoverTd);

  resultsBody.appendChild(tr);
  Globe.pulse();
}

function setScanning(isScanning) {
  scanBtn.disabled = isScanning;
  scanBtn.querySelector(".btn-label").textContent = isScanning ? "Scannen..." : "Start scan";
  stopBtn.hidden = !isScanning;
  domainInput.disabled = isScanning;
  globalStatus.classList.toggle("active", isScanning);
  if (!isScanning) globalStatus.classList.remove("error");
}

function startScan() {
  const domain = domainInput.value.trim().toLowerCase();
  if (!domain) {
    statusLine.textContent = "Voer eerst een domein in.";
    return;
  }

  resetTable();
  resultsBody.innerHTML = '<tr class="empty-row"><td colspan="6">Scan bezig...</td></tr>';
  exportBtn.hidden = true;
  progressWrap.hidden = false;
  progressFill.style.width = "0%";
  progressText.textContent = "";
  globalStatusText.textContent = "Scannen";
  setScanning(true);

  const params = new URLSearchParams({
    domain,
    bruteforce: bruteforceToggle.checked,
    ports: portsToggle.checked,
    takeover: takeoverToggle.checked,
    wordlist: wordlistInput.value.trim(),
  });

  eventSource = new EventSource(`/api/scan?${params.toString()}`);
  let firstResult = true;

  eventSource.addEventListener("status", (e) => {
    const data = JSON.parse(e.data);
    statusLine.textContent = data.message;
  });

  eventSource.addEventListener("progress", (e) => {
    const data = JSON.parse(e.data);
    const pct = data.total ? Math.round((data.checked / data.total) * 100) : 0;
    progressFill.style.width = pct + "%";
    progressText.textContent = `${data.checked}/${data.total} gecontroleerd — ${data.live} actief, ${data.takeovers} takeover-risico's`;
    statChecked.textContent = data.checked;
    statLive.textContent = data.live;
    statTakeover.textContent = data.takeovers;
  });

  eventSource.addEventListener("result", (e) => {
    const entry = JSON.parse(e.data);
    if (firstResult) {
      resultsBody.innerHTML = "";
      firstResult = false;
    }
    allResults.push(entry);
    renderRow(entry);
    countBadge.textContent = allResults.length;
  });

  eventSource.addEventListener("done", (e) => {
    const data = JSON.parse(e.data);
    statusLine.textContent = `Klaar. ${data.live_found} actieve subdomeinen, ${data.takeovers_found} mogelijke takeovers, van ${data.total_checked} gecontroleerd.`;
    statWildcard.textContent = data.wildcard_detected ? "Ja" : "Nee";
    globalStatusText.textContent = "Klaar";
    if (allResults.length === 0) {
      resultsBody.innerHTML = '<tr class="empty-row"><td colspan="6">Geen actieve subdomeinen gevonden.</td></tr>';
    } else {
      exportBtn.hidden = false;
    }
    setScanning(false);
    eventSource.close();
  });

  eventSource.onerror = () => {
    statusLine.textContent = "Verbinding verbroken of scan gestopt.";
    globalStatusText.textContent = "Fout";
    globalStatus.classList.add("error");
    setScanning(false);
    if (eventSource) eventSource.close();
  };
}

function stopScan() {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
  statusLine.textContent = "Scan gestopt door gebruiker.";
  globalStatusText.textContent = "Gestopt";
  setScanning(false);
}

function exportCsv() {
  if (!allResults.length) return;
  const rows = [["subdomein", "ips", "http_status", "titel", "server", "open_poorten", "wildcard_match", "takeover_service", "takeover_status", "takeover_cname"]];
  allResults.forEach(entry => {
    const httpStr = (entry.http || []).map(h => `${h.scheme}:${h.status_code}`).join("|");
    const title = (entry.http && entry.http[0] && entry.http[0].title) || "";
    const server = (entry.http && entry.http[0] && entry.http[0].server) || "";
    const tk = entry.takeover || {};
    rows.push([
      entry.host,
      entry.ips.join("|"),
      httpStr,
      title.replace(/,/g, " "),
      server,
      (entry.open_ports || []).join("|"),
      entry.wildcard_match ? "yes" : "no",
      tk.service || "",
      tk.vulnerable === true ? "vulnerable" : (tk.vulnerable === null && tk.service ? "check" : ""),
      tk.cname || "",
    ]);
  });
  const csv = rows.map(r => r.map(field => `"${String(field).replace(/"/g, '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `subdomains_${domainInput.value.trim() || "scan"}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

scanBtn.addEventListener("click", startScan);
stopBtn.addEventListener("click", stopScan);
exportBtn.addEventListener("click", exportCsv);
domainInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") startScan();
});
