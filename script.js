const domainInput = document.getElementById("domain");
const bruteforceToggle = document.getElementById("bruteforce");
const portsToggle = document.getElementById("ports");
const wordlistField = document.getElementById("wordlistField");
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

let eventSource = null;
let allResults = [];

bruteforceToggle.addEventListener("change", () => {
  wordlistField.hidden = !bruteforceToggle.checked;
});

function resetTable() {
  resultsBody.innerHTML = "";
  allResults = [];
  countBadge.textContent = "0";
}

function statusClassForCode(code) {
  if (code >= 200 && code < 300) return "http-2xx";
  if (code >= 300 && code < 400) return "http-3xx";
  return code >= 500 ? "http-5xx" : "http-4xx";
}

function renderRow(entry) {
  const tr = document.createElement("tr");

  const hostTd = document.createElement("td");
  hostTd.className = "host-cell";
  hostTd.textContent = entry.host;
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

  resultsBody.appendChild(tr);
}

function setScanning(isScanning) {
  scanBtn.disabled = isScanning;
  scanBtn.querySelector(".btn-label").textContent = isScanning ? "Scannen..." : "Start scan";
  stopBtn.hidden = !isScanning;
  domainInput.disabled = isScanning;
}

function startScan() {
  const domain = domainInput.value.trim().toLowerCase();
  if (!domain) {
    statusLine.textContent = "Voer eerst een domein in.";
    return;
  }

  resetTable();
  resultsBody.innerHTML = '<tr class="empty-row"><td colspan="5">Scan bezig...</td></tr>';
  exportBtn.hidden = true;
  progressWrap.hidden = false;
  progressFill.style.width = "0%";
  progressText.textContent = "";
  setScanning(true);

  const params = new URLSearchParams({
    domain,
    bruteforce: bruteforceToggle.checked,
    ports: portsToggle.checked,
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
    progressText.textContent = `${data.checked}/${data.total} gecontroleerd — ${data.live} actief gevonden`;
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
    statusLine.textContent = `Klaar. ${data.live_found} actieve subdomeinen gevonden van ${data.total_checked} gecontroleerd.`;
    if (allResults.length === 0) {
      resultsBody.innerHTML = '<tr class="empty-row"><td colspan="5">Geen actieve subdomeinen gevonden.</td></tr>';
    } else {
      exportBtn.hidden = false;
    }
    setScanning(false);
    eventSource.close();
  });

  eventSource.onerror = () => {
    statusLine.textContent = "Verbinding verbroken of scan gestopt.";
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
  setScanning(false);
}

function exportCsv() {
  if (!allResults.length) return;
  const rows = [["subdomein", "ips", "http_status", "titel", "server", "open_poorten"]];
  allResults.forEach(entry => {
    const httpStr = (entry.http || []).map(h => `${h.scheme}:${h.status_code}`).join("|");
    const title = (entry.http && entry.http[0] && entry.http[0].title) || "";
    const server = (entry.http && entry.http[0] && entry.http[0].server) || "";
    rows.push([
      entry.host,
      entry.ips.join("|"),
      httpStr,
      title.replace(/,/g, " "),
      server,
      (entry.open_ports || []).join("|"),
    ]);
  });
  const csv = rows.map(r => r.map(field => `"${String(field).replace(/"/g, '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `subdomains_${domainInput.value.trim()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

scanBtn.addEventListener("click", startScan);
stopBtn.addEventListener("click", stopScan);
exportBtn.addEventListener("click", exportCsv);
domainInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") startScan();
});
