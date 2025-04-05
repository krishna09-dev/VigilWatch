// Global variables for alerts and sort order
let fullAlerts = [];
let allAlerts = [];
let currentPage = 1;
const pageSize = 10;
let sortOrder = "latest"; // "latest" or "oldest"

// Fetch alerts from server and update both fullAlerts and allAlerts
function fetchAllAlerts() {
  fetch('/alerts')
    .then(response => response.json())
    .then(data => {
      fullAlerts = data;
      // Always sort fullAlerts as latest first initially
      fullAlerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      allAlerts = fullAlerts.slice();
      currentPage = 1;
      renderAlertsForPage(currentPage);
      updateCharts(allAlerts);
      updatePagination();
    })
    .catch(err => console.error("Error fetching alerts:", err));
}

document.addEventListener("DOMContentLoaded", () => {
  fetchAllAlerts();
});

// Event listener for filter button
document.getElementById("applyFilter").addEventListener("click", (event) => {
  event.preventDefault();
  filterAlerts();
});

// Event listener for sort toggle button
document.getElementById("toggleSort").addEventListener("click", (event) => {
  event.preventDefault();
  toggleSortOrder();
});

// Function to toggle sort order and re-render alerts
function toggleSortOrder() {
  if (sortOrder === "latest") {
    sortOrder = "oldest";
    document.getElementById("toggleSort").textContent = "Sort: Oldest First";
  } else {
    sortOrder = "latest";
    document.getElementById("toggleSort").textContent = "Sort: Latest First";
  }
  // Re-sort fullAlerts based on the chosen order
  fullAlerts.sort((a, b) => {
    if (sortOrder === "latest") {
      return new Date(b.timestamp) - new Date(a.timestamp);
    } else {
      return new Date(a.timestamp) - new Date(b.timestamp);
    }
  });
  // Reapply the current filter if any
  filterAlerts();
}

function filterAlerts() {
  const severity = document.getElementById("severityFilter").value;
  const startDate = document.getElementById("startDate").value;
  const endDate = document.getElementById("endDate").value;
  
  let filtered = fullAlerts.slice();
  
  if (severity) {
    filtered = filtered.filter(a => a.severity.toLowerCase() === severity.toLowerCase());
  }
  if (startDate) {
    filtered = filtered.filter(a => new Date(a.timestamp) >= new Date(startDate));
  }
  if (endDate) {
    filtered = filtered.filter(a => new Date(a.timestamp) <= new Date(endDate));
  }
  
  allAlerts = filtered;
  currentPage = 1;
  console.log("Filtered alerts:", filtered);
  renderAlertsForPage(currentPage);
  updateCharts(filtered);
  updatePagination();
}

function renderAlertsForPage(page) {
  const tbody = document.querySelector("#alertsTable tbody");
  tbody.innerHTML = "";
  
  const start = (page - 1) * pageSize;
  const paginatedAlerts = allAlerts.slice(start, start + pageSize);
  
  if (paginatedAlerts.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="3" style="text-align:center;">No alerts to display.</td>`;
    tbody.appendChild(tr);
  } else {
    paginatedAlerts.forEach(alert => {
      const tr = document.createElement("tr");
      tr.classList.add("alert-row");
      tr.setAttribute("data-alert", JSON.stringify(alert));
      tr.innerHTML = `
        <td>${alert.timestamp}</td>
        <td>${alert.severity}</td>
        <td>${alert.message}</td>
      `;
      tr.addEventListener("click", () => showAlertDetails(alert));
      tbody.appendChild(tr);
    });
  }
}

function updatePagination() {
  const paginationDiv = document.getElementById("pagination");
  if (!paginationDiv) return;
  paginationDiv.innerHTML = "";
  
  const totalPages = Math.ceil(allAlerts.length / pageSize);
  if (totalPages <= 1) return;
  
  for (let i = 1; i <= totalPages; i++) {
    const btn = document.createElement("button");
    btn.textContent = i;
    btn.style.margin = "0 5px";
    btn.style.padding = "8px 12px";
    btn.style.cursor = "pointer";
    if (i === currentPage) {
      btn.style.backgroundColor = "#2980b9";
      btn.style.color = "#fff";
    } else {
      btn.style.backgroundColor = "#ecf0f1";
      btn.style.color = "#2c3e50";
    }
    btn.addEventListener("click", () => {
      currentPage = i;
      renderAlertsForPage(currentPage);
      updatePagination();
    });
    paginationDiv.appendChild(btn);
  }
}

let severityChart, timeChart;
function updateCharts(alerts) {
  const severityCounts = { Low: 0, Medium: 0, Critical: 0 };
  alerts.forEach(a => {
    if (severityCounts[a.severity] !== undefined) {
      severityCounts[a.severity]++;
    }
  });
  
  const ctx1 = document.getElementById("severityChart").getContext("2d");
  const pieData = {
    labels: Object.keys(severityCounts),
    datasets: [{
      data: Object.values(severityCounts),
      backgroundColor: ["#4CAF50", "#FFC107", "#F44336"]
    }]
  };
  if (severityChart) severityChart.destroy();
  severityChart = new Chart(ctx1, {
    type: "pie",
    data: pieData
  });
  
  const timeBuckets = {};
  alerts.forEach(a => {
    const minute = new Date(a.timestamp).toISOString().substring(0,16);
    timeBuckets[minute] = (timeBuckets[minute] || 0) + 1;
  });
  const sortedTimes = Object.keys(timeBuckets).sort();
  const ctx2 = document.getElementById("timeChart").getContext("2d");
  const lineData = {
    labels: sortedTimes,
    datasets: [{
      label: "Alerts per Minute",
      data: sortedTimes.map(t => timeBuckets[t]),
      borderColor: "#2196F3",
      fill: false
    }]
  };
  if (timeChart) timeChart.destroy();
  timeChart = new Chart(ctx2, {
    type: "line",
    data: lineData
  });
}

function showAlertDetails(alert) {
  document.getElementById("alertDetails").textContent = JSON.stringify(alert, null, 2);
  document.getElementById("alertModal").style.display = "block";
}

document.getElementById("closeModal").addEventListener("click", () => {
  document.getElementById("alertModal").style.display = "none";
});

document.getElementById("configForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const newConfig = {
    rate_limit_requests: parseInt(document.getElementById("rate_limit_requests").value),
    failed_login_threshold: parseInt(document.getElementById("failed_login_threshold").value),
    download_threshold: parseInt(document.getElementById("download_threshold").value)
  };
  fetch("/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(newConfig)
  })
  .then(res => res.json())
  .then(data => {
    showModal(`Configuration updated:\n${JSON.stringify(data.config, null, 2)}`);
  })
  .catch(err => {
    showModal(`Failed to update config: ${err}`);
  });
});

function showModal(message) {
  document.getElementById("alertDetails").textContent = message;
  document.getElementById("alertModal").style.display = "block";
}
