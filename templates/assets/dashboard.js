(function () {
  const config = window.DOMAIN_ANALYSER_CONFIG || {};
  const state = {
    summary: null,
    domains: [],
    sortKey: "priority_score",
    sortDirection: "desc",
    charts: []
  };

  function byId(id) {
    return document.getElementById(id);
  }

  function textContent(id, value) {
    const element = byId(id);
    if (element) {
      element.textContent = value;
    }
  }

  function safeArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function safeObject(value) {
    return value && typeof value === "object" ? value : {};
  }

  function severityClass(severity) {
    return String(severity || "unknown").toLowerCase();
  }

  function statusClass(status) {
    return String(status || "inactive").toLowerCase();
  }

  function formatDate(value) {
    if (!value) {
      return "Unknown";
    }
    return value;
  }

  function escapeHtml(value) {
    return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  async function fetchJson(path) {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) {
      throw new Error("Failed to load " + path);
    }
    return response.json();
  }

  function populateSelect(selectId, values, labelBuilder) {
    const select = byId(selectId);
    if (!select) return;
    const existing = new Set(Array.from(select.options).map((option) => option.value));
    values.forEach((value) => {
      if (!value || existing.has(value)) return;
      const option = document.createElement("option");
      option.value = value;
      option.textContent = labelBuilder ? labelBuilder(value) : value;
      select.appendChild(option);
    });
  }

  function renderSummary(summary) {
    state.summary = summary;
    textContent("stat-total", summary.total_domains || 0);
    textContent("stat-active", summary.active_malicious || 0);
    textContent("stat-inactive", summary.inactive_down || 0);
    textContent("stat-ips", summary.unique_ips || 0);
    textContent("stat-registrars", summary.unique_registrars || 0);
    textContent("stat-categories", Object.keys(safeObject(summary.category_counts)).length);
  }

  function clearCharts() {
    state.charts.forEach((chart) => chart.destroy());
    state.charts = [];
  }

  function makeGradient(canvas, startColor, endColor) {
    const context = canvas.getContext("2d");
    const gradient = context.createLinearGradient(0, 0, 0, canvas.height || 320);
    gradient.addColorStop(0, startColor);
    gradient.addColorStop(1, endColor);
    return gradient;
  }

  function makeChart(canvasId, chartConfigBuilder) {
    const canvas = byId(canvasId);
    if (!canvas || typeof window.Chart === "undefined") {
      return null;
    }
    const chart = new window.Chart(canvas, chartConfigBuilder(canvas));
    state.charts.push(chart);
    return chart;
  }

  function chartDefaults() {
    return {
      maintainAspectRatio: false,
      animation: {
        duration: 700,
        easing: "easeOutQuart"
      },
      plugins: {
        legend: {
          labels: {
            color: "#294764",
            usePointStyle: true,
            boxWidth: 10,
            boxHeight: 10,
            padding: 16,
            font: {
              family: "Manrope",
              weight: "700"
            }
          }
        },
        tooltip: {
          backgroundColor: "rgba(255, 255, 255, 0.98)",
          titleColor: "#102744",
          bodyColor: "#294764",
          borderColor: "rgba(19, 46, 78, 0.12)",
          borderWidth: 1,
          padding: 12
        }
      },
      scales: {
        x: {
          ticks: { color: "#647d97" },
          grid: { color: "rgba(19, 46, 78, 0.08)" },
          border: { display: false }
        },
        y: {
          ticks: { color: "#647d97" },
          grid: { color: "rgba(19, 46, 78, 0.08)" },
          border: { display: false }
        }
      }
    };
  }

  function renderCharts(summary) {
    clearCharts();
    const severityCounts = safeObject(summary.severity_counts);
    const categoryCounts = safeObject(summary.category_counts);
    const countries = safeArray(summary.top_hosting_countries);

    makeChart("severity-chart", function (canvas) {
      return {
        type: "doughnut",
        data: {
          labels: Object.keys(severityCounts),
          datasets: [{
            data: Object.values(severityCounts),
            backgroundColor: ["#d94f5e", "#f18a2e", "#efc148", "#33a570", "#8c97a8", "#5388c5"],
            borderWidth: 2,
            borderColor: "#ffffff",
            hoverOffset: 10
          }]
        },
        options: Object.assign(chartDefaults(), {
          cutout: "68%",
          plugins: {
            legend: chartDefaults().plugins.legend,
            tooltip: chartDefaults().plugins.tooltip
          },
          scales: {}
        })
      };
    });

    makeChart("category-chart", function (canvas) {
      return {
        type: "bar",
        data: {
          labels: Object.keys(categoryCounts),
          datasets: [{
            data: Object.values(categoryCounts),
            borderRadius: 999,
            backgroundColor: makeGradient(canvas, "rgba(15, 78, 168, 0.92)", "rgba(11, 140, 161, 0.74)"),
            borderSkipped: false
          }]
        },
        options: Object.assign(chartDefaults(), {
          indexAxis: "y",
          plugins: {
            legend: { display: false },
            tooltip: chartDefaults().plugins.tooltip
          }
        })
      };
    });

    makeChart("country-chart", function (canvas) {
      return {
        type: "bar",
        data: {
          labels: countries.map((item) => item.country),
          datasets: [{
            data: countries.map((item) => item.count),
            borderRadius: 18,
            backgroundColor: makeGradient(canvas, "rgba(215, 163, 22, 0.9)", "rgba(28, 138, 82, 0.74)"),
            borderSkipped: false
          }]
        },
        options: Object.assign(chartDefaults(), {
          plugins: {
            legend: { display: false },
            tooltip: chartDefaults().plugins.tooltip
          }
        })
      };
    });
  }

  function renderBrands(brands) {
    const tbody = byId("brands-table-body");
    if (!tbody) return;
    tbody.innerHTML = "";
    if (!brands.length) {
      tbody.innerHTML = '<tr><td colspan="2" class="empty-state">No brand impersonation detected in the published batch.</td></tr>';
      return;
    }
    brands.forEach((brand) => {
      const row = document.createElement("tr");
      row.innerHTML = "<td>" + escapeHtml(brand.brand) + "</td><td>" + escapeHtml(brand.count) + "</td>";
      tbody.appendChild(row);
    });
  }

  function renderHolders(holders) {
    const panel = byId("holders-panel");
    const tbody = byId("holders-table-body");
    if (!tbody) return;
    tbody.innerHTML = "";
    if (!holders.length) {
      if (panel) panel.hidden = true;
      return;
    }
    if (panel) panel.hidden = false;
    holders.forEach((holder) => {
      const row = document.createElement("tr");
      row.innerHTML = "<td>" + escapeHtml(holder.holder) + "</td><td>" + escapeHtml(holder.count) + "</td>";
      tbody.appendChild(row);
    });
  }

  function renderClusters(clusters) {
    const tbody = byId("cluster-table-body");
    if (!tbody) return;
    tbody.innerHTML = "";
    if (!clusters.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No shared infrastructure clusters met the publishing threshold.</td></tr>';
      return;
    }
    clusters.forEach((cluster) => {
      const row = document.createElement("tr");
      row.innerHTML = [
        "<td>" + escapeHtml(cluster.indicator) + "</td>",
        "<td>" + escapeHtml(cluster.cluster_type) + "</td>",
        "<td>" + escapeHtml(cluster.size) + "</td>",
        "<td>" + escapeHtml(safeArray(cluster.domains).join(", ")) + "</td>"
      ].join("");
      tbody.appendChild(row);
    });
  }

  function topEntry(entries, labelKey) {
    const list = safeArray(entries);
    if (!list.length) {
      return null;
    }
    return list[0][labelKey];
  }

  function renderHeadlineInsights(summary) {
    const container = byId("headline-insights");
    if (!container) return;

    const category = topEntry(
      Object.entries(safeObject(summary.category_counts)).map(function (entry) {
        return { label: entry[0], count: entry[1] };
      }).sort(function (left, right) { return right.count - left.count; }),
      "label"
    );
    const cluster = safeArray(summary.clusters)[0];
    const holder = topEntry(safeArray(summary.top_allocation_holders), "holder");

    const items = [
      {
        title: "Active review load",
        text: "The batch currently exposes " + (summary.active_malicious || 0) + " domains assessed as active malicious infrastructure requiring review."
      },
      {
        title: "Dominant threat pattern",
        text: category ? "The most common assigned category in this publication is " + category + "." : "No dominant category has emerged in the current publication."
      },
      {
        title: "Strongest shared infrastructure signal",
        text: cluster ? cluster.cluster_type + " signals connect " + cluster.size + " domains through indicator " + cluster.indicator + "." : "No multi-domain cluster exceeded the current reporting threshold."
      },
      {
        title: "Primary allocation-holder concentration",
        text: holder ? "APNIC enrichment points most often to allocation holder " + holder + " in the current dataset." : "No holder concentration was strong enough to highlight in this publication."
      }
    ];

    container.innerHTML = items.map(function (item) {
      return [
        '<article class="briefing-item">',
        "<strong>" + escapeHtml(item.title) + "</strong>",
        "<p>" + escapeHtml(item.text) + "</p>",
        "</article>"
      ].join("");
    }).join("");
  }

  function valueForSort(row, key) {
    if (key === "registered") {
      return row[key] || "";
    }
    if (key === "vt_malicious" || key === "priority_score") {
      return Number(row[key] || 0);
    }
    return String(row[key] || "").toLowerCase();
  }

  function activeFilters() {
    return {
      search: (byId("search-input")?.value || "").trim().toLowerCase(),
      severity: byId("severity-filter")?.value || "",
      category: byId("category-filter")?.value || "",
      country: byId("country-filter")?.value || "",
      dateFrom: byId("date-from-filter")?.value || "",
      dateTo: byId("date-to-filter")?.value || ""
    };
  }

  function filterDomains() {
    const filters = activeFilters();
    const filtered = state.domains.filter((row) => {
      const haystack = [
        row.domain,
        row.brand_impersonated,
        row.registrar,
        row.allocation_holder,
        row.apnic_region,
        row.payment_summary
      ].join(" ").toLowerCase();
      if (filters.search && !haystack.includes(filters.search)) {
        return false;
      }
      if (filters.severity && row.severity !== filters.severity) {
        return false;
      }
      if (filters.category && row.category !== filters.category) {
        return false;
      }
      if (filters.country && row.hosting_country !== filters.country) {
        return false;
      }
      if (filters.dateFrom && row.registered && row.registered < filters.dateFrom) {
        return false;
      }
      if (filters.dateTo && row.registered && row.registered > filters.dateTo) {
        return false;
      }
      return true;
    });

    filtered.sort((left, right) => {
      const leftValue = valueForSort(left, state.sortKey);
      const rightValue = valueForSort(right, state.sortKey);
      if (leftValue < rightValue) return state.sortDirection === "asc" ? -1 : 1;
      if (leftValue > rightValue) return state.sortDirection === "asc" ? 1 : -1;
      return 0;
    });
    return filtered;
  }

  function actionLinks(row) {
    const pdfLink = row.pdf_report_available
      ? '<a href="' + row.pdf_report_link + '" download>PDF</a>'
      : '<span class="muted-link">PDF pending</span>';
    const zipLink = row.evidence_available
      ? '<a href="' + row.evidence_link + '" download>ZIP</a>'
      : '<span class="muted-link">ZIP pending</span>';

    return [
      '<div class="actions-inline">',
      '<a href="' + row.report_link + '">Report</a>',
      pdfLink,
      '<a href="' + row.raw_json_link + '">JSON</a>',
      zipLink,
      "</div>"
    ].join("");
  }

  function domainCell(row) {
    const subLines = [];
    if (row.brand_impersonated) {
      subLines.push("Brand: " + row.brand_impersonated);
    }
    if (row.payment_summary) {
      subLines.push("Payment rails: " + row.payment_summary);
    } else if (row.registrar && row.registrar !== "Unknown") {
      subLines.push("Registrar: " + row.registrar);
    }
    return [
      '<div class="table-domain">',
      '<a class="domain-link" href="' + row.report_link + '">' + escapeHtml(row.domain) + "</a>",
      subLines.length ? '<div class="table-sub">' + escapeHtml(subLines.join(" • ")) + "</div>" : "",
      "</div>"
    ].join("");
  }

  function holderCell(row) {
    const sub = row.registrar && row.registrar !== "Unknown" ? row.registrar : "Registrar unavailable";
    return [
      '<div class="table-domain">',
      "<span>" + escapeHtml(row.allocation_holder || "Unknown") + "</span>",
      '<div class="table-sub">' + escapeHtml(sub) + "</div>",
      "</div>"
    ].join("");
  }

  function renderDomainRows() {
    const tbody = byId("domains-table-body");
    if (!tbody) return;
    tbody.innerHTML = "";
    const rows = filterDomains();
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="9" class="empty-state">No domains match the current filters.</td></tr>';
      return;
    }
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      tr.innerHTML = [
        "<td>" + domainCell(row) + "</td>",
        '<td><span class="severity-pill ' + severityClass(row.severity) + '">' + escapeHtml(row.severity) + "</span></td>",
        '<td><div class="table-domain"><span>' + escapeHtml(row.category) + '</span><div class="table-sub">Priority ' + escapeHtml(row.priority_score) + "</div></div></td>",
        "<td>" + escapeHtml(row.vt_score) + "</td>",
        "<td>" + escapeHtml(formatDate(row.registered)) + "</td>",
        "<td>" + holderCell(row) + "</td>",
        '<td><div class="table-domain"><span>' + escapeHtml(row.apnic_region || "Unknown") + '</span><div class="table-sub">' + escapeHtml(row.hosting_country || "Unknown") + "</div></div></td>",
        '<td><span class="status-pill ' + statusClass(row.status) + '">' + escapeHtml(row.status) + "</span></td>",
        "<td>" + actionLinks(row) + "</td>"
      ].join("");
      tbody.appendChild(tr);
    });
  }

  function bindFilters() {
    ["search-input", "severity-filter", "category-filter", "country-filter", "date-from-filter", "date-to-filter"].forEach((id) => {
      const element = byId(id);
      if (!element) return;
      element.addEventListener("input", renderDomainRows);
      element.addEventListener("change", renderDomainRows);
    });

    document.querySelectorAll(".sort-button").forEach((button) => {
      button.addEventListener("click", function () {
        const key = button.getAttribute("data-sort");
        if (state.sortKey === key) {
          state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
        } else {
          state.sortKey = key;
          state.sortDirection = key === "domain" ? "asc" : "desc";
        }
        renderDomainRows();
      });
    });
  }

  async function init() {
    try {
      const results = await Promise.all([
        fetchJson(config.summaryJsonPath),
        fetchJson(config.domainsJsonPath)
      ]);
      const summary = results[0];
      const domains = results[1];

      state.domains = safeArray(domains);
      renderSummary(summary);
      renderCharts(summary);
      renderHeadlineInsights(summary);
      renderBrands(safeArray(summary.top_impersonated_brands));
      renderHolders(safeArray(summary.top_allocation_holders));
      renderClusters(safeArray(summary.clusters));
      populateSelect("severity-filter", Object.keys(safeObject(summary.severity_counts)));
      populateSelect("category-filter", Object.keys(safeObject(summary.category_counts)));
      populateSelect(
        "country-filter",
        Array.from(new Set(state.domains.map((row) => row.hosting_country).filter(Boolean))).sort()
      );
      bindFilters();
      renderDomainRows();
    } catch (error) {
      const tbody = byId("domains-table-body");
      if (tbody) {
        tbody.innerHTML = '<tr><td colspan="9" class="empty-state">Dashboard data could not be loaded.</td></tr>';
      }
      console.error(error);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
