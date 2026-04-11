(function () {
  const config = window.DOMAIN_ANALYSER_CONFIG || {};
  const state = {
    summary: null,
    domains: [],
    sortKey: "priority_score",
    sortDirection: "desc"
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

  function severityClass(severity) {
    return String(severity || "unknown").toLowerCase();
  }

  function safeArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function safeObject(value) {
    return value && typeof value === "object" ? value : {};
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

  function makeChart(canvasId, config) {
    const canvas = byId(canvasId);
    if (!canvas || typeof window.Chart === "undefined") {
      return null;
    }
    return new window.Chart(canvas, config);
  }

  function renderCharts(summary) {
    makeChart("severity-chart", {
      type: "doughnut",
      data: {
        labels: Object.keys(safeObject(summary.severity_counts)),
        datasets: [{
          data: Object.values(safeObject(summary.severity_counts)),
          backgroundColor: ["#b22222", "#cc5500", "#b8860b", "#1a6b3a", "#5a5a5a", "#607d8b"]
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { labels: { color: "#f5f5f5" } } }
      }
    });

    makeChart("category-chart", {
      type: "bar",
      data: {
        labels: Object.keys(safeObject(summary.category_counts)),
        datasets: [{
          label: "Domains",
          data: Object.values(safeObject(summary.category_counts)),
          backgroundColor: "#2e6da4"
        }]
      },
      options: {
        responsive: true,
        scales: {
          x: { ticks: { color: "#f5f5f5" }, grid: { color: "rgba(255,255,255,0.08)" } },
          y: { ticks: { color: "#f5f5f5" }, grid: { color: "rgba(255,255,255,0.08)" } }
        },
        plugins: { legend: { display: false } }
      }
    });

    const countries = safeArray(summary.top_hosting_countries);
    makeChart("country-chart", {
      type: "bar",
      data: {
        labels: countries.map((item) => item.country),
        datasets: [{
          label: "Hosting Countries",
          data: countries.map((item) => item.count),
          backgroundColor: "#4b90c8"
        }]
      },
      options: {
        responsive: true,
        scales: {
          x: { ticks: { color: "#f5f5f5" }, grid: { color: "rgba(255,255,255,0.08)" } },
          y: { ticks: { color: "#f5f5f5" }, grid: { color: "rgba(255,255,255,0.08)" } }
        },
        plugins: { legend: { display: false } }
      }
    });
  }

  function renderBrands(brands) {
    const tbody = byId("brands-table-body");
    if (!tbody) return;
    tbody.innerHTML = "";
    if (!brands.length) {
      tbody.innerHTML = '<tr><td colspan="2" class="empty-state">No brand impersonation detected.</td></tr>';
      return;
    }
    brands.forEach((brand) => {
      const row = document.createElement("tr");
      row.innerHTML = "<td>" + brand.brand + "</td><td>" + brand.count + "</td>";
      tbody.appendChild(row);
    });
  }

  function renderClusters(clusters) {
    const tbody = byId("cluster-table-body");
    if (!tbody) return;
    tbody.innerHTML = "";
    if (!clusters.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No shared infrastructure clusters met the report threshold.</td></tr>';
      return;
    }
    clusters.forEach((cluster) => {
      const row = document.createElement("tr");
      row.innerHTML = [
        "<td>" + cluster.indicator + "</td>",
        "<td>" + cluster.cluster_type + "</td>",
        "<td>" + cluster.size + "</td>",
        "<td>" + safeArray(cluster.domains).join(", ") + "</td>"
      ].join("");
      tbody.appendChild(row);
    });
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
      const haystack = [row.domain, row.brand_impersonated, row.registrar].join(" ").toLowerCase();
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
    return [
      '<div class="actions-inline">',
      '<a href="' + row.report_link + '">Report</a>',
      '<a href="' + row.raw_json_link + '">JSON</a>',
      '<a href="' + row.evidence_link + '">ZIP</a>',
      "</div>"
    ].join("");
  }

  function renderDomainRows() {
    const tbody = byId("domains-table-body");
    if (!tbody) return;
    tbody.innerHTML = "";
    const rows = filterDomains();
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No domains match the current filters.</td></tr>';
      return;
    }
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      tr.innerHTML = [
        "<td><a href=\"" + row.report_link + "\">" + row.domain + "</a></td>",
        "<td><span class=\"severity-pill " + severityClass(row.severity) + "\">" + row.severity + "</span></td>",
        "<td>" + row.category + "</td>",
        "<td>" + row.vt_score + "</td>",
        "<td>" + (row.registered || "Unknown") + "</td>",
        "<td>" + row.status + "</td>",
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
      const [summary, domains] = await Promise.all([
        fetchJson(config.summaryJsonPath),
        fetchJson(config.domainsJsonPath)
      ]);

      state.domains = safeArray(domains);
      renderSummary(summary);
      renderCharts(summary);
      renderBrands(safeArray(summary.top_impersonated_brands));
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
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Dashboard data could not be loaded.</td></tr>';
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
