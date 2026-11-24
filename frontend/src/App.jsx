import { useEffect, useState } from "react";
import ReactMarkdown from "react-markdown";
import "./App.css";

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loginToken, setLoginToken] = useState("");
  const [loginError, setLoginError] = useState("");
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [searchTerm, setSearchTerm] = useState("");
  const [sortBy, setSortBy] = useState("NEWEST");
  const [sortOpen, setSortOpen] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState("");

  const API_BASE_URL =
    import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

  // Fetch alerts from backend.
  // cache: no-store ensures the browser does not reuse an old response.
  const fetchAlerts = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/alerts`, {
        credentials: "include",
        cache: "no-store",
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch alerts: ${response.status}`);
      }

      const data = await response.json();

      if (!Array.isArray(data.alerts)) {
        throw new Error("Invalid alert response received from backend.");
      }

      setAlerts(data.alerts);

      // Keep the investigation panel synchronized with refreshed data.
      setSelectedAlert((currentSelected) => {
        if (!currentSelected) {
          return null;
        }

        const refreshedAlert = data.alerts.find(
          (alert) => alert.id === currentSelected.id
        );

        return refreshedAlert || currentSelected;
      });
    } catch (error) {
      console.error("Error fetching alerts:", error);
    }
  };

  // Login
  const handleLogin = async (event) => {
    event.preventDefault();
    setLoginError("");

    try {
      const response = await fetch(`${API_BASE_URL}/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify({ token: loginToken }),
      });

      const data = await response.json();

      if (!response.ok) {
        setLoginError(data.detail || "Login failed. Please try again.");
        return;
      }

      const checkResponse = await fetch(`${API_BASE_URL}/auth/check`, {
        credentials: "include",
        cache: "no-store",
      });

      if (!checkResponse.ok) {
        setLoginError("Login succeeded, but session verification failed.");
        return;
      }

      setIsAuthenticated(true);
      setLoginToken("");

      // Immediately load the latest alerts after login.
      await fetchAlerts();
    } catch (error) {
      console.error("Login error:", error);
      setLoginError(
        "Cannot connect to the backend. Check that it is running."
      );
    }
  };

  // Automatic dashboard synchronization.
  // Fetch immediately after authentication and then every 5 seconds.
  useEffect(() => {
    if (!isAuthenticated) {
      return;
    }

    fetchAlerts();

    const refreshInterval = setInterval(() => {
      fetchAlerts();
    }, 5000);

    return () => {
      clearInterval(refreshInterval);
    };
  }, [isAuthenticated]);

  // Update alert status
  const updateStatus = async (alertId, newStatus) => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/alerts/${alertId}/status?status=${encodeURIComponent(
          newStatus
        )}`,
        {
          method: "PUT",
          credentials: "include",
        }
      );

      const data = await response.json();

      if (response.ok && data.status === "success") {
        setAlerts((currentAlerts) =>
          currentAlerts.map((alert) =>
            alert.id === alertId
              ? { ...alert, status: newStatus }
              : alert
          )
        );

        setSelectedAlert((current) =>
          current && current.id === alertId
            ? { ...current, status: newStatus }
            : current
        );
      } else {
        console.error("Error updating alert:", data);
        window.alert(
          data.detail ||
            data.message ||
            "Failed to update alert status."
        );
      }
    } catch (error) {
      console.error("Error updating alert status:", error);
      window.alert("Could not connect to the backend.");
    }
  };

  // Upload security log CSV
  const uploadLog = async (event) => {
    const file = event.target.files[0];

    if (!file) {
      return;
    }

    const formData = new FormData();
    formData.append("file", file);
    setUploading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/upload-log`, {
        method: "POST",
        credentials: "include",
        body: formData,
      });

      const data = await response.json();

      if (response.ok && data.status === "success") {
        window.alert(
          `Log uploaded successfully!\n\n` +
            `Total Logs: ${data.total_logs}\n` +
            `Valid Logs: ${data.valid_logs}\n` +
            `Invalid Logs: ${data.invalid_logs}`
        );

        await fetchAlerts();
      } else {
        window.alert(data.message || "Upload failed.");
      }
    } catch (error) {
      console.error("Error uploading log:", error);
      window.alert(
        "Unable to upload log. Make sure the backend is running."
      );
    } finally {
      setUploading(false);
      event.target.value = "";
    }
  };

  // Analyze selected alert using Ollama AI
  const analyzeWithAI = async (alertId) => {
    setAiLoading(true);
    setAiAnalysis("");
    setAiError("");

    try {
      const response = await fetch(
        `${API_BASE_URL}/alerts/${alertId}/analyze`,
        {
          method: "POST",
          credentials: "include",
        }
      );

      const data = await response.json();

      if (response.ok && data.status === "success") {
        setAiAnalysis(data.analysis);
      } else {
        setAiError(
          data.detail ||
            data.message ||
            "AI analysis failed."
        );
      }
    } catch (error) {
      console.error("Error running AI analysis:", error);
      setAiError(
        "Unable to connect to the AI analysis service."
      );
    } finally {
      setAiLoading(false);
    }
  };

  // Open investigation panel
  const openInvestigation = (alert) => {
    setSelectedAlert(alert);
    setAiAnalysis("");
    setAiError("");
    setAiLoading(false);
  };

  // Dashboard statistics
  const totalAlerts = alerts.length;

  const criticalAlerts = alerts.filter(
    (alert) => alert.severity === "CRITICAL"
  ).length;

  const highAlerts = alerts.filter(
    (alert) => alert.severity === "HIGH"
  ).length;

  const mediumAlerts = alerts.filter(
    (alert) => alert.severity === "MEDIUM"
  ).length;

  const lowAlerts = alerts.filter(
    (alert) => alert.severity === "LOW"
  ).length;

  const resolvedAlerts = alerts.filter(
    (alert) => alert.status === "RESOLVED"
  ).length;

  // Filter, search, and sort alerts
  const filteredAlerts = alerts
    .filter((alert) => {
      const matchesSeverity =
        severityFilter === "ALL" ||
        alert.severity === severityFilter;

      const matchesStatus =
        statusFilter === "ALL" ||
        alert.status === statusFilter;

      const search = searchTerm.trim().toLowerCase();

      const matchesSearch =
        !search ||
        String(alert.source_ip || "")
          .toLowerCase()
          .includes(search) ||
        String(alert.alert_type || "")
          .toLowerCase()
          .includes(search) ||
        String(alert.severity || "")
          .toLowerCase()
          .includes(search) ||
        String(alert.status || "")
          .toLowerCase()
          .includes(search);

      return (
        matchesSeverity &&
        matchesStatus &&
        matchesSearch
      );
    })
    .sort((a, b) => {
      if (sortBy === "SEVERITY") {
        const severityRank = {
          CRITICAL: 4,
          HIGH: 3,
          MEDIUM: 2,
          LOW: 1,
        };

        return (
          (severityRank[b.severity] || 0) -
          (severityRank[a.severity] || 0)
        );
      }

      const timeA = a.created_at
        ? new Date(
            a.created_at.replace(" ", "T") + "Z"
          ).getTime()
        : 0;

      const timeB = b.created_at
        ? new Date(
            b.created_at.replace(" ", "T") + "Z"
          ).getTime()
        : 0;

      return sortBy === "OLDEST"
        ? timeA - timeB
        : timeB - timeA;
    });

  const clearFilters = () => {
    setSeverityFilter("ALL");
    setStatusFilter("ALL");
    setSearchTerm("");
  };

  return (
    <>
      {!isAuthenticated ? (
        <div className="login-container">
          <form
            className="login-form"
            onSubmit={handleLogin}
          >
            <h1>SOC Alert Analyzer</h1>
            <p>
              Sign in to access your security dashboard.
            </p>

            <input
              type="password"
              placeholder="Enter API token"
              value={loginToken}
              onChange={(event) =>
                setLoginToken(event.target.value)
              }
              autoComplete="current-password"
              required
            />

            <button type="submit">Login</button>

            {loginError && (
              <p className="login-error">
                {loginError}
              </p>
            )}
          </form>
        </div>
      ) : (
        <div className="dashboard">
          <aside className="sidebar">
            <div className="sidebar-brand">
              <div className="brand-icon">S</div>
              <div>
                <h2>SOC ANALYZER</h2>
                <span>Security Operations</span>
              </div>
            </div>

            <div className="sidebar-user">
              <div className="user-avatar">S</div>
              <div className="user-info">
                <strong>Sachin</strong>
                <span>Security Analyst</span>
              </div>
              <span className="user-online-dot"></span>
            </div>

            <div className="sidebar-heading">
              WORKSPACE
            </div>

            <nav
              className="sidebar-nav"
              aria-label="Dashboard navigation"
            >
              <a
                className="nav-item active"
                href="#dashboard-overview"
              >
                <span className="nav-icon">⌂</span>
                Dashboard
              </a>

              <a
                className="nav-item"
                href="#security-alerts"
              >
                <span className="nav-icon">♧</span>
                Security Alerts
                <span className="nav-badge">
                  {totalAlerts}
                </span>
              </a>

              <a
                className="nav-item"
                href="#security-alerts"
              >
                <span className="nav-icon">▤</span>
                Log Analysis
              </a>

              <a
                className="nav-item"
                href="#threat-distribution"
              >
                <span className="nav-icon">⛨</span>
                Threat Intelligence
              </a>

              <a
                className="nav-item"
                href="#ai-investigation"
              >
                <span className="nav-icon">✳</span>
                AI Assistant
              </a>

              <a
                className="nav-item"
                href="#dashboard-charts"
              >
                <span className="nav-icon">▧</span>
                Reports
              </a>

              <a
                className="nav-item"
                href="#system-status-panel"
              >
                <span className="nav-icon">◉</span>
                System Health
              </a>

              <a
                className="nav-item"
                href="#system-status-panel"
              >
                <span className="nav-icon">⚙</span>
                Settings
              </a>
            </nav>

            <div className="sidebar-footer">
              <span className="status-dot"></span>
              Backend connection status
              <strong>Check dashboard</strong>
            </div>
          </aside>

          <div className="dashboard-main">
            <header className="header">
              <div className="welcome-copy">
                <h1>
                  Welcome back, Sachin{" "}
                  <span aria-hidden="true">👋</span>
                </h1>
                <p>
                  Here's your security operations
                  overview for today.
                </p>
              </div>

              <div className="header-tools">
                <label className="global-search">
                  <span>⌕</span>
                  <input
                    aria-label="Search alerts"
                    placeholder="Search IP, alert type, logs..."
                    value={searchTerm}
                    onChange={(event) =>
                      setSearchTerm(event.target.value)
                    }
                  />
                </label>

                <div className="header-date">
                  <span>▣</span>
                  <div>
                    <strong>
                      {new Date().toLocaleDateString(
                        undefined,
                        {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                        }
                      )}
                    </strong>

                    <small>
                      {new Date().toLocaleTimeString(
                        undefined,
                        {
                          hour: "2-digit",
                          minute: "2-digit",
                        }
                      )}
                    </small>
                  </div>
                </div>

                <div className="system-status">
                  <span className="status-dot"></span>
                  SYSTEM ONLINE
                </div>
              </div>
            </header>

            <div className="dashboard-workspace">
              <main id="dashboard-overview">
                {/* Dashboard Statistics */}
                <section className="stats">
                  <div className="stat-card">
                    <h3>Total Alerts</h3>
                    <strong>{totalAlerts}</strong>
                  </div>

                  <div className="stat-card critical">
                    <h3>Critical</h3>
                    <strong>
                      {criticalAlerts}
                      <small>
                        (
                        {totalAlerts
                          ? Math.round(
                              (criticalAlerts /
                                totalAlerts) *
                                100
                            )
                          : 0}
                        %)
                      </small>
                    </strong>
                  </div>

                  <div className="stat-card high">
                    <h3>High</h3>
                    <strong>
                      {highAlerts}
                      <small>
                        (
                        {totalAlerts
                          ? Math.round(
                              (highAlerts /
                                totalAlerts) *
                                100
                            )
                          : 0}
                        %)
                      </small>
                    </strong>
                  </div>

                  <div className="stat-card medium">
                    <h3>Medium</h3>
                    <strong>
                      {mediumAlerts}
                      <small>
                        (
                        {totalAlerts
                          ? Math.round(
                              (mediumAlerts /
                                totalAlerts) *
                                100
                            )
                          : 0}
                        %)
                      </small>
                    </strong>
                  </div>

                  <div className="stat-card low">
                    <h3>Low</h3>
                    <strong>
                      {lowAlerts}
                      <small>
                        (
                        {totalAlerts
                          ? Math.round(
                              (lowAlerts /
                                totalAlerts) *
                                100
                            )
                          : 0}
                        %)
                      </small>
                    </strong>
                  </div>

                  <div className="stat-card resolved">
                    <h3>Resolved</h3>
                    <strong>
                      {resolvedAlerts}
                    </strong>
                  </div>
                </section>

                {/* Security Alerts */}
                <section
                  className="alerts-section"
                  id="security-alerts"
                >
                  <div className="section-header">
                    <div>
                      <h2>Security Alerts</h2>
                      <p>
                        Detected suspicious security
                        activity
                      </p>
                    </div>

                    <div className="header-actions">
                      <label className="upload-button">
                        {uploading
                          ? "Uploading..."
                          : "Upload Log"}

                        <input
                          type="file"
                          accept=".csv"
                          onChange={uploadLog}
                          hidden
                          disabled={uploading}
                        />
                      </label>

                      <button
                        onClick={fetchAlerts}
                      >
                        Refresh
                      </button>
                    </div>
                  </div>

                  <div className="alert-toolbar">
                    <div className="search-bar">
                      <input
                        type="text"
                        placeholder="Search by IP address, alert type, severity, or status..."
                        value={searchTerm}
                        onChange={(event) =>
                          setSearchTerm(
                            event.target.value
                          )
                        }
                      />
                    </div>

                    <div className="filter-controls">
                      <div className="filter-group">
                        <span className="filter-label">
                          Severity
                        </span>

                        <div className="filter-options">
                          {[
                            "ALL",
                            "CRITICAL",
                            "HIGH",
                            "MEDIUM",
                            "LOW",
                          ].map((option) => (
                            <button
                              key={option}
                              type="button"
                              className={`filter-option ${
                                severityFilter ===
                                option
                                  ? "active"
                                  : ""
                              }`}
                              onClick={() =>
                                setSeverityFilter(
                                  option
                                )
                              }
                            >
                              {option === "ALL"
                                ? "All Severities"
                                : option}
                            </button>
                          ))}
                        </div>
                      </div>

                      <div className="filter-group">
                        <span className="filter-label">
                          Status
                        </span>

                        <div className="filter-options">
                          {[
                            "ALL",
                            "NEW",
                            "INVESTIGATING",
                            "RESOLVED",
                          ].map((option) => (
                            <button
                              key={option}
                              type="button"
                              className={`filter-option ${
                                statusFilter ===
                                option
                                  ? "active"
                                  : ""
                              }`}
                              onClick={() =>
                                setStatusFilter(
                                  option
                                )
                              }
                            >
                              {option === "ALL"
                                ? "All Statuses"
                                : option}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div className="sort-controls">
                      <label>Sort by:</label>

                      <div className="custom-sort">
                        <button
                          type="button"
                          className="custom-sort-trigger"
                          onClick={() =>
                            setSortOpen(
                              (open) => !open
                            )
                          }
                          aria-expanded={sortOpen}
                        >
                          {sortBy === "NEWEST"
                            ? "Newest First"
                            : sortBy === "OLDEST"
                            ? "Oldest First"
                            : "Highest Severity"}

                          <span
                            className={`sort-arrow ${
                              sortOpen
                                ? "open"
                                : ""
                            }`}
                          >
                            ▾
                          </span>
                        </button>

                        {sortOpen && (
                          <div className="custom-sort-menu">
                            {[
                              {
                                value: "NEWEST",
                                label: "Newest First",
                              },
                              {
                                value: "OLDEST",
                                label: "Oldest First",
                              },
                              {
                                value: "SEVERITY",
                                label: "Highest Severity",
                              },
                            ].map((option) => (
                              <button
                                key={
                                  option.value
                                }
                                type="button"
                                className={`custom-sort-option ${
                                  sortBy ===
                                  option.value
                                    ? "selected"
                                    : ""
                                }`}
                                onClick={() => {
                                  setSortBy(
                                    option.value
                                  );
                                  setSortOpen(false);
                                }}
                              >
                                {option.label}
                                {sortBy ===
                                  option.value && (
                                  <span>
                                    ✓
                                  </span>
                                )}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {alerts.length === 0 ? (
                    <div className="no-alerts">
                      No security alerts detected.
                    </div>
                  ) : (
                    <div className="alert-list">
                      <div className="alert-count">
                        <span>
                          Showing{" "}
                          <strong>
                            {filteredAlerts.length}
                          </strong>{" "}
                          of{" "}
                          <strong>
                            {alerts.length}
                          </strong>{" "}
                          alerts
                        </span>

                        {(severityFilter !==
                          "ALL" ||
                          statusFilter !== "ALL" ||
                          searchTerm.trim() !==
                            "") && (
                          <button
                            type="button"
                            className="clear-filters-button"
                            onClick={
                              clearFilters
                            }
                          >
                            Clear Filters
                          </button>
                        )}
                      </div>

                      {filteredAlerts.length ===
                      0 ? (
                        <div className="no-alerts">
                          No alerts match your
                          search or selected
                          filters.
                        </div>
                      ) : (
                        filteredAlerts.map(
                          (alert) => (
                            <div
                              className="alert-card"
                              key={alert.id}
                            >
                              <div
                                className={`severity ${String(
                                  alert.severity ||
                                    ""
                                ).toLowerCase()}`}
                              >
                                {alert.severity}
                              </div>

                              <div className="alert-content">
                                <h3>
                                  {alert.alert_type}
                                </h3>

                                <p>
                                  {
                                    alert.description
                                  }
                                </p>

                                <div className="alert-details">
                                  <span>
                                    <b>
                                      Source IP:
                                    </b>{" "}
                                    {
                                      alert.source_ip
                                    }
                                  </span>

                                  <span>
                                    <b>
                                      Failed Attempts:
                                    </b>{" "}
                                    {
                                      alert.failed_attempts
                                    }
                                  </span>

                                  <span>
                                    <b>
                                      Status:
                                    </b>{" "}
                                    {
                                      alert.status
                                    }
                                  </span>
                                </div>

                                <div className="alert-timestamp">
                                  Detected:{" "}
                                  {alert.created_at
                                    ? new Date(
                                        alert.created_at.replace(
                                          " ",
                                          "T"
                                        ) + "Z"
                                      ).toLocaleString()
                                    : "Time unavailable"}
                                </div>

                                <div className="status-buttons">
                                  <button
                                    className="details-button"
                                    onClick={() =>
                                      openInvestigation(
                                        alert
                                      )
                                    }
                                  >
                                    View Details
                                  </button>

                                  {alert.status ===
                                    "NEW" && (
                                    <button
                                      onClick={() =>
                                        updateStatus(
                                          alert.id,
                                          "INVESTIGATING"
                                        )
                                      }
                                    >
                                      Investigate
                                    </button>
                                  )}

                                  {alert.status ===
                                    "INVESTIGATING" && (
                                    <button
                                      onClick={() =>
                                        updateStatus(
                                          alert.id,
                                          "RESOLVED"
                                        )
                                      }
                                    >
                                      Resolve
                                    </button>
                                  )}
                                </div>
                              </div>
                            </div>
                          )
                        )
                      )}
                    </div>
                  )}
                </section>
              </main>
            </div>

            <aside className="dashboard-rail">
              <section
                className="rail-panel"
                id="system-status-panel"
              >
                <div className="rail-title">
                  <span className="rail-title-icon green">
                    ●
                  </span>
                  <h2>System Status</h2>
                  <span className="online-pill">
                    ONLINE
                  </span>
                </div>

                <div className="system-grid">
                  <div className="system-item">
                    <span className="system-dot"></span>
                    <div>
                      <strong>
                        Backend API
                      </strong>
                      <small>Connected</small>
                    </div>
                  </div>

                  <div className="system-item">
                    <span className="system-dot"></span>
                    <div>
                      <strong>
                        Log Collector
                      </strong>
                      <small>Ready</small>
                    </div>
                  </div>

                  <div className="system-item">
                    <span className="system-dot"></span>
                    <div>
                      <strong>
                        AI Analysis
                      </strong>
                      <small>
                        Available on request
                      </small>
                    </div>
                  </div>

                  <div className="system-item">
                    <span className="system-dot"></span>
                    <div>
                      <strong>Database</strong>
                      <small>
                        Alerts loaded
                      </small>
                    </div>
                  </div>
                </div>
              </section>

              <section
                className="rail-panel"
                id="threat-distribution"
              >
                <div className="rail-title">
                  <span className="rail-title-icon purple">
                    ✦
                  </span>
                  <h2>
                    Threat Distribution
                  </h2>
                </div>

                <div className="threat-content">
                  <div className="donut-chart">
                    <div className="donut-hole">
                      <strong>
                        {totalAlerts}
                      </strong>
                      <span>
                        Total Alerts
                      </span>
                    </div>
                  </div>

                  <div className="threat-legend">
                    <div>
                      <i className="legend-critical"></i>
                      <span>Critical</span>
                      <strong>
                        {criticalAlerts}
                      </strong>
                    </div>

                    <div>
                      <i className="legend-high"></i>
                      <span>High</span>
                      <strong>
                        {highAlerts}
                      </strong>
                    </div>

                    <div>
                      <i className="legend-medium"></i>
                      <span>Medium</span>
                      <strong>
                        {mediumAlerts}
                      </strong>
                    </div>

                    <div>
                      <i className="legend-low"></i>
                      <span>Low</span>
                      <strong>
                        {lowAlerts}
                      </strong>
                    </div>
                  </div>
                </div>
              </section>

              <section className="rail-panel activity-panel">
                <div className="rail-title">
                  <span className="rail-title-icon blue">
                    ◷
                  </span>
                  <h2>Recent Activity</h2>
                </div>

                <div className="activity-list">
                  {filteredAlerts
                    .slice(0, 4)
                    .map((alert, index) => (
                      <div
                        className="activity-item"
                        key={`activity-${alert.id}`}
                      >
                        <span
                          className={`activity-marker ${String(
                            alert.severity ||
                              "low"
                          ).toLowerCase()}`}
                        >
                          {alert.status ===
                          "RESOLVED"
                            ? "✓"
                            : index === 1
                            ? "⌕"
                            : "+"}
                        </span>

                        <div>
                          <strong>
                            {alert.status ===
                            "RESOLVED"
                              ? "Alert marked as resolved"
                              : alert.status ===
                                "INVESTIGATING"
                              ? "Investigation in progress"
                              : "New alert detected"}
                          </strong>

                          <p>
                            {alert.alert_type} (
                            {alert.source_ip})
                          </p>
                        </div>
                      </div>
                    ))}

                  {filteredAlerts.length ===
                    0 && (
                    <p className="empty-activity">
                      No recent alerts to
                      display.
                    </p>
                  )}
                </div>
              </section>
            </aside>
          </div>

          <section
            className="charts-row"
            id="dashboard-charts"
          >
            <div className="chart-panel trend-panel">
              <div className="chart-heading">
                <div>
                  <h2>Alerts Trend</h2>
                  <p>
                    Illustrative 24-hour activity
                    layout
                  </p>
                </div>

                <span className="chart-badge">
                  All alerts
                </span>
              </div>

              <div className="trend-visual">
                <div className="chart-y-labels">
                  <span>
                    {Math.max(totalAlerts, 10)}
                  </span>
                  <span>6</span>
                  <span>3</span>
                  <span>0</span>
                </div>

                <svg
                  viewBox="0 0 520 150"
                  role="img"
                  aria-label="Illustrative alert trend chart"
                  preserveAspectRatio="none"
                >
                  <defs>
                    <linearGradient
                      id="trendFill"
                      x1="0"
                      x2="0"
                      y1="0"
                      y2="1"
                    >
                      <stop
                        offset="0%"
                        stopColor="#7ca8ff"
                        stopOpacity=".38"
                      />
                      <stop
                        offset="100%"
                        stopColor="#7ca8ff"
                        stopOpacity=".03"
                      />
                    </linearGradient>
                  </defs>

                  <path
                    d="M0 125 C35 110 48 100 75 105 S120 128 150 92 S205 82 230 97 S280 45 310 57 S350 102 385 78 S425 34 450 62 S490 58 520 22 L520 150 L0 150 Z"
                    fill="url(#trendFill)"
                  />

                  <path
                    d="M0 125 C35 110 48 100 75 105 S120 128 150 92 S205 82 230 97 S280 45 310 57 S350 102 385 78 S425 34 450 62 S490 58 520 22"
                    fill="none"
                    stroke="#4c83f4"
                    strokeWidth="3"
                    vectorEffect="non-scaling-stroke"
                  />
                </svg>
              </div>

              <div className="chart-x-labels">
                <span>12 AM</span>
                <span>4 AM</span>
                <span>8 AM</span>
                <span>12 PM</span>
                <span>4 PM</span>
                <span>8 PM</span>
              </div>

              <p className="chart-footnote">
                Trend line is illustrative; event-time
                aggregation is not connected yet.
              </p>
            </div>

            <div className="chart-panel top-types-panel">
              <div className="chart-heading">
                <div>
                  <h2>Top Alert Types</h2>
                  <p>
                    Most common alert categories
                  </p>
                </div>
              </div>

              {Object.entries(
                alerts.reduce(
                  (acc, alert) => {
                    const key =
                      alert.alert_type ||
                      "Unknown";

                    acc[key] =
                      (acc[key] || 0) + 1;

                    return acc;
                  },
                  {}
                )
              )
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5)
                .map(
                  ([type, count], index) => (
                    <div
                      className="type-bar-row"
                      key={type}
                    >
                      <span title={type}>
                        {type}
                      </span>

                      <div className="type-bar-track">
                        <i
                          className={`type-bar color-${
                            index % 5
                          }`}
                          style={{
                            width: `${Math.min(
                              100,
                              (count /
                                Math.max(
                                  1,
                                  alerts.length
                                )) *
                                100
                            )}%`,
                          }}
                        ></i>
                      </div>

                      <strong>{count}</strong>
                    </div>
                  )
                )}

              {alerts.length === 0 && (
                <p className="empty-activity">
                  No alert types yet.
                </p>
              )}
            </div>

            <div className="chart-panel severity-chart-panel">
              <div className="chart-heading">
                <div>
                  <h2>Severity Breakdown</h2>
                  <p>
                    Alerts by severity level
                  </p>
                </div>
              </div>

              <div className="severity-bars">
                {[
                  {
                    label: "Critical",
                    value: criticalAlerts,
                    color: "bar-critical",
                  },
                  {
                    label: "High",
                    value: highAlerts,
                    color: "bar-high",
                  },
                  {
                    label: "Medium",
                    value: mediumAlerts,
                    color: "bar-medium",
                  },
                  {
                    label: "Low",
                    value: lowAlerts,
                    color: "bar-low",
                  },
                ].map((item) => (
                  <div
                    className="severity-bar-column"
                    key={item.label}
                  >
                    <strong>
                      {item.value}
                    </strong>

                    <div
                      className={`severity-bar ${item.color}`}
                      style={{
                        height: `${
                          Math.max(
                            5,
                            (item.value /
                              Math.max(
                                1,
                                criticalAlerts,
                                highAlerts,
                                mediumAlerts,
                                lowAlerts
                              )) *
                              100
                          )
                        }%`,
                      }}
                    ></div>

                    <span>
                      {item.label}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* Investigation Panel */}
          {selectedAlert && (
            <section
              className="investigation-panel"
              id="ai-investigation"
            >
              <div className="investigation-header">
                <div>
                  <h2>Alert Investigation</h2>
                  <p>
                    Security alert analysis and
                    investigation details
                  </p>
                </div>

                <button
                  className="close-button"
                  onClick={() => {
                    setSelectedAlert(null);
                    setAiAnalysis("");
                    setAiError("");
                    setAiLoading(false);
                  }}
                >
                  Close
                </button>
              </div>

              <div className="investigation-content">
                <div className="investigation-title">
                  <span
                    className={`severity ${String(
                      selectedAlert.severity ||
                        ""
                    ).toLowerCase()}`}
                  >
                    {selectedAlert.severity}
                  </span>

                  <h3>
                    {selectedAlert.alert_type}
                  </h3>
                </div>

                <div className="investigation-grid">
                  <div className="investigation-item">
                    <span>Alert ID</span>
                    <strong>
                      {selectedAlert.id}
                    </strong>
                  </div>

                  <div className="investigation-item">
                    <span>Source IP</span>
                    <strong>
                      {selectedAlert.source_ip}
                    </strong>
                  </div>

                  <div className="investigation-item">
                    <span>Failed Attempts</span>
                    <strong>
                      {
                        selectedAlert.failed_attempts
                      }
                    </strong>
                  </div>

                  <div className="investigation-item">
                    <span>
                      Successful Logins
                    </span>
                    <strong>
                      {
                        selectedAlert.successful_logins
                      }
                    </strong>
                  </div>

                  <div className="investigation-item">
                    <span>Current Status</span>
                    <strong>
                      {selectedAlert.status}
                    </strong>
                  </div>

                  {selectedAlert.created_at && (
                    <div className="investigation-item">
                      <span>
                        Detected At
                      </span>
                      <strong>
                        {new Date(
                          selectedAlert.created_at.replace(
                            " ",
                            "T"
                          ) + "Z"
                        ).toLocaleString()}
                      </strong>
                    </div>
                  )}
                </div>

                <div className="analysis-box">
                  <h3>
                    Detection Analysis
                  </h3>

                  <p>
                    {selectedAlert.description}
                  </p>
                </div>

                <div className="investigation-actions">
                  <button
                    onClick={() =>
                      analyzeWithAI(
                        selectedAlert.id
                      )
                    }
                    disabled={aiLoading}
                  >
                    {aiLoading
                      ? "Analyzing with AI..."
                      : "Analyze with AI"}
                  </button>

                  {selectedAlert.status ===
                    "NEW" && (
                    <button
                      onClick={() =>
                        updateStatus(
                          selectedAlert.id,
                          "INVESTIGATING"
                        )
                      }
                    >
                      Start Investigation
                    </button>
                  )}

                  {selectedAlert.status ===
                    "INVESTIGATING" && (
                    <button
                      onClick={() =>
                        updateStatus(
                          selectedAlert.id,
                          "RESOLVED"
                        )
                      }
                    >
                      Mark as Resolved
                    </button>
                  )}
                </div>

                {aiLoading && (
                  <div className="ai-analysis-box">
                    <h3>
                      🤖 AI Security Analysis
                    </h3>
                    <p>
                      Ollama is analyzing the
                      alert...
                    </p>
                  </div>
                )}

                {aiError && (
                  <div className="ai-analysis-box">
                    <h3>
                      AI Analysis Error
                    </h3>
                    <p>{aiError}</p>
                  </div>
                )}

                {aiAnalysis && (
                  <div className="ai-analysis-box">
                    <h3>
                      🤖 AI Security Analysis
                    </h3>

                    <div className="ai-analysis-content">
                      <ReactMarkdown>
                        {aiAnalysis}
                      </ReactMarkdown>
                    </div>

                    <div className="ai-note">
                      <strong>Note:</strong> AI-generated
                      analysis is an assistance tool.
                      Final security decisions should
                      be made by the SOC analyst.
                    </div>
                  </div>
                )}
              </div>
            </section>
          )}

          <footer>
            AI-Powered SOC Alert Analyzer • Prototype
          </footer>
        </div>
      )}
    </>
  );
}

export default App;