// Formatting and status-aggregation helpers for the Wazuh Server View panel.
// Pure functions only, no QML/Quickshell imports, so this stays reusable and
// easy to reason about (and test) on its own.

function errorLabel(code) {
  var map = {
    not_configured: "Not configured, see plugin README for setup",
    auth_failed: "Authentication failed, check the API/indexer credentials",
    tls_error: "TLS certificate verification failed",
    connection_error: "Could not reach the server (network, DNS, or timeout)",
    not_available: "Not available on this Wazuh manager version",
    http_error: "Unexpected response from the server",
    read_error: "Could not read this data",
    invalid_agent_id: "Invalid agent id",
    insecure_url: "Refusing to send credentials over a non-HTTPS URL",
    unsafe_permissions: "Credentials file has unsafe permissions, run chmod 600 on it",
  }
  return map[code] || "Unknown error"
}

// Three-tier status used for text/icon coloring: "good" | "warn" | "bad" |
// "unknown" (data not readable, distinct from a real pass/fail verdict).
function agentStatusTier(status) {
  if (status === "active") return "good"
  if (status === "pending") return "warn"
  if (status === "disconnected" || status === "never_connected") return "bad"
  return "unknown"
}

function agentStatusLabel(status) {
  var map = {
    active: "Active",
    disconnected: "Disconnected",
    never_connected: "Never connected",
    pending: "Pending",
  }
  return map[status] || "Unknown"
}

function sectionTier(section) {
  if (!section) return "unknown"
  if (section.error) return (section.configured === false || section.error === "not_configured") ? "unknown" : "bad"
  if (section.readable === false) return "unknown"
  return "good"
}

function scaStatus(sca) {
  if (!sca || !sca.readable) return sectionTier(sca)
  if (sca.failedChecks && sca.failedChecks.length > 0) return "warn"
  return "good"
}

function worstStatus(statuses) {
  if (statuses.indexOf("bad") >= 0) return "bad"
  if (statuses.indexOf("warn") >= 0) return "warn"
  if (statuses.indexOf("unknown") >= 0) return "unknown"
  return "good"
}

function levelTier(level) {
  if (level === null || level === undefined) return "unknown"
  if (level >= 12) return "bad"
  if (level >= 7) return "warn"
  return "good"
}

function summarize(payload) {
  if (!payload) return { status: "unknown", label: "LOADING" }
  if (payload.apiError === "not_configured") return { status: "unknown", label: "NOT CONFIGURED" }
  if (payload.apiError) return { status: "bad", label: "API UNREACHABLE" }

  var roster = payload.roster || {}
  var counts = roster.counts || {}
  var statuses = [sectionTier(roster)]
  if ((counts.disconnected || 0) > 0) statuses.push("bad")
  if ((counts.pending || 0) > 0) statuses.push("warn")

  var mitre = payload.mitre || {}
  if (mitre.techniques && mitre.techniques.length > 0) statuses.push("warn")

  var status = worstStatus(statuses)
  var label
  if (status === "bad") label = "ATTENTION NEEDED"
  else if (status === "warn") label = "CHECKS FAILING"
  else if (status === "unknown") label = "PARTIAL DATA"
  else label = "HEALTHY"
  return { status: status, label: label }
}

function totalsSummary(totals) {
  if (!totals) return "-"
  var parts = []
  for (var key in totals) {
    if (Object.prototype.hasOwnProperty.call(totals, key)) {
      parts.push(totals[key] + " " + key)
    }
  }
  return parts.length ? parts.join(", ") : "-"
}

function scanSummary(scan) {
  if (!scan) return "-"
  if (scan.pass !== null && scan.pass !== undefined && scan.total) {
    return scan.pass + " / " + scan.total + " passed"
  }
  return "-"
}

function fieldOrDash(v) {
  return (v === null || v === undefined || v === "") ? "-" : String(v)
}

function boolLabel(v) {
  if (v === true) return "yes"
  if (v === false) return "no"
  return "unknown"
}

function countOf(counts, key) {
  return (counts && typeof counts[key] === "number") ? counts[key] : 0
}

function agentNameFor(agentId, roster) {
  if (!roster || !roster.agents) return agentId
  for (var i = 0; i < roster.agents.length; i++) {
    if (roster.agents[i].id === agentId) return roster.agents[i].name || agentId
  }
  return agentId
}

function matchesQuery(agent, query) {
  if (!query) return true
  var q = query.toLowerCase()
  return (agent.name && agent.name.toLowerCase().indexOf(q) >= 0) ||
         (agent.ip && agent.ip.toLowerCase().indexOf(q) >= 0) ||
         (agent.id && agent.id.toLowerCase().indexOf(q) >= 0) ||
         (agent.osName && agent.osName.toLowerCase().indexOf(q) >= 0)
}

if (typeof module !== "undefined") {
  module.exports = {
    errorLabel: errorLabel,
    agentStatusTier: agentStatusTier,
    agentStatusLabel: agentStatusLabel,
    sectionTier: sectionTier,
    scaStatus: scaStatus,
    worstStatus: worstStatus,
    levelTier: levelTier,
    summarize: summarize,
    totalsSummary: totalsSummary,
    scanSummary: scanSummary,
    fieldOrDash: fieldOrDash,
    boolLabel: boolLabel,
    countOf: countOf,
    agentNameFor: agentNameFor,
    matchesQuery: matchesQuery,
  }
}
