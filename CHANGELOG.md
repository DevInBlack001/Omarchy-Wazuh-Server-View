# Changelog

All notable changes to this plugin are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Screenshots of the agent drill-down (Overview and SCA), Threat Hunting, and MITRE ATT&CK views, captured from a live install and referenced in the README under each feature.

## [1.0.1] - 2026-08-31

### Fixed

- Bar icon had no visible glyph: the icon `text` property held empty quotes instead of the actual Nerd Font codepoint, so the button rendered nothing and its hit-box was easy to miss entirely. Fixed by verifying the correct codepoint byte-for-byte instead of retyping it by hand.
- `manifest.json` descriptions still described the plugin as reading the manager's own local files; corrected to describe the actual REST API + indexer architecture.

### Changed

- Bar and panel icon switched from the shared shield glyph (used by the agent-side `omarchy-wazuh-view` plugin) to a distinct server icon, so the two plugins are visually distinguishable in the bar.

### Added

- Real `preview.png`, captured from a live install against an actual Wazuh manager.

## [1.0.0] - 2026-08-30

### Added

- Bar-widget panel with three top-level tabs: Overview, Threat Hunting, MITRE ATT&CK
- Overview tab: manager version, cluster status, manager daemon status, agent connection counts, and a searchable roster of every agent
- Per-agent drill-down (click any agent in the roster): connection status, SCA policy results with failed checks and remediation, FIM monitored-path count and sample, rootcheck findings, effective FIM/log-collection/active-response configuration, and that agent's recent alerts
- Threat Hunting tab: chronological feed of recent alerts across all agents with level and MITRE tags, plus a critical/warning/info count
- MITRE ATT&CK tab: only techniques observed in alerts from the last 7 days (not the full framework), with occurrence count, last-seen time, and affected agents
- Wazuh manager REST API client (agent roster, SCA, FIM, rootcheck, effective config, manager/cluster status) with JWT authentication
- Wazuh indexer (OpenSearch) client for alert search backing threat hunting and MITRE aggregation, with automatic retry against a `.keyword` field mapping if the plain field isn't aggregatable
- Credentials via environment variables first, with an explicitly-named (no default/guessed path) local JSON file as a fallback, enforced to be owned by the current user and mode 600
- HTTPS enforced for both the manager API and the indexer; a plaintext URL is refused before any credential is sent
- TLS verification on by default for both subsystems, with an explicit opt-out and CA bundle support per subsystem
- Section-by-section graceful degradation: a missing endpoint, auth failure, unreachable indexer, or version mismatch in one section never blocks the rest of the panel
