import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Ui
import qs.Commons
import "Model.js" as Model

// Server-side Wazuh view, entirely inside the Quickshell bar: no separate GUI
// window. This does NOT run on the manager and reads no local manager files;
// every field comes from the Wazuh manager REST API and, for alerts (threat
// hunting + breached MITRE ATT&CK techniques), the Wazuh indexer, exactly the
// data the Wazuh dashboard shows on login. All data collection happens in
// bin/omarchy-wazuh-server-state; this file only renders whatever that
// script reports. Credentials are never hardcoded here: see the script
// header and README for how they're supplied.
Panel {
  id: root
  moduleName: "devinblack001.wazuh-server-view"
  ipcTarget: "devinblack001.wazuh-server-view"
  manageIpc: false

  readonly property string script: String(Qt.resolvedUrl("bin/omarchy-wazuh-server-state")).replace(/^file:\/\//, "")

  property var overview: null
  property bool overviewLoadFailed: false
  property int activeTab: 0

  property string viewingAgentId: ""
  property var agentDetail: null
  property bool agentLoadFailed: false
  property int agentSubTab: 0

  property string agentSearchQuery: ""

  readonly property var rosterData: (overview && overview.roster) ? overview.roster : null
  readonly property var rosterAgents: (rosterData && rosterData.agents) ? rosterData.agents : []
  readonly property var rosterCounts: (rosterData && rosterData.counts) ? rosterData.counts : ({})
  readonly property var threatHuntingData: overview ? overview.threatHunting : null
  readonly property var mitreData: overview ? overview.mitre : null
  readonly property var clusterData: overview ? overview.cluster : null
  readonly property var daemonStatusData: overview ? overview.daemonStatus : null

  readonly property var filteredAgents: {
    var list = []
    for (var i = 0; i < rosterAgents.length; i++) {
      if (Model.matchesQuery(rosterAgents[i], root.agentSearchQuery)) list.push(rosterAgents[i])
    }
    return list
  }

  readonly property var summary: Model.summarize(overview)
  readonly property string overallStatus: summary.status

  property string cachedStateJson: JSON.stringify({ status: "", payload: null })

  function statusColor(status) {
    if (status === "bad") return root.bar.urgent
    if (status === "warn") return Color.accent
    if (status === "unknown") return Qt.darker(root.bar.foreground, 1.6)
    return root.bar.foreground
  }

  function refreshOverview() {
    if (!overviewProc.running) overviewProc.running = true
  }

  function refreshAgent() {
    if (!root.viewingAgentId) return
    if (agentProc.running) return
    agentProc.command = [root.script, "--agent", root.viewingAgentId]
    agentProc.running = true
  }

  function openAgent(id) {
    root.viewingAgentId = id
    root.agentDetail = null
    root.agentLoadFailed = false
    root.agentSubTab = 0
    refreshAgent()
  }

  function closeAgent() {
    root.viewingAgentId = ""
    root.agentDetail = null
  }

  function stateIpc() {
    return root.cachedStateJson
  }

  function utf8ByteLength(str) {
    var bytes = 0
    for (var i = 0; i < str.length; i++) {
      var code = str.charCodeAt(i)
      if (code >= 0xD800 && code <= 0xDBFF && i + 1 < str.length) {
        var next = str.charCodeAt(i + 1)
        if (next >= 0xDC00 && next <= 0xDFFF) {
          bytes += 4
          i++
          continue
        }
      }
      if (code <= 0x7F) bytes += 1
      else if (code <= 0x7FF) bytes += 2
      else bytes += 3
    }
    return bytes
  }

  IpcHandler {
    target: "devinblack001.wazuh-server-view"
    function state(): string { return root.stateIpc() }
    function open() { root.open() }
    function close() { root.close() }
    function toggle() { root.toggle() }
    function show() { root.open() }
    function hide() { root.close() }
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  Component.onCompleted: refreshOverview()
  onOpenedChanged: if (opened) { refreshOverview(); refreshAgent() }

  // Network-bound now (Wazuh manager API + indexer), not free local file
  // reads, so this polls noticeably slower than a local-only plugin would.
  Timer {
    interval: root.opened ? 10000 : 30000
    running: true
    repeat: true
    onTriggered: root.refreshOverview()
  }

  Timer {
    interval: 15000
    running: root.opened && root.viewingAgentId !== ""
    repeat: true
    onTriggered: root.refreshAgent()
  }

  readonly property int maxPayloadBytes: 4 * 1024 * 1024

  Process {
    id: overviewProc
    command: [root.script]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var raw = String(text || "null")
        if (root.utf8ByteLength(raw) > root.maxPayloadBytes) {
          root.overviewLoadFailed = true
          return
        }
        try {
          root.overview = JSON.parse(raw)
          root.overviewLoadFailed = root.overview === null
        } catch (e) {
          root.overviewLoadFailed = true
        }
        root.cachedStateJson = JSON.stringify({ status: root.overallStatus, payload: root.overview })
      }
    }
  }

  Process {
    id: agentProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var raw = String(text || "null")
        if (root.utf8ByteLength(raw) > root.maxPayloadBytes) {
          root.agentLoadFailed = true
          return
        }
        try {
          root.agentDetail = JSON.parse(raw)
          root.agentLoadFailed = root.agentDetail === null
        } catch (e) {
          root.agentLoadFailed = true
        }
      }
    }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: ""  // nf-fa-shield
    active: root.overallStatus === "bad" || root.overallStatus === "warn"
    onPressed: function(b) { root.toggle() }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(480))
    contentHeight: panel.fittedContentHeight(panelColumn.implicitHeight, Style.space(700))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      Flickable {
        id: scrollArea
        anchors.fill: parent
        contentWidth: width
        contentHeight: panelColumn.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height

        Column {
          id: panelColumn
          width: scrollArea.width
          spacing: Style.space(14)

          // ---------- Hero ----------
          Item {
            width: parent.width
            implicitHeight: Math.max(heroIcon.implicitHeight, heroLabels.implicitHeight)

            Text {
              textFormat: Text.PlainText
              id: heroIcon
              text: ""  // nf-fa-shield
              color: root.statusColor(root.overallStatus)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.display
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
            }

            Column {
              id: heroLabels
              anchors.left: heroIcon.right
              anchors.leftMargin: Style.space(14)
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(2)

              Text {
                textFormat: Text.PlainText
                text: "Wazuh Server View"
                color: root.bar.foreground
                font.family: root.bar.fontFamily
                font.pixelSize: Style.font.title
                font.bold: true
                elide: Text.ElideRight
                width: parent.width
              }

              Text {
                textFormat: Text.PlainText
                text: root.summary.label
                color: root.statusColor(root.overallStatus)
                font.family: root.bar.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1.2
                elide: Text.ElideRight
                width: parent.width
              }
            }
          }

          // ---------- Not configured ----------
          PanelSeparator { foreground: root.bar.foreground; visible: !!root.overview && root.overview.apiError === "not_configured" }

          Column {
            width: parent.width
            spacing: Style.space(6)
            visible: !!root.overview && root.overview.apiError === "not_configured"

            Text {
              textFormat: Text.PlainText
              text: "No Wazuh manager API configured. Set WAZUH_API_URL, WAZUH_API_USER, and WAZUH_API_PASSWORD (and the WAZUH_INDEXER_* equivalents for threat hunting and MITRE), or write them to ~/.config/omarchy-wazuh-server-view/credentials.json with mode 600."
              color: Qt.darker(root.bar.foreground, 1.4)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
              width: parent.width
            }
          }

          Text {
            textFormat: Text.PlainText
            visible: !root.overview && !root.overviewLoadFailed
            text: "Connecting to the Wazuh manager..."
            color: Qt.darker(root.bar.foreground, 1.4)
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.body
          }

          Text {
            textFormat: Text.PlainText
            visible: root.overviewLoadFailed
            text: "Failed to read server state."
            color: root.statusColor("bad")
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.body
          }

          Text {
            textFormat: Text.PlainText
            visible: !!root.overview && !!root.overview.apiError && root.overview.apiError !== "not_configured"
            text: root.overview ? Model.errorLabel(root.overview.apiError) : ""
            color: root.statusColor("bad")
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
            width: parent.width
          }

          Text {
            textFormat: Text.PlainText
            visible: !!root.overview && !!root.overview.credentialsFileError
            text: root.overview ? Model.errorLabel(root.overview.credentialsFileError) : ""
            color: root.statusColor("warn")
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
            width: parent.width
          }

          // ======================================================
          // Agent detail view (replaces the top-level tabs while open)
          // ======================================================
          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: root.viewingAgentId !== ""

            Row {
              width: parent.width
              spacing: Style.space(8)

              Text {
                textFormat: Text.PlainText
                text: "‹ Back"
                color: Color.accent
                font.family: root.bar.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.closeAgent() }
              }

              Text {
                textFormat: Text.PlainText
                text: (root.agentDetail && root.agentDetail.agent && root.agentDetail.agent.name) ? root.agentDetail.agent.name : ("Agent " + root.viewingAgentId)
                color: root.bar.foreground
                font.family: root.bar.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                elide: Text.ElideRight
              }
            }

            Text {
              textFormat: Text.PlainText
              visible: !root.agentDetail && !root.agentLoadFailed
              text: "Loading agent detail..."
              color: Qt.darker(root.bar.foreground, 1.4)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
            }

            Text {
              textFormat: Text.PlainText
              visible: !!root.agentDetail && !!root.agentDetail.apiError
              text: root.agentDetail ? Model.errorLabel(root.agentDetail.apiError) : ""
              color: root.statusColor("bad")
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
              width: parent.width
            }

            Row {
              width: parent.width
              spacing: Style.space(6)
              visible: !!root.agentDetail

              Repeater {
                model: [
                  { label: "Overview", index: 0 },
                  { label: "SCA", index: 1 },
                  { label: "FIM", index: 2 },
                  { label: "Rootcheck", index: 3 },
                  { label: "Config", index: 4 },
                  { label: "Logs", index: 5 }
                ]
                AgentTabButtonItem {
                  required property var modelData
                  label: modelData.label
                  index: modelData.index
                }
              }
            }

            PanelSeparator { foreground: root.bar.foreground; visible: !!root.agentDetail }

            // ---- Agent Overview ----
            Column {
              width: parent.width
              spacing: Style.space(6)
              visible: !!root.agentDetail && root.agentSubTab === 0

              KeyValueRow { k: "ID"; v: Model.fieldOrDash(root.viewingAgentId) }
              KeyValueRow {
                k: "Status"
                v: Model.agentStatusLabel(root.agentDetail && root.agentDetail.agent ? root.agentDetail.agent.connectionStatus : null)
                vColor: root.statusColor(Model.agentStatusTier(root.agentDetail && root.agentDetail.agent ? root.agentDetail.agent.connectionStatus : null))
              }
              KeyValueRow { k: "IP"; v: Model.fieldOrDash(root.agentDetail && root.agentDetail.agent ? root.agentDetail.agent.ip : null) }
              KeyValueRow { k: "OS"; v: Model.fieldOrDash(root.agentDetail && root.agentDetail.agent ? (root.agentDetail.agent.osName + " " + root.agentDetail.agent.osVersion) : null) }
              KeyValueRow { k: "Agent version"; v: Model.fieldOrDash(root.agentDetail && root.agentDetail.agent ? root.agentDetail.agent.version : null) }
              KeyValueRow { k: "Last keepalive"; v: Model.fieldOrDash(root.agentDetail && root.agentDetail.agent ? root.agentDetail.agent.lastKeepalive : null) }
              KeyValueRow { k: "Groups"; v: (root.agentDetail && root.agentDetail.agent && root.agentDetail.agent.groups) ? root.agentDetail.agent.groups.join(", ") : "-" }
              KeyValueRow { k: "Registered"; v: Model.fieldOrDash(root.agentDetail && root.agentDetail.agent ? root.agentDetail.agent.registered : null) }
            }

            // ---- SCA ----
            Column {
              width: parent.width
              spacing: Style.space(8)
              visible: !!root.agentDetail && root.agentSubTab === 1

              readonly property var sca: root.agentDetail ? root.agentDetail.sca : null

              Text {
                textFormat: Text.PlainText
                visible: !parent.sca || !parent.sca.readable
                text: parent.sca ? Model.errorLabel(parent.sca.error) : "Loading..."
                color: Qt.darker(root.bar.foreground, 1.4)
                font.family: root.bar.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
                width: parent.width
              }

              Column {
                width: parent.width
                spacing: Style.space(8)
                visible: !!(parent.sca && parent.sca.readable)

                PanelSectionHeader { text: "RESULTS"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily }
                KeyValueRow { k: "Totals"; v: Model.totalsSummary(parent.parent.sca ? parent.parent.sca.totals : null) }

                Repeater {
                  model: (parent.parent.sca && parent.parent.sca.scans) ? parent.parent.sca.scans : []
                  Column {
                    id: scanCard
                    required property var modelData
                    width: parent.width
                    spacing: Style.space(2)
                    KeyValueRow { k: Model.fieldOrDash(scanCard.modelData.name); v: Model.scanSummary(scanCard.modelData) }
                    KeyValueRow { k: "Score"; v: (scanCard.modelData.score !== null && scanCard.modelData.score !== undefined) ? (scanCard.modelData.score + "%") : "-" }
                  }
                }

                PanelSeparator { foreground: root.bar.foreground; visible: (parent.parent.sca && parent.parent.sca.failedChecks && parent.parent.sca.failedChecks.length > 0) }
                PanelSectionHeader { text: "FAILED CHECKS"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily; visible: (parent.parent.sca && parent.parent.sca.failedChecks && parent.parent.sca.failedChecks.length > 0) }

                Repeater {
                  model: (parent.parent.sca && parent.parent.sca.failedChecks) ? parent.parent.sca.failedChecks : []
                  Column {
                    id: checkCard
                    required property var modelData
                    width: parent.width
                    spacing: Style.space(2)
                    Text {
                      textFormat: Text.PlainText
                      text: checkCard.modelData.title || "Untitled check"
                      color: Color.accent
                      font.family: root.bar.fontFamily
                      font.pixelSize: Style.font.caption
                      font.bold: true
                      wrapMode: Text.WordWrap
                      width: parent.width
                    }
                    Text {
                      textFormat: Text.PlainText
                      visible: !!checkCard.modelData.remediation
                      text: checkCard.modelData.remediation || ""
                      color: Qt.darker(root.bar.foreground, 1.3)
                      font.family: root.bar.fontFamily
                      font.pixelSize: Style.font.caption
                      wrapMode: Text.WordWrap
                      width: parent.width
                    }
                  }
                }
              }
            }

            // ---- FIM ----
            Column {
              width: parent.width
              spacing: Style.space(8)
              visible: !!root.agentDetail && root.agentSubTab === 2

              readonly property var fim: root.agentDetail ? root.agentDetail.fim : null

              Text {
                textFormat: Text.PlainText
                visible: !parent.fim || !parent.fim.readable
                text: parent.fim ? Model.errorLabel(parent.fim.error) : "Loading..."
                color: Qt.darker(root.bar.foreground, 1.4)
                font.family: root.bar.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
                width: parent.width
              }

              Column {
                width: parent.width
                spacing: Style.space(6)
                visible: !!(parent.fim && parent.fim.readable)

                PanelSectionHeader { text: "BASELINE"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily }
                KeyValueRow { k: "Monitored paths"; v: Model.fieldOrDash(parent.parent.fim ? parent.parent.fim.monitoredCount : null) }

                Repeater {
                  model: (parent.parent.fim && parent.parent.fim.sample) ? parent.parent.fim.sample.slice(0, 50) : []
                  Text {
                    textFormat: Text.PlainText
                    required property var modelData
                    text: modelData
                    color: root.bar.foreground
                    font.family: root.bar.fontFamily
                    font.pixelSize: Style.font.caption
                    elide: Text.ElideMiddle
                    width: parent.width
                  }
                }
              }
            }

            // ---- Rootcheck ----
            Column {
              width: parent.width
              spacing: Style.space(6)
              visible: !!root.agentDetail && root.agentSubTab === 3

              readonly property var rc: root.agentDetail ? root.agentDetail.rootcheck : null

              Text {
                textFormat: Text.PlainText
                visible: !parent.rc || !parent.rc.available
                text: parent.rc ? Model.errorLabel(parent.rc.error || "not_available") : "Loading..."
                color: Qt.darker(root.bar.foreground, 1.4)
                font.family: root.bar.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
                width: parent.width
              }

              Column {
                width: parent.width
                spacing: Style.space(4)
                visible: !!(parent.rc && parent.rc.available)

                KeyValueRow { k: "Findings"; v: Model.fieldOrDash(parent.parent.rc ? parent.parent.rc.count : null) }
                Repeater {
                  model: (parent.parent.rc && parent.parent.rc.recent) ? parent.parent.rc.recent : []
                  Text {
                    textFormat: Text.PlainText
                    required property var modelData
                    text: modelData.text || ""
                    color: root.bar.foreground
                    font.family: root.bar.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                    width: parent.width
                  }
                }
              }
            }

            // ---- Config ----
            Column {
              width: parent.width
              spacing: Style.space(8)
              visible: !!root.agentDetail && root.agentSubTab === 4

              readonly property var cfg: root.agentDetail ? root.agentDetail.config : null

              Text {
                textFormat: Text.PlainText
                visible: !parent.cfg || !parent.cfg.readable
                text: parent.cfg ? Model.errorLabel(parent.cfg.error) : "Loading..."
                color: Qt.darker(root.bar.foreground, 1.4)
                font.family: root.bar.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
                width: parent.width
              }

              Column {
                width: parent.width
                spacing: Style.space(8)
                visible: !!(parent.cfg && parent.cfg.readable)

                PanelSectionHeader { text: "FIM DIRECTORIES"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily; visible: (parent.parent.cfg && parent.parent.cfg.fimDirs && parent.parent.cfg.fimDirs.length > 0) }
                Repeater {
                  model: (parent.parent.cfg && parent.parent.cfg.fimDirs) ? parent.parent.cfg.fimDirs : []
                  KeyValueRow {
                    required property var modelData
                    k: modelData.path
                    v: modelData.realtime ? "realtime" : "scheduled"
                  }
                }

                PanelSeparator { foreground: root.bar.foreground; visible: (parent.parent.cfg && parent.parent.cfg.logFiles && parent.parent.cfg.logFiles.length > 0) }
                PanelSectionHeader { text: "LOG SOURCES"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily; visible: (parent.parent.cfg && parent.parent.cfg.logFiles && parent.parent.cfg.logFiles.length > 0) }
                Repeater {
                  model: (parent.parent.cfg && parent.parent.cfg.logFiles) ? parent.parent.cfg.logFiles : []
                  KeyValueRow {
                    required property var modelData
                    k: modelData.location
                    v: modelData.format
                  }
                }

                PanelSeparator { foreground: root.bar.foreground; visible: !!(root.agentDetail && root.agentDetail.sca && root.agentDetail.sca.scans && root.agentDetail.sca.scans.length > 0) }
                PanelSectionHeader { text: "SCA POLICIES"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily; visible: !!(root.agentDetail && root.agentDetail.sca && root.agentDetail.sca.scans && root.agentDetail.sca.scans.length > 0) }
                Repeater {
                  model: (root.agentDetail && root.agentDetail.sca && root.agentDetail.sca.scans) ? root.agentDetail.sca.scans : []
                  Text {
                    textFormat: Text.PlainText
                    required property var modelData
                    text: modelData.name || ""
                    color: root.bar.foreground
                    font.family: root.bar.fontFamily
                    font.pixelSize: Style.font.caption
                    width: parent.width
                    elide: Text.ElideRight
                  }
                }

                PanelSeparator { foreground: root.bar.foreground }
                PanelSectionHeader { text: "ACTIVE RESPONSE"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily }
                KeyValueRow {
                  readonly property var arEnabled: parent.parent.cfg ? parent.parent.cfg.activeResponseEnabled : null
                  k: "Status"
                  v: Model.boolLabel(arEnabled)
                  vColor: root.statusColor(arEnabled === true ? "good" : (arEnabled === false ? "bad" : "unknown"))
                }
              }
            }

            // ---- Logs (this agent's recent alerts) ----
            Column {
              width: parent.width
              spacing: Style.space(6)
              visible: !!root.agentDetail && root.agentSubTab === 5

              readonly property var agentLogs: root.agentDetail ? root.agentDetail.logs : null

              Text {
                textFormat: Text.PlainText
                visible: !parent.agentLogs || !parent.agentLogs.readable
                text: parent.agentLogs ? Model.errorLabel(parent.agentLogs.error) : "Loading..."
                color: Qt.darker(root.bar.foreground, 1.4)
                font.family: root.bar.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
                width: parent.width
              }

              Repeater {
                model: (parent.agentLogs && parent.agentLogs.items) ? parent.agentLogs.items : []
                AlertRow { required property var modelData; entry: modelData; showAgent: false }
              }
            }
          }

          // ======================================================
          // Top-level tabs (hidden while an agent is open)
          // ======================================================
          PanelSeparator { foreground: root.bar.foreground; visible: root.viewingAgentId === "" }

          Row {
            width: parent.width
            spacing: Style.space(6)
            visible: root.viewingAgentId === ""

            Repeater {
              model: [
                { label: "Overview", index: 0 },
                { label: "Threat Hunting", index: 1 },
                { label: "MITRE ATT&CK", index: 2 }
              ]
              TopTabButtonItem {
                required property var modelData
                label: modelData.label
                index: modelData.index
              }
            }
          }

          PanelSeparator { foreground: root.bar.foreground; visible: root.viewingAgentId === "" }

          // ---------- Overview: server health + agent roster ----------
          Column {
            width: parent.width
            spacing: Style.space(10)
            visible: root.viewingAgentId === "" && root.activeTab === 0

            PanelSectionHeader { text: "SERVER"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily }
            KeyValueRow { k: "Manager version"; v: Model.fieldOrDash(root.overview && root.overview.managerInfo ? root.overview.managerInfo.version : null) }
            KeyValueRow { k: "Cluster"; v: (root.clusterData && root.clusterData.enabled) ? ("enabled (" + Model.fieldOrDash(root.clusterData.nodeName) + ")") : "disabled" }

            KeyValueRow { k: "Active"; v: String(Model.countOf(root.rosterCounts, "active")); vColor: root.statusColor("good") }
            KeyValueRow { k: "Disconnected"; v: String(Model.countOf(root.rosterCounts, "disconnected")); vColor: root.statusColor(Model.countOf(root.rosterCounts, "disconnected") > 0 ? "bad" : "good") }
            KeyValueRow { k: "Never connected"; v: String(Model.countOf(root.rosterCounts, "never_connected")) }
            KeyValueRow { k: "Pending"; v: String(Model.countOf(root.rosterCounts, "pending")); vColor: root.statusColor(Model.countOf(root.rosterCounts, "pending") > 0 ? "warn" : "good") }

            Column {
              width: parent.width
              spacing: Style.space(3)
              visible: !!root.daemonStatusData

              Text {
                textFormat: Text.PlainText
                text: "MANAGER DAEMONS"
                color: Qt.darker(root.bar.foreground, 1.6)
                font.family: root.bar.fontFamily
                font.pixelSize: Style.font.caption
                font.letterSpacing: 1.0
              }

              Repeater {
                model: root.daemonStatusData ? Object.keys(root.daemonStatusData) : []
                KeyValueRow {
                  required property var modelData
                  k: modelData
                  v: root.daemonStatusData[modelData]
                  vColor: (root.daemonStatusData[modelData] === "running") ? root.bar.foreground : root.bar.urgent
                }
              }
            }

            PanelSeparator { foreground: root.bar.foreground }
            PanelSectionHeader { text: "AGENTS (" + root.rosterAgents.length + ")"; foreground: root.bar.foreground; fontFamily: root.bar.fontFamily }

            TextField {
              width: parent.width
              placeholderText: "Filter by name, IP, ID, or OS..."
              text: root.agentSearchQuery
              onTextChanged: root.agentSearchQuery = text
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
            }

            Text {
              textFormat: Text.PlainText
              visible: root.rosterData && !root.rosterData.readable
              text: root.rosterData ? Model.errorLabel(root.rosterData.error) : "Loading..."
              color: Qt.darker(root.bar.foreground, 1.4)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
              width: parent.width
            }

            Repeater {
              model: root.filteredAgents
              AgentRow { required property var modelData; agent: modelData }
            }
          }

          // ---------- Threat Hunting ----------
          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: root.viewingAgentId === "" && root.activeTab === 1

            Text {
              textFormat: Text.PlainText
              visible: !root.threatHuntingData || !root.threatHuntingData.readable
              text: root.threatHuntingData ? Model.errorLabel(root.threatHuntingData.error) : "Loading..."
              color: Qt.darker(root.bar.foreground, 1.4)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
              width: parent.width
            }

            Row {
              spacing: Style.space(12)
              visible: !!(root.threatHuntingData && root.threatHuntingData.readable)

              Text { textFormat: Text.PlainText; text: Model.countOf(root.threatHuntingData ? root.threatHuntingData.counts : null, "critical") + " critical"; color: root.statusColor("bad"); font.family: root.bar.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              Text { textFormat: Text.PlainText; text: Model.countOf(root.threatHuntingData ? root.threatHuntingData.counts : null, "warning") + " warning"; color: root.statusColor("warn"); font.family: root.bar.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              Text { textFormat: Text.PlainText; text: Model.countOf(root.threatHuntingData ? root.threatHuntingData.counts : null, "info") + " info"; color: Qt.darker(root.bar.foreground, 1.3); font.family: root.bar.fontFamily; font.pixelSize: Style.font.caption }
            }

            Repeater {
              model: (root.threatHuntingData && root.threatHuntingData.items) ? root.threatHuntingData.items : []
              AlertRow { required property var modelData; entry: modelData; showAgent: true }
            }

            Text {
              textFormat: Text.PlainText
              visible: !!(root.threatHuntingData && root.threatHuntingData.readable && root.threatHuntingData.items && root.threatHuntingData.items.length === 0)
              text: "No recent alerts."
              color: Qt.darker(root.bar.foreground, 1.4)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
            }
          }

          // ---------- MITRE ATT&CK (breached techniques only) ----------
          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: root.viewingAgentId === "" && root.activeTab === 2

            Text {
              textFormat: Text.PlainText
              visible: !root.mitreData || !root.mitreData.readable
              text: root.mitreData ? Model.errorLabel(root.mitreData.error) : "Loading..."
              color: Qt.darker(root.bar.foreground, 1.4)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
              width: parent.width
            }

            Text {
              textFormat: Text.PlainText
              visible: !!(root.mitreData && root.mitreData.readable)
              text: "Techniques observed in recent alerts only, not the full ATT&CK matrix."
              color: Qt.darker(root.bar.foreground, 1.6)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
              width: parent.width
            }

            Repeater {
              model: (root.mitreData && root.mitreData.techniques) ? root.mitreData.techniques : []
              Column {
                id: techCard
                required property var modelData
                width: parent.width
                spacing: Style.space(2)

                Text {
                  textFormat: Text.PlainText
                  text: techCard.modelData.id + " " + techCard.modelData.name
                  color: root.statusColor(Model.levelTier(techCard.modelData.maxLevel))
                  font.family: root.bar.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                  wrapMode: Text.WordWrap
                  width: parent.width
                }
                Text {
                  textFormat: Text.PlainText
                  text: (techCard.modelData.tactics || []).join(", ")
                  color: Qt.darker(root.bar.foreground, 1.4)
                  font.family: root.bar.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WordWrap
                  width: parent.width
                }
                Text {
                  textFormat: Text.PlainText
                  text: techCard.modelData.count + " occurrences, last seen " + Model.fieldOrDash(techCard.modelData.lastSeen) +
                        ", agents: " + ((techCard.modelData.agents || []).map(function(a) { return Model.agentNameFor(a.id, root.rosterData) }).join(", ") || "-")
                  color: Qt.darker(root.bar.foreground, 1.2)
                  font.family: root.bar.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WordWrap
                  width: parent.width
                }
              }
            }

            Text {
              textFormat: Text.PlainText
              visible: !!(root.mitreData && root.mitreData.readable && root.mitreData.techniques && root.mitreData.techniques.length === 0)
              text: "No MITRE ATT&CK techniques observed in recent alerts."
              color: Qt.darker(root.bar.foreground, 1.4)
              font.family: root.bar.fontFamily
              font.pixelSize: Style.font.caption
            }
          }

          Item { width: parent.width; height: Style.space(4) }
        }
      }
    }
  }

  // ---------- Reusable rows/components ----------

  component KeyValueRow: Item {
    property string k: ""
    property string v: ""
    property color vColor: root.bar.foreground
    width: parent.width
    implicitHeight: kText.implicitHeight

    Text {
      textFormat: Text.PlainText
      id: kText
      text: parent.k
      color: Qt.darker(root.bar.foreground, 1.4)
      font.family: root.bar.fontFamily
      font.pixelSize: Style.font.caption
      anchors.left: parent.left
      anchors.verticalCenter: parent.verticalCenter
      width: parent.width * 0.42
      elide: Text.ElideRight
    }

    Text {
      textFormat: Text.PlainText
      text: parent.v
      color: parent.vColor
      font.family: root.bar.fontFamily
      font.pixelSize: Style.font.caption
      font.bold: true
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      width: parent.width * 0.58
      horizontalAlignment: Text.AlignRight
      elide: Text.ElideRight
    }
  }

  component TopTabButtonItem: Rectangle {
    id: tabButton
    property string label: ""
    property int index: 0
    width: tabLabel.implicitWidth + Style.space(16)
    height: tabLabel.implicitHeight + Style.space(8)
    radius: Style.cornerRadius / 2
    color: root.activeTab === index ? Qt.darker(root.bar.foreground, 4) : "transparent"

    Text {
      textFormat: Text.PlainText
      id: tabLabel
      anchors.centerIn: parent
      text: tabButton.label
      color: root.activeTab === tabButton.index ? root.bar.foreground : Qt.darker(root.bar.foreground, 1.6)
      font.family: root.bar.fontFamily
      font.pixelSize: Style.font.caption
      font.bold: root.activeTab === tabButton.index
    }

    MouseArea {
      anchors.fill: parent
      cursorShape: Qt.PointingHandCursor
      onClicked: root.activeTab = tabButton.index
    }
  }

  component AgentTabButtonItem: Rectangle {
    id: agentTabButton
    property string label: ""
    property int index: 0
    width: agentTabLabel.implicitWidth + Style.space(14)
    height: agentTabLabel.implicitHeight + Style.space(8)
    radius: Style.cornerRadius / 2
    color: root.agentSubTab === index ? Qt.darker(root.bar.foreground, 4) : "transparent"

    Text {
      textFormat: Text.PlainText
      id: agentTabLabel
      anchors.centerIn: parent
      text: agentTabButton.label
      color: root.agentSubTab === agentTabButton.index ? root.bar.foreground : Qt.darker(root.bar.foreground, 1.6)
      font.family: root.bar.fontFamily
      font.pixelSize: Style.font.caption
      font.bold: root.agentSubTab === agentTabButton.index
    }

    MouseArea {
      anchors.fill: parent
      cursorShape: Qt.PointingHandCursor
      onClicked: root.agentSubTab = agentTabButton.index
    }
  }

  component AgentRow: Rectangle {
    id: agentRowRoot
    property var agent: null
    width: parent.width
    height: agentRowColumn.implicitHeight + Style.space(10)
    radius: Style.cornerRadius / 2
    color: agentRowArea.containsMouse ? Qt.darker(root.bar.foreground, 6) : "transparent"

    Column {
      id: agentRowColumn
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.margins: Style.space(6)
      spacing: Style.space(1)

      Row {
        width: parent.width
        spacing: Style.space(6)

        Rectangle {
          width: Style.space(8)
          height: Style.space(8)
          radius: width / 2
          anchors.verticalCenter: parent.verticalCenter
          color: root.statusColor(Model.agentStatusTier(agentRowRoot.agent ? agentRowRoot.agent.connectionStatus : null))
        }

        Text {
          textFormat: Text.PlainText
          text: (agentRowRoot.agent ? agentRowRoot.agent.name : "") + (agentRowRoot.agent && agentRowRoot.agent.isManager ? " (manager)" : "")
          color: root.bar.foreground
          font.family: root.bar.fontFamily
          font.pixelSize: Style.font.caption
          font.bold: true
          elide: Text.ElideRight
          width: parent.width - Style.space(14)
        }
      }

      Text {
        textFormat: Text.PlainText
        text: Model.fieldOrDash(agentRowRoot.agent ? agentRowRoot.agent.ip : null) + "  ·  " +
              Model.fieldOrDash(agentRowRoot.agent ? agentRowRoot.agent.osName : null) + "  ·  v" +
              Model.fieldOrDash(agentRowRoot.agent ? agentRowRoot.agent.version : null)
        color: Qt.darker(root.bar.foreground, 1.4)
        font.family: root.bar.fontFamily
        font.pixelSize: Style.font.caption
        elide: Text.ElideRight
        width: parent.width
      }
    }

    MouseArea {
      id: agentRowArea
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: if (agentRowRoot.agent) root.openAgent(agentRowRoot.agent.id)
    }
  }

  component AlertRow: Column {
    id: alertRowRoot
    property var entry: null
    property bool showAgent: true
    width: parent.width
    spacing: Style.space(1)

    Row {
      width: parent.width
      spacing: Style.space(6)

      Text {
        textFormat: Text.PlainText
        text: Model.fieldOrDash(alertRowRoot.entry ? alertRowRoot.entry.timestamp : null)
        color: Qt.darker(root.bar.foreground, 1.5)
        font.family: root.bar.fontFamily
        font.pixelSize: Style.font.caption
      }

      Text {
        textFormat: Text.PlainText
        text: "L" + Model.fieldOrDash(alertRowRoot.entry ? alertRowRoot.entry.level : null)
        color: root.statusColor(Model.levelTier(alertRowRoot.entry ? alertRowRoot.entry.level : null))
        font.family: root.bar.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: true
      }

      Text {
        textFormat: Text.PlainText
        visible: alertRowRoot.showAgent
        text: Model.fieldOrDash(alertRowRoot.entry ? alertRowRoot.entry.agentName : null)
        color: Qt.darker(root.bar.foreground, 1.2)
        font.family: root.bar.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: true
        elide: Text.ElideRight
      }
    }

    Text {
      textFormat: Text.PlainText
      text: Model.fieldOrDash(alertRowRoot.entry ? alertRowRoot.entry.description : null)
      color: root.bar.foreground
      font.family: root.bar.fontFamily
      font.pixelSize: Style.font.caption
      wrapMode: Text.WordWrap
      width: parent.width
    }
  }
}
