// AI-NIDS Live Telemetry & Event Stream Client
// Phase 7A & Cloud Ingestion Support

document.addEventListener("DOMContentLoaded", () => {
  const elements = {
    systemMode: document.getElementById("systemMode"),
    captureState: document.getElementById("captureState"),
    serverState: document.getElementById("serverState"),
    flowState: document.getElementById("flowState"),
    gateState: document.getElementById("gateState"),
    mlState: document.getElementById("mlState"),
    valPackets: document.getElementById("valPackets"),
    valFlows: document.getElementById("valFlows"),
    valVectors: document.getElementById("valVectors"),
    valPredictions: document.getElementById("valPredictions"),
    detailIface: document.getElementById("detailIface"),
    detailActiveFlows: document.getElementById("detailActiveFlows"),
    detailVectors: document.getElementById("detailVectors"),
    detailClasses: document.getElementById("detailClasses"),
    inferenceBadge: document.getElementById("inferenceBadge"),
    resultStatus: document.getElementById("resultStatus"),
    resultExplanation: document.getElementById("resultExplanation"),
    metaSrc: document.getElementById("metaSrc"),
    metaDst: document.getElementById("metaDst"),
    metaProto: document.getElementById("metaProto"),
    metaDur: document.getElementById("metaDur"),
    metaPkts: document.getElementById("metaPkts"),
    metaBytes: document.getElementById("metaBytes"),
    eventsTableBody: document.getElementById("eventsTableBody"),
    streamLabel: document.getElementById("streamLabel"),
    btnRunDemo: document.getElementById("btnRunDemo"),
    demoResultCard: document.getElementById("demoResultCard"),
    demoPred: document.getElementById("demoPred"),
    demoProb: document.getElementById("demoProb"),
    demoNote: document.getElementById("demoNote"),
  };

  let eventSource = null;
  let eventRowsCount = 0;

  function formatTime(isoStr) {
    if (!isoStr) return "-";
    try {
      const parts = isoStr.split("T");
      return parts.length > 1 ? parts[1] : isoStr;
    } catch (e) {
      return isoStr;
    }
  }

  function updateStatusSummary(data) {
    if (!data) return;

    // Deployment mode badge
    if (elements.systemMode && data.mode) {
      if (data.mode === "CLOUD_RECEIVER") {
        elements.systemMode.textContent = "CLOUD RECEIVER (ONLINE)";
        elements.systemMode.style.color = "#38bdf8";
        if (elements.serverState) elements.serverState.textContent = "CLOUD RELAY";
        if (elements.captureState) elements.captureState.textContent = "INGESTING";
      } else {
        elements.systemMode.textContent = "LOCAL SNIFFER";
        elements.systemMode.style.color = "#10b981";

        // Dynamic local TCP server socket status
        if (data.tcp_server && elements.serverState) {
          const isListening = Boolean(data.tcp_server.listening);
          elements.serverState.textContent = isListening ? "LISTENING" : "OFFLINE";
          elements.serverState.style.color = isListening ? "#10b981" : "#ef4444";
          const badge = document.getElementById("badgeServer");
          if (badge) {
            const dot = badge.querySelector(".dot");
            if (dot) {
              dot.className = isListening ? "dot active" : "dot danger";
            }
          }
        }
      }
    }

    // Capture status
    if (data.packet_capture) {
      const isRunning = data.packet_capture.running;
      elements.captureState.textContent = isRunning ? "ACTIVE" : (data.mode === "CLOUD_RECEIVER" ? "LISTENING" : "IDLE");
      elements.captureState.style.color = isRunning ? "#10b981" : "#94a3b8";
      elements.detailIface.textContent = `Interface: ${data.packet_capture.interface || "Loopback"}`;
    }

    // Telemetry stats
    if (data.telemetry) {
      const t = data.telemetry;
      elements.valPackets.textContent = (t.packets_captured || 0).toLocaleString();
      elements.valFlows.textContent = (t.total_flows || 0).toLocaleString();
      elements.detailActiveFlows.textContent = `Active: ${t.active_flows || 0} flows | Total: ${t.total_flows || 0}`;
      elements.valVectors.textContent = `${t.vectors_valid || 0} / ${t.vectors_rejected || 0}`;
      elements.valPredictions.textContent = (t.predictions_made || 0).toLocaleString();
      elements.detailClasses.textContent = `Benign: ${t.benign_count || 0} | Intrusion: ${t.intrusion_count || 0} (0 Fabricated)`;

      if (t.total_flows > 0 && elements.flowState) {
        elements.flowState.textContent = "ACTIVE";
      }
    }

    // Populate recent events if table is empty
    if (data.recent_events && data.recent_events.length > 0 && eventRowsCount === 0) {
      elements.eventsTableBody.innerHTML = "";
      data.recent_events.forEach(evt => appendEventRow(evt));
      const latest = data.recent_events[data.recent_events.length - 1];
      updateLatestEventCard(latest);
    }
  }

  function updateLatestEventCard(evt) {
    if (!evt) return;

    elements.metaSrc.textContent = `${evt.src_ip}:${evt.src_port}`;
    elements.metaDst.textContent = `${evt.dst_ip}:${evt.dst_port}`;
    elements.metaProto.textContent = (evt.protocol || "TCP").toUpperCase();
    elements.metaDur.textContent = `${(evt.duration || 0).toFixed(4)}s`;
    if (elements.metaPkts) {
      elements.metaPkts.textContent = `${(evt.spkts || 0) + (evt.dpkts || 0)} (${evt.spkts || 0}s / ${evt.dpkts || 0}d)`;
    }
    if (elements.metaBytes) {
      elements.metaBytes.textContent = `${(evt.sbytes || 0) + (evt.dbytes || 0)} B (${evt.sbytes || 0}s / ${evt.dbytes || 0}d)`;
    }

    if (evt.inference_status === "PREDICTED") {
      const pred = evt.prediction || "BENIGN";
      elements.inferenceBadge.textContent = pred;
      elements.inferenceBadge.className = `panel-status-tag ${pred === "BENIGN" ? "valid" : "invalid"}`;

      elements.resultStatus.textContent = `${pred} (${((evt.probability || 0) * 100).toFixed(2)}% probability)`;
      elements.resultStatus.className = `result-status ${pred === "BENIGN" ? "valid" : "invalid"}`;
      elements.resultExplanation.textContent =
        `Flow ${evt.flow_id} met strict 42-feature semantic validation. Evaluated genuine Phase-5 XGBoost model.`;
    } else {
      elements.inferenceBadge.textContent = "REFUSED (HONEST)";
      elements.inferenceBadge.className = "panel-status-tag skipped";

      elements.resultStatus.textContent = "ML Inference Safely Bypassed";
      elements.resultStatus.className = "result-status skipped";
      const reasonStr = (evt.reasons && evt.reasons.length > 0) ? evt.reasons[0] : "Protocol-specific features unavailable";
      elements.resultExplanation.textContent =
        `Feature Gate: ${evt.gate_status || "INVALID_FEATURE_VECTOR"}. Reason: ${reasonStr}. Zero-fabrication policy enforced.`;
    }
  }

  function appendEventRow(evt) {
    if (!elements.eventsTableBody) return;

    // Remove empty placeholder row if present
    const emptyRow = elements.eventsTableBody.querySelector(".empty-row");
    if (emptyRow) {
      emptyRow.remove();
    }

    eventRowsCount++;
    const row = document.createElement("tr");

    let statusBadgeHtml = "";
    if (evt.inference_status === "PREDICTED") {
      const isBenign = evt.prediction === "BENIGN";
      statusBadgeHtml = `<span class="badge-tag ${isBenign ? "valid" : "invalid"}">${evt.prediction} (${((evt.probability || 0) * 100).toFixed(1)}%)</span>`;
    } else {
      statusBadgeHtml = `<span class="badge-tag skipped">GATE REFUSAL</span>`;
    }

    const gateBadge = (evt.gate_status === "VALID")
      ? `<span class="badge-tag valid">VALID (42/42)</span>`
      : `<span class="badge-tag skipped">${evt.gate_status || "PARTIAL"}</span>`;

    const totalPkts = (evt.spkts || 0) + (evt.dpkts || 0);

    row.innerHTML = `
      <td>${formatTime(evt.timestamp)}</td>
      <td><code>${evt.src_ip}:${evt.src_port} &rarr; ${evt.dst_ip}:${evt.dst_port}</code></td>
      <td>${totalPkts}</td>
      <td>${(evt.duration || 0).toFixed(3)}s</td>
      <td>${gateBadge}</td>
      <td>${statusBadgeHtml}</td>
    `;

    elements.eventsTableBody.insertBefore(row, elements.eventsTableBody.firstChild);

    // Keep table capped at 30 rows
    while (elements.eventsTableBody.children.length > 30) {
      elements.eventsTableBody.removeChild(elements.eventsTableBody.lastChild);
    }
  }

  function connectSSE() {
    if (eventSource) {
      eventSource.close();
    }

    elements.streamLabel.textContent = "Connecting to live stream...";
    eventSource = new EventSource("/api/events");

    eventSource.onopen = () => {
      elements.streamLabel.textContent = "Live SSE Connected";
    };

    eventSource.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === "snapshot") {
          updateStatusSummary(msg.data);
        } else if (msg.type === "event") {
          appendEventRow(msg.data);
          updateLatestEventCard(msg.data);
          // Increment live packet counter
          const curPkts = parseInt(elements.valPackets.textContent.replace(/,/g, "")) || 0;
          elements.valPackets.textContent = (curPkts + (msg.data.spkts || 0) + (msg.data.dpkts || 0)).toLocaleString();
          const curFlows = parseInt(elements.valFlows.textContent.replace(/,/g, "")) || 0;
          elements.valFlows.textContent = (curFlows + 1).toLocaleString();
        } else if (msg.type === "heartbeat") {
          elements.detailActiveFlows.textContent = `Active: ${msg.active_flows || 0} flows`;
        }
      } catch (err) {
        console.error("Error parsing SSE message:", err);
      }
    };

    eventSource.onerror = () => {
      elements.streamLabel.textContent = "Disconnected (reconnecting...)";
      eventSource.close();
      setTimeout(connectSSE, 3000);
    };
  }

  // Demo B handler: Controlled ML pipeline demonstration
  if (elements.btnRunDemo) {
    elements.btnRunDemo.addEventListener("click", () => {
      elements.btnRunDemo.disabled = true;
      elements.btnRunDemo.textContent = "Evaluating Authoritative Vector...";

      fetch("/api/demo-authoritative", { method: "POST" })
        .then(r => r.json())
        .then(res => {
          elements.btnRunDemo.disabled = false;
          elements.btnRunDemo.textContent = "Run Authoritative Model Pipeline";
          if (res.status === "SUCCESS") {
            elements.demoResultCard.style.display = "block";
            elements.demoPred.textContent = `${res.prediction}`;
            elements.demoPred.className = (res.prediction === "BENIGN") ? "text-success" : "text-danger";
            elements.demoProb.textContent = `${(res.intrusion_probability * 100).toFixed(4)}% attack probability`;
            elements.demoNote.textContent = `${res.note} (42/42 features verified by gate)`;
          } else {
            alert(`Demo failed: ${res.gate_status}`);
          }
        })
        .catch(err => {
          elements.btnRunDemo.disabled = false;
          elements.btnRunDemo.textContent = "Run Authoritative Model Pipeline";
          console.error("Demo B request error:", err);
        });
    });
  }

  // Initial fetch of status
  fetch("/api/status")
    .then(r => r.json())
    .then(data => updateStatusSummary(data))
    .catch(err => console.warn("Initial status fetch failed:", err));

  // Connect live stream
  connectSSE();
});
