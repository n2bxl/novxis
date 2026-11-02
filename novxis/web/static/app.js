"use strict";

const NS = "http://www.w3.org/2000/svg";
const svg = document.getElementById("map");
const canvas = document.querySelector(".canvas-wrap");
const viewport = document.getElementById("viewport");
const summary = document.getElementById("summary");
const inspectorTitle = document.getElementById("inspector-title");
const inspector = document.getElementById("inspector-content");
const hostPanel = document.getElementById("host-context");
const hostBody = document.getElementById("host-context-content");
const subnetPanel = document.getElementById("subnet-evidence");
const subnetBody = document.getElementById("subnet-evidence-content");

let graph = null;
let selectedId = null;
let stageHeight = 620;
let camera = { x: 0, y: 0, scale: 1 };
let dragging = null;
const PAN_THRESHOLD = 5; // Canvas SVG units: distinguish a click from a drag.
const NODE_HEIGHT = 50;
const ROW_STEP = 76;
const ROW_START = 105;
const COLUMN_X = { protocol: 114, hardware: 708 };
const manualOrders = { protocol: null, hardware: null };
let orderedByKind = { protocol: [], hardware: [] };
let moveNodesMode = false;
const openSubnetGroups = new Set();

function makeSVG(tag, attrs) {
  const element = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    element.setAttribute(key, String(value));
  }
  return element;
}

function addSVGText(group, x, y, value, className) {
  const text = makeSVG("text", { x, y });
  if (className) text.setAttribute("class", className);
  text.textContent = value;
  group.append(text);
  return text;
}

function appendDetail(label, value, parent) {
  const line = document.createElement("div");
  line.className = "detail";
  const heading = document.createElement("span");
  heading.className = "detail-label";
  heading.textContent = label;
  const content = document.createElement("span");
  content.className = "detail-value";
  content.textContent = String(value);
  line.append(heading, content);
  parent.append(line);
}

function showHostContext(context) {
  // An offline PCAP must never borrow the viewer Mac's current config.
  if (!context || context.origin !== "local-os") {
    hostPanel.hidden = true;
    hostBody.replaceChildren();
    return;
  }
  hostPanel.hidden = false;
  hostBody.replaceChildren();
  appendDetail("Source", "Local macOS configuration (not packet evidence)", hostBody);
  appendDetail("Capture interface", context.interface || "Unavailable", hostBody);
  appendDetail("Status", context.status || "Unavailable", hostBody);
  const addresses = Array.isArray(context.ipv4_addresses)
    ? context.ipv4_addresses : [];
  if (addresses.length) {
    for (const entry of addresses.slice(0, 16)) {
      appendDetail(
        "Configured IPv4 / reported prefix",
        String(entry.address) + "/" + String(entry.prefix_length) +
          " · " + String(entry.network),
        hostBody,
      );
    }
  } else {
    appendDetail("Configured IPv4", "Not reported", hostBody);
  }
  const route = context.default_route;
  if (route && route.gateway && route.interface) {
    appendDetail(
      "OS-selected IPv4 default route",
      String(route.gateway) + " via " + String(route.interface), hostBody,
    );
    appendDetail(
      "Default route uses capture interface?",
      route.interface === context.interface ? "Yes" : "No",
      hostBody,
    );
  } else {
    appendDetail("OS-selected IPv4 default route", "Not reported", hostBody);
  }
  appendDetail(
    "Context queried",
    context.observed_at || "Time not available", hostBody,
  );
}

function appendAddressButton(parent, item) {
  if (!graph || !graph.nodes.some((node) => node.id === item.node_id)) return;
  const button = document.createElement("button");
  button.type = "button";
  button.className = "subnet-address";
  button.textContent = item.address;
  button.title = "Select observed ARP address evidence";
  button.addEventListener("click", () => {
    // Explicit select, rather than toggle: multiple prefix groups can
    // correctly refer to one interface-scoped protocol address node.
    selectedId = item.node_id;
    renderGraph();
    showInspector();
  });
  parent.append(button);
}

function appendAddressSection(parent, title, entries, groupKey) {
  const details = document.createElement("details");
  // Preserve an expanded group across one-second live graph revisions.
  details.open = openSubnetGroups.has(groupKey);
  details.addEventListener("toggle", () => {
    if (details.open) openSubnetGroups.add(groupKey);
    else openSubnetGroups.delete(groupKey);
  });
  const summary = document.createElement("summary");
  summary.textContent = title + " (" + entries.length + ")";
  details.append(summary);
  if (entries.length === 0) {
    const empty = document.createElement("p");
    empty.textContent = "No matching ARP sender addresses in this capture.";
    details.append(empty);
  } else {
    const items = document.createElement("div");
    items.className = "subnet-address-list";
    // Protect the browser against large or overlapping prefix lists.
    for (const entry of entries.slice(0, 64)) {
      appendAddressButton(items, entry);
    }
    if (entries.length > 64) {
      const remainder = document.createElement("p");
      remainder.textContent = (entries.length - 64) +
        " additional address entries not listed in this debug panel.";
      items.append(remainder);
    }
    details.append(items);
  }
  parent.append(details);
}

function showSubnetEvidence(lens) {
  if (!lens || lens.origin !== "derived-comparison" || !graph) {
    subnetPanel.hidden = true;
    subnetBody.replaceChildren();
    return;
  }
  subnetPanel.hidden = false;
  subnetBody.replaceChildren();
  appendDetail(
    "Basis",
    "Local OS configured prefixes compared with interface-scoped ARP sender observations",
    subnetBody,
  );
  appendDetail("Capture interface", lens.capture_interface, subnetBody);
  appendDetail("Observed IPv4 addresses", lens.observed_ipv4_address_count, subnetBody);

  const groups = Array.isArray(lens.configured_prefixes)
    ? lens.configured_prefixes : [];
  if (!groups.length) {
    const absent = document.createElement("p");
    absent.className = "subnet-limitation";
    absent.textContent = "No valid IPv4 prefix reported by the host. " +
      "ARP evidence cannot establish a configured subnet by itself.";
    subnetBody.append(absent);
    appendAddressSection(
      subnetBody,
      "Observed IPv4 without a reported prefix",
      Array.isArray(lens.unclassified_without_prefix)
        ? lens.unclassified_without_prefix : [],
      "unclassified",
    );
  }
  for (const group of groups.slice(0, 16)) {
    appendAddressSection(
      subnetBody,
      group.network + " · configured on " + group.configured_address,
      Array.isArray(group.matching_observed_ipv4)
        ? group.matching_observed_ipv4 : [],
      "prefix:" + group.network + "@" + group.configured_address,
    );
  }
  if (groups.length) {
    appendAddressSection(
      subnetBody,
      "Outside reported prefix(es), not necessarily remote",
      Array.isArray(lens.outside_reported_prefixes)
        ? lens.outside_reported_prefixes : [],
      "outside",
    );
  }
  const gateway = lens.gateway_address_cross_reference;
  if (gateway && gateway.node_id) {
    appendDetail(
      "Independent default-route address match",
      "An observed ARP sender address also matches the OS-selected " +
      "IPv4 default-route gateway on this interface.",
      subnetBody,
    );
    appendAddressButton(subnetBody, gateway);
  }
  const caveat = document.createElement("p");
  caveat.className = "subnet-limitation";
  caveat.textContent = "Containment is only an address comparison, not " +
    "confirmed device identity, L2 adjacency, reachability or membership.";
  subnetBody.append(caveat);
}

function clearInspector(message) {
  inspector.replaceChildren();
  inspectorTitle.textContent = "Nothing selected";
  const p = document.createElement("p");
  p.textContent = message;
  inspector.append(p);
}

function showInspector() {
  if (!graph || !selectedId) {
    clearInspector("Select an address node to inspect its captured ARP evidence.");
    return;
  }
  const node = graph.nodes.find((item) => item.id === selectedId);
  if (!node) {
    selectedId = null;
    clearInspector("Select an address node to inspect its captured ARP evidence.");
    return;
  }

  inspector.replaceChildren();
  inspectorTitle.textContent = node.display_address;
  appendDetail("Evidence node", node.kind === "protocol" ? "Protocol address" : "Hardware address", inspector);
  appendDetail("Observed interface", node.interface, inspector);
  appendDetail("Address", node.display_address, inspector);
  appendDetail("ARP hardware type", node.hardware_type, inspector);
  appendDetail("ARP protocol type", "0x" + node.protocol_type.toString(16).padStart(4, "0"), inspector);
  const gatewayMatch = graph.subnet_evidence &&
    graph.subnet_evidence.gateway_address_cross_reference;
  if (gatewayMatch && gatewayMatch.node_id === node.id) {
    appendDetail(
      "Independent OS route context",
      "This IPv4 sender address also matches the Mac's configured default " +
      "gateway on the observed interface (not a verified physical link).",
      inspector,
    );
  }

  const claims = graph.claims.filter((claim) =>
    claim.source === selectedId || claim.target === selectedId
  );
  const label = document.createElement("h3");
  label.textContent = "Observed ARP sender claims (" + claims.length + ")";
  inspector.append(label);
  const indexed = new Map(graph.nodes.map((item) => [item.id, item]));
  for (const claim of claims) {
    const card = document.createElement("div");
    card.className = "claim-card";
    const title = document.createElement("strong");
    const source = indexed.get(claim.source);
    const target = indexed.get(claim.target);
    title.textContent = (source ? source.display_address : "?") +
      " → " + (target ? target.display_address : "?");
    const details = document.createElement("p");
    details.textContent = "ARP sender claim · " + claim.observation_count +
      " observation(s)";
    const times = document.createElement("p");
    times.textContent = "First " + claim.first_seen + " · Last " + claim.last_seen +
      " (capture-clock Unix seconds)";
    card.append(title, details, times);
    inspector.append(card);
  }
  const caveat = document.createElement("p");
  caveat.className = "inspector-note";
  caveat.textContent = "This is address evidence, not verified physical host identity or reachability.";
  inspector.append(caveat);
}

function setSelected(id) {
  selectedId = selectedId === id ? null : id;
  renderGraph();
  showInspector();
}

function computeAutoOrders(snapshot) {
  // Keep protocol addresses sorted for lookup, but position MAC addresses
  // by the mean row of their observed protocol neighbors. This reduces
  // crossings without interpreting ARP claims as physical topology.
  const addressOrder = (a, b) =>
    a.interface.localeCompare(b.interface) ||
    a.address_hex.localeCompare(b.address_hex) ||
    a.id.localeCompare(b.id);
  const protocol = snapshot.nodes
    .filter((node) => node.kind === "protocol").sort(addressOrder);
  const hardware = snapshot.nodes
    .filter((node) => node.kind === "hardware").sort(addressOrder);
  const protocolRank = new Map(protocol.map((node, index) => [node.id, index]));
  const neighbors = new Map(hardware.map((node) => [node.id, []]));
  for (const claim of snapshot.claims) {
    if (protocolRank.has(claim.source) && neighbors.has(claim.target)) {
      neighbors.get(claim.target).push(protocolRank.get(claim.source));
    }
  }
  const averageRank = (node) => {
    const positions = neighbors.get(node.id);
    return positions.length
      ? positions.reduce((total, value) => total + value, 0) / positions.length
      : Number.POSITIVE_INFINITY;
  };
  hardware.sort((a, b) =>
    averageRank(a) - averageRank(b) || addressOrder(a, b));
  return { protocol, hardware };
}

function preserveManualOrder(kind, automatic) {
  const ids = manualOrders[kind];
  if (!ids) return automatic;
  const byId = new Map(automatic.map((node) => [node.id, node]));
  const seen = new Set();
  const arranged = [];
  for (const id of ids) {
    if (byId.has(id)) {
      arranged.push(byId.get(id));
      seen.add(id);
    }
  }
  for (const node of automatic) {
    if (!seen.has(node.id)) arranged.push(node);
  }
  return arranged;
}

function reorderNode(kind, id, targetIndex) {
  const current = orderedByKind[kind];
  const startIndex = current.findIndex((node) => node.id === id);
  if (startIndex < 0) return false;
  const endIndex = Math.max(0, Math.min(current.length - 1, targetIndex));
  if (startIndex === endIndex) return false;
  const updated = current.map((node) => node.id);
  updated.splice(startIndex, 1);
  updated.splice(endIndex, 0, id);
  manualOrders[kind] = updated;
  return true;
}

function layoutGraph() {
  const automatic = computeAutoOrders(graph);
  orderedByKind = {
    protocol: preserveManualOrder("protocol", automatic.protocol),
    hardware: preserveManualOrder("hardware", automatic.hardware),
  };
  const count = Math.max(
    orderedByKind.protocol.length, orderedByKind.hardware.length,
  );
  stageHeight = Math.max(620, count * ROW_STEP + 175);
  svg.setAttribute("viewBox", "0 0 1080 " + stageHeight);
  const locations = new Map();
  for (const kind of ["protocol", "hardware"]) {
    orderedByKind[kind].forEach((node, index) =>
      locations.set(node.id, {
        x: COLUMN_X[kind], y: ROW_START + index * ROW_STEP,
      }));
  }
  return locations;
}

function renderGraph() {
  if (!graph) return;
  viewport.replaceChildren();

  const locations = layoutGraph();
  addSVGText(viewport, 114, 59, "PROTOCOL ADDRESSES", "column-title");
  addSVGText(viewport, 708, 59, "HARDWARE ADDRESSES", "column-title");

  for (const claim of graph.claims) {
    const source = locations.get(claim.source);
    const target = locations.get(claim.target);
    if (!source || !target) continue;
    const x1 = source.x + 256;
    const y1 = source.y + 25;
    const x2 = target.x;
    const y2 = target.y + 25;
    const mid = (x1 + x2) / 2;
    const path = makeSVG("path", {
      d: "M " + x1 + " " + y1 + " C " + mid + " " + y1 + ", " +
        mid + " " + y2 + ", " + x2 + " " + y2,
      class: "map-edge" + (
        selectedId && (claim.source === selectedId || claim.target === selectedId)
          ? " selected" : ""
      ),
    });
    viewport.append(path);
  }

  for (const node of graph.nodes) {
    const position = locations.get(node.id);
    if (!position) continue;
    const selected = node.id === selectedId;
    const group = makeSVG("g", {
      class: "map-node " + node.kind + (selected ? " selected" : ""),
      transform: "translate(" + position.x + " " + position.y + ")",
      role: "button",
      tabindex: "0",
      "aria-label": node.kind + " address " + node.display_address +
        " on " + node.interface,
      "data-node-id": node.id,
    });
    group.append(makeSVG("rect", { x: 0, y: 0, width: 256, height: NODE_HEIGHT, rx: 8 }));
    addSVGText(group, 13, 22, node.display_address);
    addSVGText(group, 13, 39, "interface: " + node.interface, "node-meta");
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        setSelected(node.id);
      } else if (moveNodesMode && event.shiftKey &&
                 (event.key === "ArrowUp" || event.key === "ArrowDown")) {
        event.preventDefault();
        const index = orderedByKind[node.kind].findIndex((item) => item.id === node.id);
        if (reorderNode(node.kind, node.id,
                        index + (event.key === "ArrowUp" ? -1 : 1))) {
          renderGraph();
          const replacement = Array.from(
            svg.querySelectorAll("[data-node-id]"),
          ).find((item) => item.getAttribute("data-node-id") === node.id);
          if (replacement) replacement.focus();
        }
      }
    });
    viewport.append(group);
  }
  updateCamera();
}

function updateCamera() {
  viewport.setAttribute("transform", "translate(" + camera.x + " " + camera.y +
    ") scale(" + camera.scale + ")");
}

function svgPoint(event) {
  const point = svg.createSVGPoint();
  point.x = event.clientX;
  point.y = event.clientY;
  const matrix = svg.getScreenCTM();
  if (!matrix) return { x: 0, y: 0 };
  return point.matrixTransform(matrix.inverse());
}

function zoomAt(factor, point) {
  const next = Math.min(3.5, Math.max(0.4, camera.scale * factor));
  const ratio = next / camera.scale;
  camera.x = point.x - (point.x - camera.x) * ratio;
  camera.y = point.y - (point.y - camera.y) * ratio;
  camera.scale = next;
  updateCamera();
}

function resetView() {
  camera = { x: 0, y: 0, scale: 1 };
  updateCamera();
}

document.getElementById("zoom-in").addEventListener("click", () =>
  zoomAt(1.2, { x: 540, y: stageHeight / 2 }));
document.getElementById("zoom-out").addEventListener("click", () =>
  zoomAt(1 / 1.2, { x: 540, y: stageHeight / 2 }));
document.getElementById("fit").addEventListener("click", resetView);
const moveButton = document.getElementById("move-nodes");
const canvasHint = document.querySelector(".canvas-hint");
moveButton.addEventListener("click", () => {
  moveNodesMode = !moveNodesMode;
  moveButton.setAttribute("aria-pressed", String(moveNodesMode));
  moveButton.classList.toggle("active", moveNodesMode);
  svg.classList.toggle("move-mode", moveNodesMode);
  canvasHint.textContent = moveNodesMode
    ? "Drag nodes to reorder · Shift + ↑/↓ to move selected row · Drag empty space to pan"
    : "Scroll to zoom · Drag to pan · Select an address";
});
document.getElementById("auto-arrange").addEventListener("click", () => {
  manualOrders.protocol = null;
  manualOrders.hardware = null;
  renderGraph();
});

// Listen on the entire canvas wrapper. Empty SVG regions are not always
// wheel hit-test targets in Safari, but the wrapper covers the whole map.
canvas.addEventListener("wheel", (event) => {
  event.preventDefault();
  if (!event.deltaY) return;
  zoomAt(event.deltaY < 0 ? 1.1 : 1 / 1.1, svgPoint(event));
}, { passive: false });

// Safari may select SVG text before pointer capture takes over navigation.
svg.addEventListener("selectstart", (event) => event.preventDefault());
svg.addEventListener("dragstart", (event) => event.preventDefault());
svg.addEventListener("pointerdown", (event) => {
  if (event.button !== 0 || dragging) return;
  event.preventDefault();
  const point = svgPoint(event);
  const targetNode = event.target.closest("[data-node-id]");
  const nodeId = targetNode ? targetNode.getAttribute("data-node-id") : null;
  const node = nodeId && graph ? graph.nodes.find((item) => item.id === nodeId) : null;
  dragging = {
    pointerId: event.pointerId, start: point,
    x: camera.x, y: camera.y, moved: false,
    nodeId, kind: node ? node.kind : null,
    fromIndex: node ? orderedByKind[node.kind].findIndex((item) => item.id === nodeId) : -1,
    mode: moveNodesMode && node ? "reorder" : "pan",
  };
  svg.setPointerCapture(event.pointerId);
});
svg.addEventListener("pointermove", (event) => {
  if (!dragging || dragging.pointerId !== event.pointerId) return;
  const point = svgPoint(event);
  const dx = point.x - dragging.start.x;
  const dy = point.y - dragging.start.y;
  if (!dragging.moved && Math.hypot(dx, dy) < PAN_THRESHOLD) return;
  dragging.moved = true;
  if (dragging.mode === "reorder") {
    svg.classList.add("reordering");
    // A row is one visual address slot. Camera scale converts pointer
    // movement to graph coordinates; no claim or node identity is mutated.
    const displacement = Math.round(dy / (ROW_STEP * camera.scale));
    const target = dragging.fromIndex + displacement;
    if (reorderNode(dragging.kind, dragging.nodeId, target)) renderGraph();
    return;
  }
  svg.classList.add("panning");
  camera.x = dragging.x + dx;
  camera.y = dragging.y + dy;
  updateCamera();
});
function endPan(event) {
  if (!dragging || dragging.pointerId !== event.pointerId) return;
  const gesture = dragging;
  dragging = null;
  svg.classList.remove("panning", "reordering");
  if (svg.hasPointerCapture(event.pointerId)) svg.releasePointerCapture(event.pointerId);
  if (event.type === "pointerup" && !gesture.moved && gesture.nodeId) {
    setSelected(gesture.nodeId);
  }
}
svg.addEventListener("pointerup", endPan);
svg.addEventListener("pointercancel", endPan);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && selectedId) {
    selectedId = null;
    renderGraph();
    showInspector();
  }
});

// Live mode requests a fresh immutable snapshot every second. The renderer
// changes only when its semantic revision changes; camera and selection stay.
let lastRevision = null;
let pollHandle = null;

async function loadGraph() {
  const response = await fetch("/api/graph", { cache: "no-store" });
  if (!response.ok) throw new Error("HTTP " + response.status);
  const payload = await response.json();
  if (payload.schema_version !== 1 ||
      !Array.isArray(payload.nodes) || !Array.isArray(payload.claims)) {
    throw new Error("Unsupported graph response");
  }
  const source = payload.source || {};
  const live = payload.mode === "live-arp";
  showHostContext(live ? payload.host_context : null);
  const status = payload.capture_status || "waiting";
  if (live) {
    summary.textContent = "LIVE ARP · " + (source.interface || "waiting for capture") +
      " · " + status + " · " + payload.nodes.length + " address nodes · " +
      payload.claims.length + " sender claims · " +
      (source.updates_seen || 0) + " binding updates";
    if (source.truncated) {
      summary.textContent += " · CAP REACHED (new addresses omitted)";
    }
  } else {
    summary.textContent = (source.capture_name || "Replay") +
      " · " + payload.nodes.length + " address nodes · " +
      payload.claims.length + " sender claims · " +
      (source.frames_replayed || 0) + " frames";
  }
  const errors = (source.decode_errors || 0) + (source.stream_errors || 0);
  if (errors) {
    summary.textContent += " · " + errors + " errors";
  }
  if (!graph || !live || lastRevision !== payload.revision) {
    graph = payload;
    lastRevision = payload.revision;
    renderGraph();
    showSubnetEvidence(live ? payload.subnet_evidence : null);
    showInspector();
  }
  if (live && !pollHandle) {
    pollHandle = window.setInterval(() => {
      loadGraph().catch((error) => {
        // Keep the last valid snapshot visible on transient HTTP failures.
        summary.textContent = "Live update unavailable: " + error.message;
      });
    }, 1000);
  }
  if (!live && !payload.nodes.length) {
    clearInspector("No usable ARP sender claims in this replay.");
  }
}

async function start() {
  try {
    await loadGraph();
  } catch (error) {
    summary.textContent = "Could not load evidence map.";
    clearInspector("Error loading local replay data: " + error.message);
  }
}
start();
