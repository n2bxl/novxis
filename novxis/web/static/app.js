"use strict";

const NS = "http://www.w3.org/2000/svg";
const svg = document.getElementById("map");
const canvas = document.querySelector(".canvas-wrap");
const viewport = document.getElementById("viewport");
const summary = document.getElementById("summary");
const inspectorTitle = document.getElementById("inspector-title");
const inspector = document.getElementById("inspector-content");

let graph = null;
let selectedId = null;
let stageHeight = 620;
let camera = { x: 0, y: 0, scale: 1 };
let dragging = null;
const PAN_THRESHOLD = 5; // Canvas SVG units: distinguish a click from a drag.

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

function layoutGraph() {
  const ordered = (kind) => graph.nodes
    .filter((node) => node.kind === kind)
    .sort((a, b) =>
      a.interface.localeCompare(b.interface) ||
      a.display_address.localeCompare(b.display_address)
    );
  const protocol = ordered("protocol");
  const hardware = ordered("hardware");
  const count = Math.max(protocol.length, hardware.length);
  stageHeight = Math.max(620, count * 76 + 175);
  svg.setAttribute("viewBox", "0 0 1080 " + stageHeight);
  const locations = new Map();
  protocol.forEach((node, index) =>
    locations.set(node.id, { x: 114, y: 105 + index * 76 }));
  hardware.forEach((node, index) =>
    locations.set(node.id, { x: 708, y: 105 + index * 76 }));
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
    group.append(makeSVG("rect", { x: 0, y: 0, width: 256, height: 50, rx: 8 }));
    addSVGText(group, 13, 22, node.display_address);
    addSVGText(group, 13, 39, "interface: " + node.interface, "node-meta");
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        setSelected(node.id);
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
  // A quick click selects a node; dragging that same node pans the map.
  // Selection is handled on pointerup so a drag cannot also select it.
  const targetNode = event.target.closest("[data-node-id]");
  dragging = {
    pointerId: event.pointerId, start: point,
    x: camera.x, y: camera.y, moved: false,
    nodeId: targetNode ? targetNode.getAttribute("data-node-id") : null,
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
  svg.classList.add("panning");
  camera.x = dragging.x + dx;
  camera.y = dragging.y + dy;
  updateCamera();
});
function endPan(event) {
  if (!dragging || dragging.pointerId !== event.pointerId) return;
  const gesture = dragging;
  dragging = null;
  svg.classList.remove("panning");
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

async function start() {
  try {
    const response = await fetch("/api/graph", { cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const payload = await response.json();
    if (payload.schema_version !== 1 ||
        !Array.isArray(payload.nodes) || !Array.isArray(payload.claims)) {
      throw new Error("Unsupported graph response");
    }
    graph = payload;
    const source = payload.source || {};
    summary.textContent = (source.capture_name || "Replay") +
      " · " + payload.nodes.length + " address nodes · " +
      payload.claims.length + " sender claims · " +
      (source.frames_replayed || 0) + " frames";
    if (source.decode_errors) {
      summary.textContent += " · " + source.decode_errors + " decode errors";
    }
    if (!payload.nodes.length) {
      clearInspector("No usable ARP sender claims in this replay.");
    }
    renderGraph();
  } catch (error) {
    summary.textContent = "Could not load evidence map.";
    clearInspector("Error loading local replay data: " + error.message);
  }
}
start();
