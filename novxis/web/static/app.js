"use strict";

const NS = "http://www.w3.org/2000/svg";
const svg = document.getElementById("map");
const canvas = document.querySelector(".canvas-wrap");
const viewport = document.getElementById("viewport");
const summary = document.getElementById("summary");
const mapTitle = document.getElementById("map-title");
const mapModeArp = document.getElementById("map-mode-arp");
const mapModeUnified = document.getElementById("map-mode-unified");
const mapModeServices = document.getElementById("map-mode-services");
const arpLegend = document.getElementById("arp-legend");
const unifiedLegend = document.getElementById("unified-legend");
const servicesLegend = document.getElementById("services-legend");
const inspectorTitle = document.getElementById("inspector-title");
const inspector = document.getElementById("inspector-content");
const hostPanel = document.getElementById("host-context");
const hostBody = document.getElementById("host-context-content");
const subnetPanel = document.getElementById("subnet-evidence");
const subnetBody = document.getElementById("subnet-evidence-content");
const mdnsPanel = document.getElementById("mdns-evidence");
const mdnsBody = document.getElementById("mdns-evidence-content");
const ndpPanel = document.getElementById("ndp-evidence");
const ndpBody = document.getElementById("ndp-evidence-content");

const sidebarTabNames = ["evidence", "subnet", "host", "services", "neighbors"];
let selectedNdpAddress = null;
const sidebarTabs = Object.fromEntries(sidebarTabNames.map((name) => [
  name, {
    button: document.getElementById("tab-" + name),
    panel: document.getElementById("panel-" + name),
  },
]));
let activeSidebarTab = "evidence";

function selectSidebarTab(name, focus = false) {
  if (!sidebarTabs[name] || sidebarTabs[name].button.disabled) return;
  activeSidebarTab = name;
  for (const key of sidebarTabNames) {
    const selected = key === name;
    const tab = sidebarTabs[key];
    tab.button.setAttribute("aria-selected", String(selected));
    tab.button.tabIndex = selected ? 0 : -1;
    tab.panel.hidden = !selected;
  }
  if (focus) sidebarTabs[name].button.focus();
}

function updateSidebarTabs(payload) {
  // Host configuration and derived prefix comparisons are unavailable
  // for offline PCAP replay, even if a previous live tab was selected.
  const live = payload.mode === "live-arp";
  const available = {
    evidence: true,
    subnet: live && payload.subnet_evidence?.origin === "derived-comparison",
    host: live && payload.host_context?.origin === "local-os",
    services: live && payload.mdns_evidence?.origin === "mdns-observation",
    neighbors: live && payload.ndp_evidence?.origin === "ndp-observation",
  };
  for (const name of sidebarTabNames) {
    const enabled = available[name] === true;
    sidebarTabs[name].button.disabled = !enabled;
    sidebarTabs[name].button.setAttribute("aria-disabled", String(!enabled));
    sidebarTabs[name].button.title = enabled ? "" :
      "Not available for this capture";
  }
  if (!available[activeSidebarTab]) activeSidebarTab = "evidence";
  selectSidebarTab(activeSidebarTab);
}

for (const name of sidebarTabNames) {
  const button = sidebarTabs[name].button;
  button.addEventListener("click", () => selectSidebarTab(name));
  button.addEventListener("keydown", (event) => {
    const enabled = sidebarTabNames.filter((key) => !sidebarTabs[key].button.disabled);
    if (!enabled.length) return;
    const current = enabled.indexOf(name);
    let next = null;
    if (event.key === "Home") next = enabled[0];
    if (event.key === "End") next = enabled[enabled.length - 1];
    if (event.key === "ArrowRight")
      next = enabled[(current + 1) % enabled.length];
    if (event.key === "ArrowLeft")
      next = enabled[(current - 1 + enabled.length) % enabled.length];
    if (next !== null) {
      event.preventDefault();
      selectSidebarTab(next, true);
    }
  });
}


let graph = null;
let lastArpSummary = "";
let lastUnifiedSummary = "";
let lastServiceSummary = "";
let activeMapMode = "arp";
let selectedId = null;
let selectedEdgeId = null;
const mapSelections = {
  arp: { node: null, edge: null },
  unified: { node: null, edge: null },
  services: { node: null, edge: null },
};
const mapCameras = {
  arp: { x: 0, y: 0, scale: 1 },
  unified: { x: 0, y: 0, scale: 1 },
  services: { x: 0, y: 0, scale: 1 },
};

function visibleAddressGraph() {
  if (activeMapMode === "services") return graph?.unified_service_graph;
  return activeMapMode === "unified" ? graph?.unified_address_graph : graph;
}

function columnKind(kind) {
  if (activeMapMode === "services" && kind === "dnssd_service") return "services";
  return kind === "hardware" ? "hardware" : "protocol";
}

function manualOrderForView() {
  if (activeMapMode === "services") return serviceManualOrders;
  return activeMapMode === "unified" ? unifiedManualOrders : manualOrders;
}

function updateMapModeControls() {
  mapModeArp.setAttribute("aria-pressed", String(activeMapMode === "arp"));
  mapModeUnified.setAttribute("aria-pressed", String(activeMapMode === "unified"));
  mapModeServices.setAttribute("aria-pressed", String(activeMapMode === "services"));
  mapTitle.textContent = activeMapMode === "services"
    ? "Unified address and service evidence map" : activeMapMode === "unified"
    ? "Unified address evidence map" : "Observed address map";
  document.getElementById("auto-arrange").title = activeMapMode === "services"
    ? "Group advertised service instances by scoped address evidence"
    : activeMapMode === "unified"
    ? "Group IPv4 and IPv6 claims around MAC evidence anchors"
    : "Minimize crossed ARP sender claims";
  arpLegend.hidden = activeMapMode !== "arp";
  unifiedLegend.hidden = activeMapMode !== "unified";
  servicesLegend.hidden = activeMapMode !== "services";
  if (!moveNodesMode) canvasHint.textContent = activeMapMode === "services"
    ? "Scroll to zoom · Drag to pan · Select an evidence connector · Reset view frames the visible evidence"
    : "Scroll to zoom · Drag to pan · Select an address";
  document.getElementById("fit").title = activeMapMode === "services"
    ? "Fit the currently rendered evidence into the map viewport"
    : "Fit the currently rendered evidence into the map viewport";
  svg.setAttribute("aria-label", activeMapMode === "services"
    ? "Interactive three-column map of hardware, IP addresses, and advertised DNS-SD services"
    : activeMapMode === "unified"
    ? "Interactive evidence graph of IPv4, IPv6, and hardware address claims"
    : "Interactive graph of observed ARP protocol and hardware addresses");
}

function switchMapMode(mode) {
  if (!["arp", "unified", "services"].includes(mode)) return;
  if (mode === "unified" && mapModeUnified.disabled) return;
  if (mode === "services" && mapModeServices.disabled) return;
  if (mode === activeMapMode) return;
  mapSelections[activeMapMode] = { node: selectedId, edge: selectedEdgeId };
  mapCameras[activeMapMode] = { ...camera };
  activeMapMode = mode;
  selectedId = mapSelections[mode].node;
  selectedEdgeId = mapSelections[mode].edge;
  camera = { ...mapCameras[mode] };
  updateMapModeControls();
  if (graph) {
    summary.textContent = mode === "services" ? lastServiceSummary :
      mode === "unified" ? lastUnifiedSummary : lastArpSummary;
    renderGraph();
    showInspector();
    selectSidebarTab("evidence");
  }
}

function updateMapModes(payload) {
  const unified = payload.unified_address_graph;
  const available = payload.mode === "live-arp" &&
    unified?.schema_version === 1 &&
    unified?.origin === "passive-arp-ndp" &&
    unified.interface === payload.source?.interface &&
    Array.isArray(unified.nodes) && Array.isArray(unified.edges);
  mapModeUnified.disabled = !available;
  mapModeUnified.title = available
    ? "Show independently observed IPv4, IPv6 and MAC address claims"
    : "Requires a live ARP + mDNS + NDP capture";
  const services = payload.unified_service_graph;
  const serviceAvailable = available &&
    services?.schema_version === 1 &&
    services?.origin === "passive-arp-ndp-mdns" &&
    services.interface === payload.source?.interface &&
    services.capture_scope === unified.capture_scope &&
    Array.isArray(services.nodes) && Array.isArray(services.edges);
  mapModeServices.disabled = !serviceAvailable;
  mapModeServices.title = serviceAvailable
    ? "Inspect PTR-backed DNS-SD service instances and endpoint evidence"
    : "Requires a live ARP + mDNS + NDP service graph";
  if (!serviceAvailable && activeMapMode === "services") {
    mapSelections.services = { node: selectedId, edge: selectedEdgeId };
    mapCameras.services = { ...camera };
    activeMapMode = "arp";
    selectedId = mapSelections.arp.node;
    selectedEdgeId = mapSelections.arp.edge;
    camera = { ...mapCameras.arp };
  }
  if (!available && activeMapMode === "unified") {
    mapSelections.unified = { node: selectedId, edge: selectedEdgeId };
    mapCameras.unified = { ...camera };
    activeMapMode = "arp";
    selectedId = mapSelections.arp.node;
    selectedEdgeId = mapSelections.arp.edge;
    camera = { ...mapCameras.arp };
  }
  updateMapModeControls();
}

mapModeArp.addEventListener("click", () => switchMapMode("arp"));
mapModeUnified.addEventListener("click", () => switchMapMode("unified"));
mapModeServices.addEventListener("click", () => switchMapMode("services"));
let stageHeight = 620;
let camera = { x: 0, y: 0, scale: 1 };
let dragging = null;
const PAN_THRESHOLD = 5; // Canvas SVG units: distinguish a click from a drag.
const NODE_HEIGHT = 50;
const ROW_STEP = 76;
const ROW_START = 105;
const COLUMN_X = { protocol: 114, hardware: 708 };
const manualOrders = { protocol: null, hardware: null };
const unifiedManualOrders = { protocol: null, hardware: null };
const serviceManualOrders = { protocol: null, hardware: null, services: null };
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
    if (activeMapMode === "unified") switchMapMode("arp");
    selectedId = item.node_id;
    selectedEdgeId = null;
    renderGraph();
    showInspector();
    selectSidebarTab("evidence");
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

// Present retained evidence fields on separate lines without changing the
// source strings, chronology, freshness, or independent claim boundaries.
// Network-derived text is always assigned with textContent, never HTML.
function appendEvidenceMetadata(parent, detail) {
  String(detail).split(" · ").forEach((value, index) => {
    const line = document.createElement("p");
    line.className = "evidence-metadata-line";
    line.textContent = (index === 0 ? "" : "· ") + value;
    parent.append(line);
  });
}

function showNDPEvidence(evidence) {
  if (!evidence || evidence.origin !== "ndp-observation") {
    ndpPanel.hidden = true;
    ndpBody.replaceChildren();
    selectedNdpAddress = null;
    return;
  }
  ndpPanel.hidden = false;
  ndpBody.replaceChildren();
  appendDetail("Origin", "Passive ICMPv6 NS/NA packet assertions", ndpBody);
  appendDetail("Capture interface", evidence.interface || "unavailable", ndpBody);
  appendDetail("NS / NA / DAD",
    String(evidence.ns) + " / " + String(evidence.na) +
      " / " + String(evidence.dad), ndpBody);
  appendDetail("Retained option-backed claims", evidence.retained_claims, ndpBody);
  appendDetail("Unlinked observations", evidence.retained_unlinked, ndpBody);
  appendDetail("Multiple advertised LLAs", evidence.multiple_lla_addresses, ndpBody);
  if (evidence.decode_errors)
    appendDetail("Malformed NDP candidates", evidence.decode_errors, ndpBody);
  if (evidence.truncated)
    appendDetail("Retention limit", "Some NDP observations were omitted.", ndpBody);

  const claims = Array.isArray(evidence.claims) ? evidence.claims : [];
  const unlinked = Array.isArray(evidence.unlinked) ? evidence.unlinked : [];
  if (selectedNdpAddress !== null) {
    appendDetail("Selected IPv6 evidence", selectedNdpAddress, ndpBody);
    const all = document.createElement("button");
    all.type = "button";
    all.textContent = "Show all IPv6 observations";
    all.addEventListener("click", () => {
      selectedNdpAddress = null;
      showNDPEvidence(graph?.ndp_evidence);
    });
    ndpBody.append(all);
  }
  const visibleClaims = claims.filter(item => selectedNdpAddress === null ||
    item.address === selectedNdpAddress);
  const visibleUnlinked = unlinked.filter(item => selectedNdpAddress === null ||
    item.source === selectedNdpAddress || item.target === selectedNdpAddress);
  const list = document.createElement("div");
  list.className = "ndp-evidence-list";
  for (const item of visibleClaims.slice(0, 64)) {
    const record = document.createElement("article");
    record.className = "ndp-evidence-item";
    const heading = document.createElement("strong");
    heading.textContent = String(item.address);
    const detail = document.createElement("p");
    detail.textContent = (item.kind === "ns_source_slla"
      ? "NS source SLLA claim" : "NA target TLLA claim") +
      " · advertised Ethernet " + String(item.mac).match(/.{2}/g)?.join(":") +
      " · " + String(item.observations) + " observation(s)" +
      " · captured " + String(item.first_seen) + " to " + String(item.last_seen);
    record.append(heading);
    appendEvidenceMetadata(record, detail.textContent);
    list.append(record);
  }
  for (const item of visibleUnlinked.slice(0, 48)) {
    const record = document.createElement("article");
    record.className = "ndp-evidence-item";
    const heading = document.createElement("strong");
    heading.textContent = String(item.reason).replaceAll("_", " ");
    const detail = document.createElement("p");
    detail.textContent = "Source " + String(item.source) + " · target " +
      String(item.target) + " · frame sender " +
      String(item.frame_source).match(/.{2}/g)?.join(":") +
      " (not a target-MAC association) · " +
      String(item.observations) + " observation(s)" +
      " · captured " + String(item.last_seen);
    record.append(heading);
    appendEvidenceMetadata(record, detail.textContent);
    list.append(record);
  }
  if (!visibleClaims.length && !visibleUnlinked.length) {
    const empty = document.createElement("p");
    empty.textContent = "No matching independent IPv6 neighbor evidence observed.";
    list.append(empty);
  }
  if (visibleClaims.length > 64 || visibleUnlinked.length > 48) {
    const more = document.createElement("p");
    more.textContent = "Additional retained observations are omitted from this view.";
    list.append(more);
  }
  ndpBody.append(list);
  const note = document.createElement("p");
  note.className = "ndp-evidence-note";
  note.textContent = "These NS source and NA target option assertions are " +
    "not verified device identity, neighbor-cache reachability, or physical " +
    "connections. DAD is tentative. No NDP freshness TTL is inferred.";
  ndpBody.append(note);
}

function showMDNSEvidence(evidence) {
  if (!evidence || evidence.origin !== "mdns-observation") {
    mdnsPanel.hidden = true;
    mdnsBody.replaceChildren();
    return;
  }
  mdnsPanel.hidden = false;
  mdnsBody.replaceChildren();
  appendDetail("Origin", "Passive UDP/5353 mDNS observations", mdnsBody);
  appendDetail("Capture interface", evidence.interface || "unavailable", mdnsBody);
  appendDetail("Messages", evidence.messages, mdnsBody);
  appendDetail("Queries / responses",
    String(evidence.queries) + " / " + String(evidence.responses), mdnsBody);
  appendDetail("IPv4 / IPv6",
    String(evidence.ipv4) + " / " + String(evidence.ipv6), mdnsBody);
  appendDetail("PTR service advertisements", evidence.ptr_advertisements, mdnsBody);
  appendDetail("Retained service instances", evidence.retained_instances, mdnsBody);
  appendDetail("Fresh PTR instances", evidence.fresh_instances, mdnsBody);
  if (evidence.decode_errors) {
    appendDetail("Malformed mDNS candidates", evidence.decode_errors, mdnsBody);
  }
  if (evidence.truncated || evidence.omitted_advertisements) {
    appendDetail("Evidence limit", "Some advertisements were omitted or " +
      "not retained. This is not a complete inventory.", mdnsBody);
  }
  const services = Array.isArray(evidence.services) ? evidence.services : [];
  const list = document.createElement("div");
  list.className = "mdns-service-list";
  for (const item of services.slice(0, 48)) {
    const record = document.createElement("article");
    record.className = "mdns-service-item";
    const heading = document.createElement("strong");
    heading.textContent = String(item.instance);
    const type = document.createElement("p");
    type.textContent = String(item.service_type) + " · " +
      (item.fresh ? "PTR fresh" : "PTR not fresh");
    const detail = document.createElement("p");
    detail.textContent = "TTL " + String(item.ttl_seconds) + "s · " +
      String(item.observations) + " observation(s) · " +
      "last captured " + String(item.last_seen) + " (Unix seconds)";
    record.append(heading);
    appendEvidenceMetadata(record, type.textContent);
    appendEvidenceMetadata(record, detail.textContent);
    const targets = Array.isArray(item.targets) ? item.targets : [];
    if (!targets.length) {
      const noTarget = document.createElement("p");
      noTarget.textContent =
        "No SRV target was observed alongside this PTR in the latest response.";
      record.append(noTarget);
    }
    for (const target of targets) {
      const claim = document.createElement("div");
      claim.className = "mdns-target-claim";
      const label = document.createElement("p");
      label.textContent = "SRV target " + String(target.target) +
        " · port " + String(target.port) +
        " · TTL " + String(target.ttl_seconds) + "s" +
        (target.path_fresh ? " · PTR+SRV fresh" : " · PTR/SRV path not fresh") +
        (target.source === "cross-mdns-response"
          ? " · joined across responses" : " · same response") +
        " · observed " + String(target.observed_at || item.last_seen);
      appendEvidenceMetadata(claim, label.textContent);
      const addresses = Array.isArray(target.addresses) ? target.addresses : [];
      if (!addresses.length) {
        const absent = document.createElement("p");
        absent.textContent = "No matching A/AAAA address supported by observed responses.";
        claim.append(absent);
      }
      for (const address of addresses) {
        const line = document.createElement("div");
        line.className = "mdns-target-address";
        const summary = document.createElement("span");
        summary.textContent = (address.family === 4 ? "A " : "AAAA ") +
          String(address.address) + " · TTL " +
          String(address.ttl) + "s" +
          (address.path_fresh ? " · chain fresh" : " · chain not fresh") +
          (address.source === "cross-mdns-response"
            ? " · joined across responses" : " · same response") +
          " · observed " + String(address.observed_at || item.last_seen);
        appendEvidenceMetadata(line, summary.textContent);
        if (typeof address.arp_node_id === "string" && graph &&
            graph.nodes.some((node) => node.id === address.arp_node_id)) {
          const button = document.createElement("button");
          button.type = "button";
          button.className = "mdns-arp-link";
          button.textContent = "Inspect independent ARP address";
          button.addEventListener("click", () => {
            if (activeMapMode === "services") switchMapMode("arp");
            if (activeMapMode === "unified") switchMapMode("arp");
            selectedId = address.arp_node_id;
            selectedEdgeId = null;
            renderGraph();
            showInspector();
            selectSidebarTab("evidence");
          });
          line.append(button);
        } else if (address.family === 6 && typeof address.ndp_address === "string" &&
            graph?.ndp_evidence?.interface === graph?.mdns_evidence?.interface &&
            graph.ndp_evidence.claims.some((item) =>
              item.interface === graph.ndp_evidence.interface &&
              item.address === address.ndp_address)) {
          const button = document.createElement("button");
          button.type = "button";
          button.className = "mdns-ndp-link";
          button.textContent = "Inspect independent IPv6 neighbor evidence";
          button.addEventListener("click", () => {
            selectedNdpAddress = address.ndp_address;
            showNDPEvidence(graph.ndp_evidence);
            selectSidebarTab("neighbors");
          });
          line.append(button);
        } else {
          const absent = document.createElement("span");
          absent.className = "mdns-address-unmatched";
          absent.textContent = address.family === 6
            ? "No same-interface option-backed NDP address match"
            : "No same-interface ARP address match";
          line.append(absent);
        }
        claim.append(line);
      }
      record.append(claim);
    }
    list.append(record);
  }
  if (!services.length) {
    const empty = document.createElement("p");
    empty.textContent = "No PTR-backed service advertisements observed.";
    list.append(empty);
  }
  if (services.length > 48) {
    const omitted = document.createElement("p");
    omitted.textContent = String(services.length - 48) +
      " other retained instances omitted from this summary.";
    list.append(omitted);
  }
  mdnsBody.append(list);
  const note = document.createElement("p");
  note.className = "mdns-limitation";
  note.textContent = "PTR, SRV and A/AAAA records are independent packet claims. " +
    "Cross-response joins require fresh matching DNS owner names on the " +
    "same capture interface; each record retains its own timestamp and TTL. " +
    "An ARP address match is separate evidence, not a verified device " +
    "identity, physical link or running service.";
  mdnsBody.append(note);
}

function clearInspector(message) {
  inspector.replaceChildren();
  inspectorTitle.textContent = "Nothing selected";
  const p = document.createElement("p");
  p.textContent = message;
  inspector.append(p);
}

const UNIFIED_EVIDENCE_LABELS = {
  arp_sender: "ARP IPv4 sender",
  ndp_ns_source_slla: "NS source SLLA",
  ndp_na_target_tlla: "NA target TLLA",
};

function unifiedEvidenceLabel(kind) {
  return UNIFIED_EVIDENCE_LABELS[kind] || "Unrecognized address claim";
}

function showUnifiedInspector() {
  const snapshot = graph?.unified_address_graph;
  if (!snapshot) {
    clearInspector("Unified graph is unavailable for this capture.");
    return;
  }
  const nodes = new Map(snapshot.nodes.map((node) => [node.id, node]));
  const edge = selectedEdgeId &&
    snapshot.edges.find((item) => item.id === selectedEdgeId);
  const node = selectedId && nodes.get(selectedId);
  if (selectedEdgeId && !edge) selectedEdgeId = null;
  if (selectedId && !node) selectedId = null;
  if (!edge && !node) {
    clearInspector("Select an IPv4, IPv6 or hardware address node, or an " +
      "evidence edge, to inspect its observed ARP/NDP provenance.");
    return;
  }

  inspector.replaceChildren();
  if (edge) {
    const source = nodes.get(edge.source);
    const target = nodes.get(edge.target);
    inspectorTitle.textContent = unifiedEvidenceLabel(edge.kind);
    appendDetail("Evidence type", unifiedEvidenceLabel(edge.kind), inspector);
    appendDetail("Protocol address", source?.display_address || "Unavailable", inspector);
    appendDetail("Advertised Ethernet address",
      target?.display_address || "Unavailable", inspector);
    appendDetail("Capture interface", edge.interface, inspector);
    appendDetail("Capture scope", edge.capture_scope, inspector);
    appendDetail("First observed (Unix seconds)", edge.first_seen, inspector);
    appendDetail("Last observed (Unix seconds)", edge.last_seen, inspector);
    appendDetail("Observation count", edge.observation_count, inspector);
    appendDetail("Aggregated source record key", edge.source_record_key, inspector);
    const note = document.createElement("p");
    note.className = "inspector-note";
    note.textContent = "This edge is an observed protocol address claim, not " +
      "a physical cable, verified device, or reachability result. Its source " +
      "record key identifies a retained aggregate, not a raw packet.";
    inspector.append(note);
    return;
  }

  inspectorTitle.textContent = node.display_address;
  appendDetail("Evidence node",
    node.kind === "hardware" ? "Hardware address evidence" :
    node.kind === "ipv6" ? "IPv6 protocol address" : "IPv4 protocol address",
    inspector);
  appendDetail("Observed interface", node.interface, inspector);
  appendDetail("Capture scope", node.capture_scope, inspector);
  appendDetail("Address", node.display_address, inspector);
  const related = snapshot.edges.filter((item) =>
    item.source === node.id || item.target === node.id);
  const heading = document.createElement("h3");
  heading.textContent = "Supporting address claims (" + related.length + ")";
  inspector.append(heading);
  for (const item of related) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "claim-card unified-edge-card";
    const from = nodes.get(item.source);
    const to = nodes.get(item.target);
    button.textContent = unifiedEvidenceLabel(item.kind) + " · " +
      (from?.display_address || "?") + " → " +
      (to?.display_address || "?") + " · " +
      item.observation_count + " observation(s)";
    button.addEventListener("click", () => setSelectedEdge(item.id));
    inspector.append(button);
  }
  const caveat = document.createElement("p");
  caveat.className = "inspector-note";
  caveat.textContent = "These are independently observed, capture-scoped " +
    "ARP/NDP address claims, not verified physical-device identities. " +
    "DAD and NDP observations without an option-backed MAC stay unlinked.";
  inspector.append(caveat);
}


// Each DNS-SD connector is a shortcut to its three independent retained
// record claims. It does not represent a directly observed running service.
function showDNSRecordDetails(title, record, kind) {
  const heading = document.createElement("h3");
  heading.textContent = title;
  inspector.append(heading);
  appendDetail("Aggregated source record key", record.source_record_key, inspector);
  if (kind === "ptr") {
    appendDetail("PTR service type", record.service_type, inspector);
    appendDetail("PTR advertised instance", record.instance, inspector);
    appendDetail("PTR observation count", record.observation_count, inspector);
  } else if (kind === "srv") {
    appendDetail("SRV owner name", record.owner_name, inspector);
    appendDetail("SRV advertised target name", record.target_name, inspector);
    appendDetail("SRV advertised port", record.port, inspector);
  } else {
    appendDetail("A/AAAA owner name", record.owner_name, inspector);
    appendDetail("Record type", record.kind.toUpperCase(), inspector);
    appendDetail("Advertised IP address", record.address, inspector);
  }
  appendDetail("Observed (Unix seconds)", record.observed_at, inspector);
  appendDetail("TTL (seconds)", record.ttl_seconds, inspector);
  appendDetail("Record freshness", record.fresh ? "Fresh" : "Not fresh / TTL expired",
    inspector);
  appendDetail("Record provenance", record.source, inspector);
}

function showServiceInspector() {
  const snapshot = graph?.unified_service_graph;
  if (!snapshot) {
    clearInspector("Service graph is unavailable for this capture.");
    return;
  }
  const nodes = new Map(snapshot.nodes.map((node) => [node.id, node]));
  const edge = selectedEdgeId &&
    snapshot.edges.find((item) => item.id === selectedEdgeId);
  const node = selectedId && nodes.get(selectedId);
  if (selectedEdgeId && !edge) selectedEdgeId = null;
  if (selectedId && !node) selectedId = null;
  if (!edge && !node) {
    clearInspector("Select a hardware or IP address, an advertised service, " +
      "or any evidence connector to inspect its source claims.");
    return;
  }
  if (edge && edge.kind !== "dnssd_advertised_endpoint") {
    // These identifiers are identical to the Unified addresses evidence
    // graph, so its existing ARP/NDP inspector remains authoritative.
    showUnifiedInspector();
    return;
  }

  inspector.replaceChildren();
  if (edge) {
    const source = nodes.get(edge.source);
    const target = nodes.get(edge.target);
    inspectorTitle.textContent = "DNS-SD advertised endpoint path";
    appendDetail("Evidence type", "DNS-SD PTR → SRV → A/AAAA", inspector);
    appendDetail("Advertised IP address",
      source?.display_address || edge.address?.address || "Unavailable", inspector);
    appendDetail("Advertised service instance",
      target?.instance || edge.ptr.instance, inspector);
    appendDetail("Path freshness", edge.path_fresh
      ? "Fresh at captured snapshot time" : "Not fresh / TTL expired", inspector);
    if (!edge.path_fresh) {
      const expired = [];
      if (!edge.ptr?.fresh) expired.push("PTR");
      if (!edge.srv?.fresh) expired.push("SRV");
      if (!edge.address?.fresh) expired.push("A/AAAA");
      appendDetail("Not-fresh supporting records",
        expired.length ? expired.join(", ") : "Unavailable", inspector);
    }
    appendDetail("Capture interface", edge.interface, inspector);
    appendDetail("Capture scope", edge.capture_scope, inspector);
    appendDetail("Freshness evaluated as of (Unix seconds)",
      snapshot.as_of, inspector);
    appendDetail("Distinct endpoint evidence path ID", edge.id, inspector);
    showDNSRecordDetails("PTR: advertised service instance", edge.ptr, "ptr");
    showDNSRecordDetails("SRV: advertised target and port", edge.srv, "srv");
    showDNSRecordDetails(
      "A/AAAA: advertised address for the SRV target", edge.address, "address");
    const note = document.createElement("p");
    note.className = "inspector-note";
    note.textContent = "This visual connector summarizes separately captured " +
      "PTR, SRV and A/AAAA packet claims. A fresh advertised path does not " +
      "prove a listening process, an open port, reachability, verified device " +
      "identity, physical cabling or service ownership. Record keys identify " +
      "retained aggregates, not raw packet identities.";
    inspector.append(note);
    if (snapshot.truncated) appendDetail("Evidence coverage",
      "Receiver retention limits were reached; this is not a complete inventory.",
      inspector);
    return;
  }

  if (node.kind === "dnssd_service") {
    inspectorTitle.textContent = node.instance;
    appendDetail("Evidence node", "PTR-backed advertised DNS-SD service", inspector);
    appendDetail("Service type", node.service_type, inspector);
    appendDetail("Service instance", node.instance, inspector);
    appendDetail("Capture interface", node.interface, inspector);
    appendDetail("Capture scope", node.capture_scope, inspector);
    appendDetail("Freshness evaluated as of (Unix seconds)", snapshot.as_of, inspector);
    showDNSRecordDetails("PTR: retained service advertisement", node.ptr, "ptr");
  } else {
    inspectorTitle.textContent = node.display_address;
    appendDetail("Evidence node", node.kind === "hardware"
      ? "Hardware address evidence" : node.kind === "ipv6"
      ? "IPv6 protocol address" : "IPv4 protocol address", inspector);
    appendDetail("Address", node.display_address, inspector);
    appendDetail("Capture interface", node.interface, inspector);
    appendDetail("Capture scope", node.capture_scope, inspector);
    if (node.kind === "ipv4" || node.kind === "ipv6") {
      const hardwareClaims = snapshot.edges.filter((item) =>
        item.source === node.id && item.kind !== "dnssd_advertised_endpoint");
      if (!hardwareClaims.length) appendDetail(
        "Independent hardware evidence",
        "No retained same-scope option-backed ARP/NDP association; " +
        "DNS-SD alone does not establish a hardware owner.",
        inspector,
      );
    }
  }
  const related = snapshot.edges.filter((item) =>
    item.source === node.id || item.target === node.id);
  const heading = document.createElement("h3");
  heading.textContent = "Supporting evidence relationships (" + related.length + ")";
  inspector.append(heading);
  if (!related.length && node.kind === "dnssd_service") {
    const absent = document.createElement("p");
    absent.textContent = "No complete retained PTR → SRV → A/AAAA endpoint " +
      "path supports an IP address for this service advertisement.";
    inspector.append(absent);
  }
  for (const item of related) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "claim-card unified-edge-card services-endpoint-card";
    const from = nodes.get(item.source);
    const to = nodes.get(item.target);
    button.textContent = item.kind === "dnssd_advertised_endpoint"
      ? "DNS-SD advertised endpoint · " +
        (from?.display_address || item.address?.address || "?") + " → " +
        (to?.instance || "?") + " · port " + item.srv.port +
        " · " + (item.path_fresh ? "chain fresh" : "chain TTL expired")
      : unifiedEvidenceLabel(item.kind) + " · " +
        (from?.display_address || "?") + " → " +
        (to?.display_address || "?") + " · " +
        item.observation_count + " observation(s)";
    button.addEventListener("click", () => setSelectedEdge(item.id));
    inspector.append(button);
  }
  const note = document.createElement("p");
  note.className = "inspector-note";
  note.textContent = "Connections here are independent ARP/NDP claims or " +
    "advertised DNS-SD endpoint record chains, not verified physical links " +
    "or proof that any service is running.";
  inspector.append(note);
  if (snapshot.truncated) appendDetail("Evidence coverage",
    "Some observations were omitted at retention limits.", inspector);
}

function showInspector() {
  if (activeMapMode === "services") {
    showServiceInspector();
    return;
  }
  if (activeMapMode === "unified") {
    showUnifiedInspector();
    return;
  }
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
  selectedEdgeId = null;
  selectedId = selectedId === id ? null : id;
  renderGraph();
  showInspector();
  selectSidebarTab("evidence");
}

function setSelectedEdge(id) {
  selectedId = null;
  selectedEdgeId = selectedEdgeId === id ? null : id;
  renderGraph();
  showInspector();
  selectSidebarTab("evidence");
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
    .filter((node) => node.kind === "protocol" ||
      node.kind === "ipv4" || node.kind === "ipv6").sort(addressOrder);
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

// Unified mode uses hardware-address evidence as a *presentation* anchor.
// It is never promoted into a device identity, physical topology, or an
// inferred relationship. Retain every edge, including conflicting options.
function computeUnifiedAutoOrders(snapshot) {
  const byAddress = (a, b) =>
    a.capture_scope.localeCompare(b.capture_scope) ||
    a.interface.localeCompare(b.interface) ||
    a.address_hex.localeCompare(b.address_hex) ||
    a.id.localeCompare(b.id);
  const hardware = snapshot.nodes
    .filter((node) => node.kind === "hardware").sort(byAddress);
  const protocol = snapshot.nodes
    .filter((node) => node.kind === "ipv4" || node.kind === "ipv6")
    .sort((a, b) =>
      (a.kind === "ipv4" ? 0 : 1) - (b.kind === "ipv4" ? 0 : 1) ||
      byAddress(a, b));
  const protocolById = new Map(protocol.map((node) => [node.id, node]));
  const hardwareById = new Map(hardware.map((node) => [node.id, node]));
  const candidates = new Map(protocol.map((node) => [node.id, new Set()]));

  for (const edge of snapshot.edges) {
    const ip = protocolById.get(edge.source);
    const mac = hardwareById.get(edge.target);
    if (!ip || !mac || ip.interface !== mac.interface ||
        ip.capture_scope !== mac.capture_scope ||
        edge.interface !== ip.interface ||
        edge.capture_scope !== ip.capture_scope) continue;
    const supported = (ip.kind === "ipv4" && edge.kind === "arp_sender") ||
      (ip.kind === "ipv6" && (
        edge.kind === "ndp_ns_source_slla" ||
        edge.kind === "ndp_na_target_tlla"));
    if (supported) candidates.get(ip.id).add(mac.id);
  }

  const groups = new Map(hardware.map((node) => [node.id, []]));
  const ungrouped = [];
  // Deterministic address-order tie-break for claims involving multiple
  // MACs. This only chooses a position: all edges remain in the SVG.
  for (const ip of protocol) {
    const anchor = hardware.find((mac) => candidates.get(ip.id).has(mac.id));
    if (anchor) groups.get(anchor.id).push(ip);
    else ungrouped.push(ip);
  }
  return { hardware, groups, ungrouped };
}

// A MAC occupies the vertical center of its observed address cluster.
// The left column receives a row per IP, including both address families.
function layoutUnifiedGraph(snapshot) {
  const automatic = computeUnifiedAutoOrders(snapshot);
  const hardware = preserveManualOrder("hardware", automatic.hardware);
  const defaultProtocol = hardware.flatMap((mac) =>
    automatic.groups.get(mac.id) || []).concat(automatic.ungrouped);
  const protocol = preserveManualOrder("protocol", defaultProtocol);
  orderedByKind = { protocol, hardware };

  const locations = new Map();
  const addressSlots = [];
  let row = 0;
  for (const mac of hardware) {
    const count = (automatic.groups.get(mac.id) || []).length;
    const span = Math.max(count, 1);
    locations.set(mac.id, {
      x: COLUMN_X.hardware,
      y: ROW_START + (row + (span - 1) / 2) * ROW_STEP,
    });
    for (let index = 0; index < count; index++) {
      addressSlots.push(row + index);
    }
    row += span;
  }
  for (const ip of automatic.ungrouped) addressSlots.push(row++);
  protocol.forEach((ip, index) => locations.set(ip.id, {
    x: COLUMN_X.protocol,
    y: ROW_START + addressSlots[index] * ROW_STEP,
  }));
  stageHeight = Math.max(620, Math.max(row, protocol.length) * ROW_STEP + 175);
  svg.setAttribute("viewBox", "0 0 1080 " + stageHeight);
  return locations;
}


// Services mode builds on the same MAC-first address clustering, but keeps a
// third independently arranged service column. Placement is not identity.
const SERVICE_COLUMN_X = { hardware: 24, protocol: 395, services: 765 };
const SERVICE_CARD_WIDTH = 282;

const SERVICE_NAME_CHARS_PER_LINE = 32;
const SERVICE_NAME_LINE_HEIGHT = 16;

// Preserve every Unicode code point in the advertised instance, including
// literal DNS escaping, without relying on SVG text auto-wrapping (which SVG
// does not provide). Prefer separators, but split overlong tokens as needed.
function serviceNameLines(instance) {
  const name = String(instance);
  const tokens = name.match(/[^._\s-]+[._\s-]*|[._\s-]+/gu) || [name];
  const lines = [];
  let line = "";
  for (const token of tokens) {
    const points = Array.from(token);
    if (line && Array.from(line).length + points.length >
        SERVICE_NAME_CHARS_PER_LINE) {
      lines.push(line);
      line = "";
    }
    for (const point of points) {
      if (Array.from(line).length >= SERVICE_NAME_CHARS_PER_LINE) {
        lines.push(line);
        line = "";
      }
      line += point;
    }
  }
  if (line || !lines.length) lines.push(line);
  return lines;
}

function serviceCardHeight(node) {
  return 72 + (serviceNameLines(node.instance).length - 1) *
    SERVICE_NAME_LINE_HEIGHT;
}

let serviceSlotCenters = [];
function layoutServiceGraph(snapshot) {
  const automatic = computeUnifiedAutoOrders(snapshot);
  const hardware = preserveManualOrder("hardware", automatic.hardware);
  const defaultProtocol = hardware.flatMap((mac) =>
    automatic.groups.get(mac.id) || []).concat(automatic.ungrouped);
  const protocol = preserveManualOrder("protocol", defaultProtocol);
  const protocolRank = new Map(protocol.map((node, index) => [node.id, index]));
  const serviceNodes = snapshot.nodes.filter((node) =>
    node.kind === "dnssd_service");
  const serviceById = new Map(serviceNodes.map((node) => [node.id, node]));
  const serviceRanks = new Map(serviceNodes.map((node) => [node.id, new Set()]));
  for (const edge of snapshot.edges) {
    if (edge.kind !== "dnssd_advertised_endpoint" ||
        !protocolRank.has(edge.source) || !serviceById.has(edge.target)) continue;
    const ip = protocol[protocolRank.get(edge.source)];
    const service = serviceById.get(edge.target);
    if (edge.interface !== ip.interface || edge.interface !== service.interface ||
        edge.capture_scope !== ip.capture_scope ||
        edge.capture_scope !== service.capture_scope) continue;
    serviceRanks.get(service.id).add(protocolRank.get(ip.id));
  }
  // Auto-arrange is a single ordered list, not separate spatial groups.
  // Sort by the FIRST supporting IP's current visual rank, with unlinked
  // services last. This is a presentation order, not an ownership inference.
  const firstRank = (node) => {
    const ranks = serviceRanks.get(node.id);
    return ranks.size ? Math.min(...ranks) : Number.POSITIVE_INFINITY;
  };
  const automaticServices = serviceNodes.slice().sort((a, b) =>
    firstRank(a) - firstRank(b) ||
    a.service_type.localeCompare(b.service_type) ||
    a.instance.localeCompare(b.instance) || a.id.localeCompare(b.id));
  const services = preserveManualOrder("services", automaticServices);
  orderedByKind = { protocol, hardware, services };

  const locations = new Map();
  const addressSlots = [];
  let row = 0;
  for (const mac of hardware) {
    const count = (automatic.groups.get(mac.id) || []).length;
    const span = Math.max(count, 1);
    locations.set(mac.id, {
      x: SERVICE_COLUMN_X.hardware,
      y: ROW_START + (row + (span - 1) / 2) * ROW_STEP,
    });
    for (let index = 0; index < count; index++) {
      addressSlots.push(row + index);
    }
    row += span;
  }
  for (const ip of automatic.ungrouped) addressSlots.push(row++);
  protocol.forEach((ip, index) => locations.set(ip.id, {
    x: SERVICE_COLUMN_X.protocol,
    y: ROW_START + addressSlots[index] * ROW_STEP,
  }));
  // Single compact Services column: every card follows its predecessor,
  // including cards with no retained address relationship. This keeps
  // evidence-derived order without imposing artificial vertical clusters.
  const SERVICE_CARD_GAP = 12;
  let lastServiceBottom = ROW_START - SERVICE_CARD_GAP;
  services.forEach((service) => {
    const y = lastServiceBottom + SERVICE_CARD_GAP;
    locations.set(service.id, { x: SERVICE_COLUMN_X.services, y });
    lastServiceBottom = y + serviceCardHeight(service);
  });
  // Center each shorter rendered column against the tallest column's
  // actual card bounds, not a count of network addresses. This remains
  // presentation-only: neither order nor evidence relationships change.
  const columns = { hardware, protocol, services };
  const bounds = new Map();
  for (const [kind, members] of Object.entries(columns)) {
    if (!members.length) continue;
    const tops = members.map((node) => locations.get(node.id).y);
    const bottoms = members.map((node) => locations.get(node.id).y +
      (kind === "services" ? serviceCardHeight(node) : 64));
    const top = Math.min(...tops);
    const bottom = Math.max(...bottoms);
    bounds.set(kind, { top, bottom, height: bottom - top });
  }
  const reference = Array.from(bounds.values()).reduce((longest, item) =>
    !longest || item.height > longest.height ? item : longest, null);
  if (reference) {
    const center = (reference.top + reference.bottom) / 2;
    for (const [kind, members] of Object.entries(columns)) {
      const columnBounds = bounds.get(kind);
      if (!columnBounds) continue;
      const delta = center -
        (columnBounds.top + columnBounds.bottom) / 2;
      for (const node of members) locations.get(node.id).y += delta;
    }
  }
  // Pointer drag targets must use the final (centered) card positions.
  serviceSlotCenters = services.map((service) =>
    locations.get(service.id).y + serviceCardHeight(service) / 2);
  const renderedBottom = Math.max(0, ...Object.entries(columns).flatMap(
    ([kind, members]) => members.map((node) =>
      locations.get(node.id).y +
        (kind === "services" ? serviceCardHeight(node) : 64))));
  stageHeight = Math.max(
    620, Math.max(row, protocol.length) * ROW_STEP + 175,
    renderedBottom + 175,
  );
  svg.setAttribute("viewBox", "0 0 1080 " + stageHeight);
  return locations;
}

function preserveManualOrder(kind, automatic) {
  const ids = manualOrderForView()[kind];
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
  manualOrderForView()[kind] = updated;
  return true;
}

function layoutGraph() {
  const active = visibleAddressGraph();
  if (activeMapMode === "services") return layoutServiceGraph(active);
  if (activeMapMode === "unified") return layoutUnifiedGraph(active);
  const automatic = computeAutoOrders(active);
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


// Services SVG is deliberately a separate presentation path. ARP-only and
// Unified addresses retain their existing geometry and edge inspectors.
function renderServicesCanvas(snapshot, locations) {
  addSVGText(viewport, SERVICE_COLUMN_X.hardware, 59,
    "HARDWARE ADDRESSES", "column-title");
  addSVGText(viewport, SERVICE_COLUMN_X.protocol, 59,
    "IPV4 / IPV6 ADDRESSES", "column-title");
  addSVGText(viewport, SERVICE_COLUMN_X.services, 59,
    "ADVERTISED SERVICES", "column-title");

  const nodes = new Map(snapshot.nodes.map((node) => [node.id, node]));
  const parallels = new Map();
  for (const edge of snapshot.edges) {
    // Keep separate source-record paths hit-testable even when they
    // share the same two visual endpoints (including NS vs NA claims).
    const pair = edge.source + "|" + edge.target;
    if (!parallels.has(pair)) parallels.set(pair, []);
    parallels.get(pair).push(edge.id);
  }
  for (const ids of parallels.values()) ids.sort();

  // Fan each visible connector into its own port on shared endpoints,
  // even when the other endpoint differs. Otherwise 10 service paths
  // may converge exactly on top of each other and appear to be one.
  const ports = new Map();
  for (const edge of snapshot.edges) {
    const dnssd = edge.kind === "dnssd_advertised_endpoint";
    const fromId = dnssd ? edge.source : edge.target;
    const toId = dnssd ? edge.target : edge.source;
    for (const key of ["out:" + fromId, "in:" + toId]) {
      if (!ports.has(key)) ports.set(key, []);
      ports.get(key).push(edge.id);
    }
  }
  for (const ids of ports.values()) ids.sort();
  const portOffset = (key, edgeId) => {
    const ids = ports.get(key) || [edgeId];
    if (ids.length <= 1) return 0;
    const spacing = Math.min(16, 52 / (ids.length - 1));
    return (ids.indexOf(edgeId) - (ids.length - 1) / 2) * spacing;
  };

  for (const edge of snapshot.edges) {
    const sourceNode = nodes.get(edge.source);
    const targetNode = nodes.get(edge.target);
    const source = locations.get(edge.source);
    const target = locations.get(edge.target);
    if (!source || !target || !sourceNode || !targetNode ||
        edge.interface !== sourceNode.interface ||
        edge.interface !== targetNode.interface ||
        edge.capture_scope !== sourceNode.capture_scope ||
        edge.capture_scope !== targetNode.capture_scope) continue;
    const dnssd = edge.kind === "dnssd_advertised_endpoint";
    if (dnssd && (
      !(sourceNode.kind === "ipv4" || sourceNode.kind === "ipv6") ||
      targetNode.kind !== "dnssd_service"
    )) continue;
    if (!dnssd && !(
      (sourceNode.kind === "ipv4" && edge.kind === "arp_sender") ||
      (sourceNode.kind === "ipv6" && (
        edge.kind === "ndp_ns_source_slla" ||
        edge.kind === "ndp_na_target_tlla"))
    )) continue;
    if (!dnssd && targetNode.kind !== "hardware") continue;

    // Address-to-MAC provenance is preserved, but the visual reading
    // direction on this mode is HARDWARE -> ADDRESS -> SERVICE.
    const from = dnssd ? source : target;
    const to = dnssd ? target : source;
    const x1 = from.x + 256;
    const x2 = to.x;
    const fromId = dnssd ? edge.source : edge.target;
    const toId = dnssd ? edge.target : edge.source;
    const y1 = from.y + 32 + portOffset("out:" + fromId, edge.id);
    const y2 = to.y + (dnssd ? serviceCardHeight(targetNode) / 2 : 32) +
      portOffset("in:" + toId, edge.id);
    const ids = parallels.get(edge.source + "|" + edge.target) || [edge.id];
    const middle = (x1 + x2) / 2;
    const path = makeSVG("path", {
      d: "M " + x1 + " " + y1 + " C " + middle + " " + y1 +
        ", " + middle + " " + y2 + ", " + x2 + " " + y2,
      class: "map-edge evidence-" + edge.kind +
        (dnssd && !edge.path_fresh ? " stale-path" : "") +
        ((selectedEdgeId === edge.id ||
          (selectedId && (edge.source === selectedId ||
                          edge.target === selectedId))) ? " selected" : ""),
    });
    const group = makeSVG("g", {
      class: "map-edge-group" + (selectedEdgeId === edge.id ? " selected" : ""),
      "data-edge-id": edge.id, role: "button", tabindex: "0",
      "aria-label": (dnssd
        ? "DNS-SD advertised endpoint: " + edge.ptr.instance +
          " via " + edge.srv.target_name + " port " + edge.srv.port +
          " to " + edge.address.address + " observed " +
          edge.address.observed_at + (edge.path_fresh ? "" : ", TTL expired")
        : unifiedEvidenceLabel(edge.kind) + " from " +
          sourceNode.display_address + " to " + targetNode.display_address) +
        " evidence relationship",
    });
    const hasSharedEndpoint =
      (ports.get("out:" + fromId)?.length || 0) > 1 ||
      (ports.get("in:" + toId)?.length || 0) > 1;
    const hit = makeSVG("path", {
      d: path.getAttribute("d"),
      class: "map-edge-hit" + (
        ids.length > 1 || hasSharedEndpoint ? " services-parallel-hit" : ""),
    });
    group.append(path, hit);
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        setSelectedEdge(edge.id);
      }
    });
    viewport.append(group);
  }

  if (!snapshot.nodes.some((node) => node.kind === "dnssd_service")) {
    addSVGText(viewport, SERVICE_COLUMN_X.services, ROW_START + 25,
      "No PTR-backed advertisements in this capture", "services-empty-label");
  }
  for (const node of snapshot.nodes) {
    const position = locations.get(node.id);
    if (!position) continue;
    const service = node.kind === "dnssd_service";
    const selected = node.id === selectedId;
    const group = makeSVG("g", {
      class: "map-node " + node.kind + (selected ? " selected" : "") +
        (service && !node.ptr?.fresh ? " stale-ptr" : ""),
      transform: "translate(" + position.x + " " + position.y + ")",
      role: "button", tabindex: "0",
      "aria-label": service
        ? "Advertised DNS-SD service " + node.instance + " on " + node.interface
        : node.kind + " address " + node.display_address + " on " + node.interface,
      "data-node-id": node.id,
    });
    group.append(makeSVG("rect", {
      x: 0, y: 0, width: service ? SERVICE_CARD_WIDTH : 256,
      height: service ? serviceCardHeight(node) : 64, rx: service ? 3 : 8,
    }));
    if (service) {
      // Render the entire advertised service instance in legible SVG lines;
      // title and accessible label retain the unchanged original string.
      const fullName = String(node.instance);
      const nameLines = serviceNameLines(fullName);
      const extraHeight = (nameLines.length - 1) * SERVICE_NAME_LINE_HEIGHT;
      const title = makeSVG("title");
      title.textContent = fullName + " (" + node.service_type + ")";
      group.append(title);
      nameLines.forEach((line, index) =>
        addSVGText(group, 12, 21 + index * SERVICE_NAME_LINE_HEIGHT,
          line, "service-name-text"));
      addSVGText(group, 12, 41 + extraHeight, node.service_type,
        "service-type-text");
      addSVGText(group, 12, 59 + extraHeight,
        "PTR " + (node.ptr?.fresh ? "fresh" : "TTL expired") +
        " · " + node.interface, "service-status-text");
    } else {
      if (node.kind === "ipv6" && node.display_address.length > 28) {
        const midpoint = node.display_address.lastIndexOf(":", 24);
        const splitAt = midpoint > 8 ? midpoint + 1 : 24;
        addSVGText(group, 13, 20, node.display_address.slice(0, splitAt),
          "ipv6-address-text");
        addSVGText(group, 13, 37, node.display_address.slice(splitAt),
          "ipv6-address-text");
      } else {
        addSVGText(group, 13, 22, node.display_address);
      }
      addSVGText(group, 13, 54,
        "interface: " + node.interface, "node-meta");
    }
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        setSelected(node.id);
      } else if (moveNodesMode && event.shiftKey &&
                 (event.key === "ArrowUp" || event.key === "ArrowDown")) {
        event.preventDefault();
        const kind = columnKind(node.kind);
        const index = orderedByKind[kind].findIndex((item) => item.id === node.id);
        if (reorderNode(kind, node.id,
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
}

function renderGraph() {
  if (!graph) return;
  viewport.replaceChildren();
  viewport.classList.toggle("map-services-canvas", activeMapMode === "services");

  const active = visibleAddressGraph();
  if (!active) return;
  const locations = layoutGraph();
  if (activeMapMode === "services") {
    renderServicesCanvas(active, locations);
    updateCamera();
    return;
  }
  addSVGText(viewport, 114, 59, activeMapMode === "unified"
    ? "IPV4 / IPV6 ADDRESSES" : "PROTOCOL ADDRESSES", "column-title");
  addSVGText(viewport, 708, 59, "HARDWARE ADDRESSES", "column-title");

  const edges = activeMapMode === "unified" ? active.edges : graph.claims;
  for (const claim of edges) {
    const source = locations.get(claim.source);
    const target = locations.get(claim.target);
    if (!source || !target) continue;
    const x1 = source.x + 256;
    const y1 = source.y + (activeMapMode === "unified" ? 32 : 25);
    const x2 = target.x;
    const y2 = target.y + (activeMapMode === "unified" ? 32 : 25);
    const mid = (x1 + x2) / 2;
    const path = makeSVG("path", {
      d: "M " + x1 + " " + y1 + " C " + mid + " " + y1 + ", " +
        mid + " " + y2 + ", " + x2 + " " + y2,
      class: "map-edge" +
        (activeMapMode === "unified" ? " evidence-" + claim.kind : "") + (
        (selectedId && (claim.source === selectedId || claim.target === selectedId)) ||
        (activeMapMode === "unified" && selectedEdgeId === claim.id)
          ? " selected" : ""
      ),
    });
    if (activeMapMode === "unified") {
      const group = makeSVG("g", {
        class: "map-edge-group" + (selectedEdgeId === claim.id ? " selected" : ""),
        "data-edge-id": claim.id,
        role: "button",
        tabindex: "0",
        "aria-label": claim.kind.replaceAll("_", " ") + " evidence relationship",
      });
      const hit = makeSVG("path", {
        d: path.getAttribute("d"), class: "map-edge-hit",
      });
      group.append(path, hit);
      group.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          setSelectedEdge(claim.id);
        }
      });
      viewport.append(group);
    } else {
      viewport.append(path);
    }
  }

  for (const node of active.nodes) {
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
    group.append(makeSVG("rect", {
      x: 0, y: 0, width: 256,
      height: activeMapMode === "unified" ? 64 : NODE_HEIGHT, rx: 8,
    }));
    if (activeMapMode === "unified" &&
        node.kind === "ipv6" && node.display_address.length > 28) {
      // Do not silently truncate a protocol address in the evidence graph.
      // Long expanded IPv6 addresses wrap at a colon; inspector retains full.
      const midpoint = node.display_address.lastIndexOf(":", 24);
      const splitAt = midpoint > 8 ? midpoint + 1 : 24;
      addSVGText(group, 13, 20, node.display_address.slice(0, splitAt),
        "ipv6-address-text");
      addSVGText(group, 13, 37, node.display_address.slice(splitAt),
        "ipv6-address-text");
    } else {
      addSVGText(group, 13, 22, node.display_address);
    }
    addSVGText(group, 13, activeMapMode === "unified" ? 54 : 39,
      "interface: " + node.interface, "node-meta");
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        setSelected(node.id);
      } else if (moveNodesMode && event.shiftKey &&
                 (event.key === "ArrowUp" || event.key === "ArrowDown")) {
        event.preventDefault();
        const kind = columnKind(node.kind);
        const index = orderedByKind[kind].findIndex((item) => item.id === node.id);
        if (reorderNode(kind, node.id,
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

function maximumZoomScale() {
  // Default SVG preserveAspectRatio is xMidYMid meet. The graph's real
  // on-screen scale therefore depends on BOTH viewBox dimensions and
  // the available CSS viewport. A row-count multiplier is insufficient
  // when Safari is resized, especially to a wide/short window.
  const rect = svg.getBoundingClientRect();
  const view = svg.viewBox.baseVal;
  if (rect.width <= 0 || rect.height <= 0 ||
      view.width <= 0 || view.height <= 0) return 3.5;
  const cssPixelsPerUnit = Math.min(
    rect.width / view.width, rect.height / view.height);
  // Allow a node's 15-unit address text to reach roughly 75 CSS pixels
  // at the upper limit, irrespective of window dimensions or graph rows.
  // Keep the historical 3.5 floor for small graphs.
  return Math.max(3.5, 5 / cssPixelsPerUnit);
}

function zoomAt(factor, point) {
  // Permit continued smooth zooming after fit scales a dense graph below 40%.
  const next = Math.min(maximumZoomScale(), Math.max(0.05, camera.scale * factor));
  const ratio = next / camera.scale;
  camera.x = point.x - (point.x - camera.x) * ratio;
  camera.y = point.y - (point.y - camera.y) * ratio;
  camera.scale = next;
  updateCamera();
}

function resetView() {
  // Measure rendered evidence in graph coordinates, not the scrollable
  // stage extent. Sparse service rows should not produce an empty lead-in.
  // getBBox excludes the viewport's camera transform.
  const bounds = viewport.getBBox();
  if (!Number.isFinite(bounds.x) || !Number.isFinite(bounds.y) ||
      !Number.isFinite(bounds.width) || !Number.isFinite(bounds.height) ||
      bounds.width <= 0 || bounds.height <= 0) {
    camera = { x: 0, y: 0, scale: 1 };
    updateCamera();
    return;
  }
  const view = svg.viewBox.baseVal;
  const padding = 36;
  const availableWidth = Math.max(1, view.width - 2 * padding);
  const availableHeight = Math.max(1, view.height - 2 * padding);
  // Never magnify sparse evidence solely because Reset view was pressed.
  // Unlike interactive wheel zoom, fit may go below the usual zoom floor.
  const scale = Math.min(1, availableWidth / bounds.width,
    availableHeight / bounds.height);
  camera = {
    x: view.x + (view.width - bounds.width * scale) / 2 - bounds.x * scale,
    y: view.y + (view.height - bounds.height * scale) / 2 - bounds.y * scale,
    scale,
  };
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
    : (activeMapMode === "services"
      ? "Scroll to zoom · Drag to pan · Select an evidence connector · Reset view frames the visible evidence"
      : "Scroll to zoom · Drag to pan · Select an address");
});
document.getElementById("auto-arrange").addEventListener("click", () => {
  if (activeMapMode === "services") {
    serviceManualOrders.protocol = null;
    serviceManualOrders.hardware = null;
    serviceManualOrders.services = null;
  } else if (activeMapMode === "unified") {
    unifiedManualOrders.protocol = null;
    unifiedManualOrders.hardware = null;
  } else {
    manualOrders.protocol = null;
    manualOrders.hardware = null;
  }
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
  const targetEdge = event.target.closest("[data-edge-id]");
  const edgeId = !nodeId && targetEdge
    ? targetEdge.getAttribute("data-edge-id") : null;
  const active = visibleAddressGraph();
  const node = nodeId && active ? active.nodes.find((item) => item.id === nodeId) : null;
  dragging = {
    pointerId: event.pointerId, start: point,
    x: camera.x, y: camera.y, moved: false,
    nodeId, edgeId, kind: node ? columnKind(node.kind) : null,
    fromIndex: node ? orderedByKind[columnKind(node.kind)].findIndex(
      (item) => item.id === nodeId) : -1,
    // Snapshot actual Services slot centers at gesture start. Do not use
    // uniform ROW_STEP increments across sparse or variable-height rows.
    serviceCenters: moveNodesMode && activeMapMode === "services" &&
      node?.kind === "dnssd_service" ? serviceSlotCenters.slice() : null,
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
    // Services have sparse, variable-height slots. Find the closest
    // original slot center to the dragged card's center, rather than
    // treating every 76 SVG units as one service. The positions are
    // snapshotted for the gesture so rerenders cannot move the target.
    let target;
    if (dragging.serviceCenters?.length &&
        dragging.fromIndex >= 0) {
      const centers = dragging.serviceCenters;
      const desired = centers[dragging.fromIndex] + dy / camera.scale;
      target = dragging.fromIndex;
      for (let index = 0; index < centers.length; index++) {
        if (Math.abs(centers[index] - desired) <
            Math.abs(centers[target] - desired)) target = index;
      }
    } else {
      const displacement = Math.round(dy / (ROW_STEP * camera.scale));
      target = dragging.fromIndex + displacement;
    }
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
  } else if (event.type === "pointerup" && !gesture.moved && gesture.edgeId) {
    setSelectedEdge(gesture.edgeId);
  }
}
svg.addEventListener("pointerup", endPan);
svg.addEventListener("pointercancel", endPan);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && (selectedId || selectedEdgeId)) {
    selectedId = null;
    selectedEdgeId = null;
    renderGraph();
    showInspector();
  }
});

// Live mode requests a fresh immutable snapshot every second. The renderer
// changes only when its semantic revision changes; camera and selection stay.
let lastRevision = null;
let lastGraphRevision = null;
let lastRenderedMapMode = null;
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
  updateMapModes(payload);
  updateSidebarTabs(payload);
  showHostContext(live ? payload.host_context : null);
  const status = payload.capture_status || "waiting";
  if (live) {
    summary.textContent = (
      payload.ndp_evidence ? "LIVE ARP + mDNS + NDP · " :
      payload.mdns_evidence ? "LIVE ARP + mDNS · " : "LIVE ARP · "
    ) +
      (source.interface || "waiting for capture") +
      " · " + status + " · " + payload.nodes.length + " address nodes · " +
      payload.claims.length + " sender claims · " +
      (source.updates_seen || 0) + " binding updates";
    if (source.truncated) {
      summary.textContent += " · CAP REACHED (new addresses omitted)";
    }
    if (payload.mdns_evidence) {
      summary.textContent += " · mDNS " +
        String(payload.mdns_evidence.messages) + " messages";
    }
    if (payload.ndp_evidence) {
      summary.textContent += " · NDP " +
        String(payload.ndp_evidence.messages) + " messages";
    }
  } else {
    summary.textContent = (source.capture_name || "Replay") +
      " · " + payload.nodes.length + " address nodes · " +
      payload.claims.length + " sender claims · " +
      (source.frames_replayed || 0) + " frames";
  }
  const errors = (source.decode_errors || 0) + (source.stream_errors || 0);
  const errorNote = errors ? " · " + errors + " errors" : "";
  lastArpSummary = summary.textContent + errorNote;
  lastUnifiedSummary = "";
  lastServiceSummary = "";
  if (live && payload.unified_service_graph) {
    const services = payload.unified_service_graph;
    const nodeCount = services.nodes.filter((node) =>
      node.kind === "dnssd_service").length;
    const endpoints = services.edges.filter((edge) =>
      edge.kind === "dnssd_advertised_endpoint").length;
    lastServiceSummary = "PASSIVE ARP + NDP + DNS-SD · " + services.interface +
      " · " + status + " · " + nodeCount + " advertised services · " +
      endpoints + " endpoint paths · " + services.nodes.length +
      " nodes · " + services.edges.length + " evidence edges" +
      (services.truncated ? " · CAP REACHED (incomplete evidence)" : "") +
      (services.omitted_mdns_advertisements
        ? " · " + services.omitted_mdns_advertisements +
          " mDNS advertisements omitted" : "") +
      (services.omitted_ndp_claims
        ? " · " + services.omitted_ndp_claims + " NDP claims omitted" : "") +
      (services.omitted_ndp_unlinked
        ? " · " + services.omitted_ndp_unlinked +
          " unlinked NDP observations omitted" : "") +
      (services.arp_bindings_truncated ? " · ARP retention cap reached" : "") +
      errorNote;
  }
  if (live && payload.unified_address_graph) {
    const unified = payload.unified_address_graph;
    lastUnifiedSummary = "UNIFIED ARP + NDP · " + unified.interface +
      " · " + status + " · " + unified.nodes.length +
      " address nodes · " + unified.edges.length + " evidence edges" +
      (unified.truncated ? " · CAP REACHED" : "") + errorNote;
  }
  summary.textContent = activeMapMode === "services" ? lastServiceSummary :
    activeMapMode === "unified" ? lastUnifiedSummary : lastArpSummary;
  const serviceRevisionChanged = live && activeMapMode === "services" &&
    payload.unified_service_graph?.revision !== lastGraphRevision;
  if (!graph || !live || lastRevision !== payload.revision ||
      serviceRevisionChanged) {
    const graphRevision = live
      ? (activeMapMode === "services"
        ? payload.unified_service_graph.revision
        : activeMapMode === "unified"
        ? payload.unified_address_graph.revision
        : (payload.graph_revision ?? payload.revision)) : null;
    const redrawGraph = !graph || !live ||
      lastGraphRevision !== graphRevision ||
      lastRenderedMapMode !== activeMapMode;
    graph = payload;
    lastRevision = payload.revision;
    lastGraphRevision = graphRevision;
    if (redrawGraph) renderGraph();
    if (redrawGraph) lastRenderedMapMode = activeMapMode;
    showSubnetEvidence(live ? payload.subnet_evidence : null);
    showMDNSEvidence(live ? payload.mdns_evidence : null);
    showNDPEvidence(live ? payload.ndp_evidence : null);
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
