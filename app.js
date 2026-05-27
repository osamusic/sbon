const state = {
  format: "未読み込み",
  components: [],
  dependencies: new Map(),
  selectedId: null,
};

const PACKAGE_KNOWLEDGE = [
  {
    pattern: /openssl|libssl/i,
    category: "crypto",
    label: "暗号",
    explanation:
      "通信の暗号化や証明書検証に使われる重要な暗号ライブラリです。製品やシステムの遠隔接続、更新、外部連携の安全性に影響します。",
  },
  {
    pattern: /busybox/i,
    category: "os",
    label: "OS基盤",
    explanation:
      "組み込みLinuxで基本コマンドを提供する軽量ツール群です。機器内部の保守性や権限管理に関係します。",
  },
  {
    pattern: /glibc|musl|libc/i,
    category: "os",
    label: "OS基盤",
    explanation:
      "多くのソフトウェアが依存するC標準ライブラリです。影響範囲が広いため、脆弱性やサポート状況の確認が重要です。",
  },
  {
    pattern: /linux|kernel/i,
    category: "os",
    label: "OS基盤",
    explanation:
      "機器やシステムの中核となるOSカーネルです。長期運用される製品では、サポート期間と更新方針の確認が必要です。",
  },
  {
    pattern: /curl|wget|http|nginx|apache|openssl|ssh|dropbear/i,
    category: "network",
    label: "ネットワーク",
    explanation:
      "ネットワーク通信に関係するコンポーネントです。院内ネットワーク接続や外部連携がある場合は優先的に確認します。",
  },
  {
    pattern: /pam|oauth|jwt|saml|login|auth/i,
    category: "auth",
    label: "認証",
    explanation:
      "認証やセッション管理に関係する可能性があります。利用者認証、権限管理、監査要件との関係を確認します。",
  },
  {
    pattern: /update|ota|opkg|apt|rpm|dnf/i,
    category: "update",
    label: "更新機構",
    explanation:
      "ソフトウェア更新やパッケージ管理に関係します。製品の保守手順、署名検証、更新停止時の影響を確認します。",
  },
];

const SAMPLE_SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  components: [
    {
      type: "library",
      name: "openssl",
      version: "1.1.1w",
      bomRef: "pkg:generic/openssl@1.1.1w",
      licenses: [{ license: { id: "Apache-2.0" } }],
      purl: "pkg:generic/openssl@1.1.1w",
    },
    {
      type: "library",
      name: "busybox",
      version: "1.31.1",
      bomRef: "pkg:generic/busybox@1.31.1",
      licenses: [{ license: { id: "GPL-2.0-only" } }],
      purl: "pkg:generic/busybox@1.31.1",
    },
    {
      type: "library",
      name: "zlib",
      version: "1.3.1",
      bomRef: "pkg:generic/zlib@1.3.1",
      licenses: [{ license: { id: "Zlib" } }],
    },
    {
      type: "operating-system",
      name: "linux-kernel",
      version: "5.4.268",
      bomRef: "pkg:generic/linux-kernel@5.4.268",
      licenses: [{ license: { id: "GPL-2.0-only" } }],
    },
  ],
  vulnerabilities: [
    {
      id: "CVE-2023-0286",
      ratings: [{ severity: "high", score: 7.4 }],
      affects: [{ ref: "pkg:generic/openssl@1.1.1w" }],
      description: "OpenSSL X.400 address type confusion vulnerability.",
    },
    {
      id: "CVE-2021-42374",
      ratings: [{ severity: "medium", score: 5.5 }],
      affects: [{ ref: "pkg:generic/busybox@1.31.1" }],
      description: "BusyBox awk use-after-free vulnerability.",
    },
  ],
  dependencies: [
    {
      ref: "product-firmware",
      dependsOn: ["pkg:generic/openssl@1.1.1w", "pkg:generic/busybox@1.31.1"],
    },
    { ref: "pkg:generic/openssl@1.1.1w", dependsOn: ["pkg:generic/zlib@1.3.1"] },
    { ref: "pkg:generic/busybox@1.31.1", dependsOn: ["pkg:generic/linux-kernel@5.4.268"] },
  ],
};

const elements = {
  fileInput: document.querySelector("#fileInput"),
  dropzone: document.querySelector("#dropzone"),
  loadSampleButton: document.querySelector("#loadSampleButton"),
  printButton: document.querySelector("#printButton"),
  csvButton: document.querySelector("#csvButton"),
  searchInput: document.querySelector("#searchInput"),
  riskFilter: document.querySelector("#riskFilter"),
  categoryFilter: document.querySelector("#categoryFilter"),
  totalComponents: document.querySelector("#totalComponents"),
  highRiskCount: document.querySelector("#highRiskCount"),
  mediumRiskCount: document.querySelector("#mediumRiskCount"),
  vulnerabilityCount: document.querySelector("#vulnerabilityCount"),
  executiveSummary: document.querySelector("#executiveSummary"),
  componentRows: document.querySelector("#componentRows"),
  emptyRowTemplate: document.querySelector("#emptyRowTemplate"),
  detailView: document.querySelector("#detailView"),
  treeView: document.querySelector("#treeView"),
  formatLabel: document.querySelector("#formatLabel"),
  tabs: document.querySelectorAll(".tab"),
};

function normalizeSbom(sbom) {
  if (Array.isArray(sbom.components) || sbom.bomFormat === "CycloneDX") {
    return normalizeCycloneDx(sbom);
  }

  if (Array.isArray(sbom.packages) || sbom.spdxVersion) {
    return normalizeSpdx(sbom);
  }

  throw new Error("CycloneDX JSON または SPDX JSON として認識できません。");
}

function normalizeCycloneDx(sbom) {
  const vulnerabilities = new Map();
  for (const vulnerability of sbom.vulnerabilities || []) {
    const affectedRefs = (vulnerability.affects || []).map((item) => item.ref).filter(Boolean);
    for (const ref of affectedRefs) {
      const list = vulnerabilities.get(ref) || [];
      list.push({
        id: vulnerability.id || "Unknown CVE",
        severity: normalizeSeverity(vulnerability.ratings?.[0]?.severity),
        score: vulnerability.ratings?.[0]?.score || "",
        description: vulnerability.description || "",
      });
      vulnerabilities.set(ref, list);
    }
  }

  const components = (sbom.components || []).map((component, index) => {
    const id = component.bomRef || component.purl || `${component.name || "unknown"}-${index}`;
    return enrichComponent({
      id,
      name: component.name || "名称不明",
      version: component.version || "不明",
      type: component.type || "不明",
      licenses: parseCycloneDxLicenses(component.licenses),
      purl: component.purl || id,
      vulnerabilities: vulnerabilities.get(id) || vulnerabilities.get(component.purl) || [],
    });
  });

  return {
    format: `CycloneDX ${sbom.specVersion || ""}`.trim(),
    components,
    dependencies: new Map((sbom.dependencies || []).map((item) => [item.ref, item.dependsOn || []])),
  };
}

function normalizeSpdx(sbom) {
  const packages = sbom.packages || [];
  const relationships = sbom.relationships || [];
  const dependencies = new Map();

  for (const relationship of relationships) {
    if (!["DEPENDS_ON", "DEPENDENCY_OF", "CONTAINS"].includes(relationship.relationshipType)) {
      continue;
    }

    const source = relationship.spdxElementId;
    const target = relationship.relatedSpdxElement;
    if (!source || !target) {
      continue;
    }

    if (relationship.relationshipType === "DEPENDENCY_OF") {
      const list = dependencies.get(target) || [];
      list.push(source);
      dependencies.set(target, list);
    } else {
      const list = dependencies.get(source) || [];
      list.push(target);
      dependencies.set(source, list);
    }
  }

  const components = packages.map((pkg, index) =>
    enrichComponent({
      id: pkg.SPDXID || `${pkg.name || "unknown"}-${index}`,
      name: pkg.name || "名称不明",
      version: pkg.versionInfo || "不明",
      type: "package",
      licenses: parseSpdxLicense(pkg),
      purl: (pkg.externalRefs || []).find((ref) => ref.referenceType === "purl")?.referenceLocator || "",
      vulnerabilities: [],
    }),
  );

  return {
    format: sbom.spdxVersion || "SPDX",
    components,
    dependencies,
  };
}

function enrichComponent(component) {
  const knowledge = PACKAGE_KNOWLEDGE.find((item) => item.pattern.test(component.name)) || {
    category: "unknown",
    label: "不明",
    explanation:
      "公開情報や社内台帳で用途を確認してください。用途が不明なOSSは、保守責任と影響範囲が判断しにくい状態です。",
  };

  const findings = [];
  if (component.vulnerabilities.some((item) => item.severity === "high" || item.severity === "critical")) {
    findings.push("高深刻度の脆弱性があります");
  }
  if (component.vulnerabilities.length > 0) {
    findings.push("既知の脆弱性があります");
  }
  if (looksEol(component)) {
    findings.push("サポート終了または長期保守リスクの可能性があります");
  }
  if (component.licenses.length === 0 || component.licenses.includes("NOASSERTION")) {
    findings.push("ライセンス情報が未確認です");
  }
  if (knowledge.category === "unknown") {
    findings.push("用途メタデータが不足しています");
  }

  const risk = scoreRisk(component, findings);

  return {
    ...component,
    category: knowledge.category,
    categoryLabel: knowledge.label,
    explanation: knowledge.explanation,
    findings,
    risk,
  };
}

function scoreRisk(component, findings) {
  if (
    component.vulnerabilities.some((item) => item.severity === "critical" || item.severity === "high") ||
    findings.some((finding) => finding.includes("サポート終了"))
  ) {
    return "high";
  }

  if (component.vulnerabilities.length > 0 || findings.length > 0) {
    return "medium";
  }

  return "low";
}

function looksEol(component) {
  const version = String(component.version || "");
  const name = component.name.toLowerCase();
  if (name.includes("openssl") && /^1\.0\.|^1\.1\./.test(version)) return true;
  if (name.includes("busybox") && /^1\.(2\d|30|31)\./.test(version)) return true;
  if (name.includes("linux") && /^(3|4|5\.4)\./.test(version)) return true;
  return false;
}

function parseCycloneDxLicenses(licenses = []) {
  return licenses
    .map((item) => item.license?.id || item.license?.name || item.expression)
    .filter(Boolean);
}

function parseSpdxLicense(pkg) {
  const license = pkg.licenseConcluded || pkg.licenseDeclared;
  return license ? [license] : [];
}

function normalizeSeverity(severity = "unknown") {
  const lowered = String(severity).toLowerCase();
  if (["critical", "high", "medium", "low"].includes(lowered)) return lowered;
  return "unknown";
}

function render() {
  const filtered = getFilteredComponents();
  renderSummary();
  renderRows(filtered);
  renderDetail();
  renderTree();
}

function renderSummary() {
  const high = state.components.filter((component) => component.risk === "high").length;
  const medium = state.components.filter((component) => component.risk === "medium").length;
  const vulnerabilityCount = state.components.reduce(
    (total, component) => total + component.vulnerabilities.length,
    0,
  );

  elements.totalComponents.textContent = state.components.length;
  elements.highRiskCount.textContent = high;
  elements.mediumRiskCount.textContent = medium;
  elements.vulnerabilityCount.textContent = vulnerabilityCount;
  elements.formatLabel.textContent = state.format;

  const overall = high > 0 ? "高" : medium > 0 ? "中" : state.components.length > 0 ? "低" : "未評価";
  elements.executiveSummary.textContent =
    state.components.length === 0
      ? "SBOMを読み込むと、調達・品質保証・セキュリティ管理向けの確認ポイントを表示します。"
      : `このSBOMには${state.components.length}件のOSSコンポーネントが含まれます。高リスク${high}件、要確認${medium}件、既知の脆弱性${vulnerabilityCount}件です。総合リスクは「${overall}」として扱い、暗号・ネットワーク・OS基盤の項目を優先確認してください。`;
}

function renderRows(components) {
  elements.componentRows.textContent = "";

  if (components.length === 0) {
    elements.componentRows.append(elements.emptyRowTemplate.content.cloneNode(true));
    return;
  }

  for (const component of components) {
    const row = document.createElement("tr");
    row.className = component.id === state.selectedId ? "is-selected" : "";
    row.tabIndex = 0;
    row.innerHTML = `
      <td><span class="pkg-name">${escapeHtml(component.name)}</span><span class="pkg-id">${escapeHtml(component.purl || component.id)}</span></td>
      <td>${escapeHtml(component.version)}</td>
      <td><span class="badge ${component.risk}">${riskLabel(component.risk)}</span></td>
      <td class="category">${escapeHtml(component.categoryLabel)}</td>
      <td>${escapeHtml(component.licenses.join(", ") || "未確認")}</td>
      <td>${component.vulnerabilities.length}</td>
    `;
    row.addEventListener("click", () => selectComponent(component.id));
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectComponent(component.id);
      }
    });
    elements.componentRows.append(row);
  }
}

function renderDetail() {
  const component = state.components.find((item) => item.id === state.selectedId);
  if (!component) {
    elements.detailView.innerHTML = '<p class="empty">一覧からコンポーネントを選択してください。</p>';
    return;
  }

  elements.detailView.innerHTML = `
    <div class="detail-title">
      <div>
        <h3>${escapeHtml(component.name)}</h3>
        <span class="pkg-id">${escapeHtml(component.purl || component.id)}</span>
      </div>
      <span class="badge ${component.risk}">${riskLabel(component.risk)}</span>
    </div>
    <div class="detail-section">
      <h4>日本語説明</h4>
      <p>${escapeHtml(component.explanation)}</p>
    </div>
    <div class="detail-section">
      <h4>確認ポイント</h4>
      ${renderList(component.findings.length ? component.findings : ["現時点で主要なリスク指標は検出されていません。"])}
    </div>
    <div class="detail-section">
      <h4>ライセンス</h4>
      <p>${escapeHtml(component.licenses.join(", ") || "未確認")}</p>
    </div>
    <div class="detail-section">
      <h4>脆弱性</h4>
      ${renderVulnerabilities(component.vulnerabilities)}
    </div>
  `;
}

function renderTree() {
  if (state.dependencies.size === 0) {
    elements.treeView.innerHTML = '<p class="empty">依存関係情報があるSBOMを読み込むと表示します。</p>';
    return;
  }

  const childRefs = new Set([...state.dependencies.values()].flat());
  const roots = [...state.dependencies.keys()].filter((ref) => !childRefs.has(ref));
  const treeRoots = roots.length ? roots : [...state.dependencies.keys()].slice(0, 5);
  elements.treeView.innerHTML = `<ul class="tree-list">${treeRoots
    .map((ref) => renderTreeNode(ref, new Set()))
    .join("")}</ul>`;
}

function renderTreeNode(ref, seen) {
  if (seen.has(ref)) {
    return `<li><span class="tree-node">${escapeHtml(resolveName(ref))}</span> <span class="tree-ref">循環参照</span></li>`;
  }

  const nextSeen = new Set(seen);
  nextSeen.add(ref);
  const children = state.dependencies.get(ref) || [];
  return `
    <li>
      <span class="tree-node">${escapeHtml(resolveName(ref))}</span>
      <span class="tree-ref">${escapeHtml(ref)}</span>
      ${children.length ? `<ul class="tree-list">${children.map((child) => renderTreeNode(child, nextSeen)).join("")}</ul>` : ""}
    </li>
  `;
}

function renderVulnerabilities(vulnerabilities) {
  if (!vulnerabilities.length) {
    return "<p>既知の脆弱性はSBOM内に記載されていません。</p>";
  }

  return renderList(
    vulnerabilities.map((item) =>
      `${item.id} (${severityLabel(item.severity)}${item.score ? `, CVSS ${item.score}` : ""}) ${item.description}`,
    ),
  );
}

function renderList(items) {
  return `<ul class="plain-list">${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function getFilteredComponents() {
  const query = elements.searchInput.value.trim().toLowerCase();
  const risk = elements.riskFilter.value;
  const category = elements.categoryFilter.value;

  return state.components.filter((component) => {
    const haystack = [
      component.name,
      component.version,
      component.purl,
      component.licenses.join(" "),
      component.vulnerabilities.map((item) => item.id).join(" "),
    ]
      .join(" ")
      .toLowerCase();
    return (
      (!query || haystack.includes(query)) &&
      (risk === "all" || component.risk === risk) &&
      (category === "all" || component.category === category)
    );
  });
}

function selectComponent(id) {
  state.selectedId = id;
  render();
}

function resolveName(ref) {
  const component = state.components.find((item) => item.id === ref || item.purl === ref);
  return component ? `${component.name} ${component.version}` : ref;
}

function riskLabel(risk) {
  return { high: "高", medium: "中", low: "低" }[risk] || "不明";
}

function severityLabel(severity) {
  return { critical: "緊急", high: "高", medium: "中", low: "低", unknown: "不明" }[severity] || "不明";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function loadFile(file) {
  try {
    const json = JSON.parse(await file.text());
    loadSbom(json);
  } catch (error) {
    alert(error.message || "JSONの読み込みに失敗しました。");
  }
}

function loadSbom(json) {
  const normalized = normalizeSbom(json);
  state.format = normalized.format;
  state.components = normalized.components;
  state.dependencies = normalized.dependencies;
  state.selectedId = state.components[0]?.id || null;
  render();
}

function exportCsv() {
  const headers = ["name", "version", "risk", "category", "licenses", "vulnerabilities", "findings"];
  const rows = state.components.map((component) => [
    component.name,
    component.version,
    riskLabel(component.risk),
    component.categoryLabel,
    component.licenses.join("; "),
    component.vulnerabilities.map((item) => item.id).join("; "),
    component.findings.join("; "),
  ]);
  const csv = [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
  const blob = new Blob([`\ufeff${csv}`], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "sbom-review.csv";
  link.click();
  URL.revokeObjectURL(url);
}

function csvCell(value) {
  return `"${String(value).replaceAll('"', '""')}"`;
}

elements.fileInput.addEventListener("change", (event) => {
  const file = event.target.files?.[0];
  if (file) loadFile(file);
});

elements.dropzone.addEventListener("dragover", (event) => {
  event.preventDefault();
  elements.dropzone.classList.add("is-dragging");
});

elements.dropzone.addEventListener("dragleave", () => {
  elements.dropzone.classList.remove("is-dragging");
});

elements.dropzone.addEventListener("drop", (event) => {
  event.preventDefault();
  elements.dropzone.classList.remove("is-dragging");
  const file = event.dataTransfer.files?.[0];
  if (file) loadFile(file);
});

elements.loadSampleButton.addEventListener("click", () => loadSbom(SAMPLE_SBOM));
elements.printButton.addEventListener("click", () => window.print());
elements.csvButton.addEventListener("click", exportCsv);
elements.searchInput.addEventListener("input", render);
elements.riskFilter.addEventListener("change", render);
elements.categoryFilter.addEventListener("change", render);

for (const tab of elements.tabs) {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab, .tab-page").forEach((item) => item.classList.remove("is-active"));
    tab.classList.add("is-active");
    document.querySelector(`#${tab.dataset.tab}View`).classList.add("is-active");
  });
}

render();
