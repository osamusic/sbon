const assert = require("assert");
const fs = require("fs");
const vm = require("vm");

function loadCore() {
  const context = {
    window: {},
    console,
  };
  context.window.window = context.window;

  for (const file of [
    "data/knowledge/packages.js",
    "data/knowledge/package-identifiers.js",
    "data/knowledge/categories.js",
    "data/knowledge/package-categories.js",
    "data/knowledge/entries-ja.js",
    "data/knowledge/review-priority-rules.js",
    "data/knowledge-base.js",
    "samples/sample-cyclonedx.js",
    "samples/sample-cyclonedx-prev.js",
    "samples/sample-spdx.js",
    "js/review-priority.js",
    "js/parser.js",
    "js/diff.js",
    "js/review.js",
    "js/export.js",
  ]) {
    vm.runInNewContext(fs.readFileSync(file, "utf8"), context, { filename: file });
  }

  return context.window;
}

function loadAppWithDom() {
  const events = new Map();
  const elements = new Map();

  function mockElement(selector = "") {
    return {
      selector,
      value: selector === "#searchInput" ? "" : "all",
      textContent: "",
      innerHTML: "",
      className: "",
      tabIndex: 0,
      dataset: datasetFor(selector),
      classList: { add() {}, remove() {}, toggle() {} },
      addEventListener(event, handler) {
        events.set(`${selector}:${event}`, handler);
      },
      append(child) {
        this.appended = child;
      },
      click() {},
    };
  }

  function datasetFor(selector) {
    if (selector.startsWith("sort-")) return { sort: selector.replace("sort-", "") };
    if (selector === ".tab-detail") return { tab: "detail" };
    if (selector === ".tab-tree") return { tab: "tree" };
    return {};
  }

  const template = mockElement("#emptyRowTemplate");
  template.content = { cloneNode: () => mockElement("empty-row") };

  function get(selector) {
    if (selector === "#emptyRowTemplate") return template;
    if (!elements.has(selector)) elements.set(selector, mockElement(selector));
    return elements.get(selector);
  }

  const sortButtons = [
    "sort-name",
    "sort-version",
    "sort-priority",
    "sort-category",
    "sort-license",
    "sort-vulnerabilities",
  ].map(mockElement);

  const document = {
    querySelector: get,
    querySelectorAll(selector) {
      if (selector === ".tab") return [mockElement(".tab-detail"), mockElement(".tab-tree")];
      if (selector === ".sort-button") return sortButtons;
      return [];
    },
    createElement(tag) {
      return mockElement(tag);
    },
  };

  const context = {
    window: { print() {} },
    document,
    console,
    Blob: function Blob() {},
    URL: { createObjectURL: () => "blob:test", revokeObjectURL() {} },
    alert(message) {
      throw new Error(message);
    },
  };

  for (const file of [
    "data/knowledge/packages.js",
    "data/knowledge/package-identifiers.js",
    "data/knowledge/categories.js",
    "data/knowledge/package-categories.js",
    "data/knowledge/entries-ja.js",
    "data/knowledge/review-priority-rules.js",
    "data/knowledge-base.js",
    "samples/sample-cyclonedx.js",
    "samples/sample-cyclonedx-prev.js",
    "samples/sample-spdx.js",
    "js/review-priority.js",
    "js/parser.js",
    "js/diff.js",
    "js/review.js",
    "js/export.js",
    "js/ui.js",
    "app.js",
  ]) {
    vm.runInNewContext(fs.readFileSync(file, "utf8"), context, { filename: file });
  }

  return { events, get };
}

function testCycloneDxSample() {
  const window = loadCore();
  assert.ok(Array.isArray(window.SBON_KNOWLEDGE_BASE.packageIdentifiers));
  const normalized = window.SBON_PARSER.normalizeSbom(window.SBON_SAMPLE_SBOM);

  assert.strictEqual(normalized.format, "CycloneDX 1.5");
  assert.strictEqual(normalized.components.length, 4);
  assert.strictEqual(normalized.dependencies.size, 3);

  const openssl = normalized.components.find((component) => component.name === "openssl");
  assert.ok(openssl);
  assert.strictEqual(openssl.packageId, "pkg.openssl");
  assert.strictEqual(openssl.matchMethod, "purl-name");
  assert.strictEqual(openssl.matchValue, "openssl");
  assert.strictEqual(openssl.matchConfidence, "high");
  assert.strictEqual(openssl.reviewPriority, "high");
  assert.strictEqual(openssl.category, "crypto");
  assert.deepStrictEqual(Array.from(openssl.vulnerabilities, (vulnerability) => vulnerability.id), [
    "CVE-2023-0286",
  ]);
  assert.strictEqual(openssl.supplier, "OpenSSL Project");
  assert.deepStrictEqual(Array.from(openssl.references, (reference) => reference.type), ["website", "vcs"]);
}

function testSpdxBasicPackage() {
  const window = loadCore();
  const normalized = window.SBON_PARSER.normalizeSbom({
    spdxVersion: "SPDX-2.3",
    packages: [
      {
        SPDXID: "SPDXRef-Package-curl",
        name: "curl",
        versionInfo: "8.7.1",
        licenseConcluded: "curl",
        externalRefs: [
          {
            referenceCategory: "PACKAGE-MANAGER",
            referenceType: "purl",
            referenceLocator: "pkg:generic/curl@8.7.1",
          },
        ],
      },
      {
        SPDXID: "SPDXRef-Package-zlib",
        name: "zlib",
        versionInfo: "1.3.1",
        licenseDeclared: "Zlib",
      },
    ],
    relationships: [
      {
        spdxElementId: "SPDXRef-Package-curl",
        relationshipType: "DEPENDS_ON",
        relatedSpdxElement: "SPDXRef-Package-zlib",
      },
    ],
  });

  assert.strictEqual(normalized.format, "SPDX-2.3");
  assert.strictEqual(normalized.components.length, 2);
  assert.deepStrictEqual(Array.from(normalized.dependencies.get("SPDXRef-Package-curl")), [
    "SPDXRef-Package-zlib",
  ]);

  const curl = normalized.components.find((component) => component.name === "curl");
  assert.ok(curl);
  assert.strictEqual(curl.packageId, null);
  assert.strictEqual(curl.category, "unknown");
  assert.strictEqual(curl.reviewPriority, "medium");
}

function testAliasMatching() {
  const window = loadCore();
  const normalized = window.SBON_PARSER.normalizeSbom({
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    components: [
      {
        type: "library",
        name: "libssl",
        version: "3.2.0",
        bomRef: "pkg:deb/debian/libssl@3.2.0",
        licenses: [{ license: { id: "Apache-2.0" } }],
        purl: "pkg:deb/debian/libssl@3.2.0",
      },
    ],
  });

  const libssl = normalized.components[0];
  assert.strictEqual(libssl.packageId, "pkg.openssl");
  assert.strictEqual(libssl.matchMethod, "regex");
  assert.strictEqual(libssl.matchValue, "^(openssl|libssl|openssl-libs)$");
  assert.strictEqual(libssl.category, "crypto");
  assert.strictEqual(libssl.reviewPriority, "low");
}

function testUnknownSbomError() {
  const window = loadCore();
  assert.throws(
    () => window.SBON_PARSER.normalizeSbom({ name: "not an sbom" }),
    /CycloneDX JSON または SPDX JSON/,
  );
  assert.throws(() => window.SBON_PARSER.normalizeSbom([]), /JSONオブジェクト/);
  assert.throws(() => window.SBON_PARSER.normalizeSbom(null), /JSONオブジェクト/);
}

function testSpdxSampleEnrichment() {
  const window = loadCore();
  const normalized = window.SBON_PARSER.normalizeSbom(window.SBON_SAMPLE_SPDX);

  assert.strictEqual(normalized.format, "SPDX-2.3");
  assert.strictEqual(normalized.components.length, 4);

  const openssl = normalized.components.find((component) => component.name === "openssl");
  assert.strictEqual(openssl.packageId, "pkg.openssl");
  assert.strictEqual(openssl.matchMethod, "purl-name");
  assert.strictEqual(openssl.supplier, "OpenSSL Project");
  assert.strictEqual(openssl.cpe, "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*");
  assert.ok(openssl.copyright.includes("OpenSSL Project Authors"));
  assert.deepStrictEqual(Array.from(openssl.references, (reference) => reference.type), [
    "website",
    "distribution",
  ]);

  // glibcはpurlを持たないため、CPE製品名で照合される。
  const glibc = normalized.components.find((component) => component.name === "glibc");
  assert.strictEqual(glibc.packageId, "pkg.glibc");
  assert.strictEqual(glibc.matchMethod, "cpe-product");
  assert.strictEqual(glibc.supplier, "GNU Project");
  assert.strictEqual(glibc.copyright, "");

  // SPDXのDEPENDENCY_OFは向きを反転して依存元へ集約する。
  assert.deepStrictEqual(Array.from(normalized.dependencies.get("SPDXRef-Package-internal-tool")), [
    "SPDXRef-Package-glibc",
  ]);
}

function testDiffLogic() {
  const window = loadCore();
  const before = window.SBON_PARSER.normalizeSbom(window.SBON_SAMPLE_PREV);
  const after = window.SBON_PARSER.normalizeSbom(window.SBON_SAMPLE_SBOM);
  const { entries, summary, dependencyChanges } = window.SBON_DIFF.diffSboms(before, after);

  assert.strictEqual(summary.added, 1, "linux-kernelが追加");
  assert.strictEqual(summary.removed, 1, "curlが削除");
  assert.strictEqual(summary.changed, 2, "openssl/zlibが更新");
  assert.strictEqual(summary.unchanged, 1, "busyboxは変更なし");
  assert.strictEqual(summary.escalated, 1, "opensslの優先度が上昇");

  const byKey = new Map(entries.map((entry) => [entry.key, entry]));
  const openssl = byKey.get("pkg:generic/openssl");
  assert.strictEqual(openssl.changeType, "changed");
  assert.strictEqual(openssl.priorityEscalated, true);
  assert.strictEqual(openssl.before.reviewPriority, "low");
  assert.strictEqual(openssl.after.reviewPriority, "high");
  // ライセンス変更（旧→新）の追跡。openssl は Apache-2.0 のままなので変更なし。
  assert.strictEqual(openssl.licenseChanged, false);
  assert.deepStrictEqual(Array.from(openssl.before.licenses), ["Apache-2.0"]);
  assert.deepStrictEqual(Array.from(openssl.after.licenses), ["Apache-2.0"]);

  assert.strictEqual(byKey.get("pkg:generic/linux-kernel").changeType, "added");
  assert.strictEqual(byKey.get("pkg:generic/curl").changeType, "removed");
  assert.strictEqual(byKey.get("pkg:generic/busybox").changeType, "unchanged");

  // 並び順: 優先度上昇の項目が先頭。
  assert.strictEqual(entries[0].key, "pkg:generic/openssl");

  // 依存関係の差分: 旧サンプルは依存定義なし → 新サンプルの全エッジが「追加」。
  assert.strictEqual(dependencyChanges.added.length, 4, "新たな依存エッジ4件");
  assert.strictEqual(dependencyChanges.removed.length, 0);
}

function testDiffLicenseAndCsv() {
  const window = loadCore();
  const before = window.SBON_PARSER.normalizeSbom(window.SBON_SAMPLE_PREV);
  // ライセンスを差し替えた「新」を合成し、ライセンス変更検出を確認する。
  const after = window.SBON_PARSER.normalizeSbom({
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    components: [
      {
        type: "library",
        name: "openssl",
        version: "3.0.13",
        bomRef: "pkg:generic/openssl@3.0.13",
        purl: "pkg:generic/openssl@3.0.13",
        licenses: [{ license: { id: "Apache-2.0" } }, { license: { id: "OpenSSL" } }],
      },
    ],
  });
  const { entries } = window.SBON_DIFF.diffSboms(before, after);
  const openssl = entries.find((entry) => entry.key === "pkg:generic/openssl");
  assert.strictEqual(openssl.changeType, "changed", "ライセンス変更だけでも更新扱い");
  assert.strictEqual(openssl.licenseChanged, true);

  const csv = window.SBON_EXPORT.buildDiffCsv(entries);
  assert.ok(
    csv.startsWith(
      '"name","change","priority_escalated","license_changed","version_before","version_after"',
    ),
  );
  assert.ok(csv.includes('"openssl"'));
  assert.ok(csv.includes('"更新"'));
  assert.ok(csv.includes('"Apache-2.0; OpenSSL"'));
}

function testReviewStore() {
  const window = loadCore();
  const store = window.SBON_REVIEW.createReviewStore();

  // 既定値（未確認・メモなし）は保存しない。
  assert.strictEqual(store.size(), 0);
  store.setStatus("pkg:generic/openssl", "approved");
  store.setNote("pkg:generic/openssl", "1.1.1w系の更新計画を確認済み");
  store.setStatus("pkg:generic/busybox", "action-required");
  assert.strictEqual(store.size(), 2);

  const openssl = store.get("pkg:generic/openssl");
  assert.strictEqual(openssl.status, "approved");
  assert.ok(openssl.note.includes("更新計画"));

  const summary = store.summary();
  assert.strictEqual(summary.approved, 1);
  assert.strictEqual(summary["action-required"], 1);
  assert.strictEqual(summary.total, 2);

  // ステータスを未確認へ戻し、メモも消すとエントリは削除される。
  store.setStatus("pkg:generic/busybox", "unreviewed");
  assert.strictEqual(store.size(), 1);

  // JSON保存→読み込みのラウンドトリップ。
  const serialized = JSON.parse(JSON.stringify(store.toJSON()));
  const restored = window.SBON_REVIEW.createReviewStore();
  restored.loadJSON(serialized);
  assert.strictEqual(restored.get("pkg:generic/openssl").status, "approved");
  assert.ok(restored.get("pkg:generic/openssl").note.includes("更新計画"));

  // 不正な形式は例外。
  assert.throws(() => restored.loadJSON({}), /reviews/);
}

function testCpeProductExtraction() {
  const window = loadCore();
  const { extractCpeProduct } = window.SBON_REVIEW_PRIORITY;
  assert.strictEqual(extractCpeProduct("cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*"), "openssl");
  assert.strictEqual(extractCpeProduct("cpe:/a:gnu:glibc:2.36"), "glibc");
  assert.strictEqual(extractCpeProduct(""), "");
  assert.strictEqual(extractCpeProduct("not-a-cpe"), "");
}

function testCsvExportShape() {
  const window = loadCore();
  const normalized = window.SBON_PARSER.normalizeSbom(window.SBON_SAMPLE_SBOM);
  const csv = window.SBON_EXPORT.buildCsv(normalized.components);

  assert.ok(csv.startsWith('"component_id","name","version","type","purl","cpe","supplier","publisher","copyright"'));
  assert.ok(csv.includes('"pkg.openssl"'));
  assert.ok(csv.includes('"purl-name"'));
  assert.ok(csv.includes('"openssl"'));
  assert.ok(csv.includes('"CVE-2023-0286"'));
  assert.ok(csv.includes("高深刻度の脆弱性があります"));
  assert.ok(csv.includes("古いOpenSSL系列が使われている可能性があります"));
}

function testUiInteractions() {
  const { events, get } = loadAppWithDom();

  events.get("#loadSampleButton:click")();
  assert.strictEqual(get("#componentCount").textContent, "4 / 4件表示");

  // 目立つCTA「サンプルSBOMで試す」も同じサンプルを読み込む。
  events.get("#trySampleButton:click")();
  assert.strictEqual(get("#componentCount").textContent, "4 / 4件表示");
  assert.ok(get("#loadStatus").textContent.includes("CycloneDX"));

  // レビュー: 選択中コンポーネントのステータスを変更すると一覧の要約に反映される。
  const reviewSelect = get("#reviewStatusSelect");
  reviewSelect.value = "approved";
  events.get("#reviewStatusSelect:change")();
  assert.ok(get("#reviewSummary").textContent.includes("承認1"));
  // レビュー結果の保存ボタンが例外なく動作する。
  events.get("#saveReviewButton:click")();

  get("#searchInput").value = "openssl";
  events.get("#searchInput:input")();
  assert.strictEqual(get("#componentCount").textContent, "1 / 4件表示");

  events.get("#resetFiltersButton:click")();
  assert.strictEqual(get("#componentCount").textContent, "4 / 4件表示");

  events.get("sort-license:click")();
  assert.strictEqual(get("#componentCount").textContent, "4 / 4件表示");

  events.get("#loadSpdxSampleButton:click")();
  assert.strictEqual(get("#componentCount").textContent, "4 / 4件表示");
  assert.ok(get("#loadStatus").textContent.includes("SPDX-2.3"));
  assert.strictEqual(get("#loadStatus").hidden, false);

  events.get("#loadDiffSampleButton:click")();
  assert.strictEqual(get("#diffSection").hidden, false);
  assert.ok(get("#diffSummary").textContent.includes("確認優先度の上昇1件"));
  assert.ok(get("#diffDependencies").innerHTML.includes("依存関係の差分"));

  // 差分CSV出力ボタンが例外なく動作する。
  events.get("#diffCsvButton:click")();

  events.get("#clearCompareButton:click")();
  assert.strictEqual(get("#diffSection").hidden, true);
}

function run() {
  testCycloneDxSample();
  testSpdxBasicPackage();
  testSpdxSampleEnrichment();
  testDiffLogic();
  testDiffLicenseAndCsv();
  testReviewStore();
  testCpeProductExtraction();
  testAliasMatching();
  testUnknownSbomError();
  testCsvExportShape();
  testUiInteractions();
  console.log("All tests passed");
}

run();
