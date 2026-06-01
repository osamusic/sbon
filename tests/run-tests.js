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
    "samples/sample-edge-cases.js",
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

function mockLocalStorage(backing = new Map()) {
  return {
    getItem: (key) => (backing.has(key) ? backing.get(key) : null),
    setItem: (key, value) => backing.set(key, String(value)),
    removeItem: (key) => backing.delete(key),
    _backing: backing,
  };
}

function loadAppWithDom(localStorage = mockLocalStorage()) {
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
    window: { print() {}, localStorage },
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
    "samples/sample-edge-cases.js",
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

  return { events, get, localStorage, window: context.window };
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
  // Two category axes: a review perspective plus a component type.
  assert.strictEqual(openssl.componentType, "system-package");
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
        // A fictitious component with no knowledge entry, to exercise the
        // unmatched ("unknown") path. (Real packages like curl/zlib now match.)
        SPDXID: "SPDXRef-Package-acme-widget",
        name: "acme-widget",
        versionInfo: "8.7.1",
        licenseConcluded: "MIT",
        externalRefs: [
          {
            referenceCategory: "PACKAGE-MANAGER",
            referenceType: "purl",
            referenceLocator: "pkg:generic/acme-widget@8.7.1",
          },
        ],
      },
      {
        SPDXID: "SPDXRef-Package-acme-helper",
        name: "acme-helper",
        versionInfo: "1.3.1",
        licenseDeclared: "MIT",
      },
    ],
    relationships: [
      {
        spdxElementId: "SPDXRef-Package-acme-widget",
        relationshipType: "DEPENDS_ON",
        relatedSpdxElement: "SPDXRef-Package-acme-helper",
      },
    ],
  });

  assert.strictEqual(normalized.format, "SPDX-2.3");
  assert.strictEqual(normalized.components.length, 2);
  assert.deepStrictEqual(Array.from(normalized.dependencies.get("SPDXRef-Package-acme-widget")), [
    "SPDXRef-Package-acme-helper",
  ]);

  const widget = normalized.components.find((component) => component.name === "acme-widget");
  assert.ok(widget);
  assert.strictEqual(widget.packageId, null);
  assert.strictEqual(widget.category, "unknown");
  assert.strictEqual(widget.reviewPriority, "medium");
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
  assert.strictEqual(libssl.matchValue, "^(openssl|libssl\\d*|libcrypto\\d*|openssl-libs)$");
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

  // リリースレビュー向け要約。
  const release = window.SBON_DIFF.buildReleaseSummary({ entries, summary, dependencyChanges });
  assert.ok(release.headline.includes("追加1件・削除1件・更新2件"));
  const high = release.points.filter((p) => p.level === "high");
  assert.ok(high.some((p) => p.text.includes("確認優先度が上がった") && p.text.includes("openssl")));
  assert.ok(release.points.some((p) => p.text.includes("新規に追加") && p.text.includes("linux-kernel")));
  assert.ok(release.points.some((p) => p.text.includes("削除された") && p.text.includes("curl")));
  assert.ok(release.points.some((p) => p.text.includes("依存関係の変化")));

  // 依存関係差分のツリー構造。旧サンプルは依存なし → 全エッジ added。
  const graph = window.SBON_DIFF.diffDependencyGraph(before, after);
  assert.strictEqual(graph.hasChanges, true);
  assert.ok(graph.roots.includes("ref:product-firmware"), "依存元の起点が根になる");
  const opensslChildren = graph.adjacency.get("pkg:generic/openssl") || [];
  assert.ok(
    opensslChildren.some((c) => c.toKey === "pkg:generic/zlib" && c.status === "added"),
    "openssl→zlib が追加エッジ",
  );
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

function testEdgeCases() {
  const window = loadCore();
  const normalized = window.SBON_PARSER.normalizeSbom(window.SBON_SAMPLE_EDGE);
  assert.strictEqual(normalized.components.length, 5);
  const byName = new Map(normalized.components.map((c) => [c.name, c]));

  // 欠損だらけの未知コンポーネント。
  const mystery = byName.get("mystery-lib");
  assert.strictEqual(mystery.version, "不明");
  assert.deepStrictEqual(Array.from(mystery.licenses), []);
  assert.strictEqual(mystery.packageId, null);
  assert.strictEqual(mystery.category, "unknown");
  assert.ok(mystery.findings.includes("用途メタデータが不足しています"));
  assert.ok(mystery.findings.includes("ライセンス情報が未確認です"));

  // ライセンス式は保持する。
  assert.deepStrictEqual(Array.from(byName.get("dual-licensed").licenses), ["(MIT OR Apache-2.0)"]);

  // NOASSERTION はライセンス一覧から除外され、未確認として扱う。
  const noAssertion = byName.get("no-assertion-lib");
  assert.deepStrictEqual(Array.from(noAssertion.licenses), []);
  assert.ok(noAssertion.findings.includes("ライセンス情報が未確認です"));

  // 名称の特殊文字は正規化段階では生のまま保持（エスケープは表示層の責務）。
  assert.ok(byName.has("<script>alert(1)</script>"));

  // critical 脆弱性を持つコンポーネントは高優先度。
  const vulnHeavy = byName.get("vuln-heavy");
  assert.strictEqual(vulnHeavy.vulnerabilities.length, 2);
  assert.strictEqual(vulnHeavy.reviewPriority, "high");
  assert.ok(vulnHeavy.findings.includes("高深刻度の脆弱性があります"));

  // 深い依存チェーンが解析される。
  assert.strictEqual(normalized.dependencies.size, 3);

  // CSV出力が例外なく生成でき、特殊文字を含む行も出力される。
  const csv = window.SBON_EXPORT.buildCsv(normalized.components);
  assert.ok(csv.includes("<script>alert(1)</script>"));
  assert.ok(csv.includes("(MIT OR Apache-2.0)"));
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

function testLargeListRendering() {
  const { get, events, window } = loadAppWithDom();
  const viewer = window.SBON_UI.createViewer({
    parser: window.SBON_PARSER,
    exporter: window.SBON_EXPORT,
    differ: window.SBON_DIFF,
    review: window.SBON_REVIEW,
  });
  viewer.start();

  const components = [];
  for (let i = 0; i < 650; i += 1) {
    components.push({
      type: "library",
      name: `lib-${i}`,
      version: "1.0.0",
      bomRef: `pkg:generic/lib-${i}@1.0.0`,
      purl: `pkg:generic/lib-${i}@1.0.0`,
      licenses: [{ license: { id: "MIT" } }],
    });
  }
  viewer.loadSbom({ bomFormat: "CycloneDX", specVersion: "1.5", components }, "巨大SBOM");

  // 件数表示は全件。1ページ100件なので7ページに分割し、ページ送りで全件にアクセスできる。
  assert.strictEqual(get("#componentCount").textContent, "650 / 650件表示");
  assert.strictEqual(get("#pagination").hidden, false);
  assert.ok(get("#pageInfo").textContent.includes("1 / 7ページ"));
  assert.ok(get("#pageInfo").textContent.includes("全650件"));
  assert.strictEqual(get("#prevPageButton").disabled, true, "1ページ目では前へが無効");
  assert.strictEqual(get("#nextPageButton").disabled, false);

  // 次へでページが進む。
  events.get("#nextPageButton:click")();
  assert.ok(get("#pageInfo").textContent.includes("2 / 7ページ"));
  assert.ok(get("#pageInfo").textContent.includes("101–200件目"));

  // 検索で絞り込むと1ページ目に戻る。
  get("#searchInput").value = "lib-1";
  events.get("#searchInput:input")();
  assert.ok(get("#pageInfo").textContent.includes("1 /") || get("#pagination").hidden);

  // CSVには全件が含まれる（ページングはあくまで一覧表示のみ）。
  const normalized = window.SBON_PARSER.normalizeSbom({ bomFormat: "CycloneDX", specVersion: "1.5", components });
  assert.strictEqual(normalized.components.length, 650);
  const csv = window.SBON_EXPORT.buildCsv(normalized.components);
  assert.ok(csv.includes("lib-649"), "CSVには最終ページの項目も含まれる");
}

function testUiInteractions() {
  const sharedStorage = mockLocalStorage();
  const { events, get } = loadAppWithDom(sharedStorage);

  events.get("#loadSampleButton:click")();
  assert.strictEqual(get("#componentCount").textContent, "4 / 4件表示");
  // 件数が少なければページネーションは表示しない。
  assert.strictEqual(get("#pagination").hidden, true);

  // 目立つCTA「サンプルSBOMで試す」も同じサンプルを読み込む。
  events.get("#trySampleButton:click")();
  assert.strictEqual(get("#componentCount").textContent, "4 / 4件表示");
  assert.ok(get("#loadStatus").textContent.includes("CycloneDX"));

  // 未確認の最優先項目アラート: opensslが高優先度かつ未確認なので表示される。
  assert.strictEqual(get("#reviewAlert").hidden, false);
  assert.ok(get("#reviewAlert").textContent.includes("最優先確認"));

  // レビュー: 選択中コンポーネント（openssl）のステータスを変更すると一覧の要約に反映される。
  const reviewSelect = get("#reviewStatusSelect");
  reviewSelect.value = "approved";
  events.get("#reviewStatusSelect:change")();
  assert.ok(get("#reviewSummary").textContent.includes("承認1"));
  // 変更は localStorage に自動保存される。
  assert.ok(sharedStorage.getItem("sbon.reviews.v1"), "レビューが自動保存される");
  // レビュー結果の保存ボタンが例外なく動作する。
  events.get("#saveReviewButton:click")();

  // 別セッション（同じ localStorage）でも自動保存されたレビューが復元される。
  const reloaded = loadAppWithDom(sharedStorage);
  reloaded.events.get("#loadSampleButton:click")();
  assert.ok(reloaded.get("#reviewSummary").textContent.includes("承認1"), "再読み込みで復元");

  get("#searchInput").value = "openssl";
  events.get("#searchInput:input")();
  assert.strictEqual(get("#componentCount").textContent, "1 / 4件表示");

  events.get("#resetFiltersButton:click")();
  assert.strictEqual(get("#componentCount").textContent, "4 / 4件表示");

  events.get("sort-category:click")();
  assert.strictEqual(get("#componentCount").textContent, "4 / 4件表示");

  events.get("#loadSpdxSampleButton:click")();
  assert.strictEqual(get("#componentCount").textContent, "4 / 4件表示");
  assert.ok(get("#loadStatus").textContent.includes("SPDX-2.3"));
  assert.strictEqual(get("#loadStatus").hidden, false);

  // 出力範囲の切替: 印刷レポートの data-scope を選択値に同期する。
  get("#reportScope").value = "procurement";
  events.get("#reportScope:change")();
  assert.strictEqual(get("#printReport").dataset.scope, "procurement");
  get("#reportScope").value = "technical";
  events.get("#reportScope:change")();
  assert.strictEqual(get("#printReport").dataset.scope, "technical");

  events.get("#loadDiffSampleButton:click")();
  assert.strictEqual(get("#diffSection").hidden, false);
  assert.ok(get("#diffSummary").textContent.includes("確認優先度の上昇1件"));
  assert.ok(get("#diffDependencies").innerHTML.includes("依存関係の差分"));
  assert.ok(get("#diffDependencies").innerHTML.includes("dep-diff-tree"), "依存差分をツリーで描画");
  assert.ok(get("#diffReleaseSummary").innerHTML.includes("リリースレビュー向け要約"));
  assert.ok(get("#diffReleaseSummary").innerHTML.includes("確認優先度が上がった"));

  // 差分CSV出力ボタンが例外なく動作する。
  events.get("#diffCsvButton:click")();

  events.get("#clearCompareButton:click")();
  assert.strictEqual(get("#diffSection").hidden, true);
}

function testMultiCpeMatching() {
  const window = loadCore();
  const normalized = window.SBON_PARSER.normalizeSbom({
    spdxVersion: "SPDX-2.3",
    packages: [
      // mbed TLS: spaced name, github purl, and several distro/vendor CPEs. The
      // purl-name "mbedtls" anchors it regardless of which CPE comes first.
      {
        SPDXID: "SPDXRef-Package-mbedtls",
        name: "mbed TLS",
        versionInfo: "3.6.3",
        externalRefs: [
          { referenceType: "cpe23Type", referenceLocator: "cpe:2.3:a:debian_package:libmbedcrypto16:3.6.3:1:*:*:*:*:*:*" },
          { referenceType: "purl", referenceLocator: "pkg:github/Mbed-TLS/mbedtls@v3.6.3" },
          { referenceType: "cpe23Type", referenceLocator: "cpe:2.3:a:arm:mbed_tls:3.6.3:*:*:*:*:*:*:*" },
          { referenceType: "cpe23Type", referenceLocator: "cpe:2.3:a:debian_package:libmbedtls-doc:3.6.3:1:*:*:*:*:*:*" },
        ],
      },
      // A package whose FIRST CPE is an unknown variant but a later one is the
      // canonical openssl product — matching must try every CPE, not just the first.
      {
        SPDXID: "SPDXRef-Package-ossl",
        name: "OpenSSL",
        versionInfo: "3.5.4",
        externalRefs: [
          { referenceType: "cpe23Type", referenceLocator: "cpe:2.3:a:some_distro:openssl-weird:3.5.4:*:*:*:*:*:*:*" },
          { referenceType: "cpe23Type", referenceLocator: "cpe:2.3:a:openssl:openssl:3.5.4:*:*:*:*:*:*:*" },
        ],
      },
    ],
  });

  const mbedtls = normalized.components.find((c) => c.name === "mbed TLS");
  assert.ok(mbedtls);
  assert.strictEqual(mbedtls.cpes.length, 3, "all three CPEs are collected");
  assert.strictEqual(mbedtls.packageId, "pkg.mbedtls");

  const ossl = normalized.components.find((c) => c.name === "OpenSSL");
  assert.strictEqual(ossl.packageId, "pkg.openssl", "matched via a non-first CPE");
  assert.strictEqual(ossl.matchMethod, "cpe-product");
}

function run() {
  testCycloneDxSample();
  testSpdxBasicPackage();
  testMultiCpeMatching();
  testSpdxSampleEnrichment();
  testDiffLogic();
  testDiffLicenseAndCsv();
  testReviewStore();
  testEdgeCases();
  testLargeListRendering();
  testCpeProductExtraction();
  testAliasMatching();
  testUnknownSbomError();
  testCsvExportShape();
  testUiInteractions();
  console.log("All tests passed");
}

run();
