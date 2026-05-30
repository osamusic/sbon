// 実SBOMで起きがちな欠損・特殊値を集めた堅牢性検証用のサンプル（主にテストで使用）。
// - 未知コンポーネント（purl/cpe/ライセンス/バージョンなし）
// - ライセンス式（OR）、NOASSERTION ライセンス
// - 名称に特殊文字（HTMLエスケープ確認）
// - 複数・高深刻度の脆弱性
// - 深い依存チェーン
window.SBON_SAMPLE_EDGE = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  components: [
    {
      // バージョン・ライセンス・purl/cpe いずれもなし → 用途不明として扱われるべき。
      type: "library",
      name: "mystery-lib",
      bomRef: "comp-mystery",
    },
    {
      type: "library",
      name: "dual-licensed",
      version: "2.0.0",
      bomRef: "pkg:generic/dual-licensed@2.0.0",
      purl: "pkg:generic/dual-licensed@2.0.0",
      licenses: [{ expression: "(MIT OR Apache-2.0)" }],
    },
    {
      // NOASSERTION はライセンス一覧から除外され、「未確認」として扱われるべき。
      type: "library",
      name: "no-assertion-lib",
      version: "1.0.0",
      bomRef: "comp-noassertion",
      licenses: [{ license: { id: "NOASSERTION" } }],
    },
    {
      // 名称に特殊文字。表示時にHTMLエスケープされる必要がある。
      type: "library",
      name: "<script>alert(1)</script>",
      version: "0.0.1",
      bomRef: "comp-xss",
      licenses: [{ license: { id: "MIT" } }],
    },
    {
      type: "library",
      name: "vuln-heavy",
      version: "1.2.3",
      bomRef: "pkg:generic/vuln-heavy@1.2.3",
      purl: "pkg:generic/vuln-heavy@1.2.3",
      licenses: [{ license: { id: "GPL-2.0-only" } }],
    },
  ],
  vulnerabilities: [
    {
      id: "CVE-2024-0001",
      ratings: [{ severity: "critical", score: 9.8 }],
      affects: [{ ref: "pkg:generic/vuln-heavy@1.2.3" }],
      description: "Critical remote code execution.",
    },
    {
      id: "CVE-2024-0002",
      ratings: [{ severity: "low", score: 3.1 }],
      affects: [{ ref: "pkg:generic/vuln-heavy@1.2.3" }],
      description: "Minor information disclosure.",
    },
  ],
  dependencies: [
    { ref: "comp-mystery", dependsOn: ["pkg:generic/dual-licensed@2.0.0"] },
    { ref: "pkg:generic/dual-licensed@2.0.0", dependsOn: ["comp-noassertion"] },
    { ref: "comp-noassertion", dependsOn: ["pkg:generic/vuln-heavy@1.2.3"] },
  ],
};
