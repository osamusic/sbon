window.SBON_KNOWLEDGE_REVIEW_PRIORITY_RULES = [
  {
    id: "priority.busybox.old-series",
    packageId: "pkg.busybox",
    ruleType: "version-prefix",
    values: ["1.20.", "1.21.", "1.22.", "1.23.", "1.24.", "1.25.", "1.26.", "1.27.", "1.28.", "1.29.", "1.30.", "1.31."],
    severity: "high",
    findingJa: "古いBusyBox系列が使われている可能性があります。製品内での利用範囲と更新可能性を確認してください。",
    enabled: true,
  },
  {
    id: "priority.linux-kernel.old-series",
    packageId: "pkg.linux-kernel",
    ruleType: "version-prefix",
    values: ["3.", "4.", "5.4."],
    severity: "high",
    findingJa: "古いLinux kernel系列が使われている可能性があります。長期保守版かどうかと更新方針を確認してください。",
    enabled: true,
  },
  {
    id: "priority.openssl.legacy-series",
    packageId: "pkg.openssl",
    ruleType: "version-prefix",
    values: ["1.0.", "1.1."],
    severity: "high",
    findingJa: "古いOpenSSL系列が使われている可能性があります。サポート状況と更新計画を確認してください。",
    enabled: true,
  },
];
