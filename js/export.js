(function () {
  function exportCsv(components) {
    const csv = buildCsv(components);
    const blob = new Blob([`\ufeff${csv}`], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `sbon-review-${todayString()}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  }

  function buildCsv(components) {
    const headers = [
      "component_id",
      "name",
      "version",
      "type",
      "purl",
      "cpe",
      "supplier",
      "publisher",
      "copyright",
      "review_priority",
      "category",
      "package_id",
      "match_method",
      "match_value",
      "match_confidence",
      "licenses",
      "vulnerability_ids",
      "vulnerability_severities",
      "findings",
      "explanation_ja",
    ];
    const rows = components.map((component) => [
      component.id,
      component.name,
      component.version,
      component.type,
      component.purl,
      component.cpe || "",
      component.supplier || "",
      component.publisher || "",
      component.copyright || "",
      reviewPriorityLabel(component.reviewPriority),
      component.categoryLabel,
      component.packageId || "",
      component.matchMethod || "",
      component.matchValue || "",
      component.matchConfidence || "",
      component.licenses.join("; "),
      component.vulnerabilities.map((item) => item.id).join("; "),
      component.vulnerabilities.map((item) => severityLabel(item.severity)).join("; "),
      component.findings.join("; "),
      component.explanation,
    ]);
    return [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
  }

  function exportDiffCsv(entries) {
    const csv = buildDiffCsv(entries);
    const blob = new Blob([`\ufeff${csv}`], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `sbon-diff-${todayString()}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  }

  function buildDiffCsv(entries) {
    const headers = [
      "name",
      "change",
      "priority_escalated",
      "license_changed",
      "version_before",
      "version_after",
      "review_priority_before",
      "review_priority_after",
      "licenses_before",
      "licenses_after",
    ];
    const rows = entries.map((entry) => [
      entry.name,
      diffChangeLabel(entry.changeType),
      entry.priorityEscalated ? "はい" : "",
      entry.licenseChanged ? "はい" : "",
      entry.before ? entry.before.version : "",
      entry.after ? entry.after.version : "",
      entry.before ? reviewPriorityLabel(entry.before.reviewPriority) : "",
      entry.after ? reviewPriorityLabel(entry.after.reviewPriority) : "",
      entry.before ? (entry.before.licenses || []).join("; ") : "",
      entry.after ? (entry.after.licenses || []).join("; ") : "",
    ]);
    return [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
  }

  function diffChangeLabel(changeType) {
    return { added: "追加", removed: "削除", changed: "更新", unchanged: "変更なし" }[changeType] || changeType;
  }

  function exportReviewJson(data) {
    const json = JSON.stringify(data, null, 2);
    const blob = new Blob([json], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `sbon-review-result-${todayString()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  function csvCell(value) {
    return `"${String(value).replaceAll('"', '""')}"`;
  }

  function reviewPriorityLabel(reviewPriority) {
    return { high: "高", medium: "中", low: "低" }[reviewPriority] || "不明";
  }

  function severityLabel(severity) {
    return { critical: "緊急", high: "高", medium: "中", low: "低", unknown: "不明" }[severity] || "不明";
  }

  function todayString() {
    return new Date().toISOString().slice(0, 10);
  }

  window.SBON_EXPORT = {
    buildCsv,
    exportCsv,
    buildDiffCsv,
    exportDiffCsv,
    exportReviewJson,
  };
})();
