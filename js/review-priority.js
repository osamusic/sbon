(function () {
  function enrichComponent(component) {
    const match = matchPackage(component);
    const knowledge = buildKnowledge(match);
    const findings = buildFindings(component, match, knowledge);
    const reviewPriority = scoreReviewPriority(component, findings);

    return {
      ...component,
      packageId: match.packageId,
      matchMethod: match.method,
      matchValue: match.value,
      matchConfidence: match.confidence,
      category: knowledge.category,
      categoryLabel: knowledge.label,
      componentType: knowledge.componentType,
      componentTypeLabel: knowledge.componentTypeLabel,
      explanation: knowledge.explanation,
      findings,
      reviewPriority,
    };
  }

  function matchPackage(component) {
    const knowledgeBase = window.SBON_KNOWLEDGE_BASE;
    const purlName = extractPurlName(component.purl);
    // A component may declare several CPEs (vendor + distro-package variants);
    // match against every product, not just the first.
    const cpeList = component.cpes && component.cpes.length ? component.cpes : component.cpe ? [component.cpe] : [];
    const cpeProducts = cpeList.map(extractCpeProduct).filter(Boolean);
    const normalizedName = normalizeName(component.name);

    for (const identifier of knowledgeBase.packageIdentifiers) {
      if (
        identifier.identifierType === "purl-name" &&
        purlName &&
        normalizeName(identifier.value) === purlName
      ) {
        return {
          packageId: identifier.packageId,
          method: "purl-name",
          value: identifier.value,
          confidence: identifier.confidence,
        };
      }
    }

    for (const identifier of knowledgeBase.packageIdentifiers) {
      if (
        identifier.identifierType === "cpe-product" &&
        cpeProducts.includes(normalizeName(identifier.value))
      ) {
        return {
          packageId: identifier.packageId,
          method: "cpe-product",
          value: identifier.value,
          confidence: identifier.confidence,
        };
      }
    }

    for (const identifier of knowledgeBase.packageIdentifiers) {
      if (identifier.identifierType === "name" && normalizeName(identifier.value) === normalizedName) {
        return {
          packageId: identifier.packageId,
          method: "name",
          value: identifier.value,
          confidence: identifier.confidence,
        };
      }
    }

    for (const identifier of knowledgeBase.packageIdentifiers) {
      if (identifier.identifierType === "regex" && new RegExp(identifier.value, "i").test(component.name)) {
        return {
          packageId: identifier.packageId,
          method: "regex",
          value: identifier.value,
          confidence: identifier.confidence,
        };
      }
    }

    return {
      packageId: null,
      method: "none",
      value: "",
      confidence: "low",
    };
  }

  function buildKnowledge(match) {
    if (!match.packageId) {
      return {
        category: "unknown",
        label: "不明",
        componentType: "",
        componentTypeLabel: "",
        explanation:
          "公開情報や社内台帳で用途を確認してください。用途が不明なOSSは、保守責任と影響範囲が判断しにくい状態です。",
      };
    }

    const knowledgeBase = window.SBON_KNOWLEDGE_BASE;
    // Categories have two axes: perspective (review angle) and type (component
    // type). Untyped categories are treated as perspective for compatibility.
    const linked = knowledgeBase.packageCategories
      .filter((item) => item.packageId === match.packageId)
      .map((pc) => knowledgeBase.categories.find((c) => c.id === pc.categoryId))
      .filter(Boolean);
    const perspective = linked.find((c) => c.kind !== "type");
    const type = linked.find((c) => c.kind === "type");
    const entry = knowledgeBase.entriesJa.find((item) => item.packageId === match.packageId);

    // A per-package description is optional. When one is missing, fall back to the
    // category's own description (perspective first, then type) so a classified
    // component is still explained at category granularity rather than as unknown.
    const categoryFallback =
      perspective?.descriptionJa ||
      type?.descriptionJa ||
      "このコンポーネントの説明は知識ベースに登録されていません。";

    return {
      category: perspective?.id || "unknown",
      label: perspective?.labelJa || "不明",
      componentType: type?.id || "",
      componentTypeLabel: type?.labelJa || "",
      explanation: entry
        ? `${entry.summary}${entry.whyItMatters ? ` ${entry.whyItMatters}` : ""}`
        : categoryFallback,
    };
  }

  function buildFindings(component, match, knowledge) {
    const findings = [];
    if (component.vulnerabilities.some((item) => item.severity === "high" || item.severity === "critical")) {
      findings.push("高深刻度の脆弱性があります");
    }
    if (component.vulnerabilities.length > 0) {
      findings.push("既知の脆弱性があります");
    }
    findings.push(...applyReviewPriorityRules(component, match));
    if (component.licenses.length === 0 || component.licenses.includes("NOASSERTION")) {
      findings.push("ライセンス情報が未確認です");
    }
    if (knowledge.category === "unknown") {
      findings.push("用途メタデータが不足しています");
    }
    return findings;
  }

  function applyReviewPriorityRules(component, match) {
    if (!match.packageId) return [];

    return window.SBON_KNOWLEDGE_BASE.reviewPriorityRules
      .filter((rule) => rule.enabled && rule.packageId === match.packageId)
      .filter((rule) => matchesReviewPriorityRule(component, rule))
      .map((rule) => rule.findingJa);
  }

  function matchesReviewPriorityRule(component, rule) {
    if (rule.ruleType === "version-prefix") {
      const version = String(component.version || "");
      return rule.values.some((value) => version.startsWith(value));
    }
    return false;
  }

  function scoreReviewPriority(component, findings) {
    if (
      component.vulnerabilities.some((item) => item.severity === "critical" || item.severity === "high") ||
      findings.some((finding) => finding.includes("古い"))
    ) {
      return "high";
    }

    if (component.vulnerabilities.length > 0 || findings.length > 0) {
      return "medium";
    }

    return "low";
  }

  function normalizeSeverity(severity = "unknown") {
    const lowered = String(severity).toLowerCase();
    if (["critical", "high", "medium", "low"].includes(lowered)) return lowered;
    return "unknown";
  }

  function extractPurlName(purl) {
    const match = String(purl || "").match(/^pkg:[^/]+\/(?:[^/]+\/)?([^@?#]+)/);
    return match ? normalizeName(decodeURIComponent(match[1])) : "";
  }

  function extractCpeProduct(cpe) {
    const value = String(cpe || "");
    // CPE 2.3: cpe:2.3:a:vendor:product:version:...
    const cpe23 = value.match(/^cpe:2\.3:[aho*-]:[^:]*:([^:]+)/i);
    if (cpe23) return normalizeName(cpe23[1]);
    // CPE 2.2: cpe:/a:vendor:product:version
    const cpe22 = value.match(/^cpe:\/[aho]:[^:]*:([^:]+)/i);
    if (cpe22) return normalizeName(cpe22[1]);
    return "";
  }

  function normalizeName(name) {
    return String(name || "").trim().toLowerCase();
  }

  window.SBON_REVIEW_PRIORITY = {
    enrichComponent,
    matchPackage,
    normalizeSeverity,
    scoreReviewPriority,
    extractCpeProduct,
  };
})();
