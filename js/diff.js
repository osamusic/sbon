(function () {
  // before / after はいずれも parser.normalizeSbom の戻り値（components を持つ）。
  // before = 旧バージョン（比較基準）、after = 新バージョン（現在読み込み中のSBOM）。
  function diffSboms(before, after) {
    const beforeComponents = before?.components || [];
    const afterComponents = after?.components || [];
    const beforeMap = indexByKey(beforeComponents);
    const afterMap = indexByKey(afterComponents);
    const keys = new Set([...beforeMap.keys(), ...afterMap.keys()]);

    const entries = [];
    for (const key of keys) {
      entries.push(buildEntry(key, beforeMap.get(key) || null, afterMap.get(key) || null));
    }

    entries.sort(compareEntries);
    const dependencyChanges = diffDependencies(before, after, beforeComponents, afterComponents);
    return { entries, summary: summarize(entries), dependencyChanges };
  }

  function indexByKey(components) {
    const map = new Map();
    for (const component of components) {
      const key = componentKey(component);
      // 同じキーが複数ある場合は最初の1件を代表とする（重複は差分対象外）。
      if (!map.has(key)) map.set(key, component);
    }
    return map;
  }

  function componentKey(component) {
    const purl = String(component.purl || "");
    if (purl.startsWith("pkg:")) {
      return purl.split("@")[0].split("?")[0].toLowerCase();
    }
    if (component.packageId) return `pkgid:${component.packageId}`;
    return `name:${String(component.name || "").trim().toLowerCase()}`;
  }

  function buildEntry(key, before, after) {
    const representative = after || before;
    const beforeSnap = before ? snapshot(before) : null;
    const afterSnap = after ? snapshot(after) : null;
    const licenseChanged =
      !!beforeSnap && !!afterSnap && !sameLicenses(beforeSnap.licenses, afterSnap.licenses);
    const changeType = resolveChangeType(beforeSnap, afterSnap, licenseChanged);
    const priorityEscalated =
      !!before && !!after && reviewPriorityRank(after.reviewPriority) < reviewPriorityRank(before.reviewPriority);

    return {
      key,
      name: representative.name,
      component: representative,
      changeType,
      priorityEscalated,
      licenseChanged,
      before: beforeSnap,
      after: afterSnap,
    };
  }

  function resolveChangeType(before, after, licenseChanged) {
    if (!before) return "added";
    if (!after) return "removed";
    if (String(before.version) !== String(after.version)) return "changed";
    if (before.reviewPriority !== after.reviewPriority) return "changed";
    if (licenseChanged) return "changed";
    return "unchanged";
  }

  function snapshot(component) {
    return {
      version: component.version,
      reviewPriority: component.reviewPriority,
      licenses: normalizeLicenses(component.licenses),
    };
  }

  function normalizeLicenses(licenses) {
    return (Array.isArray(licenses) ? licenses : [])
      .map((value) => String(value).trim())
      .filter(Boolean)
      .sort();
  }

  function sameLicenses(a, b) {
    if (a.length !== b.length) return false;
    return a.every((value, index) => value === b[index]);
  }

  function summarize(entries) {
    const summary = { added: 0, removed: 0, changed: 0, unchanged: 0, escalated: 0, total: entries.length };
    for (const entry of entries) {
      summary[entry.changeType] += 1;
      if (entry.priorityEscalated) summary.escalated += 1;
    }
    return summary;
  }

  function compareEntries(a, b) {
    // 優先度上昇 → added → removed → changed → unchanged の順で並べ、確認すべき順に表示する。
    return changeRank(a) - changeRank(b) || String(a.name).localeCompare(String(b.name), "ja");
  }

  function changeRank(entry) {
    if (entry.priorityEscalated) return 0;
    return { added: 1, removed: 2, changed: 3, unchanged: 4 }[entry.changeType] ?? 9;
  }

  function reviewPriorityRank(reviewPriority) {
    return { high: 0, medium: 1, low: 2 }[reviewPriority] ?? 9;
  }

  // 依存関係（ref→依存先refの配列のMap）を、コンポーネントキー単位の有向エッジに正規化して突合する。
  function diffDependencies(before, after, beforeComponents, afterComponents) {
    const beforeEdges = edgeMap(before?.dependencies, beforeComponents);
    const afterEdges = edgeMap(after?.dependencies, afterComponents);

    const added = [];
    const removed = [];
    for (const [id, edge] of afterEdges) {
      if (!beforeEdges.has(id)) added.push(edge);
    }
    for (const [id, edge] of beforeEdges) {
      if (!afterEdges.has(id)) removed.push(edge);
    }
    added.sort(compareEdge);
    removed.sort(compareEdge);
    return { added, removed };
  }

  function edgeMap(dependencies, components) {
    const edges = new Map();
    if (!dependencies || typeof dependencies.forEach !== "function") return edges;

    const resolver = buildRefResolver(components);
    dependencies.forEach((targets, source) => {
      const from = resolver(source);
      for (const target of targets || []) {
        const to = resolver(target);
        const id = `${from.key}=>${to.key}`;
        if (!edges.has(id)) edges.set(id, { from: from.name, to: to.name });
      }
    });
    return edges;
  }

  function buildRefResolver(components) {
    const byRef = new Map();
    for (const component of components || []) {
      if (component.id) byRef.set(String(component.id), component);
      if (component.purl) byRef.set(String(component.purl), component);
    }
    return function resolve(ref) {
      const component = byRef.get(String(ref));
      if (component) {
        return { key: componentKey(component), name: `${component.name} ${component.version}` };
      }
      return { key: `ref:${String(ref).toLowerCase()}`, name: String(ref) };
    };
  }

  function compareEdge(a, b) {
    return String(a.from).localeCompare(String(b.from), "ja") || String(a.to).localeCompare(String(b.to), "ja");
  }

  const PRIORITY_LABELS = { high: "高", medium: "中", low: "低" };

  // diffSboms の結果から、リリースレビュー向けの日本語要約を生成する。
  // 返り値: { headline, points: [{ level: "high"|"info", text }] }
  function buildReleaseSummary(diff) {
    const entries = diff?.entries || [];
    const summary = diff?.summary || { added: 0, removed: 0, changed: 0, unchanged: 0 };
    const dependencyChanges = diff?.dependencyChanges || { added: [], removed: [] };

    const headline = `前回SBOMと比べて、追加${summary.added}件・削除${summary.removed}件・更新${summary.changed}件の変更があります（変更なし${summary.unchanged}件）。`;
    const points = [];

    const escalated = entries.filter((entry) => entry.priorityEscalated);
    if (escalated.length) {
      const names = nameList(
        escalated.map(
          (entry) =>
            `${entry.name}（${priorityLabel(entry.before?.reviewPriority)}→${priorityLabel(entry.after?.reviewPriority)}）`,
        ),
      );
      points.push({
        level: "high",
        text: `確認優先度が上がった項目が${escalated.length}件あります: ${names}。優先的に確認してください。`,
      });
    }

    const licenseChanged = entries.filter((entry) => entry.licenseChanged);
    if (licenseChanged.length) {
      points.push({
        level: "high",
        text: `ライセンスが変更された項目が${licenseChanged.length}件あります: ${nameList(licenseChanged.map((entry) => entry.name))}。利用条件を再確認してください。`,
      });
    }

    const added = entries.filter((entry) => entry.changeType === "added");
    if (added.length) {
      points.push({
        level: "info",
        text: `新規に追加されたコンポーネントが${added.length}件あります: ${nameList(added.map((entry) => `${entry.name} ${entry.after?.version || ""}`.trim()))}。用途と来歴を確認してください。`,
      });
    }

    const removed = entries.filter((entry) => entry.changeType === "removed");
    if (removed.length) {
      points.push({
        level: "info",
        text: `削除されたコンポーネントが${removed.length}件あります: ${nameList(removed.map((entry) => `${entry.name} ${entry.before?.version || ""}`.trim()))}。依存先への影響を確認してください。`,
      });
    }

    const versionUpdated = entries.filter(
      (entry) => entry.changeType === "changed" && !entry.priorityEscalated && !entry.licenseChanged,
    );
    if (versionUpdated.length) {
      points.push({
        level: "info",
        text: `バージョンが更新された項目が${versionUpdated.length}件あります: ${nameList(versionUpdated.map((entry) => entry.name))}。`,
      });
    }

    if (dependencyChanges.added.length || dependencyChanges.removed.length) {
      points.push({
        level: "info",
        text: `依存関係の変化があります（依存先の追加${dependencyChanges.added.length}件 / 削除${dependencyChanges.removed.length}件）。`,
      });
    }

    if (!points.length) {
      points.push({ level: "info", text: "確認が必要な大きな変更は検出されませんでした。" });
    }

    return { headline, points };
  }

  function priorityLabel(reviewPriority) {
    return PRIORITY_LABELS[reviewPriority] || "不明";
  }

  function nameList(names, max = 5) {
    if (names.length <= max) return names.join("、");
    return `${names.slice(0, max).join("、")} ほか${names.length - max}件`;
  }

  window.SBON_DIFF = {
    diffSboms,
    componentKey,
    buildReleaseSummary,
  };
})();
