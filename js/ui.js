(function () {
  function createViewer({ parser, exporter, differ, review, sampleSbom, spdxSampleSbom, diffSampleSboms }) {
    const state = {
      format: "未読み込み",
      components: [],
      dependencies: new Map(),
      selectedId: null,
      sortKey: "priority",
      sortDirection: "asc",
      compareFormat: "",
      compareComponents: null,
      compareDependencies: null,
      reviews: review ? review.createReviewStore(() => persistReviews()) : null,
    };

    const REVIEW_STORAGE_KEY = "sbon.reviews.v1";

    function reviewStorage() {
      try {
        return typeof window !== "undefined" && window.localStorage ? window.localStorage : null;
      } catch (error) {
        return null; // プライベートモード等で localStorage が例外になる場合に備える。
      }
    }

    function persistReviews() {
      const storage = reviewStorage();
      if (!storage || !state.reviews) return;
      try {
        storage.setItem(REVIEW_STORAGE_KEY, JSON.stringify(state.reviews.toJSON()));
      } catch (error) {
        /* 保存に失敗しても操作は継続する。 */
      }
    }

    function restoreReviews() {
      const storage = reviewStorage();
      if (!storage || !state.reviews) return;
      let raw;
      try {
        raw = storage.getItem(REVIEW_STORAGE_KEY);
      } catch (error) {
        return;
      }
      if (!raw) return;
      try {
        state.reviews.loadJSON(JSON.parse(raw));
      } catch (error) {
        /* 壊れた保存データは無視する。 */
      }
    }

    function reviewKey(component) {
      if (differ && differ.componentKey) return differ.componentKey(component);
      return component.id;
    }

    const elements = {
      fileInput: document.querySelector("#fileInput"),
      dropzone: document.querySelector("#dropzone"),
      loadStatus: document.querySelector("#loadStatus"),
      loadSampleButton: document.querySelector("#loadSampleButton"),
      loadSpdxSampleButton: document.querySelector("#loadSpdxSampleButton"),
      trySampleButton: document.querySelector("#trySampleButton"),
      trySpdxSampleButton: document.querySelector("#trySpdxSampleButton"),
      compareFileInput: document.querySelector("#compareFileInput"),
      loadCompareButton: document.querySelector("#loadCompareButton"),
      loadDiffSampleButton: document.querySelector("#loadDiffSampleButton"),
      clearCompareButton: document.querySelector("#clearCompareButton"),
      diffSection: document.querySelector("#diffSection"),
      diffFormats: document.querySelector("#diffFormats"),
      diffSummary: document.querySelector("#diffSummary"),
      diffReleaseSummary: document.querySelector("#diffReleaseSummary"),
      diffRows: document.querySelector("#diffRows"),
      diffDependencies: document.querySelector("#diffDependencies"),
      diffCsvButton: document.querySelector("#diffCsvButton"),
      printButton: document.querySelector("#printButton"),
      csvButton: document.querySelector("#csvButton"),
      reportScope: document.querySelector("#reportScope"),
      printReport: document.querySelector("#printReport"),
      saveReviewButton: document.querySelector("#saveReviewButton"),
      loadReviewButton: document.querySelector("#loadReviewButton"),
      reviewFileInput: document.querySelector("#reviewFileInput"),
      reviewSummary: document.querySelector("#reviewSummary"),
      reviewAlert: document.querySelector("#reviewAlert"),
      searchInput: document.querySelector("#searchInput"),
      priorityFilter: document.querySelector("#priorityFilter"),
      categoryFilter: document.querySelector("#categoryFilter"),
      resetFiltersButton: document.querySelector("#resetFiltersButton"),
      totalComponents: document.querySelector("#totalComponents"),
      highPriorityCount: document.querySelector("#highPriorityCount"),
      mediumPriorityCount: document.querySelector("#mediumPriorityCount"),
      vulnerabilityCount: document.querySelector("#vulnerabilityCount"),
      executiveSummary: document.querySelector("#executiveSummary"),
      reportDate: document.querySelector("#reportDate"),
      reportFormat: document.querySelector("#reportFormat"),
      reportSummary: document.querySelector("#reportSummary"),
      reportRows: document.querySelector("#reportRows"),
      reportDetails: document.querySelector("#reportDetails"),
      componentRows: document.querySelector("#componentRows"),
      componentCount: document.querySelector("#componentCount"),
      emptyRowTemplate: document.querySelector("#emptyRowTemplate"),
      detailView: document.querySelector("#detailView"),
      treeView: document.querySelector("#treeView"),
      formatLabel: document.querySelector("#formatLabel"),
      sortButtons: document.querySelectorAll(".sort-button"),
      tabs: document.querySelectorAll(".tab"),
    };

    function start() {
      restoreReviews();
      bindEvents();
      applyReportScope();
      render();
    }

    function applyReportScope() {
      if (!elements.printReport || !elements.reportScope) return;
      elements.printReport.dataset.scope = elements.reportScope.value || "both";
    }

    function bindEvents() {
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

      elements.loadSampleButton.addEventListener("click", () => loadSbom(sampleSbom, "CycloneDXサンプル"));
      if (elements.trySampleButton) {
        elements.trySampleButton.addEventListener("click", () => loadSbom(sampleSbom, "CycloneDXサンプル"));
      }
      if (spdxSampleSbom) {
        elements.loadSpdxSampleButton.addEventListener("click", () => loadSbom(spdxSampleSbom, "SPDXサンプル"));
        if (elements.trySpdxSampleButton) {
          elements.trySpdxSampleButton.addEventListener("click", () => loadSbom(spdxSampleSbom, "SPDXサンプル"));
        }
      }

      elements.loadCompareButton.addEventListener("click", () => elements.compareFileInput.click());
      elements.compareFileInput.addEventListener("change", (event) => {
        const file = event.target.files?.[0];
        if (file) loadCompareFile(file);
      });
      elements.clearCompareButton.addEventListener("click", clearCompare);
      if (elements.diffCsvButton) {
        elements.diffCsvButton.addEventListener("click", () => {
          if (state.compareComponents) exporter.exportDiffCsv(computeDiff().entries);
        });
      }
      if (diffSampleSboms) {
        elements.loadDiffSampleButton.addEventListener("click", loadDiffSample);
      }
      elements.printButton.addEventListener("click", () => window.print());
      if (elements.reportScope) {
        elements.reportScope.addEventListener("change", applyReportScope);
      }
      elements.csvButton.addEventListener("click", () => exporter.exportCsv(state.components));
      if (state.reviews && elements.saveReviewButton) {
        elements.saveReviewButton.addEventListener("click", () => {
          exporter.exportReviewJson(state.reviews.toJSON());
        });
      }
      if (state.reviews && elements.loadReviewButton && elements.reviewFileInput) {
        elements.loadReviewButton.addEventListener("click", () => elements.reviewFileInput.click());
        elements.reviewFileInput.addEventListener("change", (event) => {
          const file = event.target.files?.[0];
          if (file) loadReviewFile(file);
        });
      }
      elements.searchInput.addEventListener("input", render);
      elements.priorityFilter.addEventListener("change", render);
      elements.categoryFilter.addEventListener("change", render);
      elements.resetFiltersButton.addEventListener("click", resetFilters);

      for (const button of elements.sortButtons) {
        button.addEventListener("click", () => {
          updateSort(button.dataset.sort);
        });
      }

      for (const tab of elements.tabs) {
        tab.addEventListener("click", () => {
          document.querySelectorAll(".tab, .tab-page").forEach((item) => item.classList.remove("is-active"));
          tab.classList.add("is-active");
          document.querySelector(`#${tab.dataset.tab}View`).classList.add("is-active");
        });
      }
    }

    async function loadFile(file) {
      let json;
      try {
        json = JSON.parse(await file.text());
      } catch (error) {
        showLoadStatus(`「${file.name}」を読み込めませんでした。正しいJSONファイルか確認してください。`, "error");
        return;
      }
      loadSbom(json, file.name);
    }

    function loadSbom(json, sourceName) {
      let normalized;
      try {
        normalized = parser.normalizeSbom(json);
      } catch (error) {
        showLoadStatus(error.message || "SBOMの読み込みに失敗しました。", "error");
        return;
      }

      state.format = normalized.format;
      state.components = normalized.components;
      state.dependencies = normalized.dependencies;
      state.selectedId = state.components[0]?.id || null;
      showLoadStatus(
        `${sourceName ? `「${sourceName}」を` : ""}${normalized.format} として読み込みました。コンポーネント${normalized.components.length}件。`,
        normalized.components.length === 0 ? "warning" : "success",
      );
      render();
    }

    function showLoadStatus(message, kind) {
      const status = elements.loadStatus;
      if (!status) return;
      status.textContent = message;
      status.hidden = false;
      status.dataset.kind = kind;
    }

    async function loadCompareFile(file) {
      let json;
      try {
        json = JSON.parse(await file.text());
      } catch (error) {
        showLoadStatus(`比較対象「${file.name}」を読み込めませんでした。正しいJSONか確認してください。`, "error");
        return;
      }
      loadCompareSbom(json, file.name);
    }

    function loadCompareSbom(json, sourceName) {
      let normalized;
      try {
        normalized = parser.normalizeSbom(json);
      } catch (error) {
        showLoadStatus(`比較対象の読み込みに失敗しました: ${error.message}`, "error");
        return;
      }

      state.compareFormat = normalized.format;
      state.compareComponents = normalized.components;
      state.compareDependencies = normalized.dependencies;
      showLoadStatus(
        `${sourceName ? `「${sourceName}」を` : ""}比較対象（旧）として読み込みました。差分を下部に表示します。`,
        "success",
      );
      render();
    }

    function loadDiffSample() {
      loadSbom(diffSampleSboms.after, "CycloneDXサンプル（新）");
      loadCompareSbom(diffSampleSboms.before, "CycloneDXサンプル（旧）");
    }

    async function loadReviewFile(file) {
      let data;
      try {
        data = JSON.parse(await file.text());
      } catch (error) {
        showLoadStatus(`レビュー結果「${file.name}」を読み込めませんでした。正しいJSONか確認してください。`, "error");
        return;
      }
      try {
        state.reviews.loadJSON(data);
      } catch (error) {
        showLoadStatus(error.message || "レビュー結果の読み込みに失敗しました。", "error");
        return;
      }
      showLoadStatus(`レビュー結果「${file.name}」を読み込みました。`, "success");
      render();
    }

    function clearCompare() {
      state.compareFormat = "";
      state.compareComponents = null;
      state.compareDependencies = null;
      render();
    }

    function render() {
      const filtered = getFilteredComponents();
      const sorted = sortComponents(filtered);
      renderSummary();
      renderPrintReport();
      renderRows(sorted);
      renderListMeta(sorted.length);
      renderDetail(sorted);
      renderTree();
      renderDiff();
    }

    function computeDiff() {
      return differ.diffSboms(
        { components: state.compareComponents, dependencies: state.compareDependencies },
        { components: state.components, dependencies: state.dependencies },
      );
    }

    function renderDiff() {
      if (!elements.diffSection) return;

      if (!differ || !state.compareComponents) {
        elements.diffSection.hidden = true;
        return;
      }

      const diff = computeDiff();
      const { entries, summary, dependencyChanges } = diff;
      const changes = entries.filter((entry) => entry.changeType !== "unchanged");

      elements.diffSection.hidden = false;
      elements.diffFormats.textContent = `旧: ${state.compareFormat} ／ 新: ${state.format}`;
      elements.diffSummary.textContent = `追加${summary.added}件、削除${summary.removed}件、更新${summary.changed}件、確認優先度の上昇${summary.escalated}件（変更なし${summary.unchanged}件）。`;
      renderReleaseSummary(diff);
      elements.diffRows.textContent = "";

      if (changes.length === 0) {
        const row = document.createElement("tr");
        row.innerHTML = '<td colspan="5" class="empty-cell">2つのSBOM間に変更されたコンポーネントはありません。</td>';
        elements.diffRows.append(row);
      } else {
        for (const entry of changes) {
          const row = document.createElement("tr");
          row.className = entry.priorityEscalated ? "diff-escalated" : "";
          row.innerHTML = `
            <td><span class="pkg-name">${escapeHtml(entry.name)}</span></td>
            <td>${diffChangeBadge(entry)}</td>
            <td>${escapeHtml(diffVersionText(entry))}</td>
            <td>${diffPriorityText(entry)}</td>
            <td>${diffLicenseText(entry)}</td>
          `;
          elements.diffRows.append(row);
        }
      }

      const graph = differ.diffDependencyGraph
        ? differ.diffDependencyGraph(
            { components: state.compareComponents, dependencies: state.compareDependencies },
            { components: state.components, dependencies: state.dependencies },
          )
        : null;
      renderDependencyDiff(dependencyChanges, graph);
    }

    function renderReleaseSummary(diff) {
      if (!elements.diffReleaseSummary) return;
      if (!differ.buildReleaseSummary) {
        elements.diffReleaseSummary.innerHTML = "";
        return;
      }

      const { headline, points } = differ.buildReleaseSummary(diff);
      const items = points
        .map(
          (point) =>
            `<li class="release-point ${point.level}">${escapeHtml(point.text)}</li>`,
        )
        .join("");
      elements.diffReleaseSummary.innerHTML = `
        <h3 class="release-summary-title">リリースレビュー向け要約</h3>
        <p class="release-headline">${escapeHtml(headline)}</p>
        <ul class="release-points">${items}</ul>
      `;
    }

    function renderDependencyDiff(dependencyChanges, graph) {
      if (!elements.diffDependencies) return;

      const changes = dependencyChanges || { added: [], removed: [] };
      if (!changes.added.length && !changes.removed.length) {
        elements.diffDependencies.innerHTML =
          '<p class="diff-dep-empty">依存関係（依存先）の追加・削除は検出されませんでした。</p>';
        return;
      }

      const tree = graph && graph.roots.length ? renderDepDiffTree(graph) : "";
      elements.diffDependencies.innerHTML = `
        <h3 class="diff-dep-heading">依存関係の差分</h3>
        <p class="diff-dep-title">依存先の追加${changes.added.length}件 / 削除${changes.removed.length}件。ツリー内で <span class="diff-badge added">追加</span> / <span class="diff-badge removed">削除</span> を強調します。</p>
        ${tree}
      `;
    }

    function renderDepDiffTree(graph) {
      const items = graph.roots.map((root) => renderDepDiffNode(graph, root, new Set([root]))).join("");
      return `<ul class="tree-list dep-diff-tree">${items}</ul>`;
    }

    function renderDepDiffNode(graph, key, seen, status) {
      const name = graph.nodes.get(key) || key;
      const badge = status && status !== "unchanged" ? depStatusBadge(status) : "";
      const children = graph.adjacency.get(key) || [];
      const childItems = children
        .map((child) => {
          if (seen.has(child.toKey)) {
            return `<li><span class="tree-node">${escapeHtml(graph.nodes.get(child.toKey) || child.toName)}</span> ${depStatusBadge(child.status)} <span class="tree-ref">循環参照</span></li>`;
          }
          const nextSeen = new Set(seen);
          nextSeen.add(child.toKey);
          return renderDepDiffNode(graph, child.toKey, nextSeen, child.status);
        })
        .join("");
      return `
        <li>
          <span class="tree-node">${escapeHtml(name)}</span> ${badge}
          ${childItems ? `<ul class="tree-list">${childItems}</ul>` : ""}
        </li>
      `;
    }

    function renderSummary() {
      const high = state.components.filter((component) => component.reviewPriority === "high").length;
      const medium = state.components.filter((component) => component.reviewPriority === "medium").length;
      const vulnerabilityCount = state.components.reduce(
        (total, component) => total + component.vulnerabilities.length,
        0,
      );

      elements.totalComponents.textContent = state.components.length;
      elements.highPriorityCount.textContent = high;
      elements.mediumPriorityCount.textContent = medium;
      elements.vulnerabilityCount.textContent = vulnerabilityCount;
      elements.formatLabel.textContent = state.format;

      const overall = high > 0 ? "高" : medium > 0 ? "中" : state.components.length > 0 ? "低" : "未評価";
      elements.executiveSummary.textContent =
        state.components.length === 0
          ? "SBOMを読み込むと、調達・品質保証・セキュリティ管理向けの確認ポイントを表示します。"
          : `このSBOMには${state.components.length}件のOSSコンポーネントが含まれます。最優先確認${high}件、要確認${medium}件、既知の脆弱性${vulnerabilityCount}件です。総合的な確認優先度は「${overall}」として扱い、暗号・ネットワーク・OS基盤の項目を優先確認してください。`;
    }

    function renderPrintReport() {
      const high = state.components.filter((component) => component.reviewPriority === "high").length;
      const medium = state.components.filter((component) => component.reviewPriority === "medium").length;
      const vulnerabilityCount = state.components.reduce(
        (total, component) => total + component.vulnerabilities.length,
        0,
      );
      const rows = state.components
        .filter((component) => component.reviewPriority !== "low")
        .sort(
          (a, b) =>
            reviewPriorityRank(a.reviewPriority) - reviewPriorityRank(b.reviewPriority) ||
            a.name.localeCompare(b.name),
        )
        .slice(0, 20);

      elements.reportFormat.textContent = state.format;
      elements.reportDate.textContent = new Date().toLocaleDateString("ja-JP");
      elements.reportSummary.textContent =
        state.components.length === 0
          ? "SBOMを読み込むと、印刷用の要約を表示します。"
          : `対象コンポーネントは${state.components.length}件です。最優先確認${high}件、要確認${medium}件、既知の脆弱性${vulnerabilityCount}件を確認しました。`;
      elements.reportRows.textContent = "";

      if (rows.length === 0) {
        const row = document.createElement("tr");
        row.innerHTML = '<td colspan="5" class="empty-cell">印刷対象の最優先確認・要確認コンポーネントはありません。</td>';
        elements.reportRows.append(row);
        renderReportDetails([]);
        return;
      }

      for (const component of rows) {
        const row = document.createElement("tr");
        row.innerHTML = `
          <td>${escapeHtml(component.name)}</td>
          <td>${escapeHtml(component.version)}</td>
          <td>${reviewPriorityLabel(component.reviewPriority)}</td>
          <td>${escapeHtml(component.categoryLabel)}</td>
          <td>${escapeHtml(component.findings[0] || "確認ポイントなし")}</td>
        `;
        elements.reportRows.append(row);
      }

      renderReportDetails(rows);
    }

    function renderReportDetails(rows) {
      if (!elements.reportDetails) return;

      if (rows.length === 0) {
        elements.reportDetails.innerHTML =
          '<p class="empty">詳細確認が必要なコンポーネントはありません。</p>';
        return;
      }

      elements.reportDetails.innerHTML = rows
        .map((component) => {
          const provenance = [component.supplier, component.publisher].filter(Boolean).join(" / ") || "未記載";
          const identifier = component.purl || component.cpe || component.id;
          const findings = component.findings.length
            ? `<ul class="plain-list">${component.findings.map((finding) => `<li>${escapeHtml(finding)}</li>`).join("")}</ul>`
            : "<p>主要な確認事項は検出されていません。</p>";
          const vulnerabilities = component.vulnerabilities.length
            ? `<ul class="plain-list">${component.vulnerabilities
                .map((item) => `<li>${escapeHtml(`${item.id} (${severityLabel(item.severity)}${item.score ? `, CVSS ${item.score}` : ""})`)}</li>`)
                .join("")}</ul>`
            : "<p>SBOM内に既知の脆弱性の記載はありません。</p>";
          const reviewEntry = state.reviews ? state.reviews.get(reviewKey(component)) : null;
          const reviewBlock =
            reviewEntry && (reviewEntry.status !== "unreviewed" || reviewEntry.note)
              ? `<p class="report-detail-label">レビュー状況</p>
                 <p>${escapeHtml(reviewStatusLabel(reviewEntry.status))}${reviewEntry.note ? ` ／ ${escapeHtml(reviewEntry.note)}` : ""}</p>`
              : "";

          return `
            <article class="report-detail">
              <div class="report-detail-head">
                <h4>${escapeHtml(component.name)} ${escapeHtml(component.version)}</h4>
                <span class="badge ${component.reviewPriority}">${reviewPriorityLabel(component.reviewPriority)}</span>
              </div>
              <p class="report-detail-meta">${escapeHtml(component.categoryLabel)} ／ ${escapeHtml(identifier)}</p>
              <p>${escapeHtml(component.explanation)}</p>
              <p class="report-detail-label">確認ポイント</p>
              ${findings}
              <p class="report-detail-label">提供元 / ライセンス</p>
              <p>${escapeHtml(provenance)} ／ ${escapeHtml(component.licenses.join(", ") || "未確認")}</p>
              ${reviewBlock}
              <p class="report-detail-label">脆弱性</p>
              ${vulnerabilities}
            </article>
          `;
        })
        .join("");
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
          <td><span class="badge ${component.reviewPriority}">${reviewPriorityLabel(component.reviewPriority)}</span></td>
          <td class="category">${escapeHtml(component.categoryLabel)}</td>
          <td>${escapeHtml(component.licenses.join(", ") || "未確認")}</td>
          <td>${component.vulnerabilities.length}</td>
          <td>${reviewStatusBadge(reviewStatusOf(component))}</td>
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

    function renderListMeta(visibleCount) {
      elements.componentCount.textContent = `${visibleCount} / ${state.components.length}件表示`;
      renderReviewSummary();
      renderReviewAlert();
      for (const button of elements.sortButtons) {
        const active = button.dataset.sort === state.sortKey;
        button.classList.toggle("is-active", active);
        button.dataset.direction = active ? state.sortDirection : "";
      }
    }

    function renderReviewSummary() {
      if (!elements.reviewSummary) return;
      if (!state.reviews || state.reviews.size() === 0) {
        elements.reviewSummary.textContent = "";
        return;
      }
      const summary = state.reviews.summary();
      const parts = [];
      if (summary["action-required"]) parts.push(`要対応${summary["action-required"]}`);
      if (summary.approved) parts.push(`承認${summary.approved}`);
      if (summary["in-progress"]) parts.push(`確認中${summary["in-progress"]}`);
      elements.reviewSummary.textContent = parts.length ? `レビュー: ${parts.join(" / ")}` : "";
    }

    function renderReviewAlert() {
      if (!elements.reviewAlert) return;
      if (!state.reviews) {
        elements.reviewAlert.hidden = true;
        return;
      }
      const pending = state.components.filter(
        (component) => component.reviewPriority === "high" && reviewStatusOf(component) === "unreviewed",
      ).length;
      if (pending === 0) {
        elements.reviewAlert.hidden = true;
        elements.reviewAlert.textContent = "";
        return;
      }
      elements.reviewAlert.hidden = false;
      elements.reviewAlert.textContent = `最優先確認の項目に未確認が${pending}件あります。確認ステータスを更新してレビューを完了してください。`;
    }

    function renderDetail(visibleComponents = state.components) {
      const component = state.components.find((item) => item.id === state.selectedId);
      if (!component) {
        const message = state.components.length
          ? "一覧からコンポーネントを選択してください。"
          : "SBOMを読み込むと、コンポーネントの詳細を表示します。";
        elements.detailView.innerHTML = `<p class="empty">${message}</p>`;
        return;
      }

      const isFilteredOut = !visibleComponents.some((item) => item.id === component.id);
      const filteredNotice = isFilteredOut
        ? '<p class="filtered-notice">この項目は現在の絞り込み条件では一覧に表示されていません。</p>'
        : "";

      elements.detailView.innerHTML = `
        ${filteredNotice}
        <div class="detail-title">
          <div>
            <h3>${escapeHtml(component.name)}</h3>
            <span class="pkg-id">${escapeHtml(component.purl || component.id)}</span>
          </div>
          <span class="badge ${component.reviewPriority}">${reviewPriorityLabel(component.reviewPriority)}</span>
        </div>
        <div class="detail-section">
          <h4>日本語説明</h4>
          <p>${escapeHtml(component.explanation)}</p>
        </div>
        <div class="detail-section">
          <h4>確認ポイント</h4>
          ${renderList(component.findings.length ? component.findings : ["現時点で主要な確認事項は検出されていません。"])}
        </div>
        ${renderReviewSection(component)}
        <div class="detail-section">
          <h4>知識ベース照合</h4>
          <p>${escapeHtml(matchSummary(component))}</p>
        </div>
        ${renderSupplierSection(component)}
        <div class="detail-section">
          <h4>ライセンス</h4>
          <p>${escapeHtml(component.licenses.join(", ") || "未確認")}</p>
        </div>
        <div class="detail-section">
          <h4>脆弱性</h4>
          ${renderVulnerabilities(component.vulnerabilities)}
        </div>
      `;

      bindReviewControls(component);
    }

    function renderReviewSection(component) {
      if (!state.reviews) return "";
      const entry = state.reviews.get(reviewKey(component));
      const options = review.STATUSES.map(
        (status) =>
          `<option value="${status}"${status === entry.status ? " selected" : ""}>${escapeHtml(review.statusLabel(status))}</option>`,
      ).join("");
      return `
        <div class="detail-section review-edit">
          <h4>レビュー</h4>
          <div class="review-controls">
            <label class="review-field">
              <span>確認ステータス</span>
              <select id="reviewStatusSelect" class="review-status-select">${options}</select>
            </label>
            <label class="review-field">
              <span>確認メモ</span>
              <textarea id="reviewNoteInput" class="review-note-input" rows="3" placeholder="確認した内容や指摘事項を記録できます。">${escapeHtml(entry.note)}</textarea>
            </label>
          </div>
        </div>
      `;
    }

    function bindReviewControls(component) {
      if (!state.reviews) return;
      const key = reviewKey(component);
      const select = document.querySelector("#reviewStatusSelect");
      if (select) {
        select.addEventListener("change", () => {
          state.reviews.setStatus(key, select.value);
          render();
        });
      }
      const note = document.querySelector("#reviewNoteInput");
      if (note) {
        // メモ入力中は詳細を作り直さない（フォーカスを失わないため）。状態のみ更新する。
        note.addEventListener("input", () => {
          state.reviews.setNote(key, note.value);
        });
      }
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
      const reviewPriority = elements.priorityFilter.value;
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
          (reviewPriority === "all" || component.reviewPriority === reviewPriority) &&
          (category === "all" || component.category === category)
        );
      });
    }

    function sortComponents(components) {
      return [...components].sort((a, b) => {
        const direction = state.sortDirection === "desc" ? -1 : 1;
        return compareComponents(a, b, state.sortKey) * direction || a.name.localeCompare(b.name);
      });
    }

    function compareComponents(a, b, sortKey) {
      if (sortKey === "priority") {
        return reviewPriorityRank(a.reviewPriority) - reviewPriorityRank(b.reviewPriority);
      }
      if (sortKey === "vulnerabilities") {
        return a.vulnerabilities.length - b.vulnerabilities.length;
      }
      if (sortKey === "category") {
        return a.categoryLabel.localeCompare(b.categoryLabel);
      }
      if (sortKey === "license") {
        return licenseText(a).localeCompare(licenseText(b));
      }
      if (sortKey === "version") {
        return String(a.version).localeCompare(String(b.version), "ja", { numeric: true });
      }
      if (sortKey === "review") {
        return reviewStatusRank(reviewStatusOf(a)) - reviewStatusRank(reviewStatusOf(b));
      }
      return a.name.localeCompare(b.name);
    }

    function updateSort(sortKey) {
      if (state.sortKey === sortKey) {
        state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
      } else {
        state.sortKey = sortKey;
        state.sortDirection = sortKey === "vulnerabilities" ? "desc" : "asc";
      }
      render();
    }

    function resetFilters() {
      elements.searchInput.value = "";
      elements.priorityFilter.value = "all";
      elements.categoryFilter.value = "all";
      render();
    }

    function licenseText(component) {
      return component.licenses.join(", ") || "未確認";
    }

    function reviewStatusOf(component) {
      if (!state.reviews) return "unreviewed";
      return state.reviews.get(reviewKey(component)).status;
    }

    function selectComponent(id) {
      state.selectedId = id;
      render();
    }

    function resolveName(ref) {
      const component = state.components.find((item) => item.id === ref || item.purl === ref);
      return component ? `${component.name} ${component.version}` : ref;
    }

    return {
      start,
      loadSbom,
    };
  }

  function reviewPriorityLabel(reviewPriority) {
    return { high: "高", medium: "中", low: "低" }[reviewPriority] || "不明";
  }

  function severityLabel(severity) {
    return { critical: "緊急", high: "高", medium: "中", low: "低", unknown: "不明" }[severity] || "不明";
  }

  function reviewStatusLabel(status) {
    return window.SBON_REVIEW ? window.SBON_REVIEW.statusLabel(status) : status;
  }

  function reviewStatusBadge(status) {
    return `<span class="review-badge ${status}">${escapeHtml(reviewStatusLabel(status))}</span>`;
  }

  function reviewStatusRank(status) {
    return { "action-required": 0, "in-progress": 1, unreviewed: 2, approved: 3 }[status] ?? 9;
  }

  function depStatusBadge(status) {
    const labels = { added: "追加", removed: "削除", unchanged: "" };
    if (!labels[status]) return "";
    return `<span class="diff-badge ${status}">${labels[status]}</span>`;
  }

  function diffChangeBadge(entry) {
    const labels = { added: "追加", removed: "削除", changed: "更新", unchanged: "変更なし" };
    const escalation = entry.priorityEscalated ? ' <span class="diff-escalation-mark">優先度上昇</span>' : "";
    return `<span class="diff-badge ${entry.changeType}">${labels[entry.changeType] || entry.changeType}</span>${escalation}`;
  }

  function diffVersionText(entry) {
    const before = entry.before ? entry.before.version : "—";
    const after = entry.after ? entry.after.version : "—";
    if (entry.changeType === "added") return `（新規） ${after}`;
    if (entry.changeType === "removed") return `${before} （削除）`;
    return `${before} → ${after}`;
  }

  function diffPriorityText(entry) {
    const before = entry.before ? reviewPriorityLabel(entry.before.reviewPriority) : "—";
    const after = entry.after ? reviewPriorityLabel(entry.after.reviewPriority) : "—";
    return `${escapeHtml(before)} → ${escapeHtml(after)}`;
  }

  function diffLicenseText(entry) {
    const before = licenseSnapshotText(entry.before);
    const after = licenseSnapshotText(entry.after);
    const text = before === after ? escapeHtml(after) : `${escapeHtml(before)} → ${escapeHtml(after)}`;
    return entry.licenseChanged ? `<span class="diff-license-changed">${text}</span>` : text;
  }

  function licenseSnapshotText(snapshot) {
    if (!snapshot) return "—";
    return (snapshot.licenses || []).join(", ") || "未確認";
  }

  function renderSupplierSection(component) {
    const rows = [
      ["提供元", component.supplier],
      ["発行元", component.publisher],
      ["CPE", component.cpe],
      ["著作権表示", component.copyright],
      ["SBOM内の説明", component.description],
    ].filter(([, value]) => value);

    const references = (component.references || []).filter((reference) => reference.url);
    if (references.length) {
      const links = references
        .map(
          (reference) =>
            `<a href="${escapeHtml(reference.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(reference.type)}</a>`,
        )
        .join("、");
      rows.push(["参照リンク", links, true]);
    }

    const body = rows.length
      ? `<dl class="detail-meta">${rows
          .map(([label, value, isHtml]) => `<div><dt>${label}</dt><dd>${isHtml ? value : escapeHtml(value)}</dd></div>`)
          .join("")}</dl>`
      : "<p>提供元・識別子情報はSBOMに記載されていません。</p>";

    return `
      <div class="detail-section">
        <h4>提供元・識別子</h4>
        ${body}
      </div>
    `;
  }

  function matchSummary(component) {
    if (!component.packageId) {
      return "知識ベースには未登録です。用途、保守責任、影響範囲を確認してください。";
    }

    return `package_id: ${component.packageId}, 照合方法: ${component.matchMethod}, 照合値: ${component.matchValue || "-"}, 信頼度: ${component.matchConfidence}`;
  }

  function reviewPriorityRank(reviewPriority) {
    return { high: 0, medium: 1, low: 2 }[reviewPriority] ?? 9;
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  window.SBON_UI = {
    createViewer,
  };
})();
