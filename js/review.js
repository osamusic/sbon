(function () {
  // レビュー状態（コンポーネントごとの確認ステータスと確認メモ）を保持する純粋ストア。
  // キーは呼び出し側が決める（UIではpurlベースの安定キーを使い、再読み込み後も突合できるようにする）。
  const STATUSES = ["unreviewed", "in-progress", "approved", "action-required"];
  const STATUS_LABELS = {
    unreviewed: "未確認",
    "in-progress": "確認中",
    approved: "承認",
    "action-required": "要対応",
  };

  function statusLabel(status) {
    return STATUS_LABELS[status] || STATUS_LABELS.unreviewed;
  }

  function normalizeStatus(status) {
    return STATUSES.includes(status) ? status : "unreviewed";
  }

  function createReviewStore() {
    const entries = new Map();

    function get(key) {
      return entries.get(key) || { status: "unreviewed", note: "" };
    }

    function commit(key, entry) {
      // 既定値（未確認・メモなし）は保存しない。差分・出力を最小限に保つ。
      if (entry.status === "unreviewed" && !entry.note) {
        entries.delete(key);
      } else {
        entries.set(key, { status: entry.status, note: entry.note });
      }
    }

    function setStatus(key, status) {
      const current = get(key);
      commit(key, { status: normalizeStatus(status), note: current.note });
    }

    function setNote(key, note) {
      const current = get(key);
      commit(key, { status: current.status, note: String(note || "") });
    }

    function summary() {
      const counts = { unreviewed: 0, "in-progress": 0, approved: 0, "action-required": 0, total: 0 };
      for (const entry of entries.values()) {
        counts[entry.status] = (counts[entry.status] || 0) + 1;
        counts.total += 1;
      }
      return counts;
    }

    function toJSON() {
      const reviews = {};
      for (const [key, entry] of entries) {
        reviews[key] = { status: entry.status, note: entry.note };
      }
      return { version: 1, savedAt: new Date().toISOString(), reviews };
    }

    function loadJSON(data) {
      entries.clear();
      const reviews = data && typeof data === "object" ? data.reviews : null;
      if (!reviews || typeof reviews !== "object") {
        throw new Error("レビューファイルの形式が正しくありません（reviews がありません）。");
      }
      for (const [key, value] of Object.entries(reviews)) {
        if (!value || typeof value !== "object") continue;
        commit(key, { status: normalizeStatus(value.status), note: String(value.note || "") });
      }
    }

    function clear() {
      entries.clear();
    }

    function size() {
      return entries.size;
    }

    return { get, setStatus, setNote, summary, toJSON, loadJSON, clear, size };
  }

  window.SBON_REVIEW = {
    createReviewStore,
    statusLabel,
    STATUSES,
    STATUS_LABELS,
  };
})();
