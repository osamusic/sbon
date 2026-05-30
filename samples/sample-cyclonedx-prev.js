// sample-cyclonedx.js（新バージョン）に対する「旧バージョン」を表すサンプル。
// 差分: openssl更新(優先度上昇)、zlib更新、curl削除、linux-kernel追加、busyboxは変更なし。
window.SBON_SAMPLE_PREV = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  components: [
    {
      type: "library",
      name: "openssl",
      version: "3.0.13",
      bomRef: "pkg:generic/openssl@3.0.13",
      licenses: [{ license: { id: "Apache-2.0" } }],
      purl: "pkg:generic/openssl@3.0.13",
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
      version: "1.2.11",
      bomRef: "pkg:generic/zlib@1.2.11",
      licenses: [{ license: { id: "Zlib" } }],
      purl: "pkg:generic/zlib@1.2.11",
    },
    {
      type: "library",
      name: "curl",
      version: "7.80.0",
      bomRef: "pkg:generic/curl@7.80.0",
      licenses: [{ license: { id: "curl" } }],
      purl: "pkg:generic/curl@7.80.0",
    },
  ],
};
