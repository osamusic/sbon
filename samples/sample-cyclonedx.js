window.SBON_SAMPLE_SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  components: [
    {
      type: "library",
      name: "openssl",
      version: "1.1.1w",
      bomRef: "pkg:generic/openssl@1.1.1w",
      licenses: [{ license: { id: "Apache-2.0" } }],
      purl: "pkg:generic/openssl@1.1.1w",
      supplier: { name: "OpenSSL Project" },
      cpe: "cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*",
      externalReferences: [
        { type: "website", url: "https://www.openssl.org/" },
        { type: "vcs", url: "https://github.com/openssl/openssl" },
      ],
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
      version: "1.3.1",
      bomRef: "pkg:generic/zlib@1.3.1",
      licenses: [{ license: { id: "Zlib" } }],
    },
    {
      type: "operating-system",
      name: "linux-kernel",
      version: "5.4.268",
      bomRef: "pkg:generic/linux-kernel@5.4.268",
      licenses: [{ license: { id: "GPL-2.0-only" } }],
    },
  ],
  vulnerabilities: [
    {
      id: "CVE-2023-0286",
      ratings: [{ severity: "high", score: 7.4 }],
      affects: [{ ref: "pkg:generic/openssl@1.1.1w" }],
      description: "OpenSSL X.400 address type confusion vulnerability.",
    },
    {
      id: "CVE-2021-42374",
      ratings: [{ severity: "medium", score: 5.5 }],
      affects: [{ ref: "pkg:generic/busybox@1.31.1" }],
      description: "BusyBox awk use-after-free vulnerability.",
    },
  ],
  dependencies: [
    {
      ref: "product-firmware",
      dependsOn: ["pkg:generic/openssl@1.1.1w", "pkg:generic/busybox@1.31.1"],
    },
    { ref: "pkg:generic/openssl@1.1.1w", dependsOn: ["pkg:generic/zlib@1.3.1"] },
    { ref: "pkg:generic/busybox@1.31.1", dependsOn: ["pkg:generic/linux-kernel@5.4.268"] },
  ],
};
