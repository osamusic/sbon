window.SBON_SAMPLE_SPDX = {
  spdxVersion: "SPDX-2.3",
  dataLicense: "CC0-1.0",
  SPDXID: "SPDXRef-DOCUMENT",
  name: "example-device-firmware",
  packages: [
    {
      SPDXID: "SPDXRef-Package-openssl",
      name: "openssl",
      versionInfo: "3.0.13",
      supplier: "Organization: OpenSSL Project",
      originator: "Organization: OpenSSL Project",
      homepage: "https://www.openssl.org/",
      downloadLocation: "https://www.openssl.org/source/openssl-3.0.13.tar.gz",
      licenseConcluded: "Apache-2.0",
      licenseDeclared: "Apache-2.0",
      copyrightText: "Copyright (c) 1998-2024 The OpenSSL Project Authors",
      description: "暗号化と証明書検証を提供するTLSライブラリ。",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: "pkg:generic/openssl@3.0.13",
        },
        {
          referenceCategory: "SECURITY",
          referenceType: "cpe23Type",
          referenceLocator: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
        },
      ],
    },
    {
      SPDXID: "SPDXRef-Package-glibc",
      name: "glibc",
      versionInfo: "2.36",
      supplier: "Organization: GNU Project",
      licenseConcluded: "LGPL-2.1-or-later",
      copyrightText: "NOASSERTION",
      externalRefs: [
        {
          referenceCategory: "SECURITY",
          referenceType: "cpe23Type",
          referenceLocator: "cpe:2.3:a:gnu:glibc:2.36:*:*:*:*:*:*:*",
        },
      ],
    },
    {
      SPDXID: "SPDXRef-Package-curl",
      name: "curl",
      versionInfo: "8.7.1",
      supplier: "Person: Daniel Stenberg",
      licenseConcluded: "curl",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: "pkg:generic/curl@8.7.1",
        },
      ],
    },
    {
      SPDXID: "SPDXRef-Package-internal-tool",
      name: "internal-config-tool",
      versionInfo: "0.4.2",
      licenseDeclared: "NOASSERTION",
      copyrightText: "NOASSERTION",
    },
  ],
  relationships: [
    {
      spdxElementId: "SPDXRef-DOCUMENT",
      relationshipType: "DESCRIBES",
      relatedSpdxElement: "SPDXRef-Package-openssl",
    },
    {
      spdxElementId: "SPDXRef-Package-openssl",
      relationshipType: "DEPENDS_ON",
      relatedSpdxElement: "SPDXRef-Package-glibc",
    },
    {
      spdxElementId: "SPDXRef-Package-curl",
      relationshipType: "DEPENDS_ON",
      relatedSpdxElement: "SPDXRef-Package-openssl",
    },
    {
      spdxElementId: "SPDXRef-Package-glibc",
      relationshipType: "DEPENDENCY_OF",
      relatedSpdxElement: "SPDXRef-Package-internal-tool",
    },
  ],
};
