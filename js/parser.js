(function () {
  function normalizeSbom(sbom) {
    if (sbom === null || typeof sbom !== "object" || Array.isArray(sbom)) {
      throw new Error("SBOMはJSONオブジェクトである必要があります。配列や数値などは読み込めません。");
    }

    if (sbom.bomFormat === "CycloneDX" || sbom.specVersion || Array.isArray(sbom.components)) {
      return normalizeCycloneDx(sbom);
    }

    if (sbom.spdxVersion || Array.isArray(sbom.packages) || sbom.SPDXID) {
      return normalizeSpdx(sbom);
    }

    throw new Error(
      "CycloneDX JSON または SPDX JSON として認識できません。CycloneDXは bomFormat / specVersion / components、SPDXは spdxVersion / packages を含む必要があります。",
    );
  }

  function normalizeCycloneDx(sbom) {
    const vulnerabilities = collectCycloneDxVulnerabilities(sbom.vulnerabilities || []);
    const components = (sbom.components || []).map((component, index) => {
      const id = component.bomRef || component.purl || `${component.name || "unknown"}-${index}`;
      return window.SBON_REVIEW_PRIORITY.enrichComponent({
        id,
        name: component.name || "名称不明",
        version: component.version || "不明",
        type: component.type || "不明",
        licenses: parseCycloneDxLicenses(component.licenses),
        purl: component.purl || id,
        cpe: component.cpe || "",
        cpes: component.cpe ? [component.cpe] : [],
        supplier: component.supplier?.name || "",
        publisher: component.publisher || component.author || "",
        copyright: component.copyright || "",
        description: component.description || "",
        references: parseCycloneDxReferences(component.externalReferences),
        vulnerabilities: vulnerabilities.get(id) || vulnerabilities.get(component.purl) || [],
      });
    });

    return {
      format: `CycloneDX ${sbom.specVersion || ""}`.trim(),
      components,
      dependencies: new Map((sbom.dependencies || []).map((item) => [item.ref, item.dependsOn || []])),
    };
  }

  function collectCycloneDxVulnerabilities(sourceVulnerabilities) {
    const vulnerabilities = new Map();
    for (const vulnerability of sourceVulnerabilities) {
      const affectedRefs = (vulnerability.affects || []).map((item) => item.ref).filter(Boolean);
      for (const ref of affectedRefs) {
        const list = vulnerabilities.get(ref) || [];
        list.push({
          id: vulnerability.id || "Unknown CVE",
          severity: window.SBON_REVIEW_PRIORITY.normalizeSeverity(vulnerability.ratings?.[0]?.severity),
          score: vulnerability.ratings?.[0]?.score || "",
          description: vulnerability.description || "",
        });
        vulnerabilities.set(ref, list);
      }
    }
    return vulnerabilities;
  }

  function normalizeSpdx(sbom) {
    const packages = sbom.packages || [];
    const relationships = sbom.relationships || [];
    const dependencies = collectSpdxDependencies(relationships);
    const components = packages.map((pkg, index) =>
      window.SBON_REVIEW_PRIORITY.enrichComponent({
        id: pkg.SPDXID || `${pkg.name || "unknown"}-${index}`,
        name: pkg.name || "名称不明",
        version: pkg.versionInfo || "不明",
        type: "package",
        licenses: parseSpdxLicense(pkg),
        purl: findSpdxExternalRef(pkg, "purl") || "",
        // SPDX packages routinely declare several CPEs (vendor + distro-package
        // variants); keep them all so matching can try each, not just the first.
        cpe: collectSpdxExternalRefs(pkg, ["cpe23Type", "cpe22Type"])[0] || "",
        cpes: collectSpdxExternalRefs(pkg, ["cpe23Type", "cpe22Type"]),
        supplier: cleanSpdxActor(pkg.supplier),
        publisher: cleanSpdxActor(pkg.originator),
        copyright: pkg.copyrightText && pkg.copyrightText !== "NOASSERTION" ? pkg.copyrightText : "",
        description: pkg.description || pkg.summary || "",
        references: parseSpdxReferences(pkg),
        vulnerabilities: [],
      }),
    );

    return {
      format: sbom.spdxVersion || "SPDX",
      components,
      dependencies,
    };
  }

  function collectSpdxDependencies(relationships) {
    const dependencies = new Map();
    for (const relationship of relationships) {
      if (!["DEPENDS_ON", "DEPENDENCY_OF", "CONTAINS"].includes(relationship.relationshipType)) {
        continue;
      }

      const source = relationship.spdxElementId;
      const target = relationship.relatedSpdxElement;
      if (!source || !target) {
        continue;
      }

      if (relationship.relationshipType === "DEPENDENCY_OF") {
        appendDependency(dependencies, target, source);
      } else {
        appendDependency(dependencies, source, target);
      }
    }
    return dependencies;
  }

  function appendDependency(dependencies, source, target) {
    const list = dependencies.get(source) || [];
    list.push(target);
    dependencies.set(source, list);
  }

  function parseCycloneDxLicenses(licenses = []) {
    return (licenses || [])
      .map((item) => item.license?.id || item.license?.name || item.expression)
      .filter(Boolean)
      // NOASSERTION / NONE は「未確認」として扱うため、ライセンス一覧からは除外する。
      .filter((value) => !["noassertion", "none"].includes(String(value).trim().toLowerCase()));
  }

  function parseSpdxLicense(pkg) {
    const license = pkg.licenseConcluded || pkg.licenseDeclared;
    if (!license || ["noassertion", "none"].includes(String(license).trim().toLowerCase())) {
      return [];
    }
    return [license];
  }

  function parseCycloneDxReferences(references = []) {
    return (references || [])
      .map((reference) => ({
        type: reference.type || "other",
        url: reference.url || "",
      }))
      .filter((reference) => reference.url);
  }

  function parseSpdxReferences(pkg) {
    const references = [];
    if (pkg.homepage && pkg.homepage !== "NOASSERTION") {
      references.push({ type: "website", url: pkg.homepage });
    }
    if (pkg.downloadLocation && pkg.downloadLocation !== "NOASSERTION" && pkg.downloadLocation !== "NONE") {
      references.push({ type: "distribution", url: pkg.downloadLocation });
    }
    return references;
  }

  function findSpdxExternalRef(pkg, referenceType) {
    return (pkg.externalRefs || []).find((ref) => ref.referenceType === referenceType)?.referenceLocator || "";
  }

  function collectSpdxExternalRefs(pkg, referenceTypes) {
    return (pkg.externalRefs || [])
      .filter((ref) => referenceTypes.includes(ref.referenceType) && ref.referenceLocator)
      .map((ref) => ref.referenceLocator);
  }

  function cleanSpdxActor(value) {
    if (!value || value === "NOASSERTION") return "";
    // SPDXの supplier / originator は "Organization: Foo" や "Person: Bar" の形式が多い。
    return String(value).replace(/^(Organization|Person|Tool):\s*/i, "");
  }

  window.SBON_PARSER = {
    normalizeSbom,
  };
})();
