const viewer = window.SBON_UI.createViewer({
  parser: window.SBON_PARSER,
  exporter: window.SBON_EXPORT,
  differ: window.SBON_DIFF,
  review: window.SBON_REVIEW,
  sampleSbom: window.SBON_SAMPLE_SBOM,
  spdxSampleSbom: window.SBON_SAMPLE_SPDX,
  diffSampleSboms: { before: window.SBON_SAMPLE_PREV, after: window.SBON_SAMPLE_SBOM },
});

viewer.start();
