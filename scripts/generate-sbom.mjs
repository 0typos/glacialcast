#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const output = process.argv[2];
if (!output) {
  console.error('usage: scripts/generate-sbom.mjs <output.spdx.json>');
  process.exit(2);
}

const cargo = spawnSync(
  'cargo',
  ['metadata', '--locked', '--format-version', '1'],
  { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
);
if (cargo.status !== 0) {
  if (cargo.error) console.error(cargo.error.message);
  process.stderr.write(cargo.stderr);
  process.exit(cargo.status ?? 1);
}

const metadata = JSON.parse(cargo.stdout);
const workspace = new Set(metadata.workspace_members);
const rootPackage = metadata.packages.find(pkg => pkg.name === 'gcrelay');
if (!rootPackage) throw new Error('workspace does not contain gcrelay');

const revision = process.env.GLACIALCAST_RELEASE_REVISION || 'uncommitted';
const epoch = Number(process.env.SOURCE_DATE_EPOCH || 0);
const created = new Date(epoch > 0 ? epoch * 1000 : Date.now())
  .toISOString()
  .replace(/\.\d{3}Z$/, 'Z');
const packageIds = new Map(
  metadata.packages.map((pkg, index) => [
    pkg.id,
    `SPDXRef-Package-${index}-${pkg.name.replace(/[^A-Za-z0-9.-]/g, '-')}`,
  ]),
);
const nativePackages = [
  ['SPDXRef-Native-PipeWire', 'PipeWire'],
  ['SPDXRef-Native-OpenH264', 'OpenH264'],
].map(([SPDXID, name]) => ({
  SPDXID,
  name,
  downloadLocation: 'NOASSERTION',
  filesAnalyzed: false,
  licenseConcluded: 'NOASSERTION',
  licenseDeclared: 'NOASSERTION',
  copyrightText: 'NOASSERTION',
  primaryPackagePurpose: 'LIBRARY',
  comment: 'System-provided runtime dependency; exact version is deployment-specific.',
}));

const packages = metadata.packages.map(pkg => ({
  SPDXID: packageIds.get(pkg.id),
  name: pkg.name,
  versionInfo: pkg.version,
  downloadLocation: pkg.source || 'NOASSERTION',
  filesAnalyzed: false,
  licenseConcluded: 'NOASSERTION',
  licenseDeclared: pkg.license || 'NOASSERTION',
  copyrightText: 'NOASSERTION',
  primaryPackagePurpose: workspace.has(pkg.id) ? 'APPLICATION' : 'LIBRARY',
  externalRefs: [{
    referenceCategory: 'PACKAGE-MANAGER',
    referenceType: 'purl',
    referenceLocator: `pkg:cargo/${encodeURIComponent(pkg.name)}@${pkg.version}`,
  }],
})).concat(nativePackages);

const relationships = [];
for (const id of metadata.workspace_members) {
  relationships.push({
    spdxElementId: 'SPDXRef-DOCUMENT',
    relationshipType: 'DESCRIBES',
    relatedSpdxElement: packageIds.get(id),
  });
}
for (const node of metadata.resolve?.nodes || []) {
  for (const dependency of node.dependencies) {
    relationships.push({
      spdxElementId: packageIds.get(node.id),
      relationshipType: 'DEPENDS_ON',
      relatedSpdxElement: packageIds.get(dependency),
    });
  }
}
const client = metadata.packages.find(pkg => pkg.name === 'gcpub');
if (!client) throw new Error('workspace does not contain gcpub');
for (const dependency of nativePackages) {
  relationships.push({
    spdxElementId: packageIds.get(client.id),
    relationshipType: 'DEPENDS_ON',
    relatedSpdxElement: dependency.SPDXID,
  });
}
const viewer = metadata.packages.find(pkg => pkg.name === 'gcview');
if (!viewer) throw new Error('workspace does not contain gcview');
relationships.push({
  spdxElementId: packageIds.get(viewer.id),
  relationshipType: 'DEPENDS_ON',
  relatedSpdxElement: 'SPDXRef-Native-OpenH264',
});

const document = {
  spdxVersion: 'SPDX-2.3',
  dataLicense: 'CC0-1.0',
  SPDXID: 'SPDXRef-DOCUMENT',
  name: `GlacialCast-${rootPackage.version}`,
  documentNamespace:
    `https://spdx.glacialcast.invalid/${rootPackage.version}/${encodeURIComponent(revision)}`,
  creationInfo: {
    created,
    creators: ['Tool: GlacialCast cargo-metadata SBOM generator'],
  },
  packages,
  relationships,
};

fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
fs.writeFileSync(output, `${JSON.stringify(document, null, 2)}\n`, { mode: 0o644 });
