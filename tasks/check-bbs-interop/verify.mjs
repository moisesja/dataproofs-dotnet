import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import jsigs from 'jsonld-signatures';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {createVerifyCryptosuite} from '@digitalbazaar/bbs-2023-cryptosuite';

const root = fileURLToPath(new URL('../../', import.meta.url));
const scratch = mkdtempSync(join(tmpdir(), 'dataproofs-bbs-interop-'));
try {
  const output = join(scratch, 'public-artifacts.json');
  const run = spawnSync('dotnet', ['run', '--project',
    'samples/DataProofsDotnet.Samples.BbsSelectiveDisclosure',
    '--', '--interop-output', output], {cwd: root, encoding: 'utf8'});
  assert.equal(run.status, 0, run.stdout + run.stderr);
  // Missing native BBS must fail this check, rather than masquerading as cross-stack success.
  const artifacts = JSON.parse(readFileSync(output, 'utf8'));
  const key = {
    '@context': 'https://w3id.org/security/multikey/v1',
    id: artifacts.verificationMethod, controller: artifacts.controller,
    type: 'Multikey', publicKeyMultibase: artifacts.publicKeyMultibase
  };
  const controller = {
    '@context': {id: '@id', assertionMethod: {
      '@id': 'https://w3id.org/security#assertionMethod', '@type': '@id'
    }},
    id: artifacts.controller, assertionMethod: [artifacts.verificationMethod]
  };
  const documents = new Map([
    [key.id, key], [controller.id, controller],
    ['https://www.w3.org/ns/credentials/v2', JSON.parse(readFileSync(join(root, 'tests/fixtures/contexts/credentials-v2.jsonld'), 'utf8'))],
    ['https://www.w3.org/ns/credentials/examples/v2', JSON.parse(readFileSync(join(root, 'src/DataProofsDotnet.Rdfc/Contexts/credentials-examples-v2.jsonld'), 'utf8'))],
    ['https://w3id.org/security/multikey/v1', JSON.parse(readFileSync(join(root, 'tests/fixtures/contexts/multikey-v1.jsonld'), 'utf8'))]
  ]);
  const documentLoader = async url => {
    assert(documents.has(url), `Unexpected retrieval: ${url}`);
    return {contextUrl: null, documentUrl: url, document: structuredClone(documents.get(url))};
  };
  const verify = document => jsigs.verify(document, {
    suite: new DataIntegrityProof({cryptosuite: createVerifyCryptosuite({
      expectedPresentationHeader: new Uint8Array([0x11, 0x33, 0x77, 0xaa])
    })}),
    purpose: new jsigs.purposes.AssertionProofPurpose(), documentLoader
  });
  for (const reveal of artifacts.reveals) {
    const result = await verify(reveal);
    assert(result.verified, JSON.stringify(result.error));
    const altered = structuredClone(reveal);
    altered.issuer = 'https://example.invalid/altered-issuer';
    assert.equal((await verify(altered)).verified, false);
  }
  console.log(`${artifacts.reveals.length} .NET BBS disclosures verify in the pinned JavaScript stack; tampering is rejected.`);
} finally {
  rmSync(scratch, {recursive: true, force: true});
}
