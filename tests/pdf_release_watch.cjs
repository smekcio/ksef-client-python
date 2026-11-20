const assert = require('node:assert/strict');
const watch = require('../tools/watch_pdf_releases.cjs');
const issues = [];
let releases = [
  { tag_name: '1.1.49', html_url: 'release49' },
  { tag_name: '1.2.0', html_url: 'release2' },
  { tag_name: '1.3.0-rc1', prerelease: true },
  { tag_name: '1.1.48' },
];
const calls = [];
const listReleases = () => {};
const listForRepo = () => {};
const listTags = () => {};
const github = {
  rest: { repos: { listReleases, listTags }, issues: { listForRepo,
    getLabel: async () => {},
    create: async input => {
      const data = { ...input, number: issues.length + 1 };
      issues.push(data); return { data };
    },
  } },
  paginate: async (method, params) => {
    assert.equal(params.per_page, 100);
    calls.push(method);
    if (method === listReleases) return releases;
    if (method === listTags) return [{ name: '1.4.0' }];
    return [...issues];
  },
};
const args = { github, context: { repo: { owner: 'test', repo: 'sdk' } },
  core: { info: () => {} }, upstream: { repository: 'CIRFMF/ksef-pdf-generator',
    version: '1.1.48', tag: '1.1.48' } };
(async () => {
  await watch(args);
  assert.equal(issues.length, 2);
  assert.match(issues[0].title, /1.1.49$/);
  issues[0].state = 'closed';
  await watch(args);
  assert.equal(issues.length, 2);
  releases.push({ tag_name: '1.3.0', html_url: 'release3' });
  await watch({ ...args, dryRun: true });
  assert.equal(issues.length, 2);
  releases = [];
  await watch(args);
  assert.equal(issues.length, 3);
  assert(calls.includes(listTags));
  releases = [{ tag_name: '1.5.0', html_url: 'release5' }, { tag_name: '1.6.0', html_url: 'release6' }];
  const create = github.rest.issues.create;
  let failOnce = true;
  github.rest.issues.create = async input => {
    if (input.title.endsWith('1.6.0') && failOnce) {
      failOnce = false;
      throw new Error('Temporary create failure');
    }
    return create(input);
  };
  await assert.rejects(watch(args), /Temporary create failure/);
  assert.equal(issues.length, 4);
  await watch(args);
  assert.equal(issues.length, 5);
  github.paginate = async () => { throw new Error('API failure'); };
  await assert.rejects(watch(args), /API failure/);
})().catch(error => { console.error(error); process.exitCode = 1; });
