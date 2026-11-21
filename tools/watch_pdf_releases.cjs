const fs = require('node:fs');

function version(tag) {
  const match = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(tag || '');
  return match ? match.slice(1).map(Number) : null;
}
function compare(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

module.exports = async function watch({ github, context, core, dryRun = false, upstream }) {
  const pin = upstream || JSON.parse(fs.readFileSync('src/ksef_client/_mf_pdf/upstream.json', 'utf8'));
  const baseline = version(pin.version);
  if (!baseline) throw new Error('Invalid pinned PDF version');
  const [owner, repo] = pin.repository.split('/');
  let releases = await github.paginate(github.rest.repos.listReleases, { owner, repo, per_page: 100 });
  if (!releases.length) {
    const tags = await github.paginate(github.rest.repos.listTags, { owner, repo, per_page: 100 });
    releases = tags.map(tag => ({ tag_name: tag.name,
      html_url: `https://github.com/${owner}/${repo}/releases/tag/${encodeURIComponent(tag.name)}` }));
  }
  const candidates = new Map();
  for (const release of releases) {
    const parsed = version(release.tag_name);
    if (!release.draft && !release.prerelease && parsed && compare(parsed, baseline) > 0) {
      candidates.set(parsed.join('.'), release);
    }
  }
  const target = { owner: context.repo.owner, repo: context.repo.repo };
  const label = 'ksef-pdf-generator-release';
  // Inspect all issues, even if someone removed the label after closing one.
  const issues = await github.paginate(github.rest.issues.listForRepo,
    { ...target, state: 'all', per_page: 100 });
  const ordered = [...candidates.entries()].sort((a, b) => compare(version(a[0]), version(b[0])));
  let labelReady = false;
  for (const [number, release] of ordered) {
    const marker = `<!-- ksef-pdf-generator-release:${number} -->`;
    if (issues.some(issue => !issue.pull_request && (issue.body || '').includes(marker))) continue;
    if (dryRun) {
      core.info(`Would create PDF release issue for ${number}`);
      continue;
    }
    if (!labelReady) {
      try {
        await github.rest.issues.getLabel({ ...target, name: label });
      } catch (error) {
        if (error.status !== 404) throw error;
        await github.rest.issues.createLabel({ ...target, name: label, color: '1D76DB',
          description: 'Nowe wydania generatora PDF CIRFMF' });
      }
      labelReady = true;
    }
    const body = [
      `Generator PDF MF używany przez SDK ma wersję **${pin.version}**. Dostępne wydanie **${number}**.`,
      '', `Wydanie MF ${release.html_url}`,
      `Data publikacji ${release.published_at || 'tag bez daty publikacji wydania'}`,
      `Porównanie https://github.com/${owner}/${repo}/compare/${encodeURIComponent(pin.tag)}...${encodeURIComponent(release.tag_name)}`,
      '', '- [ ] Przejrzeć changelog i licencje',
      '- [ ] Odtworzyć generator z przypiętego commitu i zaktualizować upstream.json',
      '- [ ] Sprawdzić faktury, UPO 4.2/4.3, oba tryby QR i dystrybucje wheel/sdist',
      '- [ ] Przygotować PR z aktualizacją i porównaniem wizualnym', '', marker,
    ].join('\n');
    const created = await github.rest.issues.create({ ...target,
      title: `ksef-pdf-generator: nowe wydanie ${number}`, body, labels: [label] });
    issues.push(created.data);
    core.info(`Created PDF release issue #${created.data.number}`);
  }
};
