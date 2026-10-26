# Where the fixtures come from

The newer lockfiles here are real files from public projects, trimmed to a few entries that keep each format's
edge cases. Every line is copied as it was, apart from the one noted below.

| Fixture | From | Kept |
|---|---|---|
| `pnpm-lock.yaml` | [vuejs/core@ca034820b828](https://github.com/vuejs/core/blob/ca034820b828/pnpm-lock.yaml) | both documents, a scoped package, a peer suffix in snapshots; the main importers cut to `.: {}` |
| `yarn.lock` | [facebook/react@fd51cb10dd15](https://github.com/facebook/react/blob/fd51cb10dd15/yarn.lock) | Yarn 1: a scoped entry, two versions of one package, the `string-width-cjs` alias |
| `berry/yarn.lock` | [yarnpkg/berry@683b27cb4358](https://github.com/yarnpkg/berry/blob/683b27cb4358/yarn.lock) | Yarn 4: an npm package, an alias, a patch, a workspace |
| `requirements/main.txt` | [pypi/warehouse@68dc61bfbf31](https://github.com/pypi/warehouse/blob/68dc61bfbf31/requirements/main.txt) | pip-compile output: hashes, extras, comments |
| `Gemfile.lock` | [rails/rails@ad242026bf6a](https://github.com/rails/rails/blob/ad242026bf6a/Gemfile.lock) | a PATH section, platform builds of one gem |
| `composer.lock` | [composer/composer@b56a3f558a53](https://github.com/composer/composer/blob/b56a3f558a53/composer.lock) | two packages and one dev package |
| `workflows/ci.yml` | [astral-sh/uv@656d02b61460](https://github.com/astral-sh/uv/blob/656d02b61460/.github/workflows/ci.yml) | its first 130 lines: reusable and local workflows, commit pins with tag comments |
