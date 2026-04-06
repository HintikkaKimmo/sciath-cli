# TODOs

## Documentation update (post-sprint)

Update docs across all repos to reflect the package restructuring and new features:

### sciath-cli (this repo)
- [ ] README.md: document `sciath init yocto` one-step setup flow
- [ ] README.md: document discovery module and PACKAGECONFIG maps
- [ ] CLAUDE.md: update architecture to reflect discovery/ integration
- [ ] CHANGELOG.md: add entries for discovery integration, init command, PACKAGECONFIG maps

### sciath-meta
- [ ] README.md: update to note this is now the enterprise/kas sync target
- [ ] CLAUDE.md: update architecture diagram to reflect new role
- [ ] CHANGELOG.md: add restructuring entry

### sciath (backend)
- [ ] CLAUDE.md: add context about sciath-cli discovery module and how scan pipeline consumes it
- [ ] Document new ArtifactBundle v1.1 schema with packageconfig_suppressions field

### sciath-ui
- [ ] Document waterfall demo view component (when built in Week 4)

## Package release TODOs
- [ ] Once sciath-cli is public on PyPI: update sciath backend requirements/base.txt from `git+https://...` to `sciath-cli>=0.3.0`
- [ ] Check PyPI availability of "sciath" package name before rename
- [ ] Publish sciath-cli to PyPI

## Strategic TODOs
- [ ] Timesys/Lynx+NXP distribution/partnership strategy (from CEO review)
- [ ] Set up CI sync script: sciath-cli → sciath-meta on release
