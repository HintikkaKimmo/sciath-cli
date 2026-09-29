# Publishing sciath-cli

The Python release is a wheel and a source distribution for Python 3.11+.
Publishing a GitHub Release starts `python-publish.yml`, which checks the tag
against `sciath_cli/__init__.py`, runs lint, typing, tests and dependency audits
on Python 3.11–3.13, validates both distributions, and tests clean installs.
Only then does it publish to PyPI and attach the same files to the GitHub Release.

## One-time PyPI setup

Sign in to PyPI with a verified account and two-factor authentication. For the
first upload, add a **pending publisher** at
<https://pypi.org/manage/account/publishing/>:

| Field | Value |
|-------|-------|
| PyPI project name | `sciath-cli` |
| Owner | `HintikkaKimmo` |
| Repository name | `sciath-cli` |
| Workflow name | `python-publish.yml` |
| Environment name | `pypi` |

The workflow name is the filename, without `.github/workflows/`.
Create the matching `pypi` environment in the repository's GitHub settings.
No PyPI API token or GitHub repository secret is needed.

After the first upload, manage the publisher on the project's Publishing page.
See [PyPI's pending publisher documentation](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

## Each release

1. Set the version in `sciath_cli/__init__.py`, move the unreleased changelog
   entries into a dated version section, and run `uv lock` to update package
   metadata. Re-export requirements if dependencies changed.
2. Open a pull request and wait for every CI job, including `package`, to pass.
3. Merge the release commit into `master`.
4. Create a tag matching the version and push it. For example:

   ```bash
   git switch master
   git pull --ff-only
   git tag v0.3.0
   git push origin v0.3.0
   ```

5. Create a GitHub Release for that tag, use the changelog for its notes, and
   publish it. With the GitHub CLI:

   ```bash
   gh release create v0.3.0 --verify-tag --title "sciath-cli 0.3.0" --notes-file release-notes.md
   ```

6. Wait for **Upload Python Package** to succeed. Verify a fresh installation:

   ```bash
   uvx --from sciath-cli==0.3.0 sciath --version
   ```

Create/publish the GitHub Release as a maintainer. A release created by another
workflow's default `GITHUB_TOKEN` does not trigger this publishing workflow.
See [GitHub's workflow trigger documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).

## Recovering a failed publish

If Trusted Publishing fails before uploading, correct the PyPI configuration
and rerun the failed job. The workflow can also be started manually against
the existing release tag; it refuses branch refs or a mismatched version.

PyPI does not allow replacing an uploaded file. If a version was already
published, do not rerun the upload to replace it. Fix the package, increment
the version, and release again. If only the GitHub asset upload failed, rerun
that failed job without rerunning the PyPI job.

## Standalone executables

`release.yml` is manual and is not part of the Python release. Its unfinished
PyInstaller setup needs a tracked `sciath.spec`, supported macOS runners,
and actual native/cross builds for each advertised architecture before use.
The legacy `install.sh` is not an installation route for this Python release;
use `pip install sciath-cli`.
