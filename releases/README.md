# Release notes

Place the final, approved Markdown notes for each release in this directory, for example `v6.5.md`.

After Simone approves a tested build as Golden, update the script version, `README.md`, `CHANGELOG.md`, `DEVELOPMENT_BASELINE.md` acceptance record and the release notes. Promote that exact source to `main`. Update `.github/release-request.json` on `main` to the approved version, title and notes file; this change triggers the release workflow. The workflow validates the script version and Bash syntax, then creates the tag, Release script and checksum. Verify the published assets and checksum before synchronizing `develop` to the exact `main` tree for the next cycle.

The example request contains a deliberately invalid `NEXT_VERSION` placeholder. Replace every value with the approved release before updating the real request. Do not update `release-request.json` for a development build; the workflow only runs when that file changes on `main`.
