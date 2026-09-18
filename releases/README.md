# Release notes

Place the final, approved Markdown notes for each release in this directory, for example `v6.4.md`.

After the tested source and notes are present on `main`, committing `.github/release-request.json` triggers the release workflow. The request must identify the version, release title, and notes file. The workflow validates the script version and Bash syntax before creating the tag and Release assets.

Do not create or update `release-request.json` for a development build.
