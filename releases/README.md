# Releases

The notes in this directory describe approved Golden releases. GitHub Releases holds the versioned script and, for v6.4 onward, a matching SHA-256 file. Older assets stay available; a new release does not overwrite them.

After a development build is approved, set the version and channel in `haibox-wireguard.sh`, update README, changelog, baseline and release notes, then change `.github/release-request.json` on `main`. The release workflow checks the version and Bash syntax, creates the tag and publishes the script with its checksum. Verify the assets before aligning `develop` with the published `main` tree.

`.github/release-request.example.json` is a template. Its `NEXT_VERSION` placeholder is intentionally invalid.
