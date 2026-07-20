# Release Process
This document details the process for delivering releases of the `kube-agentic-networking` project. It serves as a general guide for Release Managers.

## Versioning Strategy

We follow [Semantic Versioning (SemVer)](https://semver.org/) format: `vX.Y.Z`.
*   `X`: Major version (incompatible API changes).
*   `Y`: Minor version (backwards-compatible functionality).
*   `Z`: Patch version (backwards-compatible bug fixes).

For release candidates (pre-releases), use the suffix `-rcN` (e.g., `v1.0.0-rc1`).

## Branching Strategy

*   **`main` branch:** The primary development branch. All new features and bug fixes land here first.
*   **`release-X.Y` branches:** Cut from `main` when preparing a minor release (e.g., `release-1.0` for `v1.0.0`). All patch releases for that minor version (e.g., `v1.0.1`) are cut from this branch.
    *   **Rule of thumb:** The release branch is typically cut from `main` when the work for the first Release Candidate (RC) is complete, minimizing the need for subsequent cherry-picks.

---

## Writing and Organizing the Changelog

For minor and patch releases, we maintain a CHANGELOG file in the repository under `CHANGELOG/X.Y-CHANGELOG.md` (e.g., `CHANGELOG/1.0-CHANGELOG.md`).

To generate the changelog, we recommend using the Kubernetes `release-notes` tool.

### 1. Generate Raw Release Notes
1.  Install the tool:
    ```bash
    go install k8s.io/release/cmd/release-notes@latest
    ```
2.  Set your GitHub Token (needs repo read access):
    ```bash
    export GITHUB_TOKEN=your_github_token_here
    ```
3.  Generate the notes. Identify the `$START_SHA` (usually the tag of the previous release) and the `$END_SHA` (the commit you are releasing):
    ```bash
    release-notes generate \
      --repo kube-agentic-networking --org kubernetes-sigs \
      --branch release-X.Y \
      --start-sha $START_SHA --end-sha $END_SHA \
      --repo-path . \
      --output relnotes.md
    ```

### 2. Organize and Clean Up
The generated `relnotes.md` will contain raw release notes grouped by SIG/Kind. You **must** manually reorganize and clean it up before committing:
*   **High-Level Summary:** Write a human-readable high-level summary at the very top highlighting the major themes, features, or critical fixes in this release.
*   **Categorization:** Group changes logically (e.g., `API Changes`, `Features`, `Bug Fixes`, `Documentation`, `Deprecations`).
*   **Clean Up "Uncategorized":** Go through the "Uncategorized" section and move all items into their relevant categories. Delete the "Uncategorized" header once empty.
*   **Formatting:** Ensure consistent formatting (typically bullet points referencing the PR number and author, e.g., `#123, @username`).

Save the finalized notes to `CHANGELOG/X.Y-CHANGELOG.md` and commit them to the release branch.

---

## Releasing a Minor Version (e.g., `vX.Y.0`)

### 1. Cut the Release Branch
Create the `release-X.Y` branch from `main`:
```bash
git checkout main
git pull upstream main
git checkout -b release-X.Y
git push upstream release-X.Y
```

### 2. Prepare Release Candidate (RC)
1.  Checkout the release branch:
    ```bash
    git checkout release-X.Y
    git pull upstream release-X.Y
    ```
2.  Generate and commit the initial changelog to `CHANGELOG/X.Y-CHANGELOG.md` (from the last minor release tag to current HEAD).
3.  Update the version string in `version/version.go` to the release candidate version (e.g., `vX.Y.0-rc1`).
4.  Run `make generate` to update the generated YAML manifests and client code with the new version.
5.  Commit and push these changes to `release-X.Y` (use a PR if the branch is protected).
6.  Once the changes are on `release-X.Y` upstream, tag the RC:
    ```bash
    git checkout release-X.Y
    git pull upstream release-X.Y
    git tag -a vX.Y.0-rc1 -m "Release Candidate 1"
    git push upstream vX.Y.0-rc1
    ```
7.  Verify CI builds the images and test them. Repeat with `rc2`, `rc3` if bugs are found (fixes must land on `main` and be cherry-picked to `release-X.Y`).

### 3. Tag the Final Release
Once the RC is stable and approved by maintainers:
1.  On the `release-X.Y` branch, update the version string in `version/version.go` to the final version (e.g., `vX.Y.0`) removing the `-rcN` suffix.
2.  Run `make generate` to update the generated YAML manifests and client code.
3.  Update the CHANGELOG with any changes made during the RC phase.
4.  Commit and push these changes to `release-X.Y` (use a PR if the branch is protected).
5.  Once the changes are on `release-X.Y` upstream, tag the final release:
    ```bash
    git checkout release-X.Y
    git pull upstream release-X.Y
    git tag -a vX.Y.0 -m "Release vX.Y.0"
    git push upstream vX.Y.0
    ```
6.  Pushing the tag will automatically trigger the GitHub Actions `release` workflow, which builds the controller binaries, generates installation manifests, and creates a draft GitHub Release with these artifacts attached.
7.  Once the workflow completes, go to the GitHub Releases page:
    *   Review the generated draft release.
    *   Edit the release description to include the content of `CHANGELOG/X.Y-CHANGELOG.md`.
    *   Publish the release.

---

## Releasing a Patch Version (e.g., `vX.Y.Z`)

Patch releases contain only critical bug fixes cherry-picked from `main`.

### 1. Cherry-pick Fixes
1.  Checkout the release branch:
    ```bash
    git checkout release-X.Y
    git pull upstream release-X.Y
    ```
2.  Cherry-pick the required bug fix commits from `main`:
    ```bash
    git cherry-pick <COMMIT_SHA>
    ```
3.  Update the version string in `version/version.go` to the new patch version (e.g., `vX.Y.Z`).
4.  Run `make generate` to update the generated YAML manifests and client code.
5.  Commit and push the changes (cherry-picks, version updates, and generated YAMLs) to `release-X.Y` (use a PR if the branch is protected).

### 2. Generate Changelog
Generate release notes between the last patch release (`vX.Y.(Z-1)`) and the new HEAD. Append or update the entry in `CHANGELOG/X.Y-CHANGELOG.md`.

### 3. Tag and Publish
1.  Tag the release on the release branch:
    ```bash
    git tag -a vX.Y.Z -m "Release vX.Y.Z"
    git push upstream vX.Y.Z
    ```
2.  Pushing the tag will automatically trigger the GitHub Actions `release` workflow, which builds the controller binaries, generates installation manifests, and creates a draft GitHub Release with these artifacts attached.
3.  Once the workflow completes, go to the GitHub Releases page:
    *   Review the generated draft release.
    *   Edit the release description to include the changelog section for this patch version.
    *   Publish the release.

