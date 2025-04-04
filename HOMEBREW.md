# Publishing to Homebrew

This document explains how to publish the TAVO CLI tool to Homebrew.

## Prerequisites

1. A GitHub repository for the project
2. A GitHub repository for the Homebrew tap
3. Git and Homebrew installed on your machine

## Steps to Publish

### 1. Create a Release on GitHub

1. Create a tag for the release:
   ```bash
   git tag -a v0.1.0 -m "Release v0.1.0"
   git push origin v0.1.0
   ```

2. Create a release on GitHub with this tag

3. Generate a tarball from the release:
   ```bash
   wget https://github.com/tavo-team/tavo-cli/archive/refs/tags/v0.1.0.tar.gz
   ```

4. Calculate the SHA256 hash of the tarball:
   ```bash
   shasum -a 256 v0.1.0.tar.gz
   ```

5. Update the SHA256 hash in the Homebrew formula (`tavo.rb`):
   ```ruby
   sha256 "the-sha256-hash-you-generated"
   ```

### 2. Create a Homebrew Tap Repository

1. Create a GitHub repository named `homebrew-tavo` (must follow the naming convention `homebrew-<n>`)

2. Add your `tavo.rb` formula to this repository:
   ```bash
   cp tavo.rb /path/to/homebrew-tavo/Formula/
   cd /path/to/homebrew-tavo
   git add Formula/tavo.rb
   git commit -m "Add tavo formula"
   git push
   ```

### 3. Test the Tap Locally

1. Add the tap:
   ```bash
   brew tap tavo-team/tavo
   ```

2. Install the formula:
   ```bash
   brew install tavo
   ```

3. Verify the installation:
   ```bash
   tavo --help
   ```

### 4. Promote the Tap

1. Update the README to include installation instructions:
   ```markdown
   ## Installation

   ```bash
   brew tap tavo-team/tavo
   brew install tavo
   ```
   ```

2. Consider submitting to the core Homebrew tap if the tool becomes popular:
   - See [Homebrew's documentation](https://docs.brew.sh/Adding-Software-to-Homebrew) for details on submission to the core tap. 