# Build Specifications

[This directory](dist/buildspec/) contains build specifications for reproducible builds of guest-components.

## Overview

The build specifications define the exact environment and dependencies needed to reproduce the same build results as our official releases. These specifications are used in our CI/CD pipeline to ensure consistency and verifiability.

## Reproducible Builds

The reproducible builds are implemented using [GuanFu](https://github.com/1570005763/GuanFu/tree/v1), which provides a framework for containerized, verifiable builds. GuanFu also handles SLSA provenance generation and Rekor transparency log uploads.

Currently supported distros:
- AnolisOS 23 (an23)
- Alibaba Cloud Linux 3 (al8)

## Local Rebuild Guide

This guide explains how to perform local reproducible builds using GuanFu based on the specified buildspec.yaml file.

For complete documentation on the local rebuild process, please refer to the [GuanFu Local Rebuild Guide](https://github.com/1570005763/GuanFu/blob/v1/docs/local_rebuild_guide.md).

### Build Specification Files

- `trustiflux-<VERSION>-<RELEASE>.an23.x86_64.buildspec.yaml`: Build specification for AnolisOS 23 x86_64
- `trustiflux-<VERSION>-<RELEASE>.al8.x86_64.buildspec.yaml`: Build specification for Alibaba Cloud Linux 3 x86_64

### Prerequisites

Before starting the local reproducible build, ensure you have met the following requirements:

- Docker installed
- Python 3.7+ installed
- Git installed

### Usage

Follow these steps to perform a local reproducible build:

1. **Prepare the buildspec.yaml file**:
   Download the buildspec file for your target version and distro from the release:
   ```bash
   # Example for version v1.5.0, release 1, AnolisOS 23 - replace with your target
   wget https://github.com/inclavare-containers/guest-components/releases/download/v1.5.0/trustiflux-1.5.0-1.an23.x86_64.buildspec.yaml

   # Or for Alibaba Cloud Linux 3
   wget https://github.com/inclavare-containers/guest-components/releases/download/v1.5.0/trustiflux-1.5.0-1.al8.x86_64.buildspec.yaml
   ```

2. **Clone the GuanFu repository**:
   ```bash
   git clone --branch v1 --depth 1 https://github.com/1570005763/GuanFu.git
   cd GuanFu
   ```

3. **Execute the build**:
   ```bash
   # Run in the GuanFu project root directory
   ./src/build-runner.sh path/to/your/buildspec.yaml
   ```

4. **Verify the build results**:
   Compare the SHA256 checksums of the locally built RPMs with those from the release:
   ```bash
   # Compare checksums of local build with release artifacts
   sha256sum local-built-package.rpm
   # Compare this output with the checksums from the release page
   ```
