# Native RPM builds

On a Linux **x86_64 or aarch64** host with Git and Docker, check out the desired
release tag or source revision, then run from the repository root:

```sh
sudo bash rpm/build-rpm.sh al8   # Alibaba Cloud Linux 3
sudo bash rpm/build-rpm.sh an23  # Anolis OS 23
```

The scripts build the current tracked source files in a container of the same
architecture. They are native builds, not cross-compilation. Output:
`rpm-output/<distribution>/<architecture>/{RPMS,SRPMS}/`.

`BASE_IMAGE` overrides the distribution image; `OUTPUT_DIR` overrides the output
directory. Cargo caches use Docker volumes scoped by distribution and architecture.
The native RPM workflow builds both architectures and installs/runs the packages.

aarch64 enables CCA, system and TPM attesters. x86_64 retains its TDX, system,
TPM, CSV and Hygon DCU attesters. Intel quote generation dependencies are only
installed on x86_64. CDH and the REST API are built for the same native target.
