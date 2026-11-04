# WireNest source archive

This archive holds the source for a WireNest release, including the GPL-licensed tools it bundles, and the scripts used to build and package them.

## Contents

- **`SOURCE-REVISION.txt`:** the WireNest Git commit this archive was made from.
- **The WireNest tree at that commit:** the app source, `scripts/`, `LICENSE`, and `THIRD_PARTY_NOTICES.md`.
- **`upstream/`:** the exact third-party sources used:
  - `bash-5.3.tar.gz`, including its `COPYING` license, and official patches `bash53-001` to `bash53-020`
  - `wireguard-tools-*.tar.xz`, including its `COPYING` license
  - `wireguard-go-*.tar.xz`, including its `LICENSE`

`scripts/deps.sh` lists the SHA-256 hash of each file in `upstream/`.

## Rebuild

You need a Mac with Xcode. Builds are native, so run these on the architecture you want to build for:

```sh
mkdir -p .build/packaging
cp -R upstream .build/packaging/downloads

bash scripts/build-tools.sh
bash scripts/build-app.sh 0.1.0
bash scripts/make-dmg.sh 0.1.0
bash scripts/verify-dmg.sh "dist/WireNest-0.1.0-$(uname -m).dmg" "$(uname -m)"
```

- `build-tools.sh` applies the patches and builds `bash`, `wg`, and `wireguard-go`. It copies `wg-quick` unchanged from wireguard-tools. The results go in `.build/packaging/tools`.
- `build-app.sh` builds the app, puts those tools in `WireNest.app/Contents/Resources/Tools`, and signs the app ad hoc.
- `make-dmg.sh` creates the DMG.
- `verify-dmg.sh` checks the DMG and briefly launches WireNest.

Replace `0.1.0` with the version you are building.

## What is downloaded during a rebuild

The `upstream/` files are reused without downloading them again. `build-tools.sh` still needs network access for two things, neither of them GPL-licensed:

- The Go toolchain from go.dev, checked against the hash in `scripts/deps.sh`.
- The Go modules used by `wireguard-go` and the smoke-test peer, checked against the `go.sum` file in the wireguard-go tarball.

Xcode and the macOS SDK come from Apple and are not included.

Rebuilt files won't be byte-for-byte identical to the released ones.
