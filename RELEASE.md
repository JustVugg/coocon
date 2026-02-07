# Release Guide

This document describes how to build and release Coocon on each OS.

## Versioning

- Update `CHANGELOG.md` with the release notes.
- Bump `__version__` in `coocon/__init__.py`.
- Bump `version` in `Cargo.toml`.

## Linux

### Build

```bash
python3 -m py_compile coocon/__init__.py
cargo build --release
```

### Dependencies for strict mode

```bash
sudo apt-get update
sudo apt-get install -y bubblewrap libseccomp2 libseccomp-dev
```

### Run

```bash
./target/release/coocon
```

## macOS

### Build

```bash
python3 -m py_compile coocon/__init__.py
cargo build --release
```

### Run

```bash
./target/release/coocon
```

## Windows (PowerShell)

### Build

```powershell
py -m py_compile coocon\__init__.py
cargo build --release
```

### Run

```powershell
.\target\release\coocon.exe
```

## Smoke Test

```bash
coocon start
coocon run "print('hello')"
coocon stop
```
