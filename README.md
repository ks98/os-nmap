# os-nmap (OPNsense Nmap Plugin)

This repository contains the OPNsense plugin "os-nmap". It provides a WebUI
to run safe, pre-defined Nmap scans and custom commands.

## Features
- Quick Scan and interface scans from the UI
- Scan profiles with editable arguments
- Results display including services, MAC, and vendor info
- Export host results as JSON or CSV
- Results stored at `/var/db/nmap/scan_results.json`

## Usage (UI)
1. OPNsense: Interfaces -> Diagnostics -> Nmap
2. Quick Scan: choose target and profile
3. Interfaces: select networks and start scan
4. Custom: enter target and arguments (without "nmap" and without target)

## Scan Profiles
Default profiles are created via migration, e.g. Ping scan, Fast TCP scan,
TCP scan, Service detection, Full TCP scan, and Aggressive scan. Custom profiles
can be created and edited in the "Scan Profiles" tab.

## Development / Build
This repo follows the OPNsense plugin layout.
- `make` shows the plugin description (from `pkg-descr`)
- `make package` builds a package in `work/pkg`
- `make install DESTDIR=...` installs into a staging directory

Note: the build system expects an OPNsense builder environment (LOCALBASE, PKG,
etc.).

## Structure
- `src/opnsense/scripts/OPNsense/Nmap/nmap_scan.py`: scan runner
- `src/opnsense/mvc/app/`: UI, controllers, and model
- `src/opnsense/service/conf/actions.d/actions_nmap.conf`: configd action
- `pkg-descr`: short description and changelog

