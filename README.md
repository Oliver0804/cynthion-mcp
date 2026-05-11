# cynthion-mcp

> Drive a [Cynthion](https://github.com/greatscottgadgets/cynthion) USB test instrument from an LLM via the Model Context Protocol. **Sniff, decode, and emulate** USB devices over chat.

Cynthion is an open-source USB test instrument built around an ECP5 FPGA. It can passively capture Low/Full/High-speed USB traffic, or impersonate a USB device on its TARGET port. This project exposes those capabilities to LLMs (Claude Desktop, Claude Code, any MCP-aware client) as a set of stdio tools so the model can perform end-to-end **USB reverse engineering** workflows.

## What it does

```
                  ┌─ switch_mode('analyzer') ──────┐
                  │  capture_start                  │
plug in target ───┤  (target enumerates)            │
                  │  capture_stop                   │
                  └─ convert_to_pcap ───────────────┘
                                │
                                ▼
                  ┌─ transaction_summary ──────────┐
                  │  dissect_packets(filter, …)    │  ← LLM analyses,
                  │  find_vendor_requests          │    extracts descriptors,
                  └────────────────────────────────┘    spots protocol patterns
                                │
                                ▼
                  ┌─ switch_mode('facedancer') ────┐
                  │  emulator_diagnose             │
                  │  emulate_from_descriptor(…)    │  ← clone the device,
                  │  emulate_device('ftdi') etc    │    fuzz responses,
                  │  disconnect_device             │    replay vendor reqs
                  └────────────────────────────────┘
```

Three capability groups; the FPGA can only run one bitstream at a time and `switch_mode` flips between them transparently.

| Mode | Bitstream | What the LLM can do |
|---|---|---|
| **Sniffer** | `analyzer.bit` | Passively capture USB traffic on TARGET-C ↔ TARGET-A |
| **Decoder** | (host-side) | Turn captures into structured per-packet records via tshark |
| **Emulator** | `facedancer.bit` | Impersonate a USB device on TARGET-C (clone, fuzz, MITM) |

## Prerequisites

- A [Cynthion](https://greatscottgadgets.com/cynthion/) USB test instrument (any r0.x or r1.x).
- macOS / Linux. (Windows likely works but is untested.)
- Python ≥ 3.10.
- [`tshark`](https://www.wireshark.org/) on `$PATH` (the decoder tools shell out to it).
  - macOS: `brew install wireshark`
  - Linux: `apt install tshark` / `dnf install wireshark-cli`
- A working [`luna`](https://github.com/greatscottgadgets/luna) + [`cynthion`](https://github.com/greatscottgadgets/cynthion) Python install. The simplest setup is two source clones sharing a venv (see Setup below).

## Setup

```sh
# 1. Clone the dependencies and this project side-by-side
git clone https://github.com/greatscottgadgets/luna.git
git clone https://github.com/greatscottgadgets/cynthion.git
git clone https://github.com/Oliver0804/cynthion-mcp.git

# 2. Create a venv and install everything into it
python3 -m venv .venv
./.venv/bin/pip install -e ./luna
./.venv/bin/pip install -e ./cynthion/cynthion/python
./.venv/bin/pip install -e ./cynthion-mcp

# 3. Copy Cynthion's prebuilt bitstreams + Moondancer firmware into the source tree.
#    Without these, `cynthion run …` can't load the FPGA. They ship inside the
#    PyPI wheel; the source clone doesn't include them.
./.venv/bin/pip download cynthion --no-deps -d /tmp/cynthion-wheel
unzip /tmp/cynthion-wheel/cynthion-*.whl 'cynthion/assets/*' -d /tmp/cynthion-extracted
cp -r /tmp/cynthion-extracted/cynthion/assets/* ./cynthion/cynthion/python/assets/

# 4. Verify the board is reachable
./.venv/bin/cynthion info
```

> ⚠️ **`facedancer==3.1.1` is pinned.** facedancer 3.1.2 changed the libgreat-RPC protocol that the Moondancer SoC firmware shipped in `cynthion 0.2.4` speaks. The emulator tools will hang on `connect()` if you upgrade. Don't bump `facedancer` unless `cynthion` also ships a new firmware.

## Register with Claude Code

```sh
claude mcp add -s user cynthion /absolute/path/to/.venv/bin/cynthion-mcp
```

Restart Claude Code (`/exit` and reopen). Seventeen tools appear under the `mcp__cynthion__*` namespace.

## Register with Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "cynthion": {
      "command": "/absolute/path/to/.venv/bin/cynthion-mcp"
    }
  }
}
```

Restart Claude Desktop.

## Tool reference

### Hardware (3)
- `get_status()` — current bitstream + USB enumeration state.
- `switch_mode(applet)` — `"analyzer"` / `"facedancer"` / `"selftest"`. Handles JTAG-stuck recovery via Apollo `soft_reset`.
- `recover()` — software unstick for handoff timeouts / USB glitches.

### Sniffer (5)
- `capture_start(speed)` — `"auto"` (HS/FS/LS auto-detect on r0.6+), `"high"`, `"full"`, `"low"`.
- `capture_stop()` — returns byte count + duration.
- `capture_status()` — peek at running capture's progress.
- `list_captures()` — enumerate stored captures (`~/.cynthion-mcp/captures/`).
- `read_capture(capture_id, offset, length)` — slice raw bytes as hex (debugging mainly).

### Decoder (4) — tshark-backed
- `convert_to_pcap(capture_id)` — Cynthion native `.bin` → `LINKTYPE_USB_2_0` pcap. Idempotent.
- `dissect_packets(capture_id, display_filter, limit)` — structured per-packet records. `display_filter` accepts full Wireshark display-filter syntax (`usbll.pid == 0x96`, `usbll.device_addr == 16`, etc).
- `transaction_summary(capture_id)` — PID counts + device address counts at a glance.
- `find_vendor_requests(capture_id, limit)` — preset filter for vendor-class SETUP packets — high-value targets when reversing proprietary protocols.

### Emulator (5) — Facedancer
- `emulator_diagnose()` — probe the Moondancer SoC's libgreat-RPC. Always call before other emulator tools.
- `emulate_device(device_type, vendor_id?, product_id?)` — built-in templates: `"ftdi"` / `"keyboard"` ⚠️ / `"vendor"`. The keyboard flavour injects keystrokes — only use intentionally.
- `emulate_from_descriptor(device_descriptor_hex, configuration_descriptor_hex?, strings?)` — **device cloning**: stand up an emulation built from raw descriptor bytes you pulled out of a capture. The closed-loop pairing with `dissect_packets`.
- `disconnect_device()` — stop active emulation.
- `inject_serial(text)` — push UTF-8 out an active FTDI emulation's bulk-IN endpoint.

## Example session

A round-trip "clone an unknown USB device" prompt for Claude:

```
1. switch to analyzer mode
2. start a capture in auto speed
3. tell me when I should plug in the target — I'll do it after you say go
4. capture for 5 seconds after I plug it in, then stop
5. summarise the bus activity and list all unique device addresses you observed
6. dissect the DATA0/DATA1 packets that followed GET_DESCRIPTOR setups
   and pull out the 18-byte device descriptor and the config descriptor
7. switch to facedancer mode, diagnose, then emulate from those descriptors
8. tell me when the clone is up
```

## What works on which devices

Cynthion's analyzer captures USB 1.1 / 2.0 (Low / Full / High speed). **SuperSpeed (USB 3.x) lanes are not teed** — but virtually every USB 3.x device falls back to USB 2.0 HS when only D+/D- is wired, so most still work.

| Device class | Sniff | Clone via `emulate_from_descriptor` |
|---|---|---|
| HID — mouse / keyboard / gamepad | ✅ | 🟢 simple (descriptor + report) |
| Serial — FTDI / CH340 / CDC-ACM | ✅ | 🟢 built-in template |
| Mass storage (flash drive) | ✅ — falls back to HS | 🟡 needs SCSI command emulation (`facedancer.devices.umass`) |
| Webcam (UVC) | ✅ HS | 🔴 isochronous + complex descriptors |
| Audio (UAC) | ✅ | 🔴 isochronous |
| Printer / network adapter (CDC-ECM/RNDIS) | ✅ | 🟡 protocol-dependent |
| Vendor proprietary protocols | ✅ | 🟡 needs a vendor-request handler |
| Pure SuperSpeed-only (rare) | ❌ | ❌ |

> ⚠️ **Flash-drive caveat**: a busy HS bulk transfer (~30–60 MB/s) overruns Cynthion's internal FIFO and the gateware emits `CAPTURE_STOP_FULL`. For RE work, sniff the **enumeration phase only** — re-plug the target, then immediately stop the capture once it's connected; don't actually read/write large files while capturing.

## Known limitations / non-goals

- **Higher-layer dissection** (HID, MSC, UVC class) only kicks in once the capture includes the device's enumeration. Re-plug the target while capturing for the richest tshark output.
- **SuperSpeed (USB 3.x)** is out of scope — the analyzer applet doesn't observe SS lanes.
- The HID **keyboard** emulator will inject keystrokes into whatever host is connected to TARGET-C. If that's the same machine running the MCP server, those keystrokes land in whichever app has focus. Use sparingly.

## Architecture

```
cynthion-mcp/
├── pyproject.toml
└── src/cynthion_mcp/
    ├── server.py        # FastMCP entrypoint (17 tools)
    ├── hardware.py      # Apollo MCU + bitstream switching, JTAG-stuck recovery
    ├── capture.py       # analyzer.bit USB driver (vendor reqs + bulk drain)
    ├── decoder.py       # Cynthion native frame format → pcap LINKTYPE_USB_2_0
    ├── tshark.py        # tshark JSON wrapper + USB PID name table
    └── emulator.py      # Facedancer integration (diagnose, template + descriptor emulation)
```

The capture path drives the analyzer applet directly through libusb (vendor requests 0–4, bulk endpoint 0x81). Capture bytes are streamed to `~/.cynthion-mcp/captures/<id>.bin` in the gateware's native frame format (big-endian 16-bit words, 4-byte event records and 4-byte packet headers, 16-bit-aligned). `decoder.py` re-frames those into a standards-compliant pcap so `tshark`'s USB dissectors (and Wireshark / Packetry) can read them directly.

The emulator path goes through facedancer's Moondancer backend, which talks libgreat-RPC to the SoC firmware running on the FPGA.

## Proof of working

See [`docs/HARDWARE-TEST-LOG.md`](./docs/HARDWARE-TEST-LOG.md) for a detailed
bring-up log: an LLM driving `cynthion-mcp` through the full reverse-engineering
loop on a Cynthion r1.4 — sniffing a Logitech wireless receiver, identifying
an unknown Edimax Bluetooth dongle from its descriptors alone (VID/PID/MAC),
and emulating an FTDI device that macOS IOKit registers.

## License

BSD 3-Clause — see [LICENSE](./LICENSE). Same as the upstream Cynthion / LUNA / facedancer projects.

## Related projects

- [Cynthion](https://github.com/greatscottgadgets/cynthion) — the hardware + host tools this builds on
- [LUNA](https://github.com/greatscottgadgets/luna) — the Amaranth HDL USB gateware library
- [Facedancer](https://github.com/greatscottgadgets/facedancer) — the USB device-emulation framework
- [Packetry](https://github.com/greatscottgadgets/packetry) — GUI viewer for Cynthion-format captures (consumes the same pcaps `convert_to_pcap` produces)
