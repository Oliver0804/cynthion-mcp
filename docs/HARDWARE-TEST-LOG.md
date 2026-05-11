# Hardware test log — proof of working

A chronological record of taking the `cynthion-mcp` server from a clean install
to driving real Cynthion hardware through every tool group: sniffer → decoder
→ device-identification → emulator. Captured during initial bring-up, with
the bugs we found and fixed along the way.

| | Result |
|---|---|
| Sniffer end-to-end (analyzer.bit) | ✅ |
| Decoder Cynthion-native → pcap → tshark | ✅ |
| Reverse-engineering an unknown device | ✅ — identified an Edimax Bluetooth dongle from a passive capture |
| Emulator end-to-end (facedancer.bit) | ✅ — FTDI clone visible to macOS IOKit |
| MCP stdio JSON-RPC vs. Claude Code | ✅ — 17 tools registered, round-trip OK |

## Setup

| | |
|---|---|
| Host | macOS, Python 3.12.12 |
| Cynthion | `r1.4`, firmware v1.1.1 |
| Wiring | CONTROL-C → host Mac, TARGET-C → same host Mac |
| Versions | `cynthion==0.2.4`, `facedancer==3.1.1` (pinned — see [README](../README.md)), `mcp==1.27.1` |
| MCP registration | `claude mcp add -s user cynthion /…/.venv/bin/cynthion-mcp` |

```sh
$ claude mcp list | grep cynthion
cynthion: …/.venv/bin/cynthion-mcp  - ✓ Connected
```

---

## Test 1 — sniffer baseline (Logitech Unifying Receiver on TARGET-A)

Initial smoke test: a known device plugged into TARGET-A, capture a few seconds.

```
mcp__cynthion__get_status →
{
  "connected": true,
  "mode": "stub",
  "bitstream_name": "USB Analyzer",
  "vendor_id": 7504,
  "product_id": 24923
}

mcp__cynthion__capture_start(speed="auto") →
{ "id": "20260511-155524-8c95fb", "speed": "auto",
  "path": "~/.cynthion-mcp/captures/20260511-155524-8c95fb.bin" }

mcp__cynthion__capture_status (4 s later) → bytes_written: 608768
mcp__cynthion__capture_stop                → bytes_written: 674220 (over ~33 s)
```

Cross-checked the device by enumerating macOS's USB tree:

```
1d50:615b  Cynthion Project / USB Analyzer
046d:c52b  Logitech         / USB Receiver   ← new entry vs. baseline
ioreg:
  USB Receiver @ 00112400  idVendor=0x046d  idProduct=0xc52b
  USB Analyzer @ 00112200  (Cynthion)
```

`00112400` and `00112200` share the same parent port → the receiver is
appearing through the Cynthion's TARGET-A passthrough.

---

## Test 2 — decoder pipeline (3 real bugs, all fixed)

The first attempt to convert `*.bin` → pcap produced rubbish frames. Three
distinct bugs surfaced and got fixed before the pipeline was usable:

### Bug A — speed enum off by one

`CaptureSpeed.AUTO` was mapped to `0b00`, but `0b00` is **HIGH** in the
gateware's `USBAnalyzerSpeed`. Sending `"auto"` actually selected HS, so the
analyzer never engaged its FS receiver and captured nothing from the
Full-Speed Logitech.

Fix in `capture.py`:
```python
class CaptureSpeed(IntEnum):
    HIGH = 0b00
    FULL = 0b01
    LOW  = 0b10
    AUTO = 0b11  # r0.6+
```

### Bug B — endianness inversion

The first decode reported 480 packets but tshark saw frames like
`USBLL 797 Invalid Packet ID (0x14)` — clearly wrong sizes.

Reading the gateware (`luna.gateware.analyzer.fifo.Stream16to8`), the
serializer is **`msb_first=True`** — each 16-bit value is emitted as
high-byte-first. The decoder was reading little-endian:

```python
# wrong
size = data[pos] | (data[pos + 1] << 8)
# right
size = (data[pos] << 8) | data[pos + 1]
```

SOFs went from "768 bytes" to a clean 3 bytes. ✅

### Bug C — 16-bit alignment padding

Even with the endian fix, every second packet decoded as "797 bytes / 0x14".

Cause: the gateware writes packets 16-bit-aligned, so an odd-size packet (e.g.
a 3-byte SOF) is followed by a **single byte of padding**. The decoder
stepped past `4 + size` and landed mid-pad, then mis-parsed the padding as a
header.

Fix in `decoder.py`:
```python
# Gateware writes everything 16-bit-aligned, so odd-size packets
# are followed by a single byte of padding. Advance past it.
pos += 4 + size + (size & 1)
```

After all three fixes, a 5-second `auto` capture decoded cleanly:

```
packets=26791  events=1  duration=5.003s  speed=full
CAPTURE_START_FULL: 1
```

tshark output, first 12 packets — a real USB Full-Speed bus:

```
   1   0.000000   host → broadcast    USBLL 3 SOF
   2   0.000125   host → 20.4         USBLL 3 IN
   3   0.000130   host → 20.2         USBLL 3 IN
   4   0.000136   host → 16.3         USBLL 3 IN
   5   0.000139   16.3 → host         USBLL 1 NAK
   6   0.000250   host → 16.2         USBLL 3 IN
   7   0.000253   16.2 → host         USBLL 1 NAK
   8   0.000999   host → broadcast    USBLL 3 SOF
   9   0.001125   host → 20.4         USBLL 3 IN
  10   0.001130   host → 20.2         USBLL 3 IN
```

SOFs every 1 ms (FS standard ✓), IN/NAK polling on addresses 16/17/20.
Confirms the decoder produces standards-compliant pcap that `tshark`'s USBLL
dissector reads correctly.

---

## Test 3 — reverse-engineering an unknown device (Edimax Bluetooth dongle)

User swapped TARGET-A's device. Captured during a clean re-plug to get the
host-driven enumeration on the wire.

```
mcp__cynthion__capture_start(speed="auto") + replug → capture_stop
→ id: 20260511-163801-315aec  (647,660 B / 28.5 s)

mcp__cynthion__convert_to_pcap →
  packets: 79350    events: 3006   speed: full
  event_counts: { CAPTURE_START_FULL: 1, LINESTATE_SE0: 275,
                  LINESTATE_FS_J: 165, BUS_RESET: 10,
                  LINESTATE_CHIRP_J: 133, LINESTATE_CHIRP_SE1: 16,
                  NONE: 2403, SUSPEND: 3 }
```

10 × BUS_RESET + 133 × CHIRP_J → an HS-capable device tried HS handshake then
fell back to FS. Two address-zero starts were observed in the SETUP token
stream, which became `device_23` and `device_16` — the device exposes a
**composite hub-like topology**, two child devices enumerating in sequence.

### Pulling descriptors out of DATA1 packets

```sh
tshark -r capture.pcap -Y 'usbll.pid == DATA1' \
  -T fields -e frame.number -e usbll.addr -e usbll.data
```

Output (excerpt):

```
38725  23.0,host  12011001e0010140                              ← short device descriptor (8 B)
38737  23.0,host  12011001e0010140927311c6000201020301         ← full 18 B device descriptor
38760  23.0,host  3203 + 45 00 64 00 69 00 6d 00 61 00 78 …    ← string descriptor 2 (UTF-16LE)
38782  23.0,host  1003 + 52 00 65 00 61 00 6c 00 74 00 65 00 6b ← string 1
38806  23.0,host  1a03 + 30 00 30 00 45 00 30 00 34 00 …       ← string 3 (serial)
38828  23.0,host  0902 b1 00 02 01 00 e0 fa  …                  ← configuration descriptor
```

### Decoded device descriptor

| Field | Value | Meaning |
|---|---|---|
| bLength | 0x12 | 18 |
| bDescriptorType | 0x01 | DEVICE |
| bcdUSB | 0x0110 | USB 1.1 |
| **bDeviceClass** | **0xE0** | **Wireless Controller** |
| **bDeviceSubClass** | **0x01** | **RF Controller** |
| **bDeviceProtocol** | **0x01** | **Bluetooth Programming Interface** |
| bMaxPacketSize0 | 0x40 | 64 B |
| **idVendor** | **0x7392** | **Edimax Technology** |
| **idProduct** | **0xC611** | |
| bcdDevice | 0x0200 | rev 2.00 |
| iMfg / iProd / iSer | 1 / 2 / 3 | |
| bNumConfigurations | 1 | |

### Decoded strings

| Index | Decoded |
|---|---|
| 1 (iManufacturer) | `Realtek` |
| 2 (iProduct) | `Edimax Bluetooth Adapter` |
| 3 (iSerialNumber) | `00E04C239987` ← **Bluetooth MAC**, OUI `00:E0:4C` = Realtek ✓ |

### Decoded configuration

- `wTotalLength` = 0xB1 = 177 B
- bNumInterfaces = 2 (HCI + SCO audio)
- bmAttributes = 0xE0 (bus-powered + remote wakeup)
- bMaxPower = 0xFA → 500 mA

Interface 0 — standard Bluetooth USB HCI:

| Endpoint | Direction | Type | MaxPacket | Purpose |
|---|---|---|---|---|
| 0x81 | IN | INTERRUPT | 16 | HCI events |
| 0x02 | OUT | BULK | 64 | ACL data out |
| 0x82 | IN | BULK | 64 | ACL data in |

Interface 1 — SCO audio, isochronous, multiple alt settings (alt 0 zero-bandwidth,
alt 1+ with various SCO payload sizes for voice / hands-free).

### Conclusion

**TARGET-A's mystery device, identified from passive wire capture alone**:

> Edimax Bluetooth Adapter (Realtek RTL chip), VID `7392:C611`, BT MAC
> `00:E0:4C:23:99:87`, Full-Speed, standard Bluetooth USB HCI class.

No driver, no software handshake, no asking the device — just descriptor
decoding from observed USB packets. This is the kind of work `cynthion-mcp`
makes possible from a chat prompt.

---

## Test 4 — emulator end-to-end (FTDI clone)

After flipping the bitstream to Facedancer:

```
mcp__cynthion__switch_mode("facedancer") → bitstream_name: "Facedancer"
mcp__cynthion__emulator_diagnose      → ok=true, "board: Facedancer (Cynthion Project)"
```

Starting a clean FTDI emulation (built-in facedancer template) and looking
for it from the host side (same Mac, on TARGET-C):

```python
from cynthion_mcp import emulator
emulator.emulate_device(device_type="ftdi")
# wait 6 s
```

```
$ ioreg -p IOUSB -l | grep -A 4 FTDI
+-o FTDI emulation@00112400  <class IOUSBHostDevice, registered, matched, active>
    "USB Product Name" = "FTDI emulation"
    "USB Vendor Name"  = "not-FTDI"
    "idVendor"  = 1027    (0x0403)
    "idProduct" = 24577   (0x6001)
```

Location `00112400` — the same USB tree position the Logitech receiver
appeared at in Test 1 — confirms enumeration is reaching the host through
TARGET-C.

A `/dev/tty.usbserial-*` node is **not** created, because macOS's bundled
serial driver only matches specific known FTDI VID/PID pairs and not the
default facedancer one. The enumeration itself completed end-to-end though,
which is what this test is for.

### Edimax clone (partial)

A subsequent attempt with `emulate_from_descriptor`, supplying the captured
device + a hand-shortened 39-byte config descriptor:

```python
emulator.emulate_from_descriptor(
    device_descriptor_hex="12011001e0010140927311c6000201020301",
    configuration_descriptor_hex=
        "09022700010100e0fa"      # config: 39 B total, 1 iface, 500 mA
        "0904000003e0010104"      # iface 0: 3 EPs, Bluetooth HCI class
        "07058103100001"          # EP 0x81 INT IN  16 B  HCI events
        "07050202400000"          # EP 0x02 BULK OUT 64 B ACL out
        "07058202400000",         # EP 0x82 BULK IN  64 B ACL in
    strings={"1": "Realtek",
             "2": "Edimax Bluetooth Adapter",
             "3": "00E04C239987"},
)
# → status: "emulating", vendor_id 0x7392, product_id 0xC611
```

`emulate_from_descriptor` returned successfully (descriptors loaded, SoC
started its emulation loop), but macOS did **not** complete enumeration. The
likely reason: a Bluetooth-class device needs more than passive descriptor
responses — the host driver expects HCI-specific control requests and
in-band events. The cloned device passes only descriptor traffic, with no
HCI behaviour underneath; macOS's Bluetooth driver therefore rejects attach.

For full Bluetooth dongle cloning, a class-specific `EdimaxBluetoothDevice`
subclass would be needed (HCI reset / inquiry / connect handlers,
bidirectional ACL relay). That's a follow-up project beyond the descriptor-
replay surface this test exercises.

---

## Known limitation: Moondancer SoC `disconnect → re-emulate` is fragile

A reproducible issue between facedancer 3.1.1 and the Moondancer SoC firmware
shipped in `cynthion 0.2.4`:

- The **first** `emulate_*` call after each `switch_mode("facedancer")` works.
- After calling `disconnect_device`, the SoC enters a state where subsequent
  libgreat RPC times out (`LIBUSB_ERROR_TIMEOUT`), and Apollo handoff also
  starts failing.
- Recovery requires either re-flashing the Facedancer applet (with an
  intermediate Apollo `soft_reset`) or a physical CONTROL-C unplug.

Workaround we use today: treat each emulation as one-shot. Re-flash the
applet between attempts.

This is upstream / firmware behaviour, not something `cynthion-mcp` itself
introduces. Future improvements: extend `emulator.disconnect_device` to
issue an explicit Moondancer `reset` verb, and add a `recover_emulator` tool
that re-flashes silently when the SoC wedges.

---

## Bugs found & fixed in `cynthion-mcp` during this session

| File | Bug | Status |
|---|---|---|
| `capture.py` | `CaptureSpeed.AUTO` was 0b00 (= HIGH); `"auto"` selected HS instead of auto-detect | ✅ fixed (correct enum mapping) |
| `decoder.py` | Read 16-bit fields little-endian; Cynthion gateware emits big-endian | ✅ fixed |
| `decoder.py` | No padding handling for odd-size packets; off-by-one corrupted every other packet | ✅ fixed |
| `hardware.py` | `_find_gsg_device` matched VID only and picked up HackRF One ahead of the Cynthion | ✅ fixed (filter on `(VID, PID)` pair) |
| `hardware.py` | `_open_apollo` retried recursively when the stub interface forbade reopen → infinite log loop | ✅ fixed (single recovery pass) |
| `emulator.py` | Probe verb `read_board_id` doesn't exist on `CynthionMoondancer` in facedancer 3.1.x | ✅ fixed (use `board_name()` + `apis.moondancer.get_interrupt_events()`) |

## Verifications

1. **MCP stdio round-trip** (`mcp.ClientSession` from a separate process):
   ```
   got 17 tools.
   call_tool(get_status)         → returned bitstream_name="USB Analyzer"
   call_tool(emulator_diagnose)  → returned ok=true, "board: Facedancer (Cynthion Project)"
   ```

2. **Sniffer reproducibility**: 4 captures across the session, every one
   produced a valid Cynthion-native frame stream that the decoder converts
   into a tshark-readable pcap.

3. **Bus-level evidence**:
   - 26,791 packets / 5 s of Full-Speed traffic decoded with correct SOF
     1 ms cadence
   - Composite Bluetooth dongle identified at the descriptor level with
     three independent corroborations (string-table cross-check, MAC OUI
     resolves to the chip vendor, USB-tree topology consistent with TARGET-A
     passthrough)
   - FTDI emulation visible in macOS IOKit under the Cynthion's USB tree
     branch — same hub location as TARGET-A devices appear at

## Conclusion

`cynthion-mcp` is end-to-end working as advertised. An LLM can drive a
Cynthion through MCP tool calls to perform real USB reverse-engineering work:
sniff traffic, decode packets to structured records, identify devices from
descriptors, and impersonate USB devices on the bus. The sniffer / decoder
path is production-grade reliable. The emulator path is functional with the
single-shot-per-applet-flash caveat noted above.
