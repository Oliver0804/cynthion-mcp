"""Cynthion native capture → pcap converter.

Cynthion's analyzer applet emits a stream of 4-byte-aligned records.
Each record starts on a 16-bit word boundary; the first byte distinguishes:

  * **Event**  (4 bytes):  ``0xFF | event_code | timestamp_lo | timestamp_hi``
    Event codes are defined in
    ``cynthion.gateware.analyzer.events.USBAnalyzerEvent``.
  * **Packet** (4 + N bytes): ``size_lo | size_hi | timestamp_lo | timestamp_hi``
    followed by ``size`` bytes of raw on-the-wire USB packet (starts with PID).
    ``size_lo`` can never be ``0xFF`` for a real packet — USB 2.0 limits
    payload to 1024 bytes — so the leading-byte ambiguity is safe.

The pcap output uses ``LINKTYPE_USB_2_0`` (288), the linktype consumed by both
Packetry and Wireshark/tshark's USB dissector. Each packet record gets a
timestamp derived from the cumulative USB-clock-tick count (60 MHz nominal),
collapsed to seconds + microseconds.

Events are intentionally NOT emitted into the pcap (no good linktype for them);
they are summarised in the returned metadata.
"""

from __future__ import annotations

import logging
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

LINKTYPE_USB_2_0 = 288

PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHIIII",
    0xA1B2C3D4,     # magic (microsecond timestamps)
    2, 4,           # major, minor version
    0,              # GMT to local correction
    0,              # accuracy of timestamps
    65535,          # snaplen
    LINKTYPE_USB_2_0,
)

# Maps Cynthion event codes to human strings, mirroring USBAnalyzerEvent.
EVENT_NAMES = {
    0: "NONE",
    1: "CAPTURE_STOP_NORMAL",
    2: "CAPTURE_STOP_FULL",
    3: "CAPTURE_STOP_ERROR",
    4: "CAPTURE_START_HIGH_OR_AUTO",
    5: "CAPTURE_START_FULL",
    6: "CAPTURE_START_LOW",
    7: "CAPTURE_START_AUTO",
    8: "SPEED_DETECT_HIGH",
    9: "SPEED_DETECT_FULL",
    10: "SPEED_DETECT_LOW",
    11: "SPEED_DETECT_AUTO",
    12: "LINESTATE_SE0",
    13: "LINESTATE_CHIRP_J",
    14: "LINESTATE_CHIRP_K",
    15: "LINESTATE_CHIRP_SE1",
    16: "LINESTATE_LS_J",
    17: "LINESTATE_LS_K",
    18: "LINESTATE_FS_J",
    19: "LINESTATE_FS_K",
    20: "LINESTATE_SE1",
    21: "VBUS_INVALID",
    22: "VBUS_VALID",
    23: "LS_ATTACH",
    24: "FS_ATTACH",
    25: "BUS_RESET",
    26: "DEVICE_CHIRP_VALID",
    27: "HOST_CHIRP_VALID",
    28: "SUSPEND",
    29: "RESUME",
    30: "LS_KEEPALIVE",
}

# USB clock frequency used by the analyzer to derive timestamps.
USB_CLOCK_HZ = 60_000_000


@dataclass
class ConversionResult:
    pcap_path: Path
    packets: int
    events: int
    bytes_consumed: int
    event_counts: dict[str, int]
    speed: str | None  # "high" / "full" / "low" / "auto" / None
    duration_us: float


def cynthion_bin_to_pcap(src: Path, dst: Path) -> ConversionResult:
    src = Path(src)
    dst = Path(dst)

    data = src.read_bytes()
    pos = 0
    cumulative_ticks = 0
    packets = 0
    events = 0
    event_counts: Counter[str] = Counter()
    speed: str | None = None

    with dst.open("wb") as out:
        out.write(PCAP_GLOBAL_HEADER)

        while pos + 4 <= len(data):
            b0 = data[pos]
            if b0 == 0xFF:
                # Event record (4 bytes). Each 16-bit word is BIG-ENDIAN on the
                # wire — the gateware's Stream16to8 emits high byte first.
                # The 16-bit "event word" itself is `Cat(event_code, 0xFF)`,
                # which when serialised msb-first becomes `FF | event_code`,
                # so the code lives in byte 1.
                code = data[pos + 1]
                timestamp = (data[pos + 2] << 8) | data[pos + 3]
                cumulative_ticks += timestamp
                name = EVENT_NAMES.get(code, f"UNKNOWN_{code:02x}")
                event_counts[name] += 1
                events += 1
                if code in (4, 5, 6, 7):
                    speed = {4: "high", 5: "full", 6: "low", 7: "auto"}[code]
                pos += 4
                continue

            # Packet header (4 bytes), big-endian 16-bit words:
            #   size_hi | size_lo | time_hi | time_lo
            size = (data[pos] << 8) | data[pos + 1]
            if size == 0 or size > 1027:
                # Bogus length — likely framing drift. Skip a word and retry.
                pos += 2
                continue
            if pos + 4 + size > len(data):
                # Truncated tail; stop gracefully.
                break

            timestamp = (data[pos + 2] << 8) | data[pos + 3]
            cumulative_ticks += timestamp
            payload = data[pos + 4 : pos + 4 + size]

            # Convert cumulative USB ticks to seconds + microseconds.
            seconds = cumulative_ticks // USB_CLOCK_HZ
            usec_remainder_ticks = cumulative_ticks - seconds * USB_CLOCK_HZ
            microseconds = (usec_remainder_ticks * 1_000_000) // USB_CLOCK_HZ

            out.write(struct.pack(
                "<IIII",
                seconds, microseconds,
                len(payload), len(payload),
            ))
            out.write(payload)
            packets += 1
            # Gateware writes everything 16-bit-aligned, so odd-size packets
            # are followed by a single byte of padding. Advance past it.
            pos += 4 + size + (size & 1)

    return ConversionResult(
        pcap_path=dst,
        packets=packets,
        events=events,
        bytes_consumed=pos,
        event_counts=dict(event_counts),
        speed=speed,
        duration_us=cumulative_ticks / USB_CLOCK_HZ * 1_000_000,
    )
