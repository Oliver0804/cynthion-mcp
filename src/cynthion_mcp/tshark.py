"""tshark-based USB dissection helpers.

Wraps the `tshark -T json` command line so we can hand LLMs structured
USB-Link-Layer (and higher-layer where descriptors have been observed)
transactions instead of raw hex.

The conversion pipeline:

    capture.bin  ->  decoder.cynthion_bin_to_pcap  ->  pcap (USB 2.0)
                                                              |
                                                              v
                                                       tshark -T json
                                                              |
                                                              v
                                                  list[dict] (LLM-friendly)
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .decoder import ConversionResult, cynthion_bin_to_pcap

CAPTURES_DIR = Path.home() / ".cynthion-mcp" / "captures"

TSHARK_EXE = shutil.which("tshark") or "/opt/homebrew/bin/tshark"


def _capture_paths(capture_id: str) -> tuple[Path, Path]:
    bin_path = CAPTURES_DIR / f"{capture_id}.bin"
    pcap_path = CAPTURES_DIR / f"{capture_id}.pcap"
    if not bin_path.is_file():
        raise FileNotFoundError(f"no capture with id {capture_id}")
    return bin_path, pcap_path


def ensure_pcap(capture_id: str, *, force: bool = False) -> ConversionResult:
    bin_path, pcap_path = _capture_paths(capture_id)
    if pcap_path.exists() and not force:
        # We still need the stats; cheap re-parse is fine for small files.
        # For large captures we could cache, but pragmatic for now.
        pass
    return cynthion_bin_to_pcap(bin_path, pcap_path)


def run_tshark(
    pcap_path: Path,
    display_filter: str | None = None,
    limit: int | None = None,
    fields: list[str] | None = None,
) -> list[dict]:
    args = [TSHARK_EXE, "-r", str(pcap_path), "-T", "json"]
    if display_filter:
        args.extend(["-Y", display_filter])
    if limit is not None:
        args.extend(["-c", str(limit)])
    proc = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"tshark exited {proc.returncode}: {proc.stderr.strip()}")
    if not proc.stdout.strip():
        return []
    return json.loads(proc.stdout)


def summarise_packet(p: dict) -> dict:
    """Flatten the tshark JSON record into something a LLM can scan quickly."""
    layers = p.get("_source", {}).get("layers", {})
    frame = layers.get("frame", {})
    usbll = layers.get("usbll", {})

    pid = usbll.get("usbll.pid")
    pid_name = PID_NAMES.get(pid, "UNKNOWN") if pid else None
    consumed = {
        "usbll.pid", "usbll.src", "usbll.dst",
        "usbll.device_addr", "usbll.endp", "usbll.addr",
        "usbll.sof.framenumber", "usbll.crc5", "usbll.crc5.status",
    }
    return {
        "frame_number": int(frame.get("frame.number", 0)),
        "time": float(frame.get("frame.time_relative", 0)),
        "length": int(frame.get("frame.len", 0)),
        "pid": pid,
        "pid_name": pid_name,
        "src": usbll.get("usbll.src"),
        "dst": usbll.get("usbll.dst"),
        "device": usbll.get("usbll.device_addr"),
        "endpoint": usbll.get("usbll.endp"),
        "sof_frame": usbll.get("usbll.sof.framenumber"),
        "extra": {k: v for k, v in usbll.items() if k not in consumed},
    }


# USB PID byte values. Low nibble is the PID; high nibble is its complement.
PID_NAMES = {
    "0xa5": "SOF",
    "0x2d": "SETUP",
    "0x69": "IN",
    "0xe1": "OUT",
    "0x78": "SPLIT",
    "0xb4": "PING",
    "0xc3": "DATA0",
    "0x4b": "DATA1",
    "0x87": "DATA2",
    "0x0f": "MDATA",
    "0xd2": "ACK",
    "0x5a": "NAK",
    "0x1e": "STALL",
    "0x96": "NYET",
    "0x3c": "PRE_OR_ERR",
}
