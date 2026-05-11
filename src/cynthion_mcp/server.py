"""MCP server entrypoint — exposes Cynthion sniffer + Facedancer tools over stdio."""

# Deliberately NOT using `from __future__ import annotations` here — FastMCP
# uses pydantic to build per-tool argument models, and pydantic needs annotations
# to evaluate to real objects (not stringified) so it can resolve forward
# references like `Literal[...]` through the @_safe wrapper.

import functools
import inspect
import logging
import os
import sys
import traceback
from dataclasses import asdict
from typing import Literal

from mcp.server.fastmcp import FastMCP

from . import capture, emulator, tshark as tshark_mod
from .hardware import Applet, Hardware

log = logging.getLogger("cynthion_mcp")


def _safe(fn):
    """Wrap a tool body so unhandled exceptions become structured error responses.

    Without this, a single hardware error (libusb timeout, DebuggerNotFound,
    SoC wedge) propagates through FastMCP's RPC handler and can take down the
    whole stdio server, requiring a Claude Code restart to recover all 17
    tools. Returning a dict with an ``error`` key instead lets the LLM retry
    or call ``recover()`` without losing the rest of the session.

    We preserve ``__signature__`` so FastMCP's introspection still sees the
    real parameter schema, not ``(*args, **kwargs)``.
    """
    sig = inspect.signature(fn)

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            log.warning("tool %s failed: %s", fn.__name__, e)
            return {
                "error": f"{type(e).__name__}: {e}",
                "tool": fn.__name__,
                "traceback_tail": traceback.format_exc().strip().splitlines()[-3:],
            }

    wrapper.__signature__ = sig
    return wrapper

mcp = FastMCP(
    name="cynthion",
    instructions=(
        "Drive a Cynthion USB test instrument. Two modes:\n"
        "  - sniffer (analyzer.bit): passively capture USB traffic on TARGET-C\n"
        "  - emulator (facedancer.bit): impersonate a USB device on TARGET-C\n"
        "Only one bitstream can be loaded at a time. Use `switch_mode` to flip."
    ),
)

_hw = Hardware()


# - hardware -----------------------------------------------------------------


@mcp.tool()
@_safe
def get_status() -> dict:
    """Return current Cynthion connection + bitstream state."""
    return asdict(_hw.get_status())


@mcp.tool()
@_safe
def switch_mode(applet: Literal["analyzer", "facedancer", "selftest"]) -> dict:
    """Load the named applet onto the FPGA.

    'analyzer' enables sniffer mode. 'facedancer' enables emulator mode.
    Use this any time the active bitstream doesn't match the tool you want
    to call.
    """
    status = _hw.switch_to(applet)  # type: ignore[arg-type]
    return asdict(status)


@mcp.tool()
@_safe
def recover() -> dict:
    """Attempt software recovery if the board is stuck (handoff timeout, JTAG hang).

    If recovery returns mode=='missing' or remains stuck, physically replug
    the CONTROL-C cable while holding the PROGRAM button.
    """
    return asdict(_hw.recover())


# - sniffer ------------------------------------------------------------------


@mcp.tool()
@_safe
def capture_start(speed: Literal["auto", "high", "full", "low"] = "auto") -> dict:
    """Begin capturing USB traffic on the TARGET-C / TARGET-A passthrough.

    Requires the analyzer bitstream. Use 'auto' on Cynthion r0.6+.
    """
    s = capture.start_capture(speed)
    return {
        "id": s.id,
        "speed": s.speed,
        "path": str(s.path),
        "started_at": s.started_at,
    }


@mcp.tool()
@_safe
def capture_stop() -> dict:
    """Stop the active capture and return summary stats."""
    s = capture.stop_capture()
    return {
        "id": s.id,
        "speed": s.speed,
        "started_at": s.started_at,
        "finished_at": s.finished_at,
        "bytes_written": s.bytes_written,
        "path": str(s.path),
        "error": s.error,
    }


@mcp.tool()
@_safe
def capture_status() -> dict | None:
    """Return information about the currently active capture, or None."""
    return capture.session_status()


@mcp.tool()
@_safe
def list_captures() -> list[dict]:
    """List all captures stored under ~/.cynthion-mcp/captures/."""
    return capture.list_captures()


@mcp.tool()
@_safe
def read_capture(capture_id: str, offset: int = 0, length: int = 4096) -> dict:
    """Read raw bytes from a stored capture file.

    Returns the bytes as a hex string. Capture files are in Cynthion's native
    framed format — proper USB-packet decoding is a Phase 2 capability.
    """
    data = capture.read_capture_bytes(capture_id, offset=offset, length=length)
    return {
        "capture_id": capture_id,
        "offset": offset,
        "length_requested": length,
        "length_returned": len(data),
        "hex": data.hex(),
    }


# - decode (tshark-backed) ---------------------------------------------------


@mcp.tool()
@_safe
def convert_to_pcap(capture_id: str, force: bool = False) -> dict:
    """Convert a Cynthion native .bin capture into a pcap (LINKTYPE_USB_2_0).

    Idempotent — re-uses the existing pcap if present unless ``force=True``.
    Returns conversion stats including packet/event counts and observed speed.
    """
    result = tshark_mod.ensure_pcap(capture_id, force=force)
    return {
        "capture_id": capture_id,
        "pcap_path": str(result.pcap_path),
        "packets": result.packets,
        "events": result.events,
        "speed": result.speed,
        "duration_s": result.duration_us / 1_000_000,
        "event_counts": result.event_counts,
    }


@mcp.tool()
@_safe
def dissect_packets(
    capture_id: str,
    display_filter: str | None = None,
    limit: int = 100,
) -> dict:
    """Run tshark on a capture and return structured per-packet records.

    ``display_filter`` accepts Wireshark display-filter syntax, e.g.:
      - ``usbll.pid == 0x96``  → only NAK handshakes
      - ``usbll.device_address == 16``  → only traffic to/from device 16
      - ``usbll.pid == 0x2d``  → SETUP tokens only
      - ``usb.transfer_type == 0x02``  → control transfers (when assembled)

    ``limit`` caps the number of packets returned. Set to a small number
    while exploring; raise for analysis.
    """
    _ = tshark_mod.ensure_pcap(capture_id)
    _, pcap_path = tshark_mod._capture_paths(capture_id)
    raw = tshark_mod.run_tshark(pcap_path, display_filter=display_filter, limit=limit)
    summarised = [tshark_mod.summarise_packet(p) for p in raw]
    return {
        "capture_id": capture_id,
        "display_filter": display_filter,
        "limit": limit,
        "returned": len(summarised),
        "packets": summarised,
    }


@mcp.tool()
@_safe
def transaction_summary(capture_id: str) -> dict:
    """High-level counts of token, data, and handshake packets in a capture.

    Useful as a first pass to understand bus activity at a glance.
    """
    _ = tshark_mod.ensure_pcap(capture_id)
    _, pcap_path = tshark_mod._capture_paths(capture_id)
    raw = tshark_mod.run_tshark(pcap_path, display_filter=None, limit=None)

    from collections import Counter
    pid_counter: Counter[str] = Counter()
    device_counter: Counter[str] = Counter()
    for p in raw:
        u = p.get("_source", {}).get("layers", {}).get("usbll", {})
        pid = u.get("usbll.pid")
        if pid:
            name = tshark_mod.PID_NAMES.get(pid, pid)
            pid_counter[name] += 1
        addr = u.get("usbll.device_addr")
        if addr:
            device_counter[f"device_{addr}"] += 1
    return {
        "capture_id": capture_id,
        "total_packets": len(raw),
        "pid_counts": dict(pid_counter),
        "device_counts": dict(device_counter),
    }


@mcp.tool()
@_safe
def find_vendor_requests(capture_id: str, limit: int = 100) -> dict:
    """Find vendor-class SETUP tokens — the high-value targets for reverse engineering.

    Vendor-specific control requests are how proprietary protocols smuggle
    commands. This filters SETUP packets where bmRequestType.type == 2 (vendor).
    """
    return dissect_packets(
        capture_id=capture_id,
        display_filter="usb.bmRequestType.type == 0x2",
        limit=limit,
    )


# - emulator -----------------------------------------------------------------


@mcp.tool()
@_safe
def emulator_diagnose() -> dict:
    """Probe the Moondancer SoC for libgreat-RPC responsiveness.

    Returns ok=True iff the SoC firmware answers basic verbs. Use this before
    other emulator_* tools to verify the facedancer ↔ moondancer stack is
    healthy on this install.
    """
    ok, msg = emulator.probe_moondancer_responsive()
    return {"ok": ok, "message": msg}


@mcp.tool()
@_safe
def emulate_device(
    device_type: Literal["ftdi", "keyboard", "vendor"] = "ftdi",
    vendor_id: int | None = None,
    product_id: int | None = None,
) -> dict:
    """Start emulating a USB device on the TARGET-C port.

    ⚠️  device_type='keyboard' injects keystrokes into the connected host.
    Only use intentionally — if TARGET-C is plugged into the same machine
    running this MCP server, keystrokes will land in whatever app has focus.
    """
    return emulator.emulate_device(
        device_type=device_type,
        vendor_id=vendor_id,
        product_id=product_id,
    )


@mcp.tool()
@_safe
def emulate_from_descriptor(
    device_descriptor_hex: str,
    configuration_descriptor_hex: str | None = None,
    strings: dict[int, str] | None = None,
) -> dict:
    """Clone a USB device: stand up an emulation built from raw descriptor bytes.

    This is the closed-loop replay tool that pairs with `dissect_packets`:
    extract the descriptor bytes a sniffer saw the target send, hand them
    here, and Cynthion now talks the same descriptors back at any host.

    Both descriptor arguments are hex strings (no spaces, no `0x` prefix).
    ``device_descriptor_hex`` must be at least 18 bytes.
    ``configuration_descriptor_hex`` is optional but strongly recommended —
    without it the cloned device exposes no interfaces / endpoints and most
    hosts will be confused.
    """
    return emulator.emulate_from_descriptor(
        device_descriptor_hex=device_descriptor_hex,
        configuration_descriptor_hex=configuration_descriptor_hex,
        strings=strings,
    )


@mcp.tool()
@_safe
def disconnect_device() -> dict:
    """Stop the active device emulation."""
    return emulator.disconnect_device()


@mcp.tool()
@_safe
def inject_serial(text: str) -> dict:
    """Push text out the bulk IN endpoint of an active FTDI emulation."""
    return emulator.inject_serial(text)


# - entrypoint ---------------------------------------------------------------


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("CYNTHION_MCP_LOG", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    mcp.run("stdio")


if __name__ == "__main__":
    main()
