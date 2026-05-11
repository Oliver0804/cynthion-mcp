"""Sniffer-mode (analyzer.bit) capture driver.

Speaks the gateware's vendor protocol directly via libusb1:

  - vendor request 1 (SET_STATE) on interface 0: enable/disable + speed select
  - bulk IN endpoint 0x81: stream of captured packets (Cynthion native format)

Raw capture bytes are written to a file under ``captures/`` for later decode.
Packet decoding into USB transactions is intentionally NOT done here —
Packetry is the reference decoder; for MCP use cases LLMs typically want raw
bytes + summary stats, with deeper decode deferred to a follow-up tool.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Literal

import usb.core
import usb.util

log = logging.getLogger(__name__)

ANALYZER_VID = 0x1D50
ANALYZER_PID = 0x615B
BULK_ENDPOINT_ADDR = 0x81
VENDOR_IFACE = 0


class VendorRequest(IntEnum):
    GET_STATE = 0
    SET_STATE = 1
    GET_SPEEDS = 2
    SET_TEST_CONFIG = 3
    GET_MINOR_VERSION = 4


class CaptureSpeed(IntEnum):
    # State-register bits 1-2 encoding the analyzer speed.
    # The mapping mirrors USBAnalyzerSpeed in cynthion.gateware.analyzer.speeds:
    # HIGH = USBSpeed.HIGH(=0), FULL = USBSpeed.FULL(=1), LOW = USBSpeed.LOW(=2),
    # AUTO = 0b11. The earlier comment in top.py (`0b00=HS, 0b01=FS, 0b11=LS`)
    # is *out of date* — 0b10 is now LOW and 0b11 is AUTO on r0.6+.
    HIGH = 0b00
    FULL = 0b01
    LOW = 0b10
    AUTO = 0b11


SPEED_NAMES = {
    "auto": CaptureSpeed.AUTO,
    "high": CaptureSpeed.HIGH,
    "full": CaptureSpeed.FULL,
    "low": CaptureSpeed.LOW,
}

CAPTURES_DIR = Path.home() / ".cynthion-mcp" / "captures"


@dataclass
class CaptureSession:
    id: str
    speed: str
    started_at: float
    path: Path
    _thread: threading.Thread | None = field(default=None, repr=False)
    _stop_flag: threading.Event = field(default_factory=threading.Event, repr=False)
    _dev: Any = field(default=None, repr=False)  # pyusb Device handle owned by the drainer
    bytes_written: int = 0
    finished_at: float | None = None
    error: str | None = None


_active: CaptureSession | None = None
_lock = threading.Lock()


def _open_analyzer() -> usb.core.Device:
    dev = usb.core.find(idVendor=ANALYZER_VID, idProduct=ANALYZER_PID)
    if dev is None:
        raise RuntimeError(
            "Analyzer USB device not found at 1d50:615b. "
            "Is the analyzer bitstream loaded? Try `switch_mode('analyzer')` first."
        )
    try:
        dev.set_configuration()
    except usb.core.USBError:
        # Already configured — that's fine.
        pass
    return dev


def _vendor_write(dev: usb.core.Device, request: VendorRequest, value: int) -> None:
    # bmRequestType: host-to-device | vendor | interface
    dev.ctrl_transfer(
        bmRequestType=0x41,
        bRequest=int(request),
        wValue=value,
        wIndex=VENDOR_IFACE,
        data_or_wLength=None,
        timeout=1000,
    )


def _set_state(dev: usb.core.Device, enable: bool, speed: CaptureSpeed) -> None:
    state = (1 if enable else 0) | (int(speed) << 1)
    _vendor_write(dev, VendorRequest.SET_STATE, state)


def start_capture(speed: Literal["auto", "high", "full", "low"] = "auto") -> CaptureSession:
    global _active
    with _lock:
        if _active is not None and _active.finished_at is None:
            raise RuntimeError(
                f"a capture is already running (id={_active.id}); call stop_capture() first"
            )

        speed_norm = speed.lower()
        if speed_norm not in SPEED_NAMES:
            raise ValueError(
                f"unknown speed {speed!r}; choose one of {list(SPEED_NAMES)}"
            )
        cs = SPEED_NAMES[speed_norm]

        CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
        capture_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        path = CAPTURES_DIR / f"{capture_id}.bin"

        session = CaptureSession(
            id=capture_id,
            speed=speed_norm,
            started_at=time.time(),
            path=path,
        )

        dev = _open_analyzer()
        _set_state(dev, enable=True, speed=cs)
        session._dev = dev

        def drainer():
            # One USB handle owned by this thread for the lifetime of the
            # capture. The drainer is also responsible for disabling capture
            # and disposing the handle on exit, so we never have two threads
            # claiming the same device.
            try:
                with path.open("wb") as fp:
                    while not session._stop_flag.is_set():
                        try:
                            chunk = dev.read(BULK_ENDPOINT_ADDR, 16384, timeout=200)
                        except usb.core.USBTimeoutError:
                            continue
                        except Exception as e:
                            session.error = f"{type(e).__name__}: {e}"
                            break
                        if chunk:
                            fp.write(chunk)
                            session.bytes_written += len(chunk)
            finally:
                # Disable the analyzer state register, then release the handle.
                try:
                    _set_state(dev, enable=False, speed=CaptureSpeed.AUTO)
                except Exception as e:
                    log.warning("could not disable analyzer state: %s", e)
                try:
                    usb.util.dispose_resources(dev)
                except Exception as e:
                    log.info("dispose_resources skipped: %s", e)
                session.finished_at = time.time()

        t = threading.Thread(target=drainer, daemon=True, name=f"capture-{capture_id}")
        session._thread = t
        t.start()

        _active = session
        log.info("capture %s started (speed=%s)", capture_id, speed_norm)
        return session


def stop_capture() -> CaptureSession:
    global _active
    with _lock:
        if _active is None or _active.finished_at is not None:
            raise RuntimeError("no active capture to stop")
        session = _active

    # Drainer disables analyzer state and disposes the USB handle in its
    # finally block, so we just signal stop and wait.
    session._stop_flag.set()
    if session._thread is not None:
        session._thread.join(timeout=3.0)

    log.info(
        "capture %s stopped (%d bytes, %.2f s)",
        session.id,
        session.bytes_written,
        (session.finished_at or time.time()) - session.started_at,
    )
    return session


def list_captures() -> list[dict]:
    if not CAPTURES_DIR.exists():
        return []
    out = []
    for p in sorted(CAPTURES_DIR.glob("*.bin")):
        st = p.stat()
        out.append({
            "id": p.stem,
            "path": str(p),
            "size": st.st_size,
            "mtime": st.st_mtime,
        })
    return out


def read_capture_bytes(capture_id: str, offset: int = 0, length: int = 4096) -> bytes:
    path = CAPTURES_DIR / f"{capture_id}.bin"
    if not path.is_file():
        raise FileNotFoundError(f"no capture with id {capture_id}")
    with path.open("rb") as fp:
        fp.seek(offset)
        return fp.read(length)


def session_status() -> dict | None:
    if _active is None:
        return None
    return {
        "id": _active.id,
        "speed": _active.speed,
        "started_at": _active.started_at,
        "bytes_written": _active.bytes_written,
        "finished_at": _active.finished_at,
        "error": _active.error,
        "path": str(_active.path),
    }
