"""Emulator-mode (facedancer.bit) device emulation driver.

⚠️  Currently blocked on a version compatibility issue between facedancer 3.1.2
(PyPI) and the Moondancer SoC firmware bundled in the cynthion 0.2.4 wheel.
Symptom: every libgreat RPC to the SoC (including the basic ``read_board_id``)
times out, even though the bitstream loads and the USB endpoints enumerate.

The MCP tool surface is finalised here so that once the version skew is
resolved (downgrade ``facedancer`` to 3.1.1 / 3.1.0, or rebuild
``moondancer.bin`` from cynthion source via the Rust toolchain), no callers
need to change.

The pre-flight check (``probe_moondancer_responsive``) is fast (~2 seconds)
and gives a clean error message instead of the 5-second libusb timeout. Every
public function calls it before doing real work.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

log = logging.getLogger(__name__)

_PROBE_TIMEOUT_MS = 1500


class EmulatorUnavailable(RuntimeError):
    """Raised when the Moondancer SoC isn't responding to libgreat RPC."""


def probe_moondancer_responsive() -> tuple[bool, str]:
    """Quick check: does the SoC firmware answer the most basic libgreat verb?

    Returns ``(ok, message)``. Never raises.
    """
    try:
        import cynthion  # type: ignore
        dev = cynthion.Cynthion()
        # The bulk-RPC has a built-in retry/abort path that takes ~5s when the
        # SoC is wedged. We shrink that window by setting a custom timeout on
        # the comms backend if possible — otherwise we accept the longer wait.
        comms = getattr(dev, "comms", None)
        backend = getattr(comms, "comms_backend", None) if comms is not None else None
        if backend is not None and hasattr(backend, "default_timeout"):
            backend.default_timeout = _PROBE_TIMEOUT_MS
        try:
            # `board_name` is a Cynthion property that goes through libgreat
            # core RPC. If the SoC firmware is running, we get back a string
            # like "Facedancer (Cynthion Project)". `get_interrupt_events` is
            # the Moondancer-specific verb that confirms the emulator class is
            # wired up too — empty tuple is the expected idle response.
            name = dev.board_name() if callable(dev.board_name) else dev.board_name
            _ = dev.apis.moondancer.get_interrupt_events()
            return True, f"Moondancer SoC responsive (board: {name})"
        except Exception as e:  # libgreat timeout, libusb timeout, etc
            return False, f"Moondancer SoC not responsive: {type(e).__name__}: {e}"
    except Exception as e:
        return False, f"could not open Cynthion comms: {type(e).__name__}: {e}"


def _require_emulator() -> None:
    ok, msg = probe_moondancer_responsive()
    if not ok:
        raise EmulatorUnavailable(
            f"{msg}\n\n"
            "Likely cause: facedancer Python package vs. Moondancer SoC firmware "
            "version skew. Fixes to try (in order):\n"
            "  1. Switch back to analyzer applet to confirm the board itself is OK.\n"
            "  2. Downgrade facedancer to a version released near cynthion 0.2.4:\n"
            "       pip install 'facedancer==3.1.1'\n"
            "  3. Rebuild moondancer.bin from cynthion source with the Rust toolchain:\n"
            "       cd /Users/oliver/code/goodtools/cynthion/cynthion/python && make binaries\n"
        )


# - Public MCP tool surface ------------------------------------------------


_emulation_thread: threading.Thread | None = None
_emulation_loop: asyncio.AbstractEventLoop | None = None
_active_device: Any | None = None


def emulate_device(
    *,
    device_type: str = "ftdi",
    vendor_id: int | None = None,
    product_id: int | None = None,
) -> dict:
    """Start emulating a USB device on the TARGET-C port.

    Args:
        device_type: One of ``"ftdi"``, ``"keyboard"`` (HID — only use intentionally),
                     or ``"vendor"`` for a bare vendor-class device.
        vendor_id, product_id: Override the device's defaults.
    """
    _require_emulator()

    from facedancer import USBDevice  # type: ignore

    if device_type == "ftdi":
        from facedancer.devices.ftdi import FTDIDevice  # type: ignore
        device = FTDIDevice()
    elif device_type == "keyboard":
        from facedancer.devices.keyboard import USBKeyboardDevice  # type: ignore
        device = USBKeyboardDevice()
    elif device_type == "vendor":
        # Built dynamically rather than imported — facedancer doesn't ship a
        # generic vendor-only device.
        from facedancer import (
            USBConfiguration,
            USBInterface,
            USBEndpoint,
            USBDirection,
            USBTransferType,
            use_inner_classes_automatically,
        )

        @use_inner_classes_automatically
        class _Vendor(USBDevice):
            vendor_id_: int = 0x1209  # pid.codes test range
            product_id_: int = 0xBEEF
            product_string: str = "Cynthion MCP vendor device"

            class _Cfg(USBConfiguration):
                class _Iface(USBInterface):
                    class_number: int = 0xFF

                    class _In(USBEndpoint):
                        number: int = 1
                        direction: USBDirection = USBDirection.IN
                        transfer_type: USBTransferType = USBTransferType.BULK

                    class _Out(USBEndpoint):
                        number: int = 2
                        direction: USBDirection = USBDirection.OUT
                        transfer_type: USBTransferType = USBTransferType.BULK

        device = _Vendor()
    else:
        raise ValueError(f"unknown device_type {device_type!r}")

    if vendor_id is not None:
        device.vendor_id = vendor_id
    if product_id is not None:
        device.product_id = product_id

    return _spawn_emulation(device, device_type)


def emulate_from_descriptor(
    device_descriptor_hex: str,
    configuration_descriptor_hex: str | None = None,
    strings: dict[int, str] | None = None,
) -> dict:
    """Stand up an emulated device from raw descriptor bytes captured on the wire.

    This is the **device-cloning** entry point. Workflow:

      1. Sniff the target device during enumeration (switch_mode('analyzer'),
         capture_start, replug target, capture_stop).
      2. Use ``dissect_packets`` to locate the DATA0/DATA1 packets that
         followed the host's GET_DESCRIPTOR SETUPs.
      3. Extract the device descriptor (18 bytes) and the configuration
         descriptor (variable length — the wTotalLength field at offset 2-3
         of the config descriptor tells you).
      4. Pass them here. Cynthion will impersonate the target device on
         TARGET-C from this moment until disconnect_device().
    """
    _require_emulator()
    from facedancer import USBDevice  # type: ignore
    from facedancer.device import USBBaseDevice  # type: ignore

    dev_bytes = bytes.fromhex(device_descriptor_hex)
    if len(dev_bytes) < 18:
        raise ValueError(
            f"device descriptor must be at least 18 bytes; got {len(dev_bytes)}"
        )

    string_table = {int(k): v for k, v in (strings or {}).items()}
    device = USBBaseDevice.from_binary_descriptor(dev_bytes, strings=string_table)

    if configuration_descriptor_hex:
        from facedancer import USBConfiguration  # type: ignore
        cfg_bytes = bytes.fromhex(configuration_descriptor_hex)
        cfg = USBConfiguration.from_binary_descriptor(cfg_bytes)
        device.add_configuration(cfg)

    return _spawn_emulation(device, "from_descriptor")


def disconnect_device() -> dict:
    global _emulation_thread, _emulation_loop, _active_device
    if _emulation_thread is None:
        raise RuntimeError("no emulation is running")

    from facedancer.errors import EndEmulation  # type: ignore

    loop = _emulation_loop
    if loop is not None:
        async def _stop():
            raise EndEmulation("disconnect_device called")
        try:
            asyncio.run_coroutine_threadsafe(_stop(), loop)
        except Exception:
            pass

    _emulation_thread.join(timeout=3.0)
    _emulation_thread = None
    _emulation_loop = None
    _active_device = None
    return {"status": "disconnected"}


def inject_serial(text: str) -> dict:
    """Send a UTF-8 string out through an emulated FTDI device's bulk IN endpoint."""
    _require_emulator()
    if _active_device is None or type(_active_device).__name__ != "FTDIDevice":
        raise RuntimeError("inject_serial requires an active FTDI emulation; call emulate_device(device_type='ftdi') first")
    # Defer to facedancer FTDI's send_data when available.
    payload = text.encode("utf-8")
    send = getattr(_active_device, "send_data", None) or getattr(_active_device, "send", None)
    if send is None:
        raise RuntimeError("the active FTDI emulation doesn't expose a send/send_data method")
    send(payload)
    return {"status": "sent", "bytes": len(payload)}


# - internals --------------------------------------------------------------


def _spawn_emulation(device: Any, device_type: str) -> dict:
    """Run `device.emulate()` in a worker thread with its own asyncio loop."""
    global _emulation_thread, _emulation_loop, _active_device

    started = threading.Event()
    error: dict = {}

    def runner():
        global _emulation_loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        _emulation_loop = loop
        try:
            device.connect()
            started.set()
            loop.run_until_complete(device.run())
        except Exception as e:
            error["err"] = f"{type(e).__name__}: {e}"
            started.set()
        finally:
            try:
                device.disconnect()
            except Exception:
                pass
            loop.close()

    _active_device = device
    t = threading.Thread(target=runner, daemon=True, name="emulator")
    _emulation_thread = t
    t.start()

    started.wait(timeout=5.0)
    if "err" in error:
        _active_device = None
        raise EmulatorUnavailable(error["err"])

    return {
        "status": "emulating",
        "device_type": device_type,
        "vendor_id": getattr(device, "vendor_id", None),
        "product_id": getattr(device, "product_id", None),
    }
