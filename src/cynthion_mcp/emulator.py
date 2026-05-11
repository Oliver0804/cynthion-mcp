"""Emulator-mode (facedancer.bit) device emulation driver.

Drives the Moondancer SoC running on the Facedancer applet to impersonate a
USB device on TARGET-C. Uses facedancer's standard `device.emulate(*coroutines)`
lifecycle so we get the upstream-correct connect → run → disconnect path —
including raising ``EndEmulation`` from a watcher coroutine to stop cleanly.

Earlier attempts here tried to inject ``EndEmulation`` via
``asyncio.run_coroutine_threadsafe`` from outside the loop, which wedged the
SoC because the exception never reached ``device.run()``'s try-block. The
current code uses a periodic watcher coroutine that the main thread signals
via ``threading.Event``.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

_PROBE_TIMEOUT_MS = 1500


class EmulatorUnavailable(RuntimeError):
    """Raised when the Moondancer SoC isn't responding to libgreat RPC."""


def probe_moondancer_responsive() -> tuple[bool, str]:
    """Quick check: does the SoC firmware answer the most basic libgreat verbs?"""
    try:
        import cynthion  # type: ignore
        dev = cynthion.Cynthion()
        comms = getattr(dev, "comms", None)
        backend = getattr(comms, "comms_backend", None) if comms is not None else None
        if backend is not None and hasattr(backend, "default_timeout"):
            backend.default_timeout = _PROBE_TIMEOUT_MS
        try:
            name = dev.board_name() if callable(dev.board_name) else dev.board_name
            _ = dev.apis.moondancer.get_interrupt_events()
            return True, f"Moondancer SoC responsive (board: {name})"
        except Exception as e:
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
            "  3. Rebuild moondancer.bin from cynthion source with the Rust toolchain.\n"
        )


# - Active emulation state -------------------------------------------------


@dataclass
class _ActiveEmulation:
    device: Any
    device_type: str
    stop_signal: threading.Event
    started: threading.Event
    thread: threading.Thread | None = None
    error: str | None = None


_active: _ActiveEmulation | None = None
_lock = threading.Lock()


# - Public MCP tool surface ------------------------------------------------


def emulate_device(
    *,
    device_type: str = "ftdi",
    vendor_id: int | None = None,
    product_id: int | None = None,
) -> dict:
    """Start emulating a USB device on the TARGET-C port."""
    _require_emulator()

    if device_type == "ftdi":
        from facedancer.devices.ftdi import FTDIDevice  # type: ignore
        device = FTDIDevice()
    elif device_type == "keyboard":
        from facedancer.devices.keyboard import USBKeyboardDevice  # type: ignore
        device = USBKeyboardDevice()
    elif device_type == "vendor":
        device = _build_vendor_device()
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
    """Clone a USB device from raw descriptor bytes captured on the wire."""
    _require_emulator()

    try:
        dev_bytes = bytes.fromhex(device_descriptor_hex.replace(" ", "").replace(":", ""))
    except ValueError as e:
        raise ValueError(f"device_descriptor_hex is not valid hex: {e}") from None
    if len(dev_bytes) < 18:
        raise ValueError(
            f"device descriptor must be at least 18 bytes; got {len(dev_bytes)}"
        )

    string_table = {int(k): v for k, v in (strings or {}).items()}

    from facedancer.device import USBBaseDevice  # type: ignore
    device = USBBaseDevice.from_binary_descriptor(dev_bytes, strings=string_table)

    if configuration_descriptor_hex:
        try:
            cfg_bytes = bytes.fromhex(
                configuration_descriptor_hex.replace(" ", "").replace(":", "")
            )
        except ValueError as e:
            raise ValueError(
                f"configuration_descriptor_hex is not valid hex: {e}"
            ) from None
        from facedancer import USBConfiguration  # type: ignore
        cfg = USBConfiguration.from_binary_descriptor(cfg_bytes)
        device.add_configuration(cfg)

    return _spawn_emulation(device, "from_descriptor")


def disconnect_device() -> dict:
    """Signal the active emulation to stop and wait for the worker thread."""
    global _active
    with _lock:
        if _active is None:
            raise RuntimeError("no emulation is running")
        state = _active

    state.stop_signal.set()
    if state.thread is not None:
        state.thread.join(timeout=5.0)
        if state.thread.is_alive():
            log.warning("emulator thread did not exit cleanly within 5 s")

    with _lock:
        _active = None

    return {
        "status": "disconnected",
        "device_type": state.device_type,
        "error": state.error,
    }


def inject_serial(text: str) -> dict:
    """Push a string out the active FTDI emulation's bulk-IN endpoint.

    Requires an active ``emulate_device('ftdi')`` session.
    """
    global _active
    with _lock:
        state = _active
    if state is None or state.device_type != "ftdi":
        raise RuntimeError(
            "inject_serial requires an active FTDI emulation; "
            "call emulate_device(device_type='ftdi') first"
        )
    payload = text.encode("utf-8")
    # facedancer 3.1.x FTDIDevice exposes either `transmit` or `send`.
    send = getattr(state.device, "transmit", None) or getattr(state.device, "send", None)
    if send is None:
        raise RuntimeError(
            "the active FTDI emulation doesn't expose a transmit/send method"
        )
    send(payload)
    return {"status": "sent", "bytes": len(payload)}


# - internals --------------------------------------------------------------


def _build_vendor_device() -> Any:
    from facedancer import (  # type: ignore
        USBDevice,
        USBConfiguration,
        USBInterface,
        USBEndpoint,
        USBDirection,
        USBTransferType,
        use_inner_classes_automatically,
    )

    @use_inner_classes_automatically
    class _Vendor(USBDevice):
        vendor_id: int = 0x1209  # pid.codes test range
        product_id: int = 0xBEEF
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

    return _Vendor()


def _spawn_emulation(device: Any, device_type: str) -> dict:
    """Run ``device.emulate(watcher)`` in a worker thread.

    The watcher is a coroutine that polls a ``threading.Event`` every 100 ms
    and raises ``EndEmulation`` when set — that's facedancer's documented exit
    signal, and the only path that cleanly tears down the SoC USB peripheral
    state. Trying to inject the exception from outside the asyncio loop (as
    the original implementation did) wedged Moondancer's command processor.
    """
    global _active
    with _lock:
        if _active is not None:
            raise RuntimeError(
                f"an emulation is already running (device_type={_active.device_type}); "
                "call disconnect_device() first"
            )

    state = _ActiveEmulation(
        device=device,
        device_type=device_type,
        stop_signal=threading.Event(),
        started=threading.Event(),
    )

    from facedancer.errors import EndEmulation  # type: ignore

    async def _watcher():
        while not state.stop_signal.is_set():
            await asyncio.sleep(0.1)
        raise EndEmulation("disconnect_device called")

    def runner():
        try:
            # Connect synchronously so any USB error surfaces on the worker
            # thread; signal "started" only after connect() returns.
            device.connect()
            state.started.set()
            device.run_with(_watcher())
        except EndEmulation:
            pass
        except Exception as e:
            state.error = f"{type(e).__name__}: {e}"
            state.started.set()
        finally:
            try:
                device.disconnect()
            except Exception as e:
                state.error = (state.error or "") + f" [disconnect: {e}]"

    state.thread = threading.Thread(target=runner, daemon=True, name="emulator")
    state.thread.start()

    state.started.wait(timeout=5.0)
    if state.error is not None and not state.started.is_set():
        raise EmulatorUnavailable(state.error)

    with _lock:
        _active = state

    return {
        "status": "emulating",
        "device_type": device_type,
        "vendor_id": getattr(device, "vendor_id", None),
        "product_id": getattr(device, "product_id", None),
        "error": state.error,
    }
