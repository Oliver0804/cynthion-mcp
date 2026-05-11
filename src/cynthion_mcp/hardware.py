"""Hardware abstraction for the Cynthion board.

Wraps cynthion + apollo_fpga + the asset lookup logic so the MCP tools can call
high-level operations like `get_status()` and `switch_to("analyzer")` without
each worrying about JTAG recovery.

The recovery routine encodes a hard-won lesson: after a failed `cynthion run
facedancer`, the FPGA's JTAG TAP can get stuck and reject subsequent bitstream
loads with "data past SRAM array / fffffff8". Issuing an Apollo `REQUEST_RECONFIGURE`
(soft_reset) restores the TAP. We always try that before re-running a bitstream
load when the previous one failed.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Literal

import usb.core
import usb.util
from apollo_fpga import ApolloDebugger, DebuggerNotFound

log = logging.getLogger(__name__)

Applet = Literal["analyzer", "facedancer", "selftest"]

GSG_VID = 0x1D50
APOLLO_STUB_PID = 0x615B  # FPGA bitstream's Apollo stub
APOLLO_MCU_PID = 0x615C  # Apollo MCU direct (FPGA offline)


@dataclass
class BoardStatus:
    connected: bool
    mode: Literal["stub", "mcu_direct", "missing"]
    bitstream_name: str | None  # "USB Analyzer", "Facedancer", etc — None when in mcu_direct
    vendor_id: int | None
    product_id: int | None
    hardware: str | None  # "Cynthion r1.4"
    serial_number: str | None
    firmware_version: str | None


class Hardware:
    """Stateful wrapper over a Cynthion board.

    Instances do not hold long-lived USB handles — every operation opens a fresh
    ApolloDebugger to avoid stale handles after re-enumeration."""

    def get_status(self) -> BoardStatus:
        # Look at raw USB first to distinguish stub-mode vs mcu-direct vs missing.
        dev = self._find_gsg_device()
        if dev is None:
            return BoardStatus(
                connected=False,
                mode="missing",
                bitstream_name=None,
                vendor_id=None,
                product_id=None,
                hardware=None,
                serial_number=None,
                firmware_version=None,
            )

        if dev.idProduct == APOLLO_MCU_PID:
            return self._status_via_apollo(dev, mode="mcu_direct")
        return self._status_via_apollo(dev, mode="stub")

    def switch_to(self, applet: Applet) -> BoardStatus:
        """Load the named applet onto the FPGA. Recovers from stuck states."""
        from cynthion.commands.util import (
            find_cynthion_asset,
            find_cynthion_bitstream,
            flash_soc_firmware,
            run_bitstream,
        )

        log.info("switching FPGA to %s applet", applet)

        # Always do a soft_reset first — that's the move that unsticks a half-broken
        # JTAG TAP from a previous failed run.
        self._safe_soft_reset()

        for attempt in (1, 2):
            try:
                device = self._open_apollo(force_offline=True)
                if applet == "facedancer":
                    flash_soc_firmware(device, find_cynthion_asset("moondancer.bin"))
                run_bitstream(
                    device,
                    find_cynthion_bitstream(device, f"{applet}.bit"),
                )
                break
            except (OSError, IOError) as e:
                log.warning("%s applet load attempt %d failed: %s", applet, attempt, e)
                if attempt == 1:
                    log.info("attempting recovery via Apollo soft_reset")
                    self._safe_soft_reset()
                    time.sleep(2)
                else:
                    raise

        # Give the new gateware a moment to re-enumerate.
        time.sleep(2)
        return self.get_status()

    def recover(self) -> BoardStatus:
        """Best-effort attempt to unstick a non-responsive board without a physical replug."""
        self._safe_soft_reset()
        time.sleep(3)
        # USB bus reset on whatever is currently there.
        dev = self._find_gsg_device()
        if dev is not None:
            try:
                dev.reset()
            except Exception as e:
                log.info("usb reset attempt failed: %s", e)
        time.sleep(2)
        return self.get_status()

    # -- internals -----------------------------------------------------------

    def _find_gsg_device(self) -> usb.core.Device | None:
        # Filter strictly to Cynthion's known PIDs — VID 0x1d50 is shared with
        # other GSG products (HackRF One = 0x6089) and `find(idVendor=...)`
        # would silently pick whichever enumerated first.
        for pid in (APOLLO_STUB_PID, APOLLO_MCU_PID):
            dev = usb.core.find(idVendor=GSG_VID, idProduct=pid)
            if dev is not None:
                return dev
        return None

    def _open_apollo(self, force_offline: bool = False) -> ApolloDebugger:
        # Only one shot at recovery — `recover()` will USB-reset things which
        # may leave the device unfindable for a beat; trying repeatedly here
        # races with the bus and produced an infinite log loop in an earlier
        # version. If the second open also fails, propagate the error.
        try:
            return ApolloDebugger(force_offline=force_offline)
        except DebuggerNotFound as e:
            log.warning("could not open Apollo: %s — single recovery pass", e)
            self.recover()
            return ApolloDebugger(force_offline=force_offline)

    def _safe_soft_reset(self) -> None:
        try:
            dbg = ApolloDebugger()
            dbg.soft_reset()
            log.info("Apollo soft_reset issued")
        except Exception as e:
            log.info("soft_reset skipped: %s", e)

    def _status_via_apollo(self, dev, *, mode: str) -> BoardStatus:
        bitstream_name: str | None = None
        hardware: str | None = None
        serial: str | None = None
        fw: str | None = None
        if mode == "stub":
            # In stub mode the bitstream owns USB; we only read USB descriptors,
            # not Apollo state (opening ApolloDebugger() here would either fail
            # ("stub found but not requested to be forced offline") or invasively
            # take the FPGA offline — both of which the caller doesn't want from
            # a read-only status query.
            try:
                bitstream_name = usb.util.get_string(dev, dev.iProduct)
            except Exception:
                bitstream_name = None
            return BoardStatus(
                connected=True,
                mode=mode,  # type: ignore[arg-type]
                bitstream_name=bitstream_name,
                vendor_id=dev.idVendor,
                product_id=dev.idProduct,
                hardware=None,
                serial_number=None,
                firmware_version=None,
            )

        # MCU-direct: Apollo accepts a plain open.
        try:
            dbg = ApolloDebugger()
            major, minor = dbg.detect_connected_version()
            hardware = f"Cynthion r{major}.{minor}"
            serial = dbg.serial_number
            fw = str(dbg.get_firmware_version())
        except Exception as e:
            log.info("apollo info read failed: %s", e)
        return BoardStatus(
            connected=True,
            mode=mode,  # type: ignore[arg-type]
            bitstream_name=bitstream_name,
            vendor_id=dev.idVendor,
            product_id=dev.idProduct,
            hardware=hardware,
            serial_number=serial,
            firmware_version=fw,
        )
