from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from ..commands import TimeCommands
from ..devicebase import AdvertisementData, BLEDevice, DeviceBase
from ..packet import Packet
from ..pb import pd303_pb2
from ..props import (
    Field,
    ProtobufProps,
    pb_field,
    proto_attr_mapper,
    repeated_pb_field_type,
)
from ..props.protobuf_field import TransformIfMissing

# -----------------------------------------------------------------------------
# Protobuf mappers
# -----------------------------------------------------------------------------

pb_time = proto_attr_mapper(pd303_pb2.ProtoTime)
pb_push_set = proto_attr_mapper(pd303_pb2.ProtoPushAndSet)

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _errors(error_codes: pd303_pb2.ErrCode):
    if not error_codes or not error_codes.err_code:
        return []
    return [
        e
        for e in error_codes.err_code
        if e != b"\x00\x00\x00\x00\x00\x00\x00\x00"
    ]


def _get_hall_value(pb: Any, idx: int, attr: str) -> float | None:
    """
    Resolve circuit values across hall1 / hall2 / hall3.

    hall1: circuits  1–12
    hall2: circuits 13–24
    hall3: circuits 25–32
    """
    halls = [
        pb.load_info.hall1_watt if attr == "watt" else pb.load_info.hall1_curr,
        pb.load_info.hall2_watt if attr == "watt" else pb.load_info.hall2_curr,
        pb.load_info.hall3_watt if attr == "watt" else pb.load_info.hall3_curr,
    ]

    base = 0
    for hall in halls:
        if not hall:
            continue
        if base <= idx < base + len(hall):
            return hall[idx - base]
        base += len(hall)

    # SHP3 often just hasn’t published telemetry yet
    return None


# -----------------------------------------------------------------------------
# Field wrappers
# -----------------------------------------------------------------------------

@dataclass
class CircuitPowerField(
    repeated_pb_field_type(list_field=pb_time.load_info.hall1_watt)
):
    idx: int

    def get_item(self, pb) -> float | None:
        val = _get_hall_value(pb, self.idx, "watt")
        if val is None:
            # Do NOT force HA unavailable – wait for data
            raise ValueError("Circuit power not yet available")
        return round(val, 2)


@dataclass
class CircuitCurrentField(
    repeated_pb_field_type(list_field=pb_time.load_info.hall1_curr)
):
    idx: int

    def get_item(self, pb) -> float | None:
        val = _get_hall_value(pb, self.idx, "curr")
        if val is None:
            raise ValueError("Circuit current not yet available")
        return round(val, 4)


@dataclass
class ChannelPowerField(
    repeated_pb_field_type(list_field=pb_time.watt_info.ch_watt)
):
    idx: int

    def get_item(self, value: Sequence[float]) -> float | None:
        if not value or self.idx >= len(value):
            raise ValueError("Channel power not yet available")
        return round(value[self.idx], 2)


# -----------------------------------------------------------------------------
# Device
# -----------------------------------------------------------------------------

class Device(DeviceBase, ProtobufProps):
    """
    EcoFlow Smart Home Panel 3 (SHP3)

    Notes:
    - Telemetry is event-driven (idle panel reports nothing)
    - Config streaming MUST be enabled
    - Circuits span 3 halls
    """

    SN_PREFIX = (b"P101", b"HR63")
    NAME_PREFIX = "EF-SHP3"

    NUM_OF_CIRCUITS = 32
    NUM_OF_CHANNELS = 3

    # ---------------------------------------------------------------------
    # Global power
    # ---------------------------------------------------------------------

    in_use_power = pb_field(pb_time.watt_info.all_hall_watt)

    grid_power = pb_field(
        pb_time.watt_info.grid_watt,
        TransformIfMissing(lambda v: v if v is not None else 0.0),
    )

    battery_level = pb_field(
        pb_push_set.backup_incre_info.backup_bat_per
    )

    errors = pb_field(
        pb_push_set.backup_incre_info.errcode,
        _errors,
    )

    error_count = Field[int]()
    error_happened = Field[bool]()

    # ---------------------------------------------------------------------
    # Circuits (1–32)
    # ---------------------------------------------------------------------

    for i in range(NUM_OF_CIRCUITS):
        locals()[f"circuit_power_{i + 1}"] = CircuitPowerField(i)
        locals()[f"circuit_current_{i + 1}"] = CircuitCurrentField(i)
    del i

    # ---------------------------------------------------------------------
    # Channels
    # ---------------------------------------------------------------------

    channel_power_1 = ChannelPowerField(0)
    channel_power_2 = ChannelPowerField(1)
    channel_power_3 = ChannelPowerField(2)

    # ---------------------------------------------------------------------
    # Identification
    # ---------------------------------------------------------------------

    @staticmethod
    def check(sn: str) -> bool:
        return sn.startswith(Device.SN_PREFIX)

    def __init__(
        self,
        ble_dev: BLEDevice,
        adv_data: AdvertisementData,
        sn: str,
    ) -> None:
        super().__init__(ble_dev, adv_data, sn)
        self._time_commands = TimeCommands(self)

    # ---------------------------------------------------------------------
    # Packet parsing
    # ---------------------------------------------------------------------

    async def data_parse(self, packet: Packet) -> bool:
        processed = False
        self.reset_updated()

        prev_error_count = self.error_count

        # Primary data streams
        if packet.src == 0x0B and packet.cmdSet == 0x0C:
            if packet.cmdId == 0x01:
                await self._conn.replyPacket(packet)
                self.update_from_bytes(pd303_pb2.ProtoTime, packet.payload)
                processed = True

            elif packet.cmdId in (0x20, 0x21):
                await self._conn.replyPacket(packet)
                self.update_from_bytes(
                    pd303_pb2.ProtoPushAndSet, packet.payload
                )
                processed = True

        # Time request
        elif (
            packet.src == 0x35
            and packet.cmdSet == 0x01
            and packet.cmdId == Packet.NET_BLE_COMMAND_CMD_SET_RET_TIME
        ):
            if not packet.payload:
                self._time_commands.async_send_all()
            processed = True

        # Online ready → enable config streaming
        elif packet.src == 0x0B and packet.cmdSet == 0x01 and packet.cmdId == 0x55:
            self._conn._add_task(self.set_config_flag(True))
            processed = True

        elif packet.src == 0x35 and packet.cmdSet == 0x35:
            processed = True

        # Error handling
        self.error_count = len(self.errors) if self.errors is not None else None
        if (
            self.error_count is not None
            and prev_error_count is not None
            and self.error_count > prev_error_count
        ):
            self.error_happened = True

        # Push updated fields to HA
        for field_name in self.updated_fields:
            try:
                self.update_callback(field_name)
                self.update_state(field_name, getattr(self, field_name))
            except Exception:
                # Expected: data not available yet
                self._logger.debug(
                    "%s: %s awaiting data", self.address, field_name
                )

        return processed

    # ---------------------------------------------------------------------
    # Config
    # ---------------------------------------------------------------------

    async def set_config_flag(self, enable: bool):
        ppas = pd303_pb2.ProtoPushAndSet()
        ppas.is_get_cfg_flag = enable

        packet = Packet(
            0x21,
            0x0B,
            0x0C,
            0x21,
            ppas.SerializeToString(),
            0x01,
            0x01,
            0x13,
        )

        await self._conn.sendPacket(packet)
