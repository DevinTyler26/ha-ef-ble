from collections.abc import Sequence
from dataclasses import dataclass

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
from ..props.enums import IntFieldValue
from ..props.protobuf_field import TransformIfMissing


pb_time = proto_attr_mapper(pd303_pb2.ProtoTime)
pb_push_set = proto_attr_mapper(pd303_pb2.ProtoPushAndSet)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _merge_hall_values(*halls: Sequence[float] | None) -> list[float]:
    values: list[float] = []
    for h in halls:
        if h:
            values.extend(h)
    return values


def _errors(error_codes: pd303_pb2.ErrCode):
    if not error_codes or not error_codes.err_code:
        return []
    return [
        e for e in error_codes.err_code
        if e != b"\x00\x00\x00\x00\x00\x00\x00\x00"
    ]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ControlStatus(IntFieldValue):
    UNKNOWN = -1
    OFF = 0
    DISCHARGE = 1
    CHARGE = 2
    EMERGENCY_STOP = 3
    STANDBY = 4


class ForceChargeStatus(IntFieldValue):
    UNKNOWN = -1
    OFF = 0
    ON = 1


# ---------------------------------------------------------------------------
# Field wrappers
# ---------------------------------------------------------------------------

@dataclass
class CircuitPowerField(
    repeated_pb_field_type(
        list_field=lambda pb: _merge_hall_values(
            pb.load_info.hall1_watt,
            pb.load_info.hall2_watt,
            pb.load_info.hall3_watt,
        )
    )
):
    idx: int

    def get_item(self, value: Sequence[float]) -> float | None:
        return round(value[self.idx], 2) if value and len(value) > self.idx else None


@dataclass
class CircuitCurrentField(
    repeated_pb_field_type(
        list_field=lambda pb: _merge_hall_values(
            pb.load_info.hall1_curr,
            pb.load_info.hall2_curr,
            pb.load_info.hall3_curr,
        )
    )
):
    idx: int

    def get_item(self, value: Sequence[float]) -> float | None:
        return round(value[self.idx], 4) if value and len(value) > self.idx else None


@dataclass
class ChannelPowerField(
    repeated_pb_field_type(list_field=pb_time.watt_info.ch_watt)
):
    idx: int

    def get_item(self, value: Sequence[float]) -> float | None:
        return round(value[self.idx], 2) if value and len(value) > self.idx else None


# ---------------------------------------------------------------------------
# Device
# ---------------------------------------------------------------------------

class Device(DeviceBase, ProtobufProps):
    """
    EcoFlow Smart Home Panel 3

    Notes:
    - Circuits are spread across multiple halls (merged here).
    - Control paths are present but gated.
    - Inverter metadata is intentionally omitted (not panel-level).
    """

    SN_PREFIX = b"P101"
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

        # HARD safety gate
        self._enable_circuit_control = False

    # ---------------------------------------------------------------------
    # Packet parsing
    # ---------------------------------------------------------------------

    async def data_parse(self, packet: Packet) -> bool:
        processed = False
        self.reset_updated()

        prev_error_count = self.error_count

        if packet.src == 0x0B and packet.cmdSet == 0x0C:
            if packet.cmdId == 0x01:
                await
