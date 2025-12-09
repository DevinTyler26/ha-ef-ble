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


def _errors(error_codes: pd303_pb2.ErrCode):
    """Filter out empty error codes."""
    if not error_codes or not error_codes.err_code:
        return []
    return [
        e for e in error_codes.err_code
        if e != b"\x00\x00\x00\x00\x00\x00\x00\x00"
    ]


# ---------------------------------------------------------------------------
# Field wrappers
# ---------------------------------------------------------------------------


@dataclass
class CircuitPowerField(
    repeated_pb_field_type(list_field=pb_time.load_info.hall1_watt)
):
    idx: int

    def get_item(self, value: Sequence[float]) -> float | None:
        if not value or self.idx >= len(value):
            return None
        return round(value[self.idx], 2)


@dataclass
class CircuitCurrentField(
    repeated_pb_field_type(list_field=pb_time.load_info.hall1_curr)
):
    idx: int

    def get_item(self, value: Sequence[float]) -> float | None:
        if not value or self.idx >= len(value):
            return None
        return round(value[self.idx], 4)


@dataclass
class ChannelPowerField(
    repeated_pb_field_type(list_field=pb_time.watt_info.ch_watt)
):
    idx: int

    def get_item(self, value: Sequence[float]) -> float | None:
        if not value or self.idx >= len(value):
            return None
        return round(value[self.idx], 2)


# ---------------------------------------------------------------------------
# Device
# ---------------------------------------------------------------------------


class Device(DeviceBase, ProtobufProps):
    """
    EcoFlow Smart Home Panel 3.

    NOTE: This is modeled after SHP2. SHP3 has 32 circuits, but the current
    protobuf only exposes a single hall list, so circuits above the length
    of that list will show as unavailable/None.
    """

    # Serial prefix for SHP3 (example: b"HR63....")
    SN_PREFIX = (b"P101", b"HR63")
    # Bluetooth name prefix (example: "EF-HR630131")
    NAME_PREFIX = "EF-HR63"

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

    # We still bind to hall1_* like SHP2. If the underlying list has fewer
    # than 32 elements, the extra circuits will just be None.
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
    def check(sn) -> bool:
        # In the integration, `sn` is bytes for SHP2, so keep that behavior.
        # Example: sn == b"HR630131..."
        try:
            return isinstance(sn, (bytes, bytearray)) and sn.startswith(Device.SN_PREFIX)
        except Exception:
            return False

    def __init__(
        self,
        ble_dev: BLEDevice,
        adv_data: AdvertisementData,
        sn,
    ) -> None:
        super().__init__(ble_dev, adv_data, sn)
        self._time_commands = TimeCommands(self)
        # If/when we understand SHP3 relay control semantics we can flip this.
        self._enable_circuit_control = False

    # ---------------------------------------------------------------------
    # Packet parsing
    # ---------------------------------------------------------------------

    async def data_parse(self, packet: Packet) -> bool:
        processed = False
        self.reset_updated()

        prev_error_count = self.error_count

        # Same packet layout as SHP2 for now:
        #   src 0x0B, cmdSet 0x0C, cmdId 0x01 -> ProtoTime
        #   src 0x0B, cmdSet 0x0C, cmdId 0x20/0x21 -> ProtoPushAndSet
        if packet.src == 0x0B and packet.cmdSet == 0x0C:
            if packet.cmdId == 0x01:
                # master_info, load_info, backup_info, watt_info, master_ver_info
                self._logger.debug(
                    "%s: %s: Parsed ProtoTime packet: %r",
                    self.address,
                    self.name,
                    packet,
                )
                await self._conn.replyPacket(packet)
                self.update_from_bytes(
                    pd303_pb2.ProtoTime,
                    packet.payload,
                )
                processed = True

            elif packet.cmdId in (0x20, 0x21):
                # backup_incre_info / is_get_cfg_flag
                self._logger.debug(
                    "%s: %s: Parsed ProtoPushAndSet packet: %r",
                    self.address,
                    self.name,
                    packet,
                )
                await self._conn.replyPacket(packet)
                self.update_from_bytes(
                    pd303_pb2.ProtoPushAndSet,
                    packet.payload,
                )
                processed = True

        # Time sync request (same as SHP2)
        elif (
            packet.src == 0x35
            and packet.cmdSet == 0x01
            and packet.cmdId == Packet.NET_BLE_COMMAND_CMD_SET_RET_TIME
        ):
            if not packet.payload:
                # Device requested time / timezone; respond so it can send predictions/configs
                self._time_commands.async_send_all()
            processed = True

        # Ping / keep-alive
        elif packet.src == 0x35 and packet.cmdSet == 0x35:
            self._logger.debug(
                "%s: %s: Ping received: %r",
                self.address,
                self.name,
                packet,
            )
            processed = True

        # -----------------------------------------------------------------
        # Error handling / state updates
        # -----------------------------------------------------------------

        self.error_count = len(self.errors) if self.errors is not None else None

        if (
            self.error_count is not None
            and (
                prev_error_count is None
                or self.error_count > prev_error_count
            )
        ):
            self.error_happened = True
            self._logger.warning(
                "%s: %s: Error happened on device: %s",
                self.address,
                self.name,
                self.errors,
            )

        for field_name in self.updated_fields:
            try:
                self.update_callback(field_name)
                self.update_state(field_name, getattr(self, field_name))
            except Exception:
                self._logger.exception(
                    "%s: %s: Failed updating field %s",
                    self.address,
                    self.name,
                    field_name,
                )

        return processed

    # ---------------------------------------------------------------------
    # Config
    # ---------------------------------------------------------------------

    async def set_config_flag(self, enable: bool):
        """Enable/disable sending config data from device to host (same as SHP2)."""
        self._logger.debug("%s: setConfigFlag: %s", self._address, enable)

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
