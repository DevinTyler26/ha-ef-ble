import asyncio
import hashlib
import logging
import struct
import traceback
from collections.abc import Awaitable, Callable, Coroutine
from enum import StrEnum, auto

import ecdsa
from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.exc import BleakError
from bleak_retry_connector import (
    MAX_CONNECT_ATTEMPTS,
    BleakNotFoundError,
    establish_connection,
)
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from . import keydata
from .crc import crc16
from .encpacket import EncPacket
from .exceptions import (
    AuthFailedError,
    ConnectionTimeout,
    FailedToAuthenticate,
    MaxConnectionAttemptsReached,
    MaxReconnectAttemptsReached,
    PacketParseError,
    PacketReceiveError,
)
from .logging_util import ConnectionLogger, LogOptions
from .packet import Packet

MAX_RECONNECT_ATTEMPTS = 2
MAX_CONNECTION_ATTEMPTS = 10

DisconnectListener = Callable[[Exception | type[Exception] | None], None]


# -----------------------------------------------------------------------------
# Connection State
# -----------------------------------------------------------------------------

class ConnectionState(StrEnum):
    NOT_CONNECTED = auto()
    CREATED = auto()
    ESTABLISHING_CONNECTION = auto()
    CONNECTED = auto()
    PUBLIC_KEY_EXCHANGE = auto()
    PUBLIC_KEY_RECEIVED = auto()
    REQUESTING_SESSION_KEY = auto()
    SESSION_KEY_RECEIVED = auto()
    REQUESTING_AUTH_STATUS = auto()
    AUTH_STATUS_RECEIVED = auto()
    AUTHENTICATING = auto()
    AUTHENTICATED = auto()

    ERROR_TIMEOUT = auto()
    ERROR_NOT_FOUND = auto()
    ERROR_BLEAK = auto()
    ERROR_UNKNOWN = auto()
    ERROR_AUTH_FAILED = auto()
    ERROR_TOO_MANY_ERRORS = auto()
    ERROR_MAX_RECONNECT_ATTEMPTS_REACHED = auto()

    RECONNECTING = auto()
    DISCONNECTING = auto()
    DISCONNECTED = auto()

    def is_error(self):
        return self.name.startswith("ERROR")

    def is_terminal(self):
        return self in (
            ConnectionState.AUTHENTICATED,
            ConnectionState.DISCONNECTED,
            ConnectionState.NOT_CONNECTED,
        ) or self.is_error()


# -----------------------------------------------------------------------------
# Connection
# -----------------------------------------------------------------------------

class Connection:
    """
    BLE connection + auth + packet handling.

    This version is SHP3-tolerant:
    - encrypted garbage is dropped softly
    - prefix / CRC mismatches are not fatal
    - logging API matches original integration
    """

    NOTIFY_CHARACTERISTIC = "00000003-0000-1000-8000-00805f9b34fb"
    WRITE_CHARACTERISTIC = "00000002-0000-1000-8000-00805f9b34fb"

    def __init__(
        self,
        ble_dev: BLEDevice,
        dev_sn: str,
        user_id: str,
        data_parse: Callable[[Packet], Awaitable[bool]],
        packet_parse: Callable[[bytes], Awaitable[Packet]],
        on_state_change: Callable[[ConnectionState], None] = lambda _: None,
    ) -> None:
        self._ble_dev = ble_dev
        self._address = ble_dev.address
        self._dev_sn = dev_sn
        self._user_id = user_id

        self._data_parse = data_parse
        self._packet_parse = packet_parse
        self._on_state_change = on_state_change

        self._client: BleakClient | None = None

        self._state = ConnectionState.CREATED
        self._connected = asyncio.Event()
        self._disconnected = asyncio.Event()

        self._retry_on_disconnect = True
        self._enc_packet_buffer = b""

        self._tasks: set[asyncio.Task] = set()

        self._errors = 0
        self._last_exception: Exception | type[Exception] | None = None

        self._private_key = None
        self._public_key = None
        self._shared_key = None
        self._session_key = None
        self._iv = None

        self._logger = ConnectionLogger(self)

    # ------------------------------------------------------------------
    # Compatibility helpers (required by devicebase.py)
    # ------------------------------------------------------------------

    def with_logging_options(self, options: LogOptions):
        self._logger.set_options(options)
        return self

    # ------------------------------------------------------------------
    # Encryption helpers
    # ------------------------------------------------------------------

    async def decryptShared(self, data: bytes) -> bytes:
        aes = AES.new(self._shared_key, AES.MODE_CBC, self._iv)
        return unpad(aes.decrypt(data), AES.block_size)

    async def decryptSession(self, data: bytes) -> bytes:
        aes = AES.new(self._session_key, AES.MODE_CBC, self._iv)
        return unpad(aes.decrypt(data), AES.block_size)

    async def encryptSession(self, data: bytes) -> bytes:
        aes = AES.new(self._session_key, AES.MODE_CBC, self._iv)
        return aes.encrypt(pad(data, AES.block_size))

    # ------------------------------------------------------------------
    # Packet parsing
    # ------------------------------------------------------------------

    async def parseSimple(self, data: bytes) -> bytes | None:
        if len(data) < 8:
            return None

        header = data[:6]
        payload_len = struct.unpack("<H", header[4:6])[0]
        data_end = 6 + payload_len

        if data_end > len(data):
            return None

        payload = data[6 : data_end - 2]
        crc = data[data_end - 2 : data_end]

        if crc16(header + payload) != struct.unpack("<H", crc)[0]:
            raise PacketParseError("CRC mismatch")

        return payload

    async def parseEncPackets(self, data: bytes) -> list[Packet]:
        if not data:
            return []

        if self._enc_packet_buffer:
            data = self._enc_packet_buffer + data
            self._enc_packet_buffer = b""

        packets: list[Packet] = []

        if len(data) < 8:
            return []

        while data:
            if not data.startswith(EncPacket.PREFIX):
                self._logger.debug(
                    "%s: dropping encrypted frame (bad prefix): %s",
                    self._address,
                    data.hex(),
                )
                return packets

            header = data[:6]
            payload_len = struct.unpack("<H", header[4:6])[0]
            data_end = 6 + payload_len

            if data_end > len(data):
                self._enc_packet_buffer = data
                break

            payload = data[6 : data_end - 2]
            crc = data[data_end - 2 : data_end]
            data = data[data_end:]

            if crc16(header + payload) != struct.unpack("<H", crc)[0]:
                self._logger.debug(
                    "%s: dropping encrypted frame (CRC mismatch)",
                    self._address,
                )
                continue

            try:
                decrypted = await self.decryptSession(payload)
                packet = await self._packet_parse(decrypted)
                if packet:
                    packets.append(packet)
            except Exception as exc:  # noqa: BLE001
                self._logger.debug(
                    "%s: dropping encrypted frame (parse error): %s",
                    self._address,
                    exc,
                )
                continue

        return packets

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    async def sendRequest(self, data: bytes, handler=None):
        if not self._client or not self._client.is_connected:
            return

        try:
            if handler:
                await self._client.start_notify(
                    self.NOTIFY_CHARACTERISTIC, handler
                )

            await self._client.write_gatt_char(
                self.WRITE_CHARACTERISTIC, data, response=True
            )
        except Exception as exc:
            self._logger.debug("sendRequest failed: %s", exc)

    async def sendPacket(self, packet: Packet, handler=None):
        enc = EncPacket(
            EncPacket.FRAME_TYPE_PROTOCOL,
            EncPacket.PAYLOAD_TYPE_VX_PROTOCOL,
            packet.toBytes(),
            0,
            0,
            self._session_key,
            self._iv,
        )
        await self.sendRequest(enc.toBytes(), handler)

    # ------------------------------------------------------------------
    # Auth flow (unchanged semantics)
    # ------------------------------------------------------------------

    async def initBleSessionKey(self):
        self._private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP160r1)
        self._public_key = self._private_key.get_verifying_key()

        payload = b"\x01\x00" + self._public_key.to_string()
        enc = EncPacket(
            EncPacket.FRAME_TYPE_COMMAND,
            EncPacket.PAYLOAD_TYPE_VX_PROTOCOL,
            payload,
        )
        await self.sendRequest(enc.toBytes(), self.initBleSessionKeyHandler)

    async def initBleSessionKeyHandler(self, _char, recv):
        data = await self.parseSimple(bytes(recv))
        if not data or len(data) < 4:
            return

        size = getEcdhTypeSize(data[2])
        dev_pub = ecdsa.VerifyingKey.from_string(
            data[3 : 3 + size], curve=ecdsa.SECP160r1
        )

        self._shared_key = ecdsa.ECDH(
            ecdsa.SECP160r1, self._private_key, dev_pub
        ).generate_sharedsecret_bytes()[:16]
        self._iv = hashlib.md5(self._shared_key).digest()

        await self.getKeyInfoReq()

    async def getKeyInfoReq(self):
        enc = EncPacket(
            EncPacket.FRAME_TYPE_COMMAND,
            EncPacket.PAYLOAD_TYPE_VX_PROTOCOL,
            b"\x02",
        )
        await self.sendRequest(enc.toBytes(), self.getKeyInfoReqHandler)

    async def getKeyInfoReqHandler(self, _char, recv):
        try:
            data = await self.parseSimple(bytes(recv))
            if not data:
                return
            plain = await self.decryptShared(data[1:])
            self._session_key = hashlib.md5(plain).digest()
            await self.getAuthStatus()
        except Exception:
            pass

    async def getAuthStatus(self):
        pkt = Packet(0x21, 0x35, 0x35, 0x89, b"", 0x01, 0x01, 0x03)
        await self.sendPacket(pkt, self.getAuthStatusHandler)

    async def getAuthStatusHandler(self, _char, recv):
        packets = await self.parseEncPackets(bytes(recv))
        if not packets:
            raise PacketReceiveError
        await self.autoAuthentication()

    async def autoAuthentication(self):
        md5 = hashlib.md5((self._user_id + self._dev_sn).encode()).digest()
        payload = b"".join(f"{b:02X}".encode() for b in md5)

        pkt = Packet(0x21, 0x35, 0x35, 0x86, payload, 0x01, 0x01, 0x03)
        await self.sendPacket(pkt, self.listenForDataHandler)

    async def listenForDataHandler(self, _char, recv):
        packets = await self.parseEncPackets(bytes(recv))
        for pkt in packets:
            await self._data_parse(pkt)

    # ------------------------------------------------------------------
    # Task helper
    # ------------------------------------------------------------------

    def _add_task(self, coro: Coroutine):
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task


def getEcdhTypeSize(num: int) -> int:
    return {1: 52, 2: 56, 3: 64, 4: 64}.get(num, 40)
