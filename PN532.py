# Example of detecting and reading a block from a MiFare NFC card.
# Author: Manuel Fernando Galindo (mfg90@live.com)
#
# Copyright (c) 2016 Manuel Fernando Galindo
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import time
from functools import reduce

import serial


# pylint: disable=bad-whitespace
PN532_PREAMBLE                      = 0x00
PN532_STARTCODE1                    = 0x00
PN532_STARTCODE2                    = 0xFF
PN532_POSTAMBLE                     = 0x00

PN532_HOSTTOPN532                   = 0xD4
PN532_PN532TOHOST                   = 0xD5

# PN532 Commands
PN532_COMMAND_DIAGNOSE              = 0x00
PN532_COMMAND_GETFIRMWAREVERSION    = 0x02
PN532_COMMAND_GETGENERALSTATUS      = 0x04
PN532_COMMAND_READREGISTER          = 0x06
PN532_COMMAND_WRITEREGISTER         = 0x08
PN532_COMMAND_READGPIO              = 0x0C
PN532_COMMAND_WRITEGPIO             = 0x0E
PN532_COMMAND_SETSERIALBAUDRATE     = 0x10
PN532_COMMAND_SETPARAMETERS         = 0x12
PN532_COMMAND_SAMCONFIGURATION      = 0x14
PN532_COMMAND_POWERDOWN             = 0x16
PN532_COMMAND_RFCONFIGURATION       = 0x32
PN532_COMMAND_RFREGULATIONTEST      = 0x58
PN532_COMMAND_INJUMPFORDEP          = 0x56
PN532_COMMAND_INJUMPFORPSL          = 0x46
PN532_COMMAND_INLISTPASSIVETARGET   = 0x4A
PN532_COMMAND_INATR                 = 0x50
PN532_COMMAND_INPSL                 = 0x4E
PN532_COMMAND_INDATAEXCHANGE        = 0x40
PN532_COMMAND_INCOMMUNICATETHRU     = 0x42
PN532_COMMAND_INDESELECT            = 0x44
PN532_COMMAND_INRELEASE             = 0x52
PN532_COMMAND_INSELECT              = 0x54
PN532_COMMAND_INAUTOPOLL            = 0x60
PN532_COMMAND_TGINITASTARGET        = 0x8C
PN532_COMMAND_TGSETGENERALBYTES     = 0x92
PN532_COMMAND_TGGETDATA             = 0x86
PN532_COMMAND_TGSETDATA             = 0x8E
PN532_COMMAND_TGSETMETADATA         = 0x94
PN532_COMMAND_TGGETINITIATORCOMMAND = 0x88
PN532_COMMAND_TGRESPONSETOINITIATOR = 0x90
PN532_COMMAND_TGGETTARGETSTATUS     = 0x8A

PN532_RESPONSE_INDATAEXCHANGE       = 0x41
PN532_RESPONSE_INLISTPASSIVETARGET  = 0x4B

PN532_WAKEUP                        = 0x55

PN532_SPI_STATREAD                  = 0x02
PN532_SPI_DATAWRITE                 = 0x01
PN532_SPI_DATAREAD                  = 0x03
PN532_SPI_READY                     = 0x01

PN532_MIFARE_ISO14443A              = 0x00

# Mifare Commands
MIFARE_CMD_AUTH_A                   = 0x60
MIFARE_CMD_AUTH_B                   = 0x61
MIFARE_CMD_READ                     = 0x30
MIFARE_CMD_WRITE                    = 0xA0
MIFARE_CMD_TRANSFER                 = 0xB0
MIFARE_CMD_DECREMENT                = 0xC0
MIFARE_CMD_INCREMENT                = 0xC1
MIFARE_CMD_STORE                    = 0xC2
MIFARE_ULTRALIGHT_CMD_WRITE         = 0xA2

# Prefixes for NDEF Records (to identify record type)
NDEF_URIPREFIX_NONE                 = 0x00
NDEF_URIPREFIX_HTTP_WWWDOT          = 0x01
NDEF_URIPREFIX_HTTPS_WWWDOT         = 0x02
NDEF_URIPREFIX_HTTP                 = 0x03
NDEF_URIPREFIX_HTTPS                = 0x04
NDEF_URIPREFIX_TEL                  = 0x05
NDEF_URIPREFIX_MAILTO               = 0x06
NDEF_URIPREFIX_FTP_ANONAT           = 0x07
NDEF_URIPREFIX_FTP_FTPDOT           = 0x08
NDEF_URIPREFIX_FTPS                 = 0x09
NDEF_URIPREFIX_SFTP                 = 0x0A
NDEF_URIPREFIX_SMB                  = 0x0B
NDEF_URIPREFIX_NFS                  = 0x0C
NDEF_URIPREFIX_FTP                  = 0x0D
NDEF_URIPREFIX_DAV                  = 0x0E
NDEF_URIPREFIX_NEWS                 = 0x0F
NDEF_URIPREFIX_TELNET               = 0x10
NDEF_URIPREFIX_IMAP                 = 0x11
NDEF_URIPREFIX_RTSP                 = 0x12
NDEF_URIPREFIX_URN                  = 0x13
NDEF_URIPREFIX_POP                  = 0x14
NDEF_URIPREFIX_SIP                  = 0x15
NDEF_URIPREFIX_SIPS                 = 0x16
NDEF_URIPREFIX_TFTP                 = 0x17
NDEF_URIPREFIX_BTSPP                = 0x18
NDEF_URIPREFIX_BTL2CAP              = 0x19
NDEF_URIPREFIX_BTGOEP               = 0x1A
NDEF_URIPREFIX_TCPOBEX              = 0x1B
NDEF_URIPREFIX_IRDAOBEX             = 0x1C
NDEF_URIPREFIX_FILE                 = 0x1D
NDEF_URIPREFIX_URN_EPC_ID           = 0x1E
NDEF_URIPREFIX_URN_EPC_TAG          = 0x1F
NDEF_URIPREFIX_URN_EPC_PAT          = 0x20
NDEF_URIPREFIX_URN_EPC_RAW          = 0x21
NDEF_URIPREFIX_URN_EPC              = 0x22
NDEF_URIPREFIX_URN_NFC              = 0x23

PN532_GPIO_VALIDATIONBIT            = 0x80
PN532_GPIO_P30                      = 0
PN532_GPIO_P31                      = 1
PN532_GPIO_P32                      = 2
PN532_GPIO_P33                      = 3
PN532_GPIO_P34                      = 4
PN532_GPIO_P35                      = 5

PN532_ACK_FRAME                     = b'\x00\x00\xFF\x00\xFF\x00'
# pylint: enable=bad-whitespace

def millis():
    return int(time.time() * 1000)


def uint8_add(a, b):
    return ((a & 0xFF) + (b & 0xFF)) & 0xFF


def canonicalize_params(params, ignore_errors=False):
    if not params:
        return []

    ret = []
    for i, param in enumerate(params, 1):
        if isinstance(param, (list, tuple)):
            ret += canonicalize_params(param)
        elif isinstance(param, bytes):
            ret += list(param)
        elif isinstance(param, str):
            ret += list(param.encode())
        elif isinstance(param, int):
            ret.append(param & 0xFF)
        elif not ignore_errors:
            raise ValueError('Param #{} is of unsupported type: {}'.format(i, type(param)))

    return ret

class PN532:
    def __init__(self, comport, baudrate=115200):
        self.message = b''

        self.ser = serial.Serial(comport, baudrate)
        self.ser.timeout = 2

    @staticmethod
    def checksum(data):
        return ~reduce(uint8_add, data, 0xFF) & 0xFF

    def _write_frame(self, data):
        # Build frame to send as:
        # - Preamble (0x00)
        # - Start code  (0x00, 0xFF)
        # - Command length (1 byte)
        # - Command length checksum
        # - Command bytes
        # - Checksum
        # - Postamble (0x00)

        assert 0 < len(data) < 255, 'Data must be array of 1 to 255 bytes.'

        length = len(data)
        frame = bytes([
            PN532_PREAMBLE,
            PN532_STARTCODE1,
            PN532_STARTCODE2,
            length & 0xFF,
            uint8_add(~length, 1)
        ]) + data + bytes([
            self.checksum(data),
            PN532_POSTAMBLE
        ])

        self.ser.flushInput()
        ack = False
        while not ack:
            self.ser.write(frame)
            # print('>', frame)
            ack = self._ack_wait(1000)
            time.sleep(0.3)
        return True

    def _ack_wait(self, timeout):
        rx_info = b''
        start_time = millis()
        current_time = start_time

        while (current_time - start_time < timeout):
            time.sleep(0.12)  # Stability on receive
            buf = self.ser.read(self.ser.inWaiting())
            # print('<', buf)
            rx_info += buf
            current_time = millis()
            if PN532_ACK_FRAME in rx_info:
                if len(rx_info) > 6:
                    self.message = b''.join(rx_info.split(PN532_ACK_FRAME))
                else:
                    self.message = rx_info
                self.ser.flush()
                return True

        self.message = b''
        return False

    def _read_data(self):
        rx_info = b''
        if not self.message:
            self._ack_wait(1000)
        else:
            rx_info = self.message
        return rx_info

    def _read_frame(self):
        """Read a response frame from the PN532 of at most length bytes in size.
        Returns the data inside the frame if found, otherwise raises an exception
        if there is an error parsing the frame.  Note that less than length bytes
        might be returned!
        """
        # Read frame with expected length of data.
        response = self._read_data()

        # Check frame starts with 0x01 and then has 0x00FF (preceeded by optional zeros).
        if response != PN532_ACK_FRAME:
            if response[0] != 0x00:
                raise RuntimeError('Response frame does not start with 0x00!')

            # Swallow all the 0x00 values that preceed 0xFF.
            offset = 1
            while response[offset] == 0x00:
                offset += 1
                if offset >= len(response):
                    raise RuntimeError('Response frame preamble does not contain 0x00FF!')
            if response[offset] != 0xFF:
                raise RuntimeError('Response frame preamble does not contain 0x00FF!')
            offset += 1
            if offset >= len(response):
                raise RuntimeError('Response contains no data!')

            # Check length & length checksum match.
            frame_len = response[offset]
            if (frame_len + response[offset + 1]) & 0xFF:
                raise RuntimeError('Response length checksum did not match length!')

            # Check frame checksum value matches bytes.
            checksum = reduce(uint8_add, response[offset + 2:offset + 2 + frame_len + 1], 0)
            if checksum:
                raise RuntimeError('Response checksum did not match expected value!')

            # Return frame data.
            return response[offset+2:offset+2+frame_len]

        return "no_card"

    def wakeup(self):
        self.ser.write(b'\x55\x55\x00\x00\x00')

    def call_function(self, command, *params):
        """Send specified command to the PN532 and expect up to response_length
        bytes back in a response.  Note that less than the expected bytes might
        be returned!  Params can optionally specify an array of bytes to send as
        parameters to the function call.  Will wait up to timeout_secs seconds
        for a response and return a bytearray of response bytes, or None if no
        response is available within the timeout.
        """
        params = canonicalize_params(params)

        # Build frame data with command and parameters.
        data = bytes([PN532_HOSTTOPN532, command & 0xFF] + params)

        # Send frame and wait for response.
        if not self._write_frame(data):
            return None

        # Read response bytes.
        response = self._read_frame()

        # Check that response is for the called function.
        if response != "no_card":
            if response[0] != PN532_PN532TOHOST or response[1] != command + 1:
                raise RuntimeError('Received unexpected command response!')

            # Return response data.
            return response[2:]

        return response

    def begin(self):
        """Initialize communication with the PN532.  Must be called before any
        other calls are made against the PN532.
        """
        self.wakeup()

    def get_firmware_version(self):
        """Call PN532 GetFirmwareVersion function and return a tuple with the IC,
        Ver, Rev, and Support values.
        """
        response = self.call_function(PN532_COMMAND_GETFIRMWAREVERSION)
        if response is None:
            raise RuntimeError('Failed to detect the PN532!  Make sure there is sufficient power (use a 1 amp or greater power supply), the PN532 is wired correctly to the device, and the solder joints on the PN532 headers are solidly connected.')
        return (response[0], response[1], response[2], response[3])

    def SAM_configuration(self):
        """Configure the PN532 to read MiFare cards."""
        # Send SAM configuration command with configuration for:
        # - 0x01, normal mode
        # - 0x14, timeout 50ms * 20 = 1 second
        # - 0x01, use IRQ pin
        # Note that no other verification is necessary as call_function will
        # check the command was executed as expected.
        self.call_function(PN532_COMMAND_SAMCONFIGURATION, [0x01, 0x14, 0x01])

    def read_passive_target(self, card_baud=PN532_MIFARE_ISO14443A):
        """Wait for a MiFare card to be available and return its UID when found.
        Will wait up to timeout_sec seconds and return None if no card is found,
        otherwise a bytearray with the UID of the found card is returned.
        """

        # Send passive read command for 1 card.
        response = self.call_function(
            PN532_COMMAND_INLISTPASSIVETARGET,
            1,  # amount of cards
            card_baud
        )

        # If no response is available return None to indicate no card is present.
        if response is None:
            return None

        if response != "no_card":
            # Check only 1 card with up to a 7 byte UID is present.
            if response[0] != 0x01:
                raise RuntimeError('More than one card detected!')
            if response[5] > 7:
                raise RuntimeError('Found card with unexpectedly long UID!')
            # Return UID of card.
            return response[6:6 + response[5]]

        return response

    def mifare_classic_authenticate_block(self, uid, block_number, key_number, key):
        """Authenticate specified block number for a MiFare classic card.  Uid
        should be a byte array with the UID of the card, block number should be
        the block to authenticate, key number should be the key type (like
        MIFARE_CMD_AUTH_A or MIFARE_CMD_AUTH_B), and key should be a byte array
        with the key data.  Returns True if the block was authenticated, or False
        if not authenticated.
        """

        # Send InDataExchange request and verify response is 0x00.
        response = self.call_function(
            PN532_COMMAND_INDATAEXCHANGE,
            1,  # Max card numbers
            key_number,
            block_number,
            key,
            uid,
        )

        return response[0] == 0x00

    def mifare_classic_read_block(self, block_number):
        """Read a block of data from the card.  Block number should be the block
        to read.  If the block is successfully read a bytearray of length 16 with
        data starting at the specified block will be returned.  If the block is
        not read then None will be returned.
        """

        # Send InDataExchange request to read block of MiFare data.
        response = self.call_function(
            PN532_COMMAND_INDATAEXCHANGE,
            1,
            MIFARE_CMD_READ,
            block_number,
        )

        # Check first response is 0x00 to show success.
        if response[0] != 0x00:
            return None

        # Return first 4 bytes since 16 bytes are always returned.
        return response[1:]

    def mifare_classic_write_block(self, block_number: int, data: bytes):
        """Write a block of data to the card.  Block number should be the block
        to write and data should be a byte array of length 16 with the data to
        write.  If the data is successfully written then True is returned,
        otherwise False is returned.
        """

        assert len(data) == 16, 'Data must be an array of 16 bytes!'

        # Send InDataExchange request.
        response = self.call_function(
            PN532_COMMAND_INDATAEXCHANGE,
            1,  # Max card numbers
            MIFARE_CMD_WRITE,
            block_number,
            data,
        )

        return response[0] == 0x00
