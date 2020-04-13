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

import argparse
import binascii

import PN532

def main():
    p = argparse.ArgumentParser()
    p.add_argument('com_port')
    args = p.parse_args()

    # Create an instance of the PN532 class.
    pn532 = PN532.PN532(args.com_port, 115200)

    # Call begin to initialize communication with the PN532.  Must be done before
    # any other calls to the PN532!
    pn532.begin()

    # Configure PN532 to communicate with MiFare cards.
    pn532.SAM_configuration()

    # Get the firmware version from the chip and print(it out.)
    ic, ver, rev, support = pn532.get_firmware_version()
    print('Found PN532 with firmware version: {}.{}'.format(ver, rev))

    # Main loop to detect cards and read a block.
    print('Waiting for MiFare card...')
    while True:
        # Check if a card is available to read.
        uid = pn532.read_passive_target()

        # Try again if no card is available.
        if uid == 'no_card':
            continue
        print('Found card with UID: {:#x}'.format(int.from_bytes(uid, 'big')))

        # Authenticate block 4 for reading with default key (0xFFFFFFFFFFFF).
        for i in range(16):
            if not pn532.mifare_classic_authenticate_block(uid, i, PN532.MIFARE_CMD_AUTH_B, [0xFF] * 6):
                print('Failed to authenticate block {}'.format(i))
                break

            # Read block 4 data.
            data = pn532.mifare_classic_read_block(i)
            if data is None:
                print('Failed to read block {}'.format(i))
                continue
            # Note that 16 bytes are returned, so only show the first 4 bytes for the block.

            print("Block {:>2}: {} : {}".format(i, binascii.hexlify(data).decode(), data))


if __name__ == "__main__":
    main()
