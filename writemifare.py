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

import PN532


CARD_KEY = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]


def main():
    p = argparse.ArgumentParser()
    p.add_argument('com_port')
    p.add_argument('block', type=lambda n: int(n, 0))
    p.add_argument('data', type=lambda s: s.encode())
    p.add_argument('-y', '--yes', action='store_true')
    args = p.parse_args()

    if not (4 <= args.block < 16):
        p.error('block must be between 4 and 15')
    if len(args.data) > 16:
        p.error('data cannot be more than 16 bytes')

    args.data += b'\0' * (16 - len(args.data))

    # Create an instance of the PN532 class.
    pn532 = PN532.PN532(args.com_port, 115200)
    pn532.begin()
    pn532.SAM_configuration()

    # Get the firmware version from the chip and print(it out.)
    ic, ver, rev, support = pn532.get_firmware_version()
    print(('Found PN532 with firmware version: {}.{}'.format(ver, rev)))

    # Step 1, wait for card to be present.
    print('Mifare NFC Writer')
    print('')
    print('Place the card to be written on the PN532...')
    uid = pn532.read_passive_target()
    while uid == "no_card":
        uid = pn532.read_passive_target()
    print('')
    print('Found card with UID: {:#x}'.format(int.from_bytes(uid, 'big')))
    print('')
    print('==============================================================')
    print('WARNING: DO NOT REMOVE CARD FROM PN532 UNTIL FINISHED WRITING!')
    print('==============================================================')
    print('')

    print('')
    print('Block: {}'.format(args.block))
    print('Data: {}'.format(args.data))
    if (not args.yes) and input('Are you sure? [y/N] ').lower() not in ('y', 'yes'):
        print('Aborted!')
        return

    print('Writing card (DO NOT REMOVE CARD FROM PN532)...')

    # Write the card!
    # First authenticate block 4.
    if not pn532.mifare_classic_authenticate_block(uid, args.block, PN532.MIFARE_CMD_AUTH_B, CARD_KEY):
        print('Error! Failed to authenticate block 4 with the card.')
        return

    # Next build the data to write to the card.
    # Format is as follows:
    # - Bytes 0-3 are a header with ASCII value 'MCPI'
    # - Byte 4 is the block ID byte
    # - Byte 5 is 0 if block has no subtype or 1 if block has a subtype
    # - Byte 6 is the subtype byte (optional, only if byte 5 is 1)

    # Finally write the card.
    if not pn532.mifare_classic_write_block(args.block, args.data):
        print('Error! Failed to write to the card.')
        return

    print('Wrote card successfully! You may now remove the card from the PN532.')


if __name__ == "__main__":
    main()
