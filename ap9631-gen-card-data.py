#!/usr/bin/env python3
import argparse
import datetime as _dt
import os
import re
import sys
import uuid
import time
import hashlib

# -------------------- Layout constants --------------------
# 1 byte, mirrors last 2 digits of APC's internal 6-digit product code
# 0x00 = generic/bootmon (963200), 0x01 = NMC2 application image (963201)
OFFS_PRODUCT_VARIANT      = 0x00
OFFS_RESERVED_00          = 0x01  # 1 byte, reserved, always 0x00
# Hardware platform generation — ASCII string matching the hwXX firmware filename prefix
# and what the card reports as "Hardware Revision" in `about`.
# "02" = NMC1 (AP9617 family), "05" = NMC2 (AP9630/9631/9635), "21" = NMC3 (AP9641 family)
# 2 bytes ASCII, no NUL
OFFS_HW_GENERATION        = 0x02
OFFS_RESERVED_0000        = 0x04  # 2 bytes 00 00
OFFS_MANUF_DATE           = 0x13  # 10 bytes ASCII "MM/DD/YYYY" (month/day/year)
LEN_MANUF_DATE            = 10
OFFS_MANUF_DATE_NUL       = 0x1D  # 1 byte 00 (NUL after date)
OFFS_MODEL                = 0x1E  # 9 bytes: up to 8 ASCII + NUL; pad remainder with FF
LEN_MODEL_FIELD           = 9
OFFS_SERIAL               = 0x2F  # 13 bytes: up to 12 ASCII + NUL; pad remainder with 00
LEN_SERIAL_FIELD          = 13
OFFS_MAC                  = 0x50  # 6 bytes
OFFS_LANGUAGE             = 0x56  # 2 bytes, big-endian
OFFS_INTERNATIONAL        = 0x58  # 2 bytes, big-endian
OFFS_PAD_ALIGN_BEFORE_CRC = 0x5A  # 1 byte 00
OFFS_CRC16_LE             = 0x5B  # 2 bytes little-endian CRC over 0x00..0x5A
# Platform magic — factory-programmed sentinel read by bootmon before CRC validation
# as a platform compatibility check. Excluded from CRC range intentionally.
# 0x1217 = 4631 decimal, APC's internal numeric ID for the NMC2 UPS card platform.
# Stored big-endian. 2 bytes.
OFFS_PLATFORM_MAGIC       = 0x5D
PLATFORM_MAGIC_NMC2       = 0x1217

HEADER_LAST_DEFINED_INCL  = 0x5E  # last defined byte (high byte of PLATFORM_MAGIC)
TAIL_FF_COUNT             = 17    # erased-flash tail; output ends at 0x6F

HEADER_CRC_START          = 0x00
HEADER_CRC_END_EXCL       = 0x5B  # compute over 0x00..0x5A inclusive

# -------------------- CRC --------------------
def crc16_ccitt(data: bytes, init: int = 0x0000) -> int:
    """CRC-16/CCITT-FALSE: poly=0x1021, init=0x0000, no reflect, no final xor."""
    poly = 0x1021
    crc = init & 0xFFFF
    for b in data:
        crc ^= (b << 8) & 0xFFFF
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) & 0xFFFF) ^ poly
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF

# -------------------- Helpers --------------------
def gen_la_mac() -> bytes:
    """Generate a locally administered, unicast MAC using time + UUID as entropy."""
    seed = uuid.uuid4().bytes + int(time.time_ns()).to_bytes(8, "big")
    h = hashlib.sha256(seed).digest()
    mac = bytearray(h[:6])
    mac[0] = (mac[0] & 0b11111110) | 0b00000010  # clear multicast, set local
    return bytes(mac)

def parse_hw_generation(s: str) -> str:
    if not re.fullmatch(r"\d{2}", s):
        raise argparse.ArgumentTypeError("hw-generation must be exactly two digits, e.g. 05")
    return s

def parse_date(s: str) -> str:
    # month/day/year (MM/DD/YYYY)
    m = re.fullmatch(r"(\d{1,2})/(\d{1,2})/(\d{4})", s)
    if not m:
        raise argparse.ArgumentTypeError('manufacturing date must be month/day/year => MM/DD/YYYY (e.g., 06/24/2011)')
    mm, dd, yyyy = map(int, m.groups())
    try:
        _dt.date(yyyy, mm, dd)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"invalid date: {e}")
    return f"{mm:02d}/{dd:02d}/{yyyy:04d}"

def parse_model(s: str) -> str:
    if not (1 <= len(s) <= 8) or not s.isascii() or any(ord(c) < 0x20 for c in s):
        raise argparse.ArgumentTypeError("model must be 1..8 printable ASCII chars")
    return s

def parse_serial(s: str) -> str:
    if not (1 <= len(s) <= 12) or not s.isascii() or any(ord(c) < 0x20 for c in s):
        raise argparse.ArgumentTypeError("serial must be 1..12 printable ASCII chars")
    return s

def parse_mac(s: str) -> bytes:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", s)
    if len(cleaned) != 12 or not re.fullmatch(r"[0-9A-Fa-f]{12}", cleaned):
        raise argparse.ArgumentTypeError(
            "invalid MAC; examples: 02:11:22:33:44:55 or 021122334455 or 02-11-22-33-44-55"
        )
    return bytes(int(cleaned[i:i+2], 16) for i in range(0, 12, 2))

def parse_uint8(s: str) -> int:
    v = int(s, 0)
    if not (0 <= v <= 0xFF):
        raise argparse.ArgumentTypeError("must be 0..255")
    return v

def parse_uint16(s: str) -> int:
    v = int(s, 0)
    if not (0 <= v <= 0xFFFF):
        raise argparse.ArgumentTypeError("must be 0..65535")
    return v

# -------------------- Builder --------------------
def build_image(args):
    out_size = HEADER_LAST_DEFINED_INCL + 1 + TAIL_FF_COUNT
    data = bytearray([0xFF] * out_size)

    # Product variant and reserved byte
    data[OFFS_PRODUCT_VARIANT] = args.product_variant
    data[OFFS_RESERVED_00] = 0x00

    # Hardware platform generation
    data[OFFS_HW_GENERATION:OFFS_HW_GENERATION+2] = args.hw_generation.encode("ascii")

    # Reserved zeros 0x04..0x05
    data[OFFS_RESERVED_0000:OFFS_RESERVED_0000+2] = b"\x00\x00"

    # Manufacturing date + NUL
    data[OFFS_MANUF_DATE:OFFS_MANUF_DATE+LEN_MANUF_DATE] = args.manuf_date.encode("ascii")
    data[OFFS_MANUF_DATE_NUL] = 0x00

    # Model (NUL then FF padded)
    mbytes = args.model.encode("ascii")
    model_field = mbytes + b"\x00"
    model_field = model_field + b"\xFF" * (LEN_MODEL_FIELD - len(model_field))
    data[OFFS_MODEL:OFFS_MODEL+LEN_MODEL_FIELD] = model_field

    # Serial (NUL then 0x00 padded)
    sbytes = args.serial.encode("ascii")
    serial_field = (sbytes + b"\x00").ljust(LEN_SERIAL_FIELD, b"\x00")
    data[OFFS_SERIAL:OFFS_SERIAL+LEN_SERIAL_FIELD] = serial_field

    # MAC
    mac6 = args.mac if args.mac is not None else gen_la_mac()
    data[OFFS_MAC:OFFS_MAC+6] = mac6

    # Language & International
    data[OFFS_LANGUAGE:OFFS_LANGUAGE+2] = args.language.to_bytes(2, "big")
    data[OFFS_INTERNATIONAL:OFFS_INTERNATIONAL+2] = args.international.to_bytes(2, "big")

    # Pad before CRC
    data[OFFS_PAD_ALIGN_BEFORE_CRC] = 0x00

    # CRC16
    hdr_crc = crc16_ccitt(data[HEADER_CRC_START:HEADER_CRC_END_EXCL])
    data[OFFS_CRC16_LE:OFFS_CRC16_LE+2] = hdr_crc.to_bytes(2, "little")

    # Platform magic (big-endian)
    data[OFFS_PLATFORM_MAGIC:OFFS_PLATFORM_MAGIC+2] = args.platform_magic.to_bytes(2, "big")

    return data, hdr_crc, mac6

def summarize(data, hdr_crc, mac6):
    manuf_date = data[OFFS_MANUF_DATE:OFFS_MANUF_DATE+LEN_MANUF_DATE].decode("ascii")
    model      = data[OFFS_MODEL:OFFS_MODEL+LEN_MODEL_FIELD].split(b"\x00",1)[0].decode("ascii")
    serial     = data[OFFS_SERIAL:OFFS_SERIAL+LEN_SERIAL_FIELD].split(b"\x00",1)[0].decode("ascii")
    lang       = int.from_bytes(data[OFFS_LANGUAGE:OFFS_LANGUAGE+2],"big")
    intl       = int.from_bytes(data[OFFS_INTERNATIONAL:OFFS_INTERNATIONAL+2],"big")
    plat_magic = int.from_bytes(data[OFFS_PLATFORM_MAGIC:OFFS_PLATFORM_MAGIC+2],"big")
    mac_str    = ":".join(f"{b:02X}" for b in mac6)

    print("\nSummary of header fields:")
    print("------------------------------------------------------------")
    print(f"Output length         : {len(data)} bytes (0x{len(data):X})")
    print(f"Product variant       : 0x{data[OFFS_PRODUCT_VARIANT]:02X}")
    print(f"HW generation         : {data[OFFS_HW_GENERATION:OFFS_HW_GENERATION+2].decode('ascii')}")
    print(f"Manufacturing date    : {manuf_date!r}  (month/day/year, MM/DD/YYYY)")
    print(f"Model                 : {model!r}")
    print(f"Serial                : {serial!r}")
    print(f"MAC                   : {mac_str}")
    print(f"Language              : {lang}")
    print(f"International         : {intl}")
    print(f"CRC16 (0x00..0x5A)    : 0x{hdr_crc:04X} (stored little-endian)")
    print(f"Platform magic        : 0x{plat_magic:04X} (stored big-endian)")
    print("------------------------------------------------------------\n")

# -------------------- CLI --------------------
def build_argparser():
    p = argparse.ArgumentParser(
        description=("Create APC NMC2 flash identity header (0x00..0x5E plus 17 FF tail, "
                     "total 0x70 bytes). CRC16/CCITT-FALSE over 0x00..0x5A stored "
                     "little-endian at 0x5B..0x5C. Platform magic at 0x5D..0x5E is "
                     "excluded from CRC and fixed per platform.")
    )
    p.add_argument("-o", "--out", default="flash_header.bin",
                   help="output file (default: %(default)s)")
    p.add_argument("--product-variant", type=parse_uint8, default=0x01,
                   dest="product_variant",
                   help=("product variant byte at 0x00: 0x00 = generic/bootmon (963200), "
                         "0x01 = NMC2 application image (963201) (default: 0x01)"))
    p.add_argument("-r", "--hw-generation", type=parse_hw_generation, default="05",
                   dest="hw_generation",
                   help=("two ASCII digits at 0x02: hardware platform generation. "
                         "02=NMC1, 05=NMC2, 21=NMC3 (default: %(default)s)"))
    p.add_argument("-d", "--date", dest="manuf_date", type=parse_date, default="01/01/1970",
                   help=("manufacturing date in month/day/year => MM/DD/YYYY "
                         "(e.g., 06/24/2011) (default: %(default)s)"))
    p.add_argument("-m", "--model", type=parse_model, default="AP9631",
                   help="model up to 8 printable ASCII chars (default: %(default)s)")
    p.add_argument("-s", "--serial", type=parse_serial, default="111111111111",
                   help="serial up to 12 printable ASCII chars (default: %(default)s)")
    p.add_argument("-a", "--mac", type=parse_mac, default=None,
                   help=("MAC address (default: auto-generate unique locally administered MAC). "
                         "Examples: 02:11:22:33:44:55 or 021122334455 or 02-11-22-33-44-55"))
    p.add_argument("--language", type=parse_uint16, default=1,
                   help="language (uint16, big-endian; default: %(default)s)")
    p.add_argument("--international", type=parse_uint16, default=1,
                   help="international (uint16, big-endian; default: %(default)s)")
    p.add_argument("--platform-magic", type=parse_uint16, default=PLATFORM_MAGIC_NMC2,
                   dest="platform_magic",
                   help=("platform magic word at 0x5D..0x5E, stored big-endian. "
                         "Fixed sentinel used by bootmon for compatibility check. "
                         "0x1217 for all NMC2 cards (default: 0x%(default)04X)"))
    return p

def main():
    ap = build_argparser()
    args = ap.parse_args()
    data, hdr_crc, mac6 = build_image(args)
    summarize(data, hdr_crc, mac6)
    with open(args.out, "wb") as f:
        f.write(data)
    print(f"Wrote {len(data)} bytes to {os.path.abspath(args.out)}")

if __name__ == "__main__":
    main()
