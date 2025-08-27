# APC AP9631 UPS Network Management Card 2 Recovery

This repository provides tools and information to help recover an **APC AP9631 UPS Network Management Card 2** that has lost its factory header (model, serial number, MAC address).

⚠️ **Disclaimer:** This process is based on guesswork, as APC does not provide official documentation. Use at your own risk.

---

## How It Works

1. **Generate a new binary header**  
   Based on the stickers and PCB markings on your AP9631 card (model, serial number, MAC address, and revision), run:

   ```bash
   python3 ap9631-gen-card-data.py \
       --model AP9631 \
       --date 02/09/2007 \
       --revision 01 \
       --serial 111111111111 \
       --mac "AA:BB:CC:DD:EE:FF"
   ```

   This will produce a file: `flash_header.bin`

2. **Remove the flash chip**  
   The card uses a **Spansion S29JL064J55TFI00 64Mb parallel flash** in a TSOP48 package.

3. **Dump the flash contents**  
   Use a programmer with the proper adapter (e.g., **XGecu T76** + TSOP56 adapter, which also supports TSOP48).

4. **Patch the header**  
   Open the dump in a hex editor. Replace the initial block (which may be all `FF`s if the header is missing) with the generated `flash_header.bin`.

5. **Reprogram and reassemble**  
   Flash the modified binary back to the chip and solder it onto the PCB.

---

## FAQ

### ❓ Is the script guaranteed to work?
No. The script relies partly on assumptions since APC does not release official documentation. It worked for me, but **you proceed at your own risk**.

---

### ❓ How do I check if the card is alive?
If Ethernet does not respond (which it won’t with a zeroed MAC address), you’ll need to connect via **serial console**:

- Use a **serial to 2.5mm jack cable** (APC specific). Designs available on internet.
- Baud rates:
  - **57600 baud** during boot monitor. Press Enter a few times after booting the card (reinserting it or rebooting from panel).
  - **9600 baud** after full boot to log into the AOS system (default login/password: `apc/apc`).

From the boot monitor, the command:

```
mfginfo
```

will display:
- MAC address  
- Model  
- Revision  
- Serial number  
- Production date  
- International/language settings  
- CRC check (must show `CRC = PASS`)

---

### ❓ What if the entire firmware is corrupted?
If the whole firmware is damaged (not just the factory header), you can:
- Dump the flash from another working card.
- Replace only the **factory header block** with the one generated for your card’s details.
- Flash the repaired image to your chip.

### ? Will it work on other AP9xxx cards?

Unknown. Not tested.

---

## Notes

- This process requires intermediate-level soldering and familiarity with flash programmers.
- Always back up the full flash contents before making modifications.

---

## License

This project is licensed under the **GNU General Public License v3.0 (GPLv3)**.  
See the [LICENSE](LICENSE) file for details.
