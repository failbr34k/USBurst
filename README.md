# USBurst - DWC3 USB Descriptor Buffer Overflow

Apple Secure Rom Exploit - USB Descriptor Burst 

Enjoy!
-failbr3k4

> **Research-only isolate.** This repository contains a standalone extraction of
> the DWC3 USB descriptor parsing vulnerability affecting Apple A12+ SoCs.
> It is intended for authorized security research on devices you own or have
> explicit permission to test.

## Affected Hardware

| Device Family | SoC | CPID | DWC3 FW Version |
|---------------|-----|------|-----------------|
| iPhone 12 / 12 Mini / 12 Pro / 12 Pro Max | A14 (T8101) | 0x8101 | V2 |
| iPhone 13 / 13 Mini / 13 Pro / 13 Pro Max | A15 (T8110) | 0x8110 | V2 |
| iPhone SE (3rd gen) | A15 (T8110) | 0x8110 | V2 |
| MacBook Air / Pro / mini / iMac (M1) | M1 (T8103) | 0x8103 | V2 |
| MacBook Air / Pro / mini (M2) | M2 (T8112) | 0x8112 | V2 |
| iPhone XS / XS Max / XR | A12 (T8020) | 0x8020 | V1/V2 |
| iPad Pro 11" / 12.9" (3rd gen) | A12X (T8027) | 0x8027 | V1/V2 |
| iPad Pro 11" / 12.9" (4th gen) | A12Z (T8028) | 0x8028 | V1/V2 |
| iPhone 11 / 11 Pro / 11 Pro Max / SE (2nd) | A13 (T8030) | 0x8030 | V2 |

Firmware requirements: iOS 15.0 – 16.4 (A14+), macOS 12.0+ (M1/M2).
Must have vulnerable DWC3 firmware (confirmed via CVE-2023-39578).

## Vulnerability Summary

**CWE-121:** Stack-based Buffer Overflow

**Location:** `dwc3_usb_descriptor_parse()` function in Apple's DWC3 USB
controller driver.

**Root cause:** When parsing a USB device descriptor during DFU mode, the
kernel allocates a fixed-size stack/heap buffer but does not null-terminate
or properly bound-check the incoming descriptor length. A malicious host
can send a descriptor whose claimed `bLength` is smaller than the actual
data transferred, causing the parser to read past the buffer boundary and
overwrite adjacent stack memory — including the saved return address.

**Impact:** Arbitrary code execution in kernel context during DFU mode. This
enables:
- Unauthorized physical memory read/write via vendor EP0 requests
- Code execution at arbitrary physical addresses
- Secure Enclave memory access (with additional steps)
- ECDSA private key extraction from memory

## Exploit Flow

### Step-by-Step

1. **Trigger DFU Mode**
   - Connect iPhone/Mac to host via USB
   - iPhone: Hold Power + Volume Down, release Power, hold Volume Down
   - Mac: Press and hold power button

2. **Send Malicious USB Descriptor**
   - Craft a USB device descriptor with `bLength = 0x09` (claims 9 bytes)
   - Append oversized payload (ARM64 shellcode) after the header
   - Send via SET_DESCRIPTOR control transfer (bRequest = 0x07)

3. **Overflow DWC3 Buffer**
   - The `dwc3_usb_descriptor_parse()` function copies data based on the
     claimed length but the USB stack transfers the full packet
   - Saved return address on stack gets overwritten with shellcode pointer

4. **Execute Shellcode**
   - On function return, execution jumps to injected shellcode
   - Shellcode runs in kernel context with full physical memory access

5. **Enable Vendor Requests**
   - Patched DWC3 firmware exposes unauthorized vendor EP0 requests:
     - `SET_ADDR` (0x01): Set target physical address
     - `MEM_READ` (0x02): Read arbitrary physical memory
     - `MEM_WRITE` (0x03): Write arbitrary physical memory
     - `EXECUTE` (0x04): Jump to arbitrary physical address

6. **Access Secure Enclave Memory**
   - Use vendor MEM_READ to dump SE memory regions
   - Locate ECDSA private key material in SE memory map

7. **Extract ECDSA Key**
   - Read key blob from memory
   - Use HKDF with device identity derivation logic to reconstruct
   - Output private key in PEM/DER format

## Exploitation Methods

This standalone supports two exploitation approaches:

### Method 1: Debug FIFO Patching (Default)

Writes patch words to the DWC3 debug bus FIFO (`GDBGFIFOSPACE` at offset
`0xC1000`) via USB vendor control transfers. This modifies the DWC3
firmware to expose unauthorized memory read/write and execution primitives.

**Transfer format per patch word:**
```
[8 bytes: FIFO address (0x860000000 + 0xC1000)]
[4 bytes: patch word value (little-endian)]
[4 bytes: flags = 0x01]
```

### Method 2: Descriptor Overflow

Crafts malicious USB device descriptors with oversized payloads that
overflow the `dwc3_usb_descriptor_parse()` buffer, allowing arbitrary
code execution in kernel space.

**Descriptor format:**
```
Byte 0:  bLength (claims small value, e.g., 0x09)
Byte 1:  bDescriptorType (0x01 = DEVICE)
Bytes 2+: Standard device descriptor fields
Bytes 9+: ARM64 shellcode overflow payload
```

## Repository Structure

```
dwc3_standalone/
├── dwc3_exploit_chain.py      # Complete exploit chain orchestrator
├── poc_usb_descriptor.c        # C code to craft malicious descriptors
├── extract_key.py              # ECDSA key extraction and reconstruction
├── exploit.sh                  # Shell script for DFU setup and execution
└── WRITEUP.md                  # This file
```

## Requirements

- Python 3.10+
- `pyusb` (`pip install pyusb`)
- `cryptography` (optional, for key reconstruction: `pip install cryptography`)
- libusb backend (system USB access)
- USB-A cable capable of data transfer

## Supported SoCs

| CPID  | SoC   | Model       | Patch Words | FW Version |
|-------|-------|-------------|-------------|------------|
| 0x8020| T8020 | A12         | 6           | V1/V2      |
| 0x8027| T8027 | A12X        | 6           | V1/V2      |
| 0x8028| T8028 | A12Z        | 6           | V1/V2      |
| 0x8030| T8030 | A13         | 6           | V2         |
| 0x8101| T8101 | A14         | 7           | V2         |
| 0x8103| T8103 | M1          | 8           | V2         |
| 0x8110| T8110 | A15         | 8           | V2         |
| 0x8112| T8112 | M2          | 8           | V2         |

## Usage

### Quick Start

```sh
# List supported SoCs
python3 dwc3_exploit_chain.py --list-cpids

# Debug FIFO exploit for A14 (0x8101)
python3 dwc3_exploit_chain.py --method debug_fifo --timeout 30

# Descriptor overflow exploit for M1 (0x8103)
python3 dwc3_exploit_chain.py --method descriptor_overflow --timeout 30

# Full chain with payload
python3 dwc3_exploit_chain.py --method debug_fifo --monitor payload.bin
```

### Using the Shell Script

```sh
# Make executable
chmod +x exploit.sh

# Debug FIFO for A14
./exploit.sh 0x8101

# Descriptor overflow for M1
./exploit.sh 0x8103 descriptor_overflow

# With payload
./exploit.sh 0x8110 debug_fifo /path/to/payload.bin
```

### C Descriptor Crafter

```sh
# Compile
gcc -o poc_usb_descriptor poc_usb_descriptor.c

# Run
./poc_usb_descriptor
```

### Key Extraction

```sh
# Extract key from memory dump
python3 extract_key.py memory_dump.bin <device-id-hex> --output key.pem

# With base address
python3 extract_key.py memory_dump.bin 0100000000000000 \
    --base-address 0x800000000 --output key.pem
```

## Exploit Chain State Machine

```
IDLE → DFU_WAIT → CHIPSET_DETECT → PATCHING → VERIFYING → PWNDFU
                                                          ↓
                                                    LOADING → EXECUTING → COMPLETE
                                                    (or FAILED at any step)
```

### States

| State | Description |
|-------|-------------|
| `IDLE` | Initial state, no device connected |
| `DFU_WAIT` | Waiting for DFU mode device |
| `CHIPSET_DETECT` | Identifying target SoC from USB descriptors |
| `PATCHING` | Applying DWC3 exploit (debug FIFO or descriptor overflow) |
| `VERIFYING` | Checking vendor request primitives |
| `PWNDFU` | Device compromised, vendor requests active |
| `LOADING` | Transferring payload to DRAM |
| `EXECUTING` | Executing payload at entry point |
| `COMPLETE` | Full chain succeeded |
| `FAILED` | Chain failed at some step |

## Vendor Request Interface

After successful exploitation, the following vendor EP0 requests are
available:

| bRequest | Name | Direction | Data Stage |
|----------|------|-----------|------------|
| 0x01 | SET_ADDR | Host → Device | 8-byte physical address (LE) |
| 0x02 | MEM_READ | Device → Host | Returns `wLength` bytes from address |
| 0x03 | MEM_WRITE | Host → Device | Writes data to address |
| 0x04 | EXECUTE | Host → Device | Jumps to address (no data) |

Address auto-increments after MEM_READ/MEM_WRITE by the transfer length.

## DWC3 Firmware Patch Details

### V1 Patch (A12, A12X, A12Z, A13 with older firmware)

6 patch words written to `GDBGFIFOSPACE`:

```
0x4B010036, 0x00000014, 0x00003F14,
0x001A0058, 0x03D65FC0, 0x0320D51F
```

### V2 Patch (A14, M1, A15, M2, A13 with newer firmware)

- **Extended (A14):** 7 words
- **Full (M1, A15, M2):** 8 words

```
0x00000080, 0x00000014, 0x3F000014, 0x081A0058,
0xC0035FD6, 0x1F2003D5, 0x3B000014, 0x3A000014
```

## Device Memory Map

| Region | Base Address | Size |
|--------|-------------|------|
| DRAM | 0x800000000 | 4GB / 8GB |
| DWC3 MMIO | 0x860000000 | 256MB |
| Kernel base | 0xFFFFFFF007004000 | — |
| SEP (A13) | 0x82E000000 | — |
| SEP (A12 fallback) | 0x830000000 | — |

## Security Considerations

- This code is for **authorized research only**
- DFU mode provides low-level access; misuse can brick devices
- Vendor request interface has no authentication after exploitation
- Secure Enclave access requires additional SE exploitation steps
- Key extraction requires physical memory dumps, which require active exploit

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Device not found | Ensure DFU mode, try different USB port/cable |
| pyusb missing | `pip install pyusb` |
| Permission denied | Add udev rule or run with appropriate USB access |
| Patch words failed | Retry, check DWC3 firmware version |
| Vendor requests not verified | Device may not be vulnerable |

## References

- CVE-2023-39578: Related DWC3 vulnerability
- Apple DWC3 USB 3.0 controller documentation
- USB 2.0 Specification (device descriptor format)
