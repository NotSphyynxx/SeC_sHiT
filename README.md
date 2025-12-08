# 🛡️ SeC_sHiT

---

## 📚 Write-ups

### 🔍 SOC – Analyzing Malicious Traffic
**Carnage Room Breakdown**

[Read the full breakdown on Medium](https://medium.com/@larhribismail87/soc-analyzing-malicious-traffic-carnage-room-breakdown-37e8de9c304a)

---

### 🕵️ Forensics – Odyssey Finals
**Odyssey CTF Finals 2025**

| Challenge Info | Details |
| :--- | :--- |
| **Category** | Forensics |
| **Challenge Name** | idk the challenge name (i forgot) |
| **File** | `traffic.pcap` |
| **Flag Format** | `AKASEC{...}` |

#### 📝 Challenge Overview

The challenge involved analyzing a suspicious PCAP file containing USB traffic found on a computer. The goal was to recover the keystrokes captured in the network traffic to find the hidden flag.

---

#### 1️⃣ Initial Reconnaissance

We started by examining the PCAP using `tshark` to understand the protocol hierarchy.

tshark -r traffic.pcap -q -z io,phs

text

**Findings:**
- 3,276 total USB frames
- 1,616 frames with `usbhid.data` (USB Human Interface Device data)
- Traffic from multiple USB devices (1.9.3, 1.10.1, etc.)

This immediately indicated **USB keyboard traffic capture**, as HID devices include keyboards, mice, and other input devices.

---

#### 2️⃣ The Problem

An initial attempt to extract data using the standard `usb.capdata` field failed:

tshark -r traffic.pcap -Y 'usb.capdata' -T fields -e usb.capdata > usb_data.txt

text

**Result:** An empty file. This is because `usb.capdata` is often not the correct field for specific USB HID keyboard data.

---

#### 3️⃣ Solution Approach

##### Step 1: Extract the Correct Field

For USB keyboard captures, keystrokes are stored in the `usbhid.data` field, not `usb.capdata`. The correct extraction command is:

tshark -r traffic.pcap -Y 'usbhid.data' -T fields -e usbhid.data > usbhid_keys.txt

text

##### Step 2: Understanding USB HID Protocol

USB HID keyboard data consists of 8 bytes per packet:

| Byte | Purpose |
|------|---------|
| **Byte 0** | Modifier keys (Shift=0x02/0x20, Ctrl=0x01, Alt=0x04, etc.) |
| **Byte 1** | Reserved (always 0x00) |
| **Bytes 2-7** | Up to 6 simultaneous keypresses (HID keycodes) |

##### Step 3: Decoding the Keystrokes

We created a Python decoder script based on the USB HID specification:

#!/usr/bin/env python3

USB HID Keycode mapping
usb_codes = {
0x04: ['a', 'A'], 0x05: ['b', 'B'], 0x06: ['c', 'C'], 0x07: ['d', 'D'],
0x08: ['e', 'E'], 0x09: ['f', 'F'], 0x0A: ['g', 'G'], 0x0B: ['h', 'H'],
0x0C: ['i', 'I'], 0x0D: ['j', 'J'], 0x0E: ['k', 'K'], 0x0F: ['l', 'L'],
0x10: ['m', 'M'], 0x11: ['n', 'N'], 0x12: ['o', 'O'], 0x13: ['p', 'P'],
0x14: ['q', 'Q'], 0x15: ['r', 'R'], 0x16: ['s', 'S'], 0x17: ['t', 'T'],
0x18: ['u', 'U'], 0x19: ['v', 'V'], 0x1A: ['w', 'W'], 0x1B: ['x', 'X'],
0x1C: ['y', 'Y'], 0x1D: ['z', 'Z'], 0x1E: ['1', '!'], 0x1F: ['2', '@'],
0x20: ['3', '#'], 0x21: ['4', '$'], 0x22: ['5', '%'], 0x23: ['6', '^'],
0x24: ['7', '&'], 0x25: ['8', '*'], 0x26: ['9', '('], 0x27: ['0', ')'],
0x28: ['\n', '\n'], 0x29: ['<ESC>', '<ESC>'], 0x2A: ['<BACKSPACE>', '<BACKSPACE>'],
0x2B: ['\t', '\t'], 0x2C: [' ', ' '], 0x2D: ['-', '_'], 0x2E: ['=', '+'],
0x2F: ['[', '{'], 0x30: [']', '}'], 0x31: ['\', '|'], 0x33: [';', ':'],
0x34: [''', '"'], 0x35: ['`', '~'], 0x36: [',', '<'], 0x37: ['.', '>'],
0x38: ['/', '?'], 0x39: ['<CAPSLOCK>', '<CAPSLOCK>']
}

def parse_hid_data(filename):
result = []

text
with open(filename, 'r') as f:
    for line in f:
        line = line.strip()
        if not line or line == "00:00:00:00:00:00:00:00":
            continue
        
        # Parse hex bytes
        bytes_data = line.replace(':', '')
        if len(bytes_data) < 16:
            continue
        
        modifier = int(bytes_data[0:2], 16)
        keycode = int(bytes_data[4:6], 16)  # Third byte
        
        if keycode == 0:
            continue
        
        # Check if Shift is pressed
        shift = (modifier & 0x02) or (modifier & 0x20)
        
        if keycode in usb_codes:
            char = usb_codes[keycode][1 if shift else 0]
            result.append(char)

return ''.join(result)
Decode the captured keystrokes
decoded = parse_hid_data('usbhid_keys.txt')
print(decoded)

text

##### Step 4: Analyzing the Decoded Output

Running the decoder produced:

<CAPSLOCK>akasec<CAPSLOCK>{}w1r35h4rk_1s_k!<BACKSPACE>1nd4_l1k3_a_5n17ch

text

##### Step 5: Flag Reconstruction

Applying the capslock and backspace operations:

1. **CAPSLOCK pressed** → Capslock enabled
2. Type "akasec" → With capslock = **AKASEC**
3. **CAPSLOCK pressed again** → Capslock disabled
4. Type `{}w1r35h4rk_1s_k!`
5. **BACKSPACE** → Removes the "!" character
6. Type `1nd4_l1k3_a_5n17ch`

---

#### 🚩 The Flag

AKASEC{w1r35h4rk_1s_k1nd4_l1k3_a_5n17ch}

text

*(In leetspeak: "wireshark is kinda like a snitch")*

---

#### 🧠 Key Takeaways

1. **USB traffic forensics** can reveal everything typed on a keyboard by capturing USB packets
2. The correct field for USB HID keyboard data is **`usbhid.data`**, not `usb.capdata`
3. USB HID uses an **8-byte structure** with modifier keys and keycodes
4. Special keys like **CAPSLOCK**, **BACKSPACE**, and modifier keys (Shift, Ctrl, Alt) must be handled during decoding
5. The flag cleverly references how Wireshark can "snitch" on users by revealing their keystrokes through packet analysis

---

#### 🛠️ Tools Used

- **tshark** - Command-line packet analyzer for PCAP extraction
- **Python 3** - For decoding USB HID keycodes
- **USB HID specification** - For understanding the keycode mapping

---

#### 📚 References

- [USB HID Keycode Specification](https://www.usb.org/sites/default/files/documents/hut1_12v2.pdf)
- [Wireshark USB Capture Documentation](https://wiki.wireshark.org/CaptureSetup/USB)
- [CTF USB Keyboard Parser Tools](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)

---

**Author:** Sphynx  
**CTF:** Odyssey CTF Finals 2025  
**Date:** December 2025
