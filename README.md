# SSH.RP

This project is a proof of concept for a SSHv2 server firmware running on RP2040 boards with WIZnet W5500 Ethernet connectivity: the **W55RP20** (RP2040 + W5500 in one package) and a plain **RP2040 wired to a W5500 module**.

> **Status:** working demo; not security-audited.

https://github.com/user-attachments/assets/5dbaef80-8824-4386-9a1a-672467e0bc72

---

## Hardware

| PlatformIO env | Board | Ethernet link | Status LED | Default |
| :--- | :--- | :--- | :--- | :--- |
| `w55rp20` | W55RP20 | Internal W5500 on PIO-driven SPI (GPIO 20–25) | GPIO 19 | Yes |
| `rp2040_w5500` | RP2040 + W5500 | SPI0: MISO 16, CS 17, SCK 18, MOSI 19; RST 20 | GPIO 25 | No |

> **W55RP20:** GPIO 25 is the internal W5500 reset line, not an LED. Driving it drops the network. The user LED is GPIO 19. [(Core Pin Assignment)](https://github.com/earlephilhower/arduino-pico/blob/master/variants/wiznet_55rp20_evb_pico/pins_arduino.h)

Wiring for `rp2040_w5500` (W5500 module → Pico): MISO → GP16, CS → GP17, SCK → GP18, MOSI → GP19, RST → GP20, plus 3V3 and GND. The W5500-EVB-Pico already has this wiring on board.

---

## Security model

| Item | Implementation |
| :--- | :--- |
| Key exchange | `curve25519-sha256` |
| Host key | `ssh-ed25519` |
| Cipher and MAC | `aes128-ctr` + `hmac-sha2-256` with stock OpenSSH (`aes192/256-ctr` and `hmac-sha2-512` are also offered) |
| Login | User `admin` with one authorized Ed25519 key, plus an optional password |
| Randomness | Pico SDK `pico_rand` seeding wolfCrypt's Hash-DRBG |

Stock OpenSSH clients connect without extra options. wolfSSH does not implement ChaCha20-Poly1305, so don't force `chacha20-poly1305@openssh.com` on the client.

Limits: one session at a time and one authorized key. The keys are stored in the firmware, and anyone with USB access can read the flash in BOOTSEL mode.

---

## How it works

- The Arduino-Pico Ethernet drivers use the W5500 as a raw network interface; TCP/IP runs in lwIP on the RP2040.
- wolfSSL and wolfSSH are git submodules in `deps/`. PlatformIO compiles them from source, configured by `include/user_settings.h`.
- `include/keys.h` holds both keys as text, exactly as `ssh-keygen` writes them. wolfSSH needs them in binary form, so `src/main.cpp` converts them at boot.
- `src/main.cpp` waits for a client, runs the SSH handshake (60 s timeout) and then serves the shell. A client that disappears without disconnecting (cable pulled, PC asleep) is dropped after about a minute so it can't block the board.

---

## Repository layout

```text
SSH.RP/
├── platformio.ini            # Board environments and the wolfSSL/wolfSSH source list
├── include/
│   ├── KEY_MANAGEMENT.md     # How to create and setup the keys
│   ├── keys.h.example        # Template for keys.h
│   ├── keys.h                # Your keys (you create it; git-ignored)
│   └── user_settings.h       # wolfSSL/wolfSSH configuration
├── deps/
│   ├── wolfssl/              # wolfSSL submodule
│   └── wolfssh/              # wolfSSH submodule
└── src/
    └── main.cpp              # IP settings, key loading, SSH server and shell

```

---

## Quick start

### 1. Install the tools

- [VS Code](https://code.visualstudio.com/) with the **PlatformIO IDE** extension.
- [Git](https://git-scm.com/downloads), to clone the repository with its submodules.
- The OpenSSH client (`ssh`, `ssh-keygen`). It comes with Windows 10/11, macOS and Linux.
- **Windows only:** enable long paths before PlatformIO first downloads the Arduino-Pico core, or the install fails with `Filename too long`:
  1. In a Command Prompt run as administrator, run `git config --system core.longpaths true`.
  2. Turn on *Enable Win32 long paths* (Group Policy → Computer Configuration → Administrative Templates → System → Filesystem), or set the registry value `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled` to `1`.
  3. Reboot.

### 2. Clone with submodules

```bash
git clone --recurse-submodules https://github.com/RicardoJCMarques/SSH.RP.git
```

If you downloaded/cloned without `--recurse-submodules`, run `git submodule update --init --recursive` inside the folder.

### 3. Set the board's IP address

The board uses a static address, set near the top of `src/main.cpp`:

```cpp
static const IPAddress BOARD_IP(192, 168, 1, 120);
static const IPAddress BOARD_GATEWAY(192, 168, 1, 1);
static const IPAddress BOARD_NETMASK(255, 255, 255, 0);
```

Pick an unused address on your network's subnet.

### 4. Create the keys

Follow [include/KEY_MANAGEMENT.md](include/KEY_MANAGEMENT.md). The build fails with `include/keys.h is missing` until this is done.

### 5. Build and upload

Open the `SSH.RP` folder in VS Code. In the PlatformIO sidebar, expand your board's environment (`w55rp20` or `rp2040_w5500`) and click **Upload**; this builds the firmware first. The first build takes a while because PlatformIO downloads the toolchain and compiles wolfSSL.

For the first upload, hold the BOOTSEL button while plugging in USB. Later uploads reset the board automatically. If the upload can't find the board, drag `.pio/build/<env>/firmware.uf2` onto the `RPI-RP2` drive instead.

### 6. Connect

Connect the board to your network and run:

```bash
ssh -i ~/.ssh/sshrp/id_ed25519 sshrp@192.168.1.120
```

On the first connection, OpenSSH shows the board's fingerprint and asks whether to continue; answer `yes`. To connect with just `ssh sshrp@192.168.1.120`, add the board to your SSH config as shown in [KEY_MANAGEMENT.md](include/KEY_MANAGEMENT.md#4-optional-shorter-ssh-command).

---

## Shell commands

| Command | Action |
| :--- | :--- |
| `on` | Turn the status LED on |
| `off` | Turn the status LED off |
| `blink` | Blink the status LED until `on` or `off` |
| `status` | Report the LED state |
| `exit` | Close the session |

---

## Configuration

| What | Where |
| :--- | :--- |
| Board IP address | `BOARD_IP`, `BOARD_GATEWAY`, `BOARD_NETMASK` in `src/main.cpp`. To use DHCP, remove the `eth.config(...)` line in `setup()` |
| Keys and optional password | `include/keys.h` |
| Login name, port, handshake timeout, blink rate | `SSH_USER`, `SSH_PORT`, `HANDSHAKE_TIMEOUT_MS`, `BLINK_INTERVAL_MS` in `src/main.cpp` |
| LED and W5500 pins | `build_flags` of each environment in `platformio.ini` |
| Algorithms and buffer sizes | `include/user_settings.h` |

---

## Troubleshooting

| Symptom | Likely cause |
| :--- | :--- |
| `Filename too long` while PlatformIO installs packages | Windows long paths are not enabled (step 1). |
| Build error `include/keys.h is missing` | The keys haven't been created yet (step 4). |
| `ssh` times out | The board isn't reachable. Check the cable and that `BOARD_IP` is on your PC's subnet and not used by another device. |
| `Connection refused` | The board is reachable, but a key in `keys.h` is invalid, so the SSH server didn't start. |

The serial monitor (115200 baud) shows the board's status and any `[ERR]` messages. Key and login problems are covered in [KEY_MANAGEMENT.md](include/KEY_MANAGEMENT.md#troubleshooting).

---

## Dependencies

| Component | Version |
| :--- | :--- |
| wolfSSL / wolfCrypt | git submodule |
| wolfSSH | git submodule |
| Arduino-Pico core | Installed by PlatformIO through [maxgerhardt/platform-raspberrypi](https://github.com/maxgerhardt/platform-raspberrypi) |

---

## License

The firmware is licensed under **GPL-3.0-or-later**. wolfSSL, wolfSSH and Arduino-Pico keep their own licenses.