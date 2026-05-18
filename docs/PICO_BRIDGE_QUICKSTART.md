# Pi Pico bridge — quick start (5 minutes)

This is the short, end-user version. For wiring details, troubleshooting,
and alternative firmware see [`PICO_BRIDGE.md`](PICO_BRIDGE.md).

You will end up with a Raspberry Pi Pico that shows up on your computer as
a USB serial device (`/dev/ttyACM0` on Linux/macOS, `COMx` on Windows) and
relays bytes between the GBA Signer extension and the GBA link cable.

## What you need

- 1x Raspberry Pi Pico (any variant: Pico, Pico W, Pico 2)
- 1x USB cable for the Pico (micro-B for Pico/Pico W, USB-C for Pico 2)
- 1x GBA link cable wired to the Pico (3 wires: SO, SI, GND).
  See the wiring diagram in [`PICO_BRIDGE.md`](PICO_BRIDGE.md).
- 1x computer with a USB port

## Step 1 — Flash MicroPython

1. Hold the **BOOTSEL** button on the Pico, plug the USB cable.
   Keep BOOTSEL pressed until a removable drive named **`RPI-RP2`**
   appears on your computer.
2. Download the official MicroPython firmware for your Pico variant from
   <https://micropython.org/download/RPI_PICO/> (use `RPI_PICO2` for the
   Pico 2). The file is a `.uf2`.
3. Drag the `.uf2` onto the `RPI-RP2` drive. The Pico reboots and the
   drive disappears. After 1–2 seconds it reappears as a serial device.

## Step 2 — Copy `main.py` to the Pico

You have two ways to do this; pick whichever you prefer.

### Option A — One command (recommended, all OSes)

```bash
# install once
pip install --user mpremote

# copy main.py from this bundle to the Pico
mpremote cp main.py :main.py
mpremote reset
```

### Option B — Thonny (graphical, no terminal needed)

1. Install Thonny from <https://thonny.org/>.
2. Open Thonny. Bottom-right of the window, click the interpreter and
   pick **MicroPython (Raspberry Pi Pico)**.
3. View → Files. In the bottom panel ("Raspberry Pi Pico"), right click
   → **Upload to /** and select the `main.py` from this bundle.
4. Right click `main.py` on the Pico → **Run**, or unplug+replug the USB.

## Step 3 — Verify

Unplug the Pico and plug it back in. Open a terminal and run:

- **Linux**: `ls /dev/ttyACM*` should show `/dev/ttyACM0` (or higher).
- **macOS**: `ls /dev/tty.usbmodem*` should show one entry.
- **Windows**: open Device Manager → Ports (COM & LPT). You should see
  "USB Serial Device (COMx)".

That is it for the Pico side. Now connect the GBA link cable to the Pico
following the wiring diagram in [`PICO_BRIDGE.md`](PICO_BRIDGE.md), and
move on to installing the browser extension.

## Notes for advanced users

- The bridge has a 2-second "rescue window" right after boot during which
  Ctrl-C still kills the script (so you can recover the REPL). After
  those 2 seconds the script disables Ctrl-C interception so it does not
  break on binary RLP traffic.
- The serial speed is fixed at 115200 baud, 8N1. Do not change it.
- If you want lower latency than MicroPython can give you (rare for this
  workload — we send <4 KB per transaction), flash the prebuilt UF2 from
  <https://github.com/Noltari/pico-uart-bridge> instead. Same wiring, no
  Python required.
