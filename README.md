![icon](nmrpflash.svg)

nmrpflash - Netgear Unbrick Utility
====================================

`nmrpflash` uses Netgear's [NMRP protocol](https://web.archive.org/web/www.chubb.wattle.id.au/PeterChubb/nmrp.html)
to flash a new firmware image to a compatible device. It has been successfully tested with
various models (D7000, DNG3700v2, EX2700, EX6100v2, EX6120, EX6150v2, EX8000, R6020, R6080, R6100, R6220, R6400, R7000,
R7000P, R6800, R8000, R8000P, R8500, RAX40, RBR40, RBS40, RBR50, RBS50, SRR60, SRS60, WAX202, WNDR3800, WNDR4300, WNDR4500v3,
WNDR4700, WNR3500), but is likely to be compatible with most other Netgear devices as well.

Prebuilt binaries for Linux, macOS and Windows are available [here](https://github.com/jclehner/nmrpflash/releases)
([Npcap](https://nmap.org/npcap/#download) is required on Windows). 

On Linux and macOS, using [Homebrew](https://formulae.brew.sh/formula/nmrpflash) is the preferred method. Packages maintained
by your Linux distribution may be hopelessly outdated (as of 2024-10-01, the current version in Debian based distros such
as Ubuntu is 0.9.14, released more than 4 years earlier!).

A [FreeBSD package](https://ports.freebsd.org/cgi/ports.cgi?query=nmrpflash) can be fetched and installed using the `pkg` command.

```
Usage: nmrpflash [OPTIONS...]

Options (-i, and -f or -c are mandatory):
 -a <ipaddr>     IP address to assign to target device [10.164.183.253]
 -A <ipaddr>     IP address to assign to selected interface [10.164.183.252]
 -B              Blind mode (don't wait for response packets)
 -c <command>    Command to run before (or instead of) TFTP upload
 -f <firmware>   Firmware file
 -F <filename>   Remote filename to use during TFTP upload
 -i <interface>  Network interface directly connected to device
 -m <mac>        MAC address of target device (xx:xx:xx:xx:xx:xx)
 -M <netmask>    Subnet mask to assign to target device [255.255.255.0]
 -t <timeout>    Timeout (in milliseconds) for NMRP packets [10000 ms]
 -T <timeout>    Time (seconds) to wait after successfull TFTP upload [1800 s]
 -p <port>       Port to use for TFTP upload [69]
 -R <region>     Set device region (NA, WW, GR, PR, RU, BZ, IN, KO, JP)
 -S <n>          Skip <n> bytes of the firmware file
 -v              Be verbose
 -V              Print version and exit
 -L              List network interfaces
 -h              Show this screen

When using -c, the environment variables IP, PORT, NETMASK
and MAC are set to the device IP address, TFTP port, subnet
mask and MAC address, respectively.
```

### Using nmrpflash

First, download the correct firmware image for your device. When downloading from the Netgear site,
the firmware is usually contained in a `.zip` file - extract this first. The actual firmware
file will have an extension such as `.chk`, `.bin`, `.trx` or `.img`.

Now, using an Ethernet cable, connect your Netgear router to the computer that will run
`nmrpflash`. Use the LAN port, which is often colored blue on Netgear devices. If the
router has multiple LAN ports, use the one labled _1_.

Next, you'll have to determine which network interface corresponds to the one connected to
the Netgear router. All available interfaces can be listed using  

```
# nmrpflash -L
eth0      192.168.1.2  c0:de:fa:ce:01:23
eth2      0.0.0.0      ca:fe:ba:be:45:67
wifi0     10.0.10.138  de:ad:be:ef:89:ab
```

For the rest of this example, let's assume that your router is connected to `eth2`, and that
you want to flash a firmware image named `EX2700-V1.0.1.8.img`.

First of all, turn *off* the router. Then start `nmrpflash` using the following command:

```
# nmrpflash -i eth2 -f EX2700-V1.0.1.8.img
Waiting for Ethernet connection (Ctrl-C to skip).
```

As soon as you see the `Waiting for Ethernet connection.` message, turn the router *on*. If all went
well, `nmrpflash` will continue printing messages:

```
Advertising NMRP server on eth2 ... /
Received configuration request from fe:ed:1b:ad:f0:0d
Sending configuration: 10.164.183.252/24
Received upload request: filename 'firmware'.
Uploading EX2700-V1.0.1.8.img ... OK (3539077 b)
Waiting for remote to respond.
Received keep-alive request (11).
Remote finished. Closing connection.
Reboot your device now.
```

Now reboot the device, and you're good to go.

### Common issues

**In any case, run `nmrpflash` with `-vvv` before filing a bug report!**

###### "Error while loading shared libraries: ..." (Linux)

You must install your Linux distribution's `libpcap` and `libnl-3`
packages (exact names will vary depending on your distribution).

On Debian based distros (such as Ubuntu) you can install these dependencies with

    sudo apt install libpcap libnl-3

###### "The program can't start because wpcap.dll is missing" (Windows)

Install [Npcap](https://nmap.org/npcap/#download) with "WinPcap Compatibility" enabled.

Version 0.9.13 was the last version to support Windows XP.

###### "nmrpflash cannot be opened because the developer cannot be verified." (macOS)

Go to ` -> System Preferences -> Security & Privacy`. Under the `General` tab, there should
be a message like "nmrpflash was blocked from use because it is not from an identified
developer". Click the `Allow anyway` button next to it, and run `nmrpflash` again.
If that doesn't work, try [this](https://support.apple.com/guide/mac-help/open-a-mac-app-from-an-unidentified-developer-mh40616/mac).

Please note that [Homebrew](https://formulae.brew.sh/formula/nmrpflash) is the preferred method of
installing `nmrpflash` on macOS.

###### "No suitable network interfaces found."

Make sure the network interface is up (wireless interfaces are not supported).
On Windows, try restarting the Npcap service (commands must be run as
administrator):

```
C:\> net stop npf
C:\> net start npf
```

###### "No response after 60 seconds. Bailing out."

Always run `nmrpflash` in the sequence described [above](#using-nmrpflash)!

If it still doesn't work, try different Ethernet ports if your device
has more than one.

You can try specifying the MAC address using `-m xx:xx:xx:xx:xx:xx`,
or, if that still doesn't work, "blind mode" using `-B`. Note that
careful timing between running `nmrpflash` and turning on the router may
be required in this mode.

It's also possible the bootloader itself is bricked, or that the
particular device does not support the NMRP protocol.

###### Stuck at "Waiting for remote to respond."

The file transfer was successful, but the router still needs to actually
write the data to the flash chip. Depending on the image size, this can
take quite some time: times of 15 minutes and more have been reported.

Some devices will send keep-alive packets (see [below](#received-keep-alive-request))
during this time, which are esentially telling `nmrpflash` that it's still busy flashing.

Do not reboot your device at this time, because flashing is probably
still in progress (sometimes indicated by flashing LEDs). Only when
nmrpflash says `Reboot your device now.` you can assume that the
process has finished.

###### "Timeout while waiting for ACK(0)/OACK."

`nmrpflash` didn't receive a response to the initial TFTP upload request. This
either indicates an IP configuration issue, or a firewall is blocking the TFTP
packets from reaching the device running `nmrpflash`.

If you do have an active firewall, either disable it before running `nmrpflash`,
or make sure that incoming packets for port 69 aren't being blocked.

By default, `nmrpflash` will assign `10.164.183.252` to the target device, while adding
`10.164.183.253` to the network interface specified by the `-i` flag. You can use `-a`
to change the IP address assigned to the target (e.g. if your network is `192.168.1.0/24`,
specify a *free* IP address, such as `-a 192.168.1.252`), and `-A` to change the IP address
used for the network interface.

###### "Timeout while waiting for CLOSE_REQ."

After a successful file upload, `nmrpflash` waits for up to 30 minutes for an
answer from your device. You can increase this by specifying a longer timeout
using `-T` switch (argument is in seconds).

It's entirely possible that the image was flashed successfully, but the
operation took longer than 15 minutes.

###### "Address X/Y cannot be used on interface Z."

`nmrpflash` refuses to use an IP address / subnet mask combination that would
make the remote device unreachable from the device running `nmrpflash`. For
example, if the IP address of your computer is 192.168.0.1/255.255.255.0, assigning
192.168.2.1/255.255.255.0 to the router makes no sense, because the TFTP upload will
fail.

###### "IP address of X has changed. Please assign a static IP to the interface."

This can happen if the network interface in question automatically detects that
the network cable has been connected, and your computer tries to reconfigure that
interface (NetworkManager on Linux does this for example) - this can usually be
disabled.

###### "Received keep-alive request."

This usually means that flashing is in progress. On some devices, you may get a few
hundred keep-alive requests before it eventually finishes! On others, you'll only
receive a few, with many minutes between each message.

###### "TFTP block rollover. Upload might fail!"

By default, file transfers using TFTP are limited to `65535 * 512` bytes
(almost 32 MiB). Uploading files exceeding this limit might fail, depending
on the device. If it does fail, your only option is flashing an older image,
which is smaller than 32 MiB.

###### "Ignoring extra upload request."

Extraneous upload requests are usually sent by the device if the image validation
failed. Some possible causes are:

* If you downloaded a firmware that's contained in an archive (a `.zip` for
example), you must extract this file, and then use the contained firmware file
as the argument to the `-f` parameter. Some examples for file extensions used
for firmware: `.chk`, `.bin`, `.trx`, `.img`.

* Some devices prevent you from downgrading the firmware. See if it works with
the latest version available for your device. If you're already using the latest
version, it might be possible to patch the version info of the firmware file. A
future version of `nmrpflash` might incorporate an auto-patch feature for these
cases.

* Your device might expect a different image format for `nmrpflash` than when
flashing via the web interface.

###### "Timeout while waiting for 0000." after "Waiting for remote to respond."

This could indicate that the device hasn't finished flashing, after the default timeout
(15 minutes). Try increasing the timeout, using the `-T <seconds>` option,
for example use `-T 1800` to specify a timeout of 30 minutes.

###### "bind: Cannot assign requested address"

Specify the address of the router (`-a`), and address of your computer (`-A`).
For example:

`-A 10.0.0.2 -a 10.0.0.1`

or

`-A 192.168.1.2 -a 192.168.1.1`

### Building
###### Linux, Mac OS X, BSDs

On Linux, developer packages for `libpcap`, `libnl` and `libnl-route` must be installed:

```
$ sudo apt install libpcap-dev libnl-3-dev libnl-route-3-dev
```

Then, it's as easy as 

```
$ make
```

###### Windows

The repository includes a [CodeBlocks](https://www.codeblocks.org/) project
file (`nmrpflash.cbp`). Download the latest [Npcap SDK](https://nmap.org/npcap/)
and extract it into the a folder named `Npcap` in the source's root directory.

### Donate

You can [buy me a coffee](https://www.buymeacoffee.com/jclehner) if you want, but please consider
donating the money for charity instead - [Médecins Sans Frontiers](https://www.msf.org/donate) comes to mind,
but any other organization, local or international, that you think deserves support will do. Thank you!

