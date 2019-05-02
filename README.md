nmrpflash - Netgear Unbrick Utility
====================================

`nmrpflash` uses Netgear's [NMRP protocol](http://www.chubb.wattle.id.au/PeterChubb/nmrp.html)
to flash a new firmware image to a compatible device. It has been successfully used on a Netgear
EX2700, DNG3700v2 and R6220, R7000, D7000, WNR3500L, but is likely to be compatible with many
other Netgear devices.

Prebuilt binaries for Linux, ~OS X~ macOS and Windows are available
[here](https://github.com/jclehner/nmrpflash/releases)
([WinPcap](https://www.winpcap.org/install/default.htm) is required on Windows).

```
Usage: nmrpflash [OPTIONS...]

Options (-i and -f and/or -c are mandatory):
 -a <ipaddr>     IP address to assign to target device
 -A <ipaddr>     IP address to assign to interface
 -c <command>    Command to run before (or instead of) TFTP upload
 -f <firmware>   Firmware file
 -F <filename>   Remote filename to use during TFTP upload
 -i <interface>  Network interface directly connected to device
 -m <mac>        MAC address of target device (xx:xx:xx:xx:xx:xx)
 -M <netmask>    Subnet mask to assign to target device
 -t <timeout>    Timeout (in milliseconds) for regular messages
 -T <timeout>    Time (seconds) to wait after successfull TFTP upload
 -p <port>       Port to use for TFTP upload
 -R <region>     Set device region (NA, WW, GR, PR, RU, BZ, IN, KO, JP)
 -v              Be verbose
 -V              Print version and exit
 -L              List network interfaces
 -h              Show this screen
```

### Using nmrpflash

Your Netgear router must be connected to your network using an
Ethernet cable. The device running `nmrpflash` must be connected
to the same network, using either Wi-Fi or Ethernet.

All available network interfaces can be listed using

```
# nmrpflash -L
eth0      192.168.1.2  f2:11:a1:02:03:b1
```

Once you've determined the interface to use, we can flash the image. Firmware
images can usually be downloaded directly from Netgear. Power on your device
immediately after starting `nmrpflash`.

```
# nmrpflash -i eth0 -f EX2700-V1.0.1.8.img
Advertising NMRP server on eth0 ... /
Received configuration request from a4:2b:8c:00:00:01.
Sending configuration: ip 10.164.183.252, mask 255.255.255.0.
Received upload request: filename 'firmware'.
Uploading EX2700-V1.0.1.8.img ... OK
Waiting for remote to respond.
Remote finished. Closing connection.
Reboot your device now.
```

### Common issues

In any case, run `nmrpflash` with `-vvv` before filing a bug report. Also,
try connecting your Netgear router *directly* to the computer running
`nmrpflash`.

###### "Error while loading shared libraries: ..." (Linux)

You must install your Linux distribution's `libpcap` and `libnl-3`
packages (exact names will vary depending on your distribution).

###### "The program can't start because wpcap.dll is missing" (Windows)

On Windows 8.1 and older, install [WinPcap](https://www.winpcap.org/install/default.htm).
On Windows 10, install [Npcap](https://nmap.org/npcap/) (be sure to select "WinPcap Compatibility").

###### "No suitable network interfaces found."

Make sure the network interface is up (wireless interfaces are not supported).
On Windows, try restarting the WinPcap service (commands must be run as
administrator):

```
C:\> net stop npf
C:\> net start npf
```

###### "No response after 60 seconds. Bailing out."

The router did not respond. Try rebooting the device and run `nmrpflash` again.
You could also try running `nmrpflash` with `-m` and specify your router's
MAC address. It's also possible that your device does not support the NMRP protocol.

###### "Timeout while waiting for ACK(0)/OACK."

The device did not respond to `nmrpflash`'s TFTP upload request. By default,
`nmrpflash` will assign `10.164.183.252` to the target device, while adding `10.164.183.253`
to the network interface specified by the `-i` flag. You can use `-a` to change the IP
address assigned to the target (e.g. if your network is `192.168.1.0/24`, specify a *free*
IP address, such as `-a 192.168.1.252`), and `-A` to change the IP address used for the
network interface.

This error message could also indicate a bug in the TFTP code; try using an external tftp
client (busybox in this example), by specifying the `-c` flag instead of the `-f` flag:

`# nmrpflash -i eth0 -c 'busybox tftp -p -l EX2700-V1.0.1.8.img $IP'`

The environment variable `IP` is set by `nmrpflash` (other environment variables
are: `MAC`, `PORT`, `NETMASK`).

###### "Timeout while waiting for CLOSE_REQ."

After a successful file upload, `nmrpflash` waits for up to 5 minutes for an
answer from your device. You can increase this by specifying a longer timeout
using `-T` switch (argument is in seconds).

It's entirely possible that the image was flashed successfully, but the
operation took longer than 5 minutes.

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

An alternative would be to add `-c 'ifconfig <interface> <ip>'` to the command line,
for example:

`# nmrpflash -i eth0 -a 192.168.1.1 -f firmware.bin -c 'ifconfig eth0 192.168.1.2'`

This will execute the command specified by `-c` prior to starting the TFTP upload (in
this case setting the IP address to 192.168.1.2).

### Building and installing
###### Linux, Mac OS X, BSDs

```
$ make && sudo make install
```

###### Windows

The repository includes a
[DevCpp](http://sourceforge.net/projects/orwelldevcpp/)
project file (`nmrpflash.dev`). Download the latest
[WinPcap Developer Pack](https://www.winpcap.org/devel.htm)
and extract it into the root folder of the nmrpflash sources.



