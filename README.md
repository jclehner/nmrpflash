nmrpflash - Netgear Unbrick Utility
====================================

This program uses Netgear's [NMRP protocol]
(http://www.chubb.wattle.id.au/PeterChubb/nmrp.html)
to flash a new firmware image to a compatible device. This utility has been
successfully used on a Netgear EX2700 and DNG3700v2, but is likely to work
with many other Netgear routers as well.

Prebuilt binaries for Linux, OS X and Windows are available
[here](https://github.com/jclehner/nmrpflash/releases)
([WinPcap](https://www.winpcap.org/install/default.htm) is required on Windows).

```
Usage: nmrpflash [OPTIONS...]

Options (-a, -i and -f and/or -c are mandatory):
 -a <ipaddr>     IP address to assign to target device
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

Connect your Netgear router to your computer using a network cable.
Assign a static IP address to the network adapter that's plugged into
the Netgear router.

For this example, we'll assume that your network interface is `eth0`.
First, we have to assign a static IP address to our network interface.
In this example, we'll use `192.168.1.2`. All available network interfaces
can be listed using

```
# nmrpflash -L
eth0      192.168.1.2  f2:11:a1:02:03:b1
```

Now we can flash the image. The argument for the `-a` option needs
to be a *free* IP address from the same subnet as the one used by your
network interface; we'll use `192.168.1.254`. Firmware images can usually 
be downloaded directly from Netgear. For details on how to do this, see
[here](#obtaining-firmware-images). Power on your device immediately 
after starting `nmrpflash`.

```
# nmrpflash -i eth0 -a 192.168.1.254 -f EX2700-V1.0.1.8.img
Advertising NMRP server on eth0 ... /
Received configuration request from a4:2b:8c:00:00:01.
Sending configuration: ip 192.168.1.254, mask 255.255.255.0.
Received upload request: filename 'firmware'.
Uploading EX2700-V1.0.1.8.img ... OK
Waiting for remote to respond.
Remote finished. Closing connection.
Reboot your device now.
```

### Common issues

In any case, run `nmrpflash` with `-vvv` before filing a bug report.

###### "Error while loading shared libraries: libpcap.so.0.8" (Linux)

You must install your Linux distribution's `libpcap` package. In
openSUSE or Ubuntu for example, install `libpcap0.8`. Other distros
will have a similarily named package.

###### "The program can't start because wpcap.dll is missing" (Windows)

Install [WinPcap](https://www.winpcap.org/install/default.htm).

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

###### "Timeout while waiting for initial reply."

The device did not respond to `nmrpflash`'s TFTP upload request. This could indicate a bug
in the TFTP code; try using an external tftp client (busybox in this example), by specifying
the `-c` flag instead of the `-f` flag:

`# nmrpflash -i eth0 -a 192.168.1.254 -c "busybox tftp -p -l EX2700-V1.0.1.8.img 192.168.1.254"`

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

### Obtaining firmware images

Firmware images can be downloaded directly from Netgear's FTP servers. 
For the Netgear EX2700 for example, download 
ftp://updates1.netgear.com/ex2700/ww/fileinfo.txt. At the top there 
should be an entry like this:

```
[Major1]
file=EX2700-V1.0.1.8.img
...
```

The download link for the latest firmware image for this device is thus:
ftp://updates1.netgear.com/ex2700/ww/EX2700-V1.0.1.8.img. Substitute 
`ex2700` for your device (`wndr4300`, `wndr3700`, `r6100`, etc.). If
neccessary, substitute `ww` (world-wide) for a specific region.

