nmrpflash - Netgear Unbrick Utility
====================================

This program uses Netgear's [NMRP protocol]
(http://www.chubb.wattle.id.au/PeterChubb/nmrp.html)
to flash a new firmware image to a compatible device. This utility has been
tested with a Netgear EX2700, but is likely to work on many others as well.

Prebuilt binaries for Linux, OS X and Windows are available
[here](https://github.com/jclehner/nmrpflash/releases)
([WinPcap](https://www.winpcap.org/install/default.htm) is required on Windows).

````
Usage: nmrpflash [OPTIONS...]

Options (-a, -i and -f are mandatory):
 -a <ipaddr>     IP address to assign to target device
 -f <firmware>   Firmware file
 -i <interface>  Network interface directly connected to device
 -m <mac>        MAC address of target device (xx:xx:xx:xx:xx:xx)
 -M <netmask>    Subnet mask to assign to target device
 -t <timeout>    Timeout (in milliseconds) for regular messages
 -T <timeout>    Time to wait after successfull TFTP upload
 -p <port>       Port to use for TFTP upload
 -U              Test TFTP upload
 -v              Be verbose
 -V              Print version and exit
 -L              List network interfaces
 -h              Show this screen
````

### Using nmrpflash

Connect your Netgear router to your computer using a network cable.
Assign a static IP address to the network adapter that's plugged into
the Netgear router.

For this example, we'll assume that your network interface is `eth0`.
First, we have to assign a static IP address to our network interface.
In this example, we'll use `192.168.1.2`. All available network interfaces
can be listed using

````
$ nmrpflash -L
eth0      192.168.1.2  f2:11:a1:02:03:b1
````

Now we can `nmrpflash`. The argument for the `-a` option needs
to be a *free* IP address from the same subnet as the one used by your
network interface. We'll use `192.168.1.254`. Firmware images can usually 
be downloaded directly from netgear. For details on how to do this, see
[here](#obtaining-firmware-images). Power on your device immediately 
after starting `nmrpflash`.

````
$ nmrpflash -i eth0 -a 192.168.1.254 -f EX2700-V1.0.1.8.img
Advertising NMRP server on eth0 ... /
Received configuration request from a4:2b:8c:00:00:01.
Sending configuration: ip 192.168.1.254, mask 255.255.255.0.
Uploading EX2700-V1.0.1.8.img ... OK
Waiting for remote to respond.
Remote finished. Closing connection.
````

### Common issues
###### "No suitable network interfaces found."

If you're *not* on Windows, rerun `nmrpflash -L` using `sudo`. In any case,
use `-vvvL` to see more detailed messages, and file a bug report if applicable.

###### "No response after 60 seconds. Bailing out."

The router did not respond. Try running `nmrpflash` with `-m` and specify
your router's MAC address. It's also entirely possible that your device does
not support the NMRP protocol.

###### "Timeout while waiting for 0x04."

After a successful file upload, `nmrpflash` waits for up to 120 seconds for an
answer from your device. You can increase this by specifying a longer timeout
using `-T` switch (argument is in seconds).

It's entirely possible that the image was flashed successfully, but the
operation took longer than 120 seconds.

### Building and installing
###### Linux, Mac OS X, BSDs

````
$ make && sudo make install
````

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

