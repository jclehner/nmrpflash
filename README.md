nmrp-flash - Netgear Unbrick Utility
====================================

This program uses Netgear's [NMRP protocol]
(http://www.chubb.wattle.id.au/PeterChubb/nmrp.html)
to flash a new firmware image to a compatible device. This utility has been
tested with a Netgear EX2700, but is likely to work on many others as well.

### Using nmrp-flash

Connect your Netgear router to your computer using a network cable.
Assign a static IP address to your computer (more specifically, to 
the network card that's plugged into the Netgear router).


For this example, we'll assume that your network interface is `eth0`.
First, we have to assign a static IP address to our network interface.
In this example, we'll use `192.168.1.2`. All available network interfaces 
can be listed using

````
$ nmrp-flash -L
eth0      192.168.1.2  f2:11:a1:02:03:b1
````

Now we can start `nmrp-flash`. The argument for the `-a` option needs
to be a *free* IP address from the same subnet as the one used by your
network interface. We'll use `192.168.1.254`. The firmware image file
can usually be downloaded directly from Netgear's FTP servers.

````
$ nmrp-flash -i eth0 -a 192.168.1.254 -f EX2700-V1.0.1.8.img
Advertising NMRP server on eth0 ... /
Received configuration request from a4:2b:8c:00:00:01.
Sending configuration: ip 192.168.1.254, mask 255.255.255.0.
Uploading EX2700-V1.0.1.8.img ... OK
Waiting for remote to respond.
Remote finished. Closing connection.
````

### Building and installing
###### Linux, Mac OS X, BSDs

````
$ make && sudo make install
````

###### Windows

The repository includes a 
[DevCpp](http://sourceforge.net/projects/orwelldevcpp/)
project file (`nmrp-flash.dev`). Download the latest 
[WinPcap Developer Pack](http://www.winpcap.org/devel.htm) 
and extract it into the root folder of the nmrp-flash sources.

