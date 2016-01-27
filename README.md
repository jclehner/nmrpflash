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
First, we have to assign a static IP address to our network interface:

````
$ sudo ifconfig eth0 192.168.1.2
````

Now we can start `nmrp-flash`. The argument for the `-a` option needs
to be a *free* IP address from the same subnet as the one used by your
network interface. We'll use `192.168.1.254`. The firmware image file
can usually be downloaded directly from Netgear's FTP servers.

````
$ sudo nmrp-flash -i eth0 -a 192.168.1.254 -f EX2700-V1.0.1.8.img
Advertising NMRP server on eth0 ... /
Received configuration request from XX:XX:XX:XX:XX:XX.
Sending configuration: ip 192.168.1.254, mask 255.255.255.0.
Uploading EX2700-V1.0.1.8.img ... OK
Waiting for remote to respond.
Remote finished. Closing connection.
````

### Building and installing

Linux only for now, sorry!

````
$ make && sudo make install
````
