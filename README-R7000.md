Some helpful hints for putting firmware on the Netgear R7000
============================================================

* As of the writing of this, July 2020, the R7000's web interface does not let you downgrade its firmware, or run 3rd party firmware on it.
* Older versions of the R7000's firmware do allow you to flash 3rd party firmware.
* You can use nrmpflash to downgrade router's firmware, for example R7000-V1.0.3.56_1.1.25.

Here is an example set of steps 
1. Plug in your router, go through the regular stock web interface setup. Note if the router's IP address is now 192.168.1.1 or 10.0.0.1
2. Connect computer your computer to LAN1 with an ethernet cable
3. At the command prompt on your computer, run: 
`sudo nmrpflash -v -i YOUR_ADAPTER_NAME -f R7000-V1.0.3.56_1.1.25.chk -t 10000 -T 10000 -A 10.0.0.2 -a 10.0.0.1`
* Note 1: The instructions from README.md that tell you how to find YOUR_ADAPTER_NAME.
* Note 2: if your router's IP address was 192.168.1.1 then swap out 10.0.0.x with 192.168.1.x for the two IP addresses above
4. Right after running the command, power on your router.  Your router checks for the nmrpflash server on boot.  If all goes well you should see this:

```
sudo nmrpflash -v -i enp0s25 -f R7000-V1.0.3.56_1.1.25.chk -t 10000 -T 10000 -A 10.0.0.2 -a 10.0.0.1
Adding 10.0.0.2 to interface enp0s25.
Advertising NMRP server on enp0s25 ... /
Received configuration request from ab:cd:ef:12:34:56.
Sending configuration: 10.0.0.1/24.
Received upload request without filename.
Using remote filename 'R7000-V1.0.3.56_1.1.25.chk'.
Uploading R7000-V1.0.3.56_1.1.25.chk ... OK
Waiting for remote to respond.
Received keep-alive request (19).  
Remote finished. Closing connection.
Reboot your device now.

```
5. Reboot the device.  You now have old firwmare, congratulations.

