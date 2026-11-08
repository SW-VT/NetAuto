This is a simple utility created for MacOS to help configure network devices that you need to plug directly into and that don't have a display or offer any other easy way to see the IP-Adress.
Before the app is usable it needs permissions to change the configuration of the network adapter, for this open the terminal and execute the setup.sh file. Use the following commands to do so:
cd ~/Downloads/NetAuto
chmod +x setup.sh
sudo ./setup.sh

When opening the app, choose the network-adapter from the dropdown. You see if the adapter is already connected by the green indicator and your IP-Adress on the right.
When switching the app to auto-mode, simply plug into the device you need to configure and the app adjust your IP-Adress to one matching the range of the device you connected to.
It does this by listening to ARP- and IP-Packets via "tcpdump" in the background. You can adjust how long the app listens to these packets below the auto-switch.
The option the define "profiles" allows to set a IP-Adress and net-mask for the network-adapter and an IP-Adress for the other device that is to be tested.
The profiles will only be tested after listening for DHCP, static IP's and LinkLocal have failed.
When not using auto mode, u can manually start the process with the "configure now" button. The "reset to DHCP" button clears all configurations done by the app and sets it back to DHCP.
The app doesn't run in the background, however the configuration aren't reset simply by closing the app so make sure to reset them via the button before terminating the app
