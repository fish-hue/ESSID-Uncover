# ESSID-Uncover
A tool to uncover hidden SSIDs

Usage:
  - sudo python uncover.py

Requires interface which can be set in Monitor mode

Once started the scan runs indefinitely, press Ctrl+c to stop.

All results are saved in the following .txt files:

  known.txt 
  
  unknown.txt
  
  uncovered.txt

In this script, the hidden network's name can be discovered through the `uncover_ap` method of the `SniffThread` class. 

When a packet is sniffed, the method checks if the packet subtype is 8, which signifies a Beacon frame. If the information element (ESSID) of the Beacon frame is a null SSID (empty or all zeros), it means the network is a hidden network. The MAC address of the access point (pkt.addr2) is then added to the list of unknown access points (self.unknown_ap). The MAC address and ESSID are written to the "unknown.txt" file.

If the information element is not a null SSID, it means the network is not hidden. The MAC address and ESSID are added to the dictionary of known access points (self.ap_list). The MAC address and ESSID are written to the "known.txt" file.

If a Probe Request frame is sniffed (packet subtype 5), it means a client is trying to connect to a hidden network. If the MAC address of the access point is in the list of unknown access points and not in the dictionary of known access points, it means the hidden network's name (ESSID) is being revealed. The MAC address and ESSID are printed to the console and written to the "uncovered.txt" file. The MAC address and ESSID are also added to the dictionary of uncovered access points (self.uncovered_ap).

The dictionary of known access points (self.ap_list) and the dictionary of uncovered access points (self.uncovered_ap) are then added to the "list" dictionary. This "list" dictionary is put in the queue for processing by the main thread.

To discover the hidden network's name, you can analyze the contents of the "uncovered.txt" file.
  
