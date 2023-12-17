# ESSID-Uncover
A tool to uncover hidden SSIDs

Usage:
  - sudo python uncover.py

Requires interface which can be set in Monitor mode

Once started the scan runs indefinitely, press Ctrl+c to stop.

All results are saved in the following .txt files:

  known.txt <------ all MAC addresses for public SSIDs
  unknown.txt <----- all MAC addresses for hidden BSSIDs
  uncovered.txt <----- discovered hidden network names
  
