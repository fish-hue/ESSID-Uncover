from datetime import datetime
from scapy.all import *
import threading
import queue
import os
import time
from tqdm import tqdm  # Progress bar library


class SniffThread(threading.Thread):
    def __init__(self, iface, queue):
        super().__init__()  # Call the base class constructor
        self.iface = iface
        self.queue = queue
        self.ap_list = {}
        self.unknown_ap = []
        self.uncovered_ap = {}
        self.list = {}
        self._stop_event = threading.Event()  # Initialize stop event
        self.start()

        # Initialize logs
        self.initialize_logs()

    def initialize_logs(self):
        with open("unknown.txt", "a") as k:
            k.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n")
        with open("known.txt", "a") as k:
            k.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n")
        with open("uncovered.txt", "a") as k:
            k.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n")

    def uncover_ap(self, pkt):
        try:
            if pkt.type == 0:  # Management frame
                if pkt.subtype == 8:  # Beacon
                    essid = pkt.info
                    if self.is_null(essid):
                        if pkt.addr2 not in self.unknown_ap:
                            self.unknown_ap.append(pkt.addr2)
                            self.log_to_file("unknown.txt", f"MAC: {pkt.addr2}\n")
                    else:  # Known ESSID
                        if pkt.addr2 not in self.ap_list:
                            self.ap_list[pkt.addr2] = essid
                            self.log_to_file("known.txt", f"MAC: {pkt.addr2} ESSID: {essid.decode()}\n")

                elif pkt.subtype == 5:  # Probe Response
                    if pkt.addr2 not in self.uncovered_ap and pkt.addr2 in self.unknown_ap:
                        print(f"MAC: {pkt.addr2} ESSID: {pkt.info}")
                        self.log_to_file("uncovered.txt", f"MAC: {pkt.addr2} ESSID: {pkt.info}\n")
                        self.uncovered_ap[pkt.addr2] = pkt.info

            self.list['kap'] = self.ap_list
            self.list['ucap'] = self.uncovered_ap
            self.queue.put(self.list)
        except AttributeError:
            pass

    def log_to_file(self, filename, data):
        with open(filename, "a") as k:
            k.write(data)

    def is_null(self, ssid):
        """Check if the SSID is null or empty"""
        return not ssid or ssid == "\x00" * len(ssid)

    def run(self):
        sniff(iface=self.iface, prn=self.uncover_ap, stop_filter=lambda x: self._stop_event.is_set())

    def stop(self):
        self._stop_event.set()


def get_iface():
    ifaces = os.listdir("/sys/class/net")
    for no, iface in enumerate(ifaces, start=1):
        print(f"[{no}] {iface}")
    choice = input("Enter Wireless Interface to Use: ")
    
    # Validate user input
    try:
        choice = int(choice)
        if 1 <= choice <= len(ifaces):
            return ifaces[choice - 1]
        else:
            print("Invalid choice, please select a valid interface number.")
            return get_iface()
    except ValueError:
        print("Invalid input. Please enter an integer.")
        return get_iface()


def in_monitor(iface):
    chk = os.popen(f"iwconfig {iface} | grep Monitor").read()
    return chk != ""


def set_monitor(op, iface):
    os.system(f"sudo ifconfig {iface} down")
    if op == 1:
        os.system(f"sudo iw dev {iface} set type monitor")
    elif op == 0:
        os.system(f"sudo iw dev {iface} set type managed")
    else:
        print("Invalid choice")
        
    os.system(f"sudo ifconfig {iface} up")
    return in_monitor(iface)


def monitor_mode(iface):
    """Enable monitor mode on the interface if not already enabled."""
    if in_monitor(iface):
        logging.info(f"Monitor mode already enabled on {iface}")
        print("[+] Monitor mode already enabled on " + iface)  # Changed message to reflect existing status
    else:
        while True:
            print(f"[x] Monitor mode not enabled on {iface}\n[+] Enabling monitor mode...")
            if set_monitor(1, iface):
                logging.info(f"Monitor mode enabled on {iface}")
                print("[+] Monitor mode has been enabled on " + iface)
                break

def clean_up(iface):
    print("[+] Cleaning up the goodness :(")
    set_monitor(0, iface)
    exit()


def main():
    """Main function to handle user interaction and manage threads."""
    interface = get_iface()
    monitor_mode(interface)
    q = queue.Queue()
    data_lock = threading.Lock()  # Lock for thread-safe access to shared data
    thread = SniffThread(interface, q)

    detected_networks = set()
    progress = tqdm(total=100, desc="Sniffing Progress", bar_format='{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} networks')

    try:
        while True:
            time.sleep(2)  # Sleep to prevent high CPU usage
            progress.update(1)  # Update the progress bar to show the script is active

            if not q.empty():
                with data_lock:  # Ensure thread-safe access
                    data = q.get()
                    detected_networks.update(data['kap'].keys())
                    
                    if detected_networks:
                        print(f"[+] Detected Networks: {len(detected_networks)}")
                        for mac in detected_networks:
                            print(f" - {mac}: {data['kap'][mac].decode()}")
                    else:
                        print("[-] Currently no networks detected. Please wait…")  # Slightly softened message

    except KeyboardInterrupt:
        print("\n[+] Interrupt received. Cleaning up...")
        thread.stop()
        clean_up(interface)
    finally:
        progress.close()  # Close the progress bar when the script ends

if __name__ == "__main__":
    if os.getuid() != 0:
        print("No mortals are allowed. Please switch to god-mode (sudo) :)")
        exit()
    else:
        main()
