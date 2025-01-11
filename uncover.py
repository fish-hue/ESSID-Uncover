from datetime import datetime
from scapy.all import *
import threading
import queue
import os
import time
from tqdm import tqdm  # Progress bar library

class SniffThread(threading.Thread):
    def __init__(self, iface, packet_queue):
        super().__init__()
        self.iface = iface
        self.packet_queue = packet_queue
        self.ap_list = {}
        self.unknown_ap = []
        self.uncovered_ap = {}
        self.list = {}
        self._stop_event = threading.Event()
        self.log_buffer = {
            "unknown": [],
            "known": [],
            "uncovered": []
        }
        self.initialize_logs()

    def initialize_logs(self):
        for filename in ["unknown.txt", "known.txt", "uncovered.txt"]:
            self.check_file_permissions(filename)
            with open(filename, "a") as f:
                f.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n")

    def check_file_permissions(self, filename):
        try:
            with open(filename, "a"):
                pass
        except IOError as e:
            print(f"Error: File {filename} is not writable. {e}")
            exit(1)

    def uncover_ap(self, pkt):
        try:
            if pkt.haslayer(Dot11):
                if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
                    essid = pkt.info
                    if self.is_null(essid):
                        if pkt.addr2 not in self.unknown_ap:
                            self.unknown_ap.append(pkt.addr2)
                            self.log_buffer["unknown"].append(f"MAC: {pkt.addr2}\n")
                    else:
                        if pkt.addr2 not in self.ap_list:
                            self.ap_list[pkt.addr2] = essid
                            self.log_buffer["known"].append(f"MAC: {pkt.addr2} ESSID: {essid.decode()}\n")
                elif pkt.type == 0 and pkt.subtype == 5:  # Probe Response
                    if pkt.addr2 not in self.uncovered_ap and pkt.addr2 in self.unknown_ap:
                        self.log_buffer["uncovered"].append(f"MAC: {pkt.addr2} ESSID: {pkt.info}\n")
                        self.uncovered_ap[pkt.addr2] = pkt.info

            self.list['kap'] = self.ap_list
            self.list['ucap'] = self.uncovered_ap
            self.packet_queue.put(self.list)

        except AttributeError as e:
            print(f"AttributeError: {e}")

    def is_null(self, ssid):
        return not ssid or ssid == b"\x00" * len(ssid)

    def run(self):
        sniff(iface=self.iface, prn=self.uncover_ap, stop_filter=lambda x: self._stop_event.is_set(), store=False)

    def stop(self):
        self._stop_event.set()
        self.flush_logs()

    def flush_logs(self):
        for key, buffer in self.log_buffer.items():
            if buffer:
                with open(f"{key}.txt", "a") as f:
                    f.writelines(buffer)
                self.log_buffer[key] = []


def get_iface():
    ifaces = os.listdir("/sys/class/net")
    for no, iface in enumerate(ifaces, start=1):
        print(f"[{no}] {iface}")
    while True:
        try:
            choice = int(input("Enter Wireless Interface to Use: "))
            if 1 <= choice <= len(ifaces):
                return ifaces[choice - 1]
        except ValueError:
            print("Invalid input. Please enter a valid interface number.")


def in_monitor(iface):
    return "Monitor" in os.popen(f"iwconfig {iface}").read()


def set_monitor(op, iface):
    os.system(f"sudo ifconfig {iface} down")
    os.system(f"sudo iw dev {iface} set type {'monitor' if op == 1 else 'managed'}")
    os.system(f"sudo ifconfig {iface} up")
    return in_monitor(iface)


def monitor_mode(iface):
    if not in_monitor(iface):
        print(f"[+] Enabling monitor mode on {iface}")
        if set_monitor(1, iface):
            print("[+] Monitor mode enabled.")
        else:
            print("[-] Failed to enable monitor mode. Exiting.")
            exit()


def clean_up(iface):
    print("[+] Cleaning up...")
    set_monitor(0, iface)
    exit()


def main():
    interface = get_iface()
    monitor_mode(interface)
    packet_queue = queue.Queue()
    data_lock = threading.Lock()
    sniff_thread = SniffThread(interface, packet_queue)

    detected_networks = set()
    sniff_thread.start()

    progress = tqdm(total=100, desc="Sniffing Progress", bar_format='{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} networks')

    try:
        while not sniff_thread._stop_event.is_set():
            if not packet_queue.empty():
                with data_lock:
                    data = packet_queue.get()
                    detected_networks.update(data['kap'].keys())
                    progress.n = len(detected_networks)
                    progress.update(0)  # Refresh progress bar

            time.sleep(0.1)  # Small sleep to reduce CPU usage
    except KeyboardInterrupt:
        print("\n[+] Interrupt received. Cleaning up...")
        sniff_thread.stop()
        sniff_thread.join()
        clean_up(interface)
    finally:
        progress.close()


if __name__ == "__main__":
    if os.getuid() != 0:
        print("Please run as root.")
        exit()
    main()
