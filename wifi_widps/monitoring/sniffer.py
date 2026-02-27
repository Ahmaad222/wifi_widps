# monitoring/sniffer.py

from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon
import threading
import os
import time
import datetime

from config import INTERFACE
from utils import get_ssid, extract_channel
from core.event_bus import event_queue


def build_event(packet):
    return {
        "timestamp": datetime.datetime.now(),
        "bssid": packet[Dot11].addr2,
        "ssid": get_ssid(packet),
        "channel": extract_channel(packet),
        "signal": getattr(packet, "dBm_AntSignal", None)
    }


def handle_packet(packet):
    if packet.haslayer(Dot11Beacon):
        if packet[Dot11].addr2:
            event = build_event(packet)
            event_queue.put(event)


def channel_hopper():
    while True:
        for ch in range(1, 14):
            os.system(f"iwconfig {INTERFACE} channel {ch}")
            time.sleep(0.4)


def start_monitoring():
    hopper = threading.Thread(target=channel_hopper)
    hopper.daemon = True
    hopper.start()

    sniff(iface=INTERFACE, prn=handle_packet, store=False)