# detector.py
import time, hashlib
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, Raw

# TUNE THESE FOR DEMO ON WINDOWS (small values for visible demo)
PACKET_RATE_THRESHOLD = 20    # packets within WINDOW_SECONDS to trigger
PORT_SCAN_PORT_THRESHOLD = 8  # distinct dest ports within WINDOW_SECONDS
WINDOW_SECONDS = 5

class Detector:
    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.ip_timestamps = defaultdict(deque)
        self.ip_ports = defaultdict(lambda: defaultdict(float))

    def packet_metadata(self, pkt):
        meta = {}
        try:
            if IP in pkt:
                meta['src'] = pkt[IP].src
                meta['dst'] = pkt[IP].dst
                meta['proto'] = pkt[IP].proto
            else:
                return None
            if TCP in pkt:
                meta['sport'] = pkt[TCP].sport
                meta['dport'] = pkt[TCP].dport
            elif UDP in pkt:
                meta['sport'] = pkt[UDP].sport
                meta['dport'] = pkt[UDP].dport
            else:
                meta['sport'] = None
                meta['dport'] = None
            raw_bytes = bytes(pkt[Raw].load) if Raw in pkt else b""
            meta['payload_sha256'] = hashlib.sha256(raw_bytes).hexdigest() if raw_bytes else None
            meta['timestamp'] = time.time()
            return meta
        except Exception as e:
            print("[detector] error:", e)
            return None

    def handle_packet(self, pkt):
        meta = self.packet_metadata(pkt)
        if not meta:
            return
        src = meta['src']
        now = meta['timestamp']
        dq = self.ip_timestamps[src]
        dq.append(now)
        while dq and dq[0] < now - WINDOW_SECONDS:
            dq.popleft()
        pkt_count = len(dq)
        if meta.get('dport'):
            ports_map = self.ip_ports[src]
            ports_map[meta['dport']] = now
            for p, t in list(ports_map.items()):
                if t < now - WINDOW_SECONDS:
                    del ports_map[p]
            distinct_ports = len(ports_map)
        else:
            distinct_ports = 0

        if pkt_count >= PACKET_RATE_THRESHOLD:
            reason = f"High packet rate: {pkt_count} pkts in last {WINDOW_SECONDS}s"
            alert_obj = {"timestamp": now, "src": src, "dst": meta['dst'], "reason": reason, "meta": meta}
            self.alert_callback(alert_obj)
            dq.clear()
            self.ip_ports[src].clear()
            return

        if distinct_ports >= PORT_SCAN_PORT_THRESHOLD:
            reason = f"Possible port scan: {distinct_ports} distinct dest ports in last {WINDOW_SECONDS}s"
            alert_obj = {"timestamp": now, "src": src, "dst": meta['dst'], "reason": reason, "meta": meta}
            self.alert_callback(alert_obj)
            dq.clear()
            self.ip_ports[src].clear()
            return

def start_sniff(detector: Detector, iface=None, count=0):
    print(f"[detector] Starting sniff on iface={iface}. (Run as Administrator!) Ctrl+C to stop.")
    sniff(iface=iface, prn=detector.handle_packet, store=0, count=count)
