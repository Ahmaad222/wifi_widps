# detection/threat_manager.py

from core.event_bus import event_queue, threat_queue
from detection.risk_engine import RiskEngine


class ThreatManager:

    def __init__(self):
        self.engine = RiskEngine()
        self.history = {}

    def start(self):
        while True:
            event = event_queue.get()
            status, score, reasons = self.engine.analyze(event)

            bssid = event["bssid"]

            if bssid not in self.history:
                self.history[bssid] = 1
            else:
                self.history[bssid] += 1

            # تأكيد التهديد بعد 3 مرات
            if status == "ROGUE" and self.history[bssid] >= 3:
                threat = {
                    "status": status,
                    "score": score,
                    "reasons": reasons,
                    "event": event
                }
                threat_queue.put(threat)