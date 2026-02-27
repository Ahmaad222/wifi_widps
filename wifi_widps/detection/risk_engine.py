# detection/risk_engine.py

from config import TRUSTED_APS


class RiskEngine:

    def analyze(self, event):
        score = 0
        reasons = []

        ssid = event["ssid"]
        bssid = event["bssid"]
        channel = event["channel"]
        signal = event["signal"]

        if ssid in TRUSTED_APS:
            trusted = TRUSTED_APS[ssid]

            if bssid.lower() != trusted["bssid"]:
                score += 6
                reasons.append("Evil Twin suspected")

            if channel != trusted["channel"]:
                score += 2
                reasons.append("Channel mismatch")

        else:
            score += 3
            reasons.append("SSID not trusted")

        if signal and signal > -30:
            score += 2
            reasons.append("Unusually strong signal")

        return self.classify(score), score, reasons

    def classify(self, score):
        if score >= 6:
            return "ROGUE"
        elif score >= 3:
            return "SUSPICIOUS"
        return "LEGIT"