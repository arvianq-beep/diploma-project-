# secure_ai.py
import random
import datetime
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder


class SecureDecisionModel:
    """
    ML model (Random Forest) for demo secure decision-making workflow.

    Fixes:
    - Avoids sklearn warning: "X does not have valid feature names..." by using DataFrame
      with the same feature names as during training.
    - Ensures numpy types are converted to Python types for JSON serialization.
    """

    FEATURE_COLUMNS = ["protocol", "bytes", "duration"]

    def __init__(self):
        print("[AI INIT] Preparing training data...")
        self.clf = RandomForestClassifier(
            n_estimators=100,
            max_depth=5,
            random_state=42
        )
        self.encoder_proto = LabelEncoder()
        self._train_model()
        print("[AI INIT] Model trained successfully!")

    def _train_model(self):
        # 1) Generate synthetic training data
        data = []
        labels = []  # 0 - Normal, 1 - Attack

        protocols = ["TCP", "UDP", "ICMP"]
        self.encoder_proto.fit(protocols)

        for _ in range(1000):
            is_attack = random.random() < 0.3

            if is_attack:
                proto = random.choice(["UDP", "ICMP", "TCP"])
                bytes_count = random.randint(1000, 50000)
                duration = random.randint(5, 60)
                labels.append(1)
            else:
                proto = random.choice(["TCP", "UDP"])
                bytes_count = random.randint(64, 1500)
                duration = random.randint(0, 2)
                labels.append(0)

            data.append([proto, bytes_count, duration])

        df = pd.DataFrame(data, columns=self.FEATURE_COLUMNS)
        df["protocol"] = self.encoder_proto.transform(df["protocol"])

        # Fit model on DataFrame -> it will store feature_names_in_
        self.clf.fit(df, labels)

    def analyze_packet(self):
        # 1) Simulate an incoming packet / flow
        is_adversarial_attempt = random.random() < 0.15

        if is_adversarial_attempt:
            current_proto = "TCP"
            current_bytes = random.randint(1600, 3000)
            current_duration = random.randint(2, 5)
        elif random.random() < 0.2:
            current_proto = "UDP"
            current_bytes = random.randint(10000, 40000)
            current_duration = random.randint(10, 30)
        else:
            current_proto = "TCP"
            current_bytes = random.randint(100, 1200)
            current_duration = 0

        # 2) Encode protocol safely
        try:
            proto_encoded = int(self.encoder_proto.transform([current_proto])[0])
        except ValueError:
            proto_encoded = 0  # fallback for unknown protocol

        # 3) Build features with valid feature names (fix sklearn warning)
        x = pd.DataFrame(
            [[proto_encoded, int(current_bytes), int(current_duration)]],
            columns=self.FEATURE_COLUMNS
        )

        # 4) Predict probability
        prediction_prob = self.clf.predict_proba(x)[0]
        attack_probability = float(prediction_prob[1])

        is_threat = bool(attack_probability > 0.5)

        threat_name = "Normal Traffic"
        if is_threat:
            if current_proto == "ICMP":
                threat_name = "Smurf Attack"
            elif current_bytes > 20000:
                threat_name = "DDoS Volumetric"
            else:
                threat_name = "Port Scanning"

        # 5) Verification module (secure decision layer)
        is_verified = True
        verification_details = "Verified by Random Forest Ensemble"

        if is_threat and attack_probability < 0.78:
            is_verified = False
            verification_details = "Low Confidence! Possible Adversarial Perturbation detected."

        src_ip = f"192.168.1.{random.randint(2, 254)}"

        return {
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "source_ip": src_ip,
            "protocol": current_proto,
            "threat_type": threat_name,
            "is_threat": is_threat,
            "ai_confidence": round(attack_probability, 2),
            "is_verified": is_verified,
            "verification_details": verification_details,
        }