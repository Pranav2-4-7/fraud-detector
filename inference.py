import joblib
import pandas as pd
from utils import FeatureTransformer, MODEL_FEATURES

class FraudInferencePipeline:
    def __init__(self, model_path: str, artifacts_path: str):
        """
        Initializes the model and the feature simulation transformer mappings.
        """
        print(f"Loading XGBoost model from {model_path}...")
        self.model = joblib.load(model_path)
        
        print(f"Initializing transformation layer with artifacts from {artifacts_path}...")
        self.transformer = FeatureTransformer(artifacts_path)
        
    def predict(self, user_input: dict, graph_db: dict = None) -> dict:
        """
        Executes the prediction pipeline:
        1. Simulated Transformation (Simple Inputs -> 30 Features)
        2. Model Inference
        3. Risk thresholding and formulation
        """
        # Formulate features deterministically
        df_features = self.transformer.transform(user_input)
        
        # Ensure correct column ordering dynamically
        # Not strictly needed since dict is ordered, but safe
        df_features = df_features[MODEL_FEATURES]
        
        # Predict Probabilities from traditional ML
        base_prob = float(self.model.predict_proba(df_features)[0, 1])
        pos_prob = base_prob
        
        # Explainable AI (XAI) Factors Tracking
        xai = []
        
        # 1. Base ML Model Explanation (Simulated Feature Contributions)
        # In a real heavy system we use shap.TreeExplainer, here we use heuristic attribution based on values.
        amt = user_input.get("transaction_amount", 0)
        if amt > 2000:
            pos_prob += 0.20
            xai.append({"feature": "High Transaction Amount", "impact": "+20%", "type": "danger"})
        elif amt > 500:
            pos_prob += 0.05
            xai.append({"feature": "Elevated Amount", "impact": "+5%", "type": "warning"})
            
        freq = user_input.get("transaction_frequency", 1)
        if freq > 3:
            pos_prob += 0.15
            xai.append({"feature": "High Transaction Frequency", "impact": "+15%", "type": "danger"})
            
        # 2. Behavioral Analytics Integration
        mouse_speed = user_input.get("mouse_speed_px_s", 0)
        typing_speed = user_input.get("typing_speed_cpm", 0)
        time_on_page = user_input.get("time_on_page_s", 10.0)
        
        behavior_penalty = 0.0
        if time_on_page < 2.0:
            behavior_penalty += 0.15
            xai.append({"feature": "Unnaturally Fast Checkout (Bot Behavior)", "impact": "+15%", "type": "danger"})
            
        if typing_speed > 500:
            behavior_penalty += 0.10
            xai.append({"feature": "Impossible Typing Speed (Pasted/Injected)", "impact": "+10%", "type": "danger"})
            
        if time_on_page > 15.0 and mouse_speed > 50:
            # Normal human behavior reduces rate slightly
            pos_prob = max(0, pos_prob - 0.05)
            xai.append({"feature": "Human-Like Mouse Activity", "impact": "-5%", "type": "safe"})
            
        pos_prob += behavior_penalty
        pos_prob = min(0.99, max(0.01, pos_prob))
        
        # 3. Graph-Based Network Analysis (Fraud Rings)
        device = user_input.get("device_type", "unknown")
        network_alert = False
        connected_transactions = 0
        
        if graph_db is not None:
            # Use pseudo-device-ID via combination of factors
            device_id = f"dev_{device}_{user_input.get('user_location', 'US')}"
            
            # Register node
            graph_db["nodes"].append({
                "id": len(graph_db["nodes"]),
                "device_id": device_id,
                "amount": amt,
                "risk": pos_prob
            })
            
            # Count connections
            connected_transactions = sum(1 for n in graph_db["nodes"] if n["device_id"] == device_id)
            
            if connected_transactions > 3:
                network_alert = True
                pos_prob = min(0.99, pos_prob + 0.30)
                xai.append({"feature": "Graph Ring Alert (Shared Device)", "impact": "+30%", "type": "danger"})
                
        network_payload = {
            "node_count": len(graph_db["nodes"]) if graph_db else 1,
            "connected_siblings": max(0, connected_transactions - 1),
            "ring_detected": network_alert
        }
        
        # Formulate Risk Profiles (Scaled for Simulated Probabilities)
        is_fraud = 1 if pos_prob > 0.08 else 0
        
        if pos_prob < 0.04:
            risk = "LOW"
        elif pos_prob < 0.08:
            risk = "MEDIUM"
        else:
            risk = "HIGH"
            
        return {
            "fraud_probability": round(pos_prob, 4),
            "is_fraud": is_fraud,
            "risk_level": risk,
            "xai_explanations": xai,
            "network_graph": network_payload
        }
