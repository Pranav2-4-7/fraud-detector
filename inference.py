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
        
    def predict(self, user_input: dict) -> dict:
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
        
        # Predict Probabilities
        pos_prob = float(self.model.predict_proba(df_features)[0, 1])
        
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
            "risk_level": risk
        }
