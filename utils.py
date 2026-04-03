import json
import numpy as np
import pandas as pd
import hashlib

# Model expected features
MODEL_FEATURES = [
    'V257', 'V258', 'V188', 'V70', 'C4', 'V294', 'C8', 'C14', 'addr2', 
    'V156', 'C7', 'V187', 'V283', 'C1', 'V91', 'V142', 'V30', 'card6', 
    'C10', 'V162', 'C5', 'V62', 'C13', 'card3', 'M4', 'C11', 'V289', 
    'V281', 'id_17', 'card3_FE'
]

class FeatureTransformer:
    def __init__(self, artifacts_path: str):
        """
        Loads the categorical and frequency mappings constructed during training.
        """
        with open(artifacts_path, 'r') as f:
            self.artifacts = json.load(f)
            
        self.cat_mappings = self.artifacts.get('categorical_mappings', {})
        self.fe_mapping = self.artifacts.get('card3_fe_mapping', {})
        
    def _deterministic_hash(self, val: str, modulus: int) -> float:
        """Helper to create a reproducible numeric float from a string."""
        if not val:
            return np.nan
        h = int(hashlib.sha256(val.encode('utf-8')).hexdigest(), 16)
        return float(h % modulus)

    def transform(self, user_input: dict) -> pd.DataFrame:
        """
        Transforms a simplified user input into the 30-feature vector expected by XGBoost.
        NOTE: This simulates feature mapping by injecting deterministic interactions between 
        location, device, amount, and frequency to push probabilities predictably without randomness!
        """
        
        # 1. Base Inputs
        amt = float(user_input.get('transaction_amount', 0.0))
        freq = float(user_input.get('transaction_frequency', 1.0))
        c_type = str(user_input.get('card_type', 'visa')).lower()
        dev_type = str(user_input.get('device_type', 'desktop')).lower()
        loc = str(user_input.get('user_location', 'US')).upper()

        # 2. Extract Base Interaction Multipliers
        risk_multiplier = 1.0
        
        # High Risk Location Boost
        if loc in ['RU', 'NG', 'UA']:
            risk_multiplier *= 2.5
            
        # Device Influnce (Desktop historically accounts for more structured fraud in some datasets)
        if dev_type == 'desktop':
            risk_multiplier *= 1.2
        else:
            risk_multiplier *= 0.85
            
        # Feature Combinations
        interaction_term = (amt * freq) / 100.0
        amt_ratio = amt / (freq + 1.0)
        log_amt = np.log1p(amt)
        sqrt_amt = np.sqrt(amt)

        # 3. Build the exact feature dictionary
        feat = {}

        # -----------------------------
        # Categoricals (Directly mapped using training artifacts)
        # -----------------------------
        feat['card6'] = self.cat_mappings.get('card6', {}).get(c_type, np.nan)
        feat['M4'] = self.cat_mappings.get('M4', {}).get('M0' if dev_type == 'mobile' else 'M2', np.nan)
        feat['id_17'] = self._deterministic_hash(dev_type, 100)
        feat['card3'] = self._deterministic_hash(loc, 150)
        feat['addr2'] = self._deterministic_hash(loc, 90)

        # -----------------------------
        # Scale C features (Counts)
        # Combine non-linear math (amount + frequency + risk boosters)
        # -----------------------------
        c_feats = ['C4', 'C8', 'C14', 'C7', 'C1', 'C10', 'C5', 'C13', 'C11']
        for i, c in enumerate(c_feats):
            # Creates significant divergence between low-interaction users and high-interaction users
            base_c = (freq * sqrt_amt) + (interaction_term * 0.1)
            feat[c] = float(base_c * risk_multiplier * (1.1 + (i * 0.3)))

        # -----------------------------
        # Scale V features (Variables)
        # -----------------------------
        v_feats = [
            'V257', 'V258', 'V188', 'V70', 'V294', 'V156', 'V187', 'V283',
            'V91', 'V142', 'V30', 'V162', 'V62', 'V289', 'V281'
        ]
        for i, v in enumerate(v_feats):
            # Inject combinations of log(amount), amt/freq ratio, and direct multiplier risk
            if i % 2 == 0:
                feat[v] = float(log_amt * risk_multiplier * (1.5 + (i * 0.1)))
            else:
                feat[v] = float(amt_ratio * risk_multiplier * (0.8 + (i * 0.05)))

        # -----------------------------
        # Frequency Encoding Output Defaulting
        # -----------------------------
        card3_str = str(feat['card3'])
        # Replace absolute 0 fallback with 0.02 to ensure tree nodes don't aggressively drop the split
        feat['card3_FE'] = self.fe_mapping.get(card3_str, 0.02) 

        # Ensure order matches XGBoost EXACTLY
        final_row = {k: feat[k] for k in MODEL_FEATURES}
        return pd.DataFrame([final_row])
