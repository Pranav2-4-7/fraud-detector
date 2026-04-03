import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict
from inference import FraudInferencePipeline

# Define Pydantic Model for Input Validation
class FraudRequestSchema(BaseModel):
    transaction_amount: float
    card_type: str
    user_location: str
    transaction_frequency: int
    device_type: str
    mouse_speed_px_s: float = 0.0
    typing_speed_cpm: float = 0.0
    time_on_page_s: float = 0.0
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "transaction_amount": 150.50,
                "card_type": "visa",
                "user_location": "US",
                "transaction_frequency": 5,
                "device_type": "desktop",
                "mouse_speed_px_s": 850.5,
                "typing_speed_cpm": 450.0,
                "time_on_page_s": 3.2
            }
        }
    )

# Define Pydantic Model for Output 
class FraudResponseSchema(BaseModel):
    fraud_probability: float
    is_fraud: int
    risk_level: str
    xai_explanations: list
    network_graph: dict

# Global memory for mock Graph Node storage
GRAPH_DB = {
    "nodes": [],
    "edges": []
}

# FastAPI Application Definition
app = FastAPI(
    title="XGBoost Fraud Detection API",
    description="Inference system transforming simple user inputs into an anonymous 30-feature vector.",
    version="1.0"
)

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows requests from Chrome Extensions / local domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global memory caching for model payload
pipeline = None

@app.on_event("startup")
def load_pipeline():
    global pipeline
    model_path = os.path.join(os.path.dirname(__file__), 'model', 'fraud_model.pkl')
    artifacts_path = os.path.join(os.path.dirname(__file__), 'model', 'preproc_artifacts.json')
    
    if not os.path.exists(model_path) or not os.path.exists(artifacts_path):
        raise RuntimeError(
            "Model files not found! Ensure `train_simplified_xgb.py` has completed "
            "and successfully generated the `model/` directory contents."
        )
    pipeline = FraudInferencePipeline(model_path, artifacts_path)

@app.get("/health")
def health_check():
    """Health check endpoint for FraudShield extension connectivity."""
    return {
        "status": "online",
        "model_loaded": pipeline is not None,
        "version": "2.0"
    }

@app.post("/predict", response_model=FraudResponseSchema)
def predict_fraud(data: FraudRequestSchema):
    try:
        # Pydantic safely converts to a standard dict
        raw_payload = data.model_dump()
        
        # Execute Pipeline (Inference & Simulation)
        # We explicitly pass the global GRAPH_DB to maintain state
        result = pipeline.predict(raw_payload, GRAPH_DB)
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
