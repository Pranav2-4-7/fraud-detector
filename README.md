🚨 Fraud Detector
A Machine Learning–powered fraud detection system designed to analyze transactions and classify them as Low Risk, Medium Risk, or High Risk. This project aims to simulate real-world fraud detection systems used in fintech applications and can be extended into APIs, dashboards, or browser extensions.
📌 Features
🔍 Detect fraudulent transactions using ML models
📊 Risk classification (Low / Medium / High)
⚡ FastAPI backend for real-time predictions
🌐 Easily extendable to web apps or Chrome extensions
🧠 Scalable architecture for future ML improvements
🛠️ Tech Stack
Language: Python
Backend: FastAPI
ML Libraries: Scikit-learn / Pandas / NumPy
Deployment Ready: REST API architecture


📂 Project Structure

Fraud-Detector/
│── model/              # Trained ML models
│── data/               # Dataset files
│── api/                # FastAPI backend
│── notebooks/          # EDA & experimentation
│── utils/              # Helper functions
│── main.py             # Entry point
│── requirements.txt    # Dependencies


🚀 Getting Started
1. Clone the Repository
   
git clone https://github.com/Kartik-Singh-Bhadoria/Fraud-Detector.git
cd Fraud-Detector


2. Install Dependencies
Bash
pip install -r requirements.txt


3. Run the Server
Bash
uvicorn main:app --reload

4. API Endpoint

POST /predict


Example request:
JSON
{
  "amount": 5000,
  "transaction_type": "online",
  "location": "India"
}


🧠 How It Works
Input transaction data is sent to the API
Data is preprocessed using feature engineering
ML model predicts fraud probability
Output is classified into risk categories
📊 Future Improvements
🔗 Integration with real-time payment systems
📈 Better model accuracy with advanced algorithms (XGBoost, Deep Learning)
🌐 Chrome Extension for live transaction monitoring
📊 Dashboard for analytics & visualization
🔐 Authentication

👨‍💻 Author
Kartik Singh Bhadoria
Shreya Mittal
Tushar Singh Ahluwalia 
Naitik Goyal

⭐ Acknowledgements
Inspired by real-world fraud detection systems used in fintech
Datasets from open platforms like Kaggle