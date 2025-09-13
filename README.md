#  SecureSurf – AI Phishing URL Detector

SecureSurf is an AI-powered phishing detection tool integrated with  IBM Watsonx Orchestrate .  
It uses machine learning to classify URLs as **legitimate** or **phishing**, and allows interaction via an Orchestrate agent.

# Features
- 🧠 Train a phishing detection model (`train_model.py`)
- 🔍 Detect phishing URLs using `Phishing_Tool.py`
- 🤖 Integrate with IBM Watsonx Orchestrate using `phishing.yaml`
- 💬 Custom greetings via `greetings.py`

# 📂 Project Structure
C:\SecureSurf Agent
│── train_model.py # 
│── Phishing_Tool.py # Detect phishing URLs with the model
│── greetings.py # Custom greeting tool for Orchestrate
│── phishing.yaml # Watsonx Orchestrate agent config
│── requirements.txt # Python dependencies
│── README.md # Project documentation

# Watsonx Orchestrate Integration
>Import phishing.yaml into Watsonx Orchestrate.
>Add the SecureSurf Agent to your workspace.
>Use the greetings.py tool for a customized introduction (e.g., "Hey, I’m SecureSurf, your safe AI assistant!").

🛠 Requirements
>Python 3.9+
