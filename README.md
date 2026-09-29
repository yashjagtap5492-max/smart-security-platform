# Smart Security Platform

A web-based cybersecurity platform designed to monitor user login activity, analyze security risks, calculate security scores, and generate security alerts.

## Features

- User registration and authentication
- Secure login system
- Login activity monitoring
- Security risk analysis
- ML-based risk prediction
- User security score
- Security alerts
- New device detection
- New IP detection
- Brute-force activity detection
- Password security analysis
- Two-factor authentication support
- Responsive security dashboard

## Technologies Used

- Python
- Flask
- MySQL
- HTML
- CSS
- JavaScript
- Machine Learning
- Scikit-learn
- Random Forest
- SQLAlchemy
- Bcrypt

## Machine Learning

The platform uses a machine-learning model to analyze login-related security features and estimate account risk.

The model considers factors such as:

- Failed login attempts
- Unique IP addresses
- New devices
- High-risk events
- Unusual activity
- Login frequency
- Failure ratio
- Account age

## Security Workflow

User Login
↓
Login Activity Analysis
↓
Security Risk Detection
↓
ML Risk Prediction
↓
Security Score
↓
Security Alert

## Project Structure

smart-security-platform/
│
├── app/
│   ├── routes.py
│   ├── models.py
│   ├── security_engine.py
│   ├── score_engine.py
│   ├── alert_engine.py
│   └── ...
│
├── ml/
│   └── risk_model.py
│
├── requirements.txt
├── package.json
├── run.py
└── .gitignore

## Installation

Clone the repository:

git clone https://github.com/yashjagtap5492-max/smart-security-platform.git

Enter the project directory:

cd smart-security-platform

Create a virtual environment:

python -m venv venv

Activate it on Windows:

venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

Configure the required environment variables in a local `.env` file.

Run the application:

python run.py

## Project Status

This is a student cybersecurity project developed for learning and implementing practical concepts in web security, authentication, security monitoring, and machine-learning-based risk detection.

## Future Improvements

- Advanced anomaly detection
- Real-time monitoring
- Improved threat intelligence integration
- Email/SMS security notifications
- Enhanced administrator controls
- Security event visualization