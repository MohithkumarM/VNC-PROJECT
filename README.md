# VNC Security Monitor

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> A Machine Learning-based system to detect data exfiltration attacks on VNC (Virtual Network Computing) connections in real-time.

![Dashboard Preview](https://via.placeholder.com/800x400?text=VNC+Security+Monitor+Dashboard)

## Table of Contents

- [Features](#features)
- [Attack Detection](#attack-detection)
- [Architecture](#architecture)
- [Installation](#installation)
- [Dataset (Kaggle)](#dataset-kaggle)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [ML Models](#ml-models)
- [Demo](#demo)
- [Configuration](#configuration)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Features

### Security Monitoring
- **Real-time VNC Traffic Analysis** - Monitor VNC connections on ports 5900-5910
- **ML-based Threat Detection** - Ensemble model combining Random Forest, SVM, XGBoost, CNN
- **Instant Alerts** - Get notified immediately when threats are detected
- **Multi-attack Detection** - Detect 5+ different attack types

### Dashboard
- **Dark Theme UI** - Professional, eye-friendly interface
- **Real-time Charts** - Live traffic visualization with Chart.js
- **Alert Management** - View, filter, and clear security alerts
- **Statistics** - Comprehensive system statistics and metrics

### Reporting
- **PDF Reports** - Generate comprehensive security reports
- **CSV Export** - Export traffic data for external analysis
- **Attack Distribution** - Visual breakdown of attack types

## Attack Detection

The system detects the following attack scenarios:

| Attack Type | Description | Detection Method |
|-------------|-------------|------------------|
| **File Exfiltration** | Large file transfers (100MB+) | Packet size + transfer rate |
| **Clipboard Hijacking** | Stealing clipboard data | Command frequency + data patterns |
| **Screen Capture** | Excessive framebuffer requests | Framebuffer update rate |
| **Keylogging** | Keyboard event snooping | Key event frequency |
| **Unencrypted Connection** | Plain VNC without TLS | Encryption level analysis |

## Architecture

High-level components:
- Frontend: HTML/CSS/JS dashboard (Chart.js)
- Backend: Flask REST API
- ML Models: Random Forest, SVM, XGBoost, CNN (ensemble)
- Traffic Monitor: VNC traffic capture and feature extraction

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Git

### Clone Repository
```bash
git clone https://github.com/<your-username>/VNC-Security-Monitor-system.git
cd VNC-Security-Monitor-system
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Optional: GPU Support
Install GPU-enabled TensorFlow if needed.

## Dataset (Kaggle)

This project uses the Kaggle dataset **only**. Place the dataset at:
```
data/kaggle_dataset/cybersecurity_dataset.csv
```

### Option A: Download via script (recommended)
```bash
python download_dataset.py
```

### Option B: Manual download
1. Download the dataset from Kaggle: https://www.kaggle.com/datasets/smmmmmmmmmmmm/cybersecurity-intrusion-simulated-network
2. Extract and copy `cybersecurity_dataset.csv` to `data/kaggle_dataset/`

## Quick Start

### Windows
Double-click `start.bat` or run:
```bash
python run.py
```

### Linux/Mac
```bash
python run.py --port 5000 --debug
```

### Train Models (Kaggle dataset only)
```bash
python train_all_models.py
```

### Access Dashboard
Open your browser and navigate to:
```
http://localhost:5000
```

## Step-by-Step Run Guide (What Happens After What)

1. **Install dependencies**
  - Command: `pip install -r requirements.txt`
  - What happens: Python packages are installed so the API, ML models, and UI can run.

2. **Download the dataset (Kaggle only)**
  - Command: `python download_dataset.py`
  - What happens: The CSV is saved to `data/kaggle_dataset/` for training.

3. **Train ML models**
  - Command: `python train_all_models.py`
  - What happens: Model artifacts are created in `models/` and metadata files are updated.

4. **Start the server**
  - Command: `python run.py`
  - What happens: The Flask API starts and serves the dashboard and endpoints.

5. **Open the dashboard**
  - URL: `http://localhost:5000`
  - What happens: The UI loads and begins polling the API for live stats.

6. **Simulate traffic**
  - Use the dashboard buttons to generate Normal or Attack traffic.
  - What happens: The backend creates simulated events, updates stats, and emits alerts.

7. **Generate reports**
  - Use the report button or API endpoint.
  - What happens: A report is generated from the current stats and alerts.

8. **Stop the system**
  - Press Ctrl+C in the terminal running `python run.py`.
  - What happens: The API stops and the dashboard will show Offline.

## API Reference

### Health Check
```http
GET /api/health
```
Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-09T12:00:00",
  "version": "1.0.0"
}
```

### Get Traffic Statistics
```http
GET /api/traffic?limit=60
```

### Get Security Alerts
```http
GET /api/alerts?limit=50&severity=danger
```

### Simulate Attack
```http
POST /api/simulate
Content-Type: application/json

{
  "attack_type": "DoS"
}
```

### Make Prediction
```http
POST /api/predict
Content-Type: application/json

{
  "PacketSize": 500,
  "ResponseTime": 0.18,
  "Protocol": "TCP",
  "SrcIP": "192.168.1.50",
  "DstIP": "10.0.0.5",
  "SrcPort": 443,
  "DstPort": 5900,
  "PacketRate": 43.5,
  "FlowDuration": 9724,
  "NumPackets": 190,
  "PayloadSize": 100,
  "FlagCount": 5,
  "AnomalyScore": 0.04,
  "Entropy": 0.56,
  "BytesSent": 71220,
  "BytesReceived": 59758,
  "FlowRate": 4.4,
  "ActiveTime": 69.1,
  "IdleTime": 85.7
}
```

### ML Model Status
```http
GET /api/ml/status
```

### System Statistics
```http
GET /api/stats
```

## Project Structure

- backend/
  - app.py: Flask application factory
  - config.py: Configuration settings
  - database.py: In-memory database
  - routes.py: API endpoints
  - vnc_monitor.py: VNC traffic monitor
  - feature_extractor.py: Feature extraction
  - attack_simulator.py: Attack simulation
  - generate_training_data.py: Training data generator
- ml_models/
  - random_forest_detector.py: Random Forest classifier
  - autoencoder_detector.py: Autoencoder anomaly detector
  - ensemble_predictor.py: Ensemble model
- frontend/
  - templates/: HTML templates
  - static/css/style.css: Styles
  - static/js/: Frontend logic
- data/
  - processed/: Processed training data
  - raw/: Raw capture data
- models/: Trained model artifacts
- run.py: Main entry point
- demo.py: Demo script
- start.bat: Windows startup
- requirements.txt: Python dependencies

## ML Models

### Random Forest Classifier
- **Algorithm**: Random Forest with 100 estimators
- **Features**: 27 traffic features
- **Accuracy**: 100% on test data
- **Output**: Binary classification (Normal/Attack)

### Autoencoder (Anomaly Detection)
- **Architecture**: 27 → 64 → 32 → 16 → 32 → 64 → 27
- **Training**: Trained on normal traffic only
- **Detection**: Reconstruction error threshold
- **Output**: Anomaly score

### Ensemble Predictor
- Combines RF and AE predictions
- Voting mechanism for final decision
- Outputs: SAFE, SUSPICIOUS, or DANGER

## Demo

Run the interactive demo:
```bash
python demo.py
```

This will:
1. Check system health
2. Verify ML models
3. Simulate normal traffic
4. Simulate various attacks
5. Test ML predictions
6. Display statistics

## Configuration

Edit `backend/config.py` to customize:

```python
class Config:
    VNC_PORT_START = 5900
    VNC_PORT_END = 5910
    MONITORING_INTERVAL = 1.0
    MAX_ALERTS = 100
    DEBUG = True
```

## Testing

```bash
# Test API endpoints
python -c "from backend.routes import api; print('Routes OK')"

# Test ML models
python -c "from ml_models.ensemble_predictor import EnsemblePredictor; ep = EnsemblePredictor(); print(ep.get_status())"
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Acknowledgments

- TigerVNC/RealVNC for VNC protocol reference
- scikit-learn for machine learning
- TensorFlow/Keras for deep learning
- Chart.js for data visualization

---

If you find this repository useful, consider starring it.
