# VNC Security Monitor - User Manual & Run Guide

## Prerequisites
- Python 3.8+ installed
- Git installed
- Kaggle dataset downloaded (see below)

## Dataset Setup (Kaggle Only)
This project uses the Kaggle dataset **only**.

### Option A: Download using the script
```powershell
python download_dataset.py
```

### Option B: Manual download
1. Download: https://www.kaggle.com/datasets/smmmmmmmmmmmm/cybersecurity-intrusion-simulated-network
2. Place file at: `data/kaggle_dataset/cybersecurity_dataset.csv`

## 1. How to Run the System

### **Step 1: Install Dependencies**
```powershell
pip install -r requirements.txt
```

### **Step 2: Train Models (Kaggle dataset only)**
```powershell
python train_all_models.py
```

### **Step 3: Start the Backend Server**

Open your terminal (Command Prompt or PowerShell) in the project folder and run:

```powershell
python run.py
```

_Wait until you see:_ `Running on http://127.0.0.1:5000`

### **Step 4: Open the Dashboard**

Open your web browser (Chrome/Edge/Firefox) and navigate to:
URL: [http://localhost:5000](http://localhost:5000)

---

## 1A. Step-by-Step Flow (What Happens After Each Step)

1. **Install dependencies**
  - Installs Flask, ML libraries, and UI helpers from `requirements.txt`.

2. **Train models**
  - Generates model files in `models/` and caches metadata.

3. **Start the server**
  - Launches the Flask API and serves the dashboard.

4. **Open the dashboard**
  - The UI connects to the API and begins live updates every few seconds.

5. **Simulate traffic**
  - Normal traffic updates charts in green; attack traffic creates alerts.

6. **Review alerts and stats**
  - Alerts include severity and protection advice; stats show safe vs. danger counts.

7. **Stop the system**
  - Ctrl+C stops the server; the dashboard shows Offline until restarted.

---

## 2. Dashboard Features Guide

### **A. Status Indicators (Top Cards)**

- **Total Connections:** Shows the count of all network packets captured/simulated.
- **Active Threats:** Number of distinct "Danger" alerts currently active.
- **Normal Traffic %:** Percentage of traffic classified as Safe vs. Attacks.
- **System Status:**
  - **Online (Green):** Backend is running and connected.
  - **Offline (Red):** Browser cannot reach the server (Check if python script is running).

### **B. Real-time Traffic Chart**

- **Green Line:** Safe/Normal traffic.
- **Yellow Line:** Suspicious activity (Potential risks).
- **Red Line:** Confirmed Attacks (DoS, Malware, etc.).
- _Note: This chart updates every 3 seconds._

### **C. ML Model Status**

- This section proves your AI is working.
- **Green 'Loaded':** Model is active and voting.
- **Red 'Not Loaded':** Model failed (check terminal logs).
- **Ensemble:** Shows 'Loaded' when the voting system is ready.

---

## 3. How to Simulate Attacks (The Demo)

Use the buttons at the bottom of the dashboard:

### **1. Simulate Normal Traffic**

- **Click:** `Simulate Normal Traffic`
- **What happens:**
  - Generates safe VNC packets.
  - Chart shows a steady **Green** line.
  - System Status remains "Secure".
  - _Safe for demonstrating baseline behavior._

### **2. Simulate Attack**

- **Click:** `Simulate Attack`
- **What happens:**
  - Randomly generates malicious traffic (**DoS**, **PortScan**, or **Malware**).
  - **Traffic Chart:** Spikes with a **Red** line.
  - **Alerts Panel:** A new Alert card appears (Red or Yellow).
  - **Protection Advice:** Inside the alert, you will see a text like _"Advice: Block Source IP 192.168..."_.
  - _Use this to show off the detection capabilities._

### **3. Test Prediction**

- **Click:** `Test Prediction`
- **What happens:**
  - Sends a single random packet to the API.
  - Shows a "Toast" notification (top right) with the result: _"ATTACK DETECTED: DoS (95% Confidence)"_.
  - _Good for quick testing without flooding the charts._

---

## 4. Troubleshooting

**Q: The dashboard says "Offline"?**

- **Fix:** Ensure the black terminal window with `python backend/app.py` is still open and running.
- **Fix:** Refresh the page (`Ctrl + R` or `F5`).

**Q: "Random Forest" is Red/Not Loaded?**

- **Fix:** Refresh the page (`Ctrl + Shift + R`) to clear old cache. The latest update fixed a display bug here.
- **Fix:** Check terminal. If it says `[RF] Model loaded`, then the backend is fine, it's just a UI glitch.

**Q: It says "TensorFlow not available"?**

- **Fix:** Install TensorFlow (`pip install tensorflow`) to enable CNN.

---

## 5. How the System Works (Mechanism Overview)

1. **Data Ingestion**: VNC traffic is captured or simulated.
2. **Feature Extraction**: Each connection is converted into numerical features.
3. **ML Ensemble**: Random Forest, SVM, XGBoost, and CNN each predict.
4. **Majority Vote**: The final label is chosen by voting.
5. **Alerts + Advice**: Alerts are generated with protection guidance.

## 6. Mini-Presentation Script (For Teachers)

1.  "Sir/Ma'am, this is the **VNC Security Monitor**, an AI-powered Intrusion Detection System."
2.  "I trained 4 models: **Random Forest, SVM, XGBoost, and CNN** on a Kaggle Cybersecurity dataset."
3.  _(Click Simulate Normal)_ -> "Here is normal traffic. The AI correctly identifies it as Safe."
4.  _(Click Simulate Attack)_ -> "Now I simulate a **DoS Attack**. The AI instantly detects it (Red spike) and suggests **Protection Advice** here in the alert."
5.  "This system automates the job of a Security Analyst."

---
