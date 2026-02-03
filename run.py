#!/usr/bin/env python
"""
VNC Security Monitor - Main Entry Point
Run this file to start the entire system
"""

import os
import sys
import argparse
import webbrowser
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))


def check_dependencies():
    """Check if all required dependencies are installed"""
    required = [
        ('flask', 'flask'),
        ('flask_cors', 'flask-cors'),
        ('numpy', 'numpy'),
        ('pandas', 'pandas'),
        ('sklearn', 'scikit-learn'),
        ('joblib', 'joblib'),
        ('requests', 'requests')
    ]
    missing = []
    
    for package, pip_name in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(pip_name)
    
    if missing:
        print(f"Warning: Missing dependencies: {', '.join(missing)}")
        print("Run: pip install -r requirements.txt")
        return False
    
    return True


def check_models():
    """Check if ML models are trained"""
    models_dir = PROJECT_ROOT / 'models'
    rf_model = models_dir / 'random_forest_model.joblib'
    ae_model = models_dir / 'autoencoder_model.h5'
    
    status = {
        'random_forest': rf_model.exists(),
        'autoencoder': ae_model.exists()
    }
    
    return status


def print_banner():
    """Print startup banner"""
    banner = """
    ================================================================
    VNC SECURITY MONITOR
    Data Exfiltration Detection System
    ----------------------------------------------------------------
    Version: 1.0.0
    ML Models: Random Forest, SVM, XGBoost, CNN (Ensemble)
    Dashboard: http://localhost:5000
    ================================================================
    """
    print(banner)


def print_status(models_status):
    """Print system status"""
    print("\nSystem Status:")
    print("   -------------------------------------")
    
    # ML Models
    rf_status = "Loaded" if models_status['random_forest'] else "Not Found"
    ae_status = "Loaded" if models_status['autoencoder'] else "Not Found"
    
    print(f"   Random Forest Model: {rf_status}")
    print(f"   Autoencoder Model:   {ae_status}")
    
    if not models_status['random_forest'] or not models_status['autoencoder']:
        print("\n   Warning: To train models, run:")
        print("      python backend/generate_training_data.py")
        print("      (Or use the dashboard simulation feature)")
    
    print("   -------------------------------------\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='VNC Security Monitor')
    default_port = int(os.environ.get('PORT', 5000))
    parser.add_argument('--port', type=int, default=default_port, help='Port to run server on')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--no-browser', action='store_true', help='Do not open browser')
    parser.add_argument('--train', action='store_true', help='Train ML models before starting')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Check dependencies
    print("Checking dependencies...")
    if not check_dependencies():
        sys.exit(1)
    print("   All dependencies installed\n")
    
    # Check models
    models_status = check_models()
    print_status(models_status)
    
    # Train models if requested (Kaggle dataset only)
    if args.train:
        print("Training ML models using Kaggle dataset...")
        try:
            from train_all_models import train_all
            train_all()
        except Exception as e:
            print(f"   Training failed: {e}")
    elif not models_status['random_forest'] and not models_status['autoencoder']:
        print("   Warning: Models missing. Run: python train_all_models.py (Kaggle dataset only)")
    
    # Import and create Flask app
    print("Starting Flask server...")
    from backend.app import app
    
    # Open browser
    if not args.no_browser:
        def open_browser():
            time.sleep(1.5)
            webbrowser.open(f'http://localhost:{args.port}')
        
        import threading
        threading.Thread(target=open_browser, daemon=True).start()
    
    print(f"\n   Server running at: http://localhost:{args.port}")
    print("   Dashboard ready!")
    print("\n   Press Ctrl+C to stop\n")
    
    # Run the app
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        use_reloader=False  # Disable reloader to prevent double startup
    )


if __name__ == '__main__':
    main()
