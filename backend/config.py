"""
VNC Security Monitor - Configuration Settings
"""

import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent.parent

# Flask Configuration
class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'vnc-security-monitor-2026-secret-key'
    DEBUG = False
    TESTING = False
    
    # Server settings
    HOST = '0.0.0.0'
    PORT = 5000
    
    # VNC Monitoring settings
    VNC_PORT_START = 5900
    VNC_PORT_END = 5910
    MONITORING_INTERVAL = 5  # seconds
    
    # Data directories
    DATA_DIR = BASE_DIR / 'data'
    RAW_DATA_DIR = DATA_DIR / 'raw'
    PROCESSED_DATA_DIR = DATA_DIR / 'processed'
    SIMULATIONS_DIR = DATA_DIR / 'simulations'
    
    # Model directories
    MODELS_DIR = BASE_DIR / 'models'
    RF_MODEL_PATH = MODELS_DIR / 'random_forest_model.joblib'
    AE_MODEL_PATH = MODELS_DIR / 'autoencoder_model.h5'
    AE_THRESHOLD_PATH = MODELS_DIR / 'autoencoder_threshold.json'
    
    # Alert settings
    MAX_ALERTS = 100
    ALERT_RETENTION_HOURS = 24
    
    # Report settings
    REPORTS_DIR = BASE_DIR / 'reports'
    
    # Logging
    LOG_DIR = BASE_DIR / 'logs'
    LOG_LEVEL = 'INFO'


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    LOG_LEVEL = 'WARNING'


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config(env=None):
    """Get configuration based on environment"""
    if env is None:
        env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])
