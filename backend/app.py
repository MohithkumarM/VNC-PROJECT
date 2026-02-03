"""
VNC Security Monitor - Main Flask Application
"""

import os
import sys
from pathlib import Path

from flask import Flask
from flask_cors import CORS

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.config import get_config
from backend.routes import api
from backend.database import db


def create_app(config_name=None):
    """
    Application factory for Flask app.
    
    Args:
        config_name: Configuration environment ('development', 'production', 'testing')
        
    Returns:
        Flask application instance
    """
    # Create Flask app
    app = Flask(
        __name__,
        template_folder='../frontend/templates',
        static_folder='../frontend/static'
    )
    
    # Load configuration
    config = get_config(config_name)
    app.config.from_object(config)
    
    # Enable CORS for development
    CORS(app, resources={
        r"/api/*": {
            "origins": "*",
            "methods": ["GET", "POST", "PUT", "DELETE"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })
    
    # Register blueprints
    app.register_blueprint(api)
    
    # Create required directories
    _create_directories(config)
    
    # Initialize database
    _init_database()
    
    # Register error handlers
    _register_error_handlers(app)
    
    return app


def _create_directories(config):
    """Create required directories if they don't exist"""
    directories = [
        config.DATA_DIR,
        config.RAW_DATA_DIR,
        config.PROCESSED_DATA_DIR,
        config.SIMULATIONS_DIR,
        config.MODELS_DIR,
        config.REPORTS_DIR if hasattr(config, 'REPORTS_DIR') else None,
        config.LOG_DIR if hasattr(config, 'LOG_DIR') else None
    ]
    
    for directory in directories:
        if directory:
            Path(directory).mkdir(parents=True, exist_ok=True)


def _init_database():
    """Initialize the in-memory database"""
    # Add some sample data for testing
    db.add_alert(
        alert_type='system',
        severity='safe',
        message='VNC Security Monitor started',
        details={'version': '1.0.0'}
    )


def _register_error_handlers(app):
    """Register error handlers"""
    
    @app.errorhandler(404)
    def not_found(error):
        return {'error': 'Resource not found'}, 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return {'error': 'Internal server error'}, 500
    
    @app.errorhandler(400)
    def bad_request(error):
        return {'error': 'Bad request'}, 400


# Create application instance
app = create_app()


if __name__ == '__main__':
    print("""
    ================================================================
    VNC SECURITY MONITOR
    Data Exfiltration Detection System
    ----------------------------------------------------------------
    Starting Flask server...
    Dashboard: http://localhost:5000
    ================================================================
    """)
    
    app.run(
        host=app.config.get('HOST', '0.0.0.0'),
        port=app.config.get('PORT', 5000),
        debug=app.config.get('DEBUG', True)
    )
