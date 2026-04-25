#!/usr/bin/env python3
"""
Flask Integration Module for ML Attack Detection
Provides easy integration with the Flask app for real-time detection
"""

import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from detector import MLAttackDetector

class AttackDetectionManager:
    """
    Singleton manager for ML-based attack detection
    """
    _instance = None
    _detector = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AttackDetectionManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        try:
            self._detector = MLAttackDetector()
            if self._detector.load():
                self._initialized = True
                print("[OK] ML Attack Detector initialized successfully")
            else:
                print("[WARNING] Failed to load ML model, using rule-based detection")
                self._initialized = True
        except Exception as e:
            print(f"[ERROR] Error initializing detector: {e}")
            self._detector = None
            self._initialized = True
    
    def check_input(self, user_input, input_field_name="input"):
        """
        Check user input for attacks
        
        Args:
            user_input (str): User input to check
            input_field_name (str): Field name for logging
            
        Returns:
            dict: Detection result with keys:
                - color: '🔴 RED' for malicious, '🟢 GREEN' for safe
                - status: 'MALICIOUS' or 'SAFE'
                - is_malicious: bool
                - attack_type: str or None
                - confidence: float (0.0-1.0)
                - label: str ('sql_injection', 'xss', 'safe')
        """
        if not user_input:
            return {
                'color': '🟢 GREEN',
                'status': 'SAFE',
                'is_malicious': False,
                'attack_type': None,
                'confidence': 1.0,
                'label': 'safe'
            }
        
        try:
            result = self._detector.detect(str(user_input))
            return result
        except Exception as e:
            print(f"Error checking input: {e}")
            # Safe default
            return {
                'color': '🟢 GREEN',
                'status': 'SAFE',
                'is_malicious': False,
                'attack_type': None,
                'confidence': 0.5,
                'label': 'safe'
            }
    
    def is_malicious(self, user_input):
        """
        Quick check if input is malicious
        
        Args:
            user_input (str): User input to check
            
        Returns:
            bool: True if malicious, False otherwise
        """
        result = self.check_input(user_input)
        return result['is_malicious']
    
    def get_color(self, user_input):
        """
        Get color status for input
        
        Args:
            user_input (str): User input to check
            
        Returns:
            str: '🔴 RED' for malicious, '🟢 GREEN' for safe
        """
        result = self.check_input(user_input)
        return result['color']
    
    def get_status(self, user_input):
        """
        Get status string for input
        
        Args:
            user_input (str): User input to check
            
        Returns:
            str: 'MALICIOUS' or 'SAFE'
        """
        result = self.check_input(user_input)
        return result['status']

# Create singleton instance
detector_manager = AttackDetectionManager()

if __name__ == "__main__":
    # Test the integration
    print("\n" + "="*70)
    print("FLASK INTEGRATION TEST")
    print("="*70 + "\n")
    
    test_inputs = [
        "john_doe",
        "' OR '1'='1",
        "user@example.com",
        "<script>alert('xss')</script>",
    ]
    
    for inp in test_inputs:
        result = detector_manager.check_input(inp)
        print(f"Input: {inp}")
        print(f"  Color: {result['color']}")
        print(f"  Status: {result['status']}")
        print(f"  Confidence: {result['confidence']:.2%}\n")
