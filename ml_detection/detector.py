"""
Real-time Attack Detection Module
Use this to integrate ML-based detection in your Flask application
"""

import pickle
import os
from pathlib import Path

class MLAttackDetector:
    def __init__(self, model_dir=None):
        """Initialize the detector with pre-trained model"""
        if model_dir is None:
            # Use absolute path relative to this file's location
            model_dir = os.path.join(os.path.dirname(__file__), 'ml_detection', 'models')
        
        self.model_dir = model_dir
        self.vectorizer = None
        self.model = None
        self.label_encoder = None
        self.loaded = False
        
    def load(self):
        """Load the trained model"""
        try:
            vectorizer_path = os.path.join(self.model_dir, 'vectorizer.pkl')
            model_path = os.path.join(self.model_dir, 'model.pkl')
            encoder_path = os.path.join(self.model_dir, 'label_encoder.pkl')
            
            with open(vectorizer_path, 'rb') as f:
                self.vectorizer = pickle.load(f)
            
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            with open(encoder_path, 'rb') as f:
                self.label_encoder = pickle.load(f)
            
            self.loaded = True
            print("ML Attack Detector loaded successfully!")
            return True
        except Exception as e:
            print(f"Error loading ML model: {e}")
            print("Run train_model.py first to create the model.")
            return False
    
    def detect(self, input_text):
        """
        Detect if input is malicious
        
        Args:
            input_text (str): User input to check
            
        Returns:
            dict: Detection results with color status (RED/GREEN)
        """
        if not self.loaded:
            if not self.load():
                # Fallback to rule-based detection if model not available
                return self._rule_based_detection(input_text)
        
        try:
            X = self.vectorizer.transform([input_text])
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            
            label = self.label_encoder.inverse_transform([prediction])[0]
            confidence = max(probabilities)
            is_malicious = label in ['sql_injection', 'xss']
            
            return {
                'label': label,
                'confidence': float(confidence),
                'is_malicious': is_malicious,
                'attack_type': label if label != 'safe' else None,
                'color': '🔴 RED' if is_malicious else '🟢 GREEN',
                'status': 'MALICIOUS' if is_malicious else 'SAFE',
                'probabilities': {
                    class_name: float(prob) 
                    for class_name, prob in zip(self.label_encoder.classes_, probabilities)
                }
            }
        except Exception as e:
            print(f"Error in ML detection: {e}")
            return self._rule_based_detection(input_text)
    
    def _rule_based_detection(self, input_text):
        """
        Fallback rule-based detection if ML model is not available
        Returns RED/GREEN status
        """
        text_lower = input_text.lower()
        
        # SQL Injection patterns
        sql_patterns = [
            "' or '", "' or 1=1", "or 1=1", "'; drop", "'; delete",
            "union select", "' union", "' and '", "--", "/*", "#",
            "waitfor delay", "sleep(", "benchmark(", " or ", " and "
        ]
        
        # XSS patterns
        xss_patterns = [
            "<script", "javascript:", "onerror=", "onload=", "<img",
            "<svg", "alert(", "eval(", "<iframe", "onclick=", "onfocus="
        ]
        
        is_sql = any(pattern in text_lower for pattern in sql_patterns)
        is_xss = any(pattern in text_lower for pattern in xss_patterns)
        
        if is_sql:
            return {
                'label': 'sql_injection',
                'confidence': 0.85,
                'is_malicious': True,
                'attack_type': 'sql_injection',
                'color': '🔴 RED',
                'status': 'MALICIOUS',
                'probabilities': {'sql_injection': 0.85, 'xss': 0.10, 'safe': 0.05}
            }
        elif is_xss:
            return {
                'label': 'xss',
                'confidence': 0.85,
                'is_malicious': True,
                'attack_type': 'xss',
                'color': '🔴 RED',
                'status': 'MALICIOUS',
                'probabilities': {'sql_injection': 0.10, 'xss': 0.85, 'safe': 0.05}
            }
        else:
            return {
                'label': 'safe',
                'confidence': 0.90,
                'is_malicious': False,
                'attack_type': None,
                'color': '🟢 GREEN',
                'status': 'SAFE',
                'probabilities': {'sql_injection': 0.05, 'xss': 0.05, 'safe': 0.90}
            }
    
    def is_safe(self, input_text, threshold=0.5):
        """
        Quick check if input is safe
        
        Args:
            input_text (str): Input to check
            threshold (float): Confidence threshold (0-1)
            
        Returns:
            bool: True if safe, False if malicious
        """
        result = self.detect(input_text)
        return not result['is_malicious'] or result['confidence'] < threshold


# Singleton instance for easy import
_detector_instance = None

def get_detector():
    """Get singleton detector instance"""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = MLAttackDetector()
    return _detector_instance


# Example usage
if __name__ == "__main__":
    detector = get_detector()
    
    test_inputs = [
        "admin",
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "normal_username",
        "'; DROP TABLE users--",
        "test@example.com",
        "<img src=x onerror=alert(1)>",
        "{{7*7}}"
    ]
    
    print("Testing ML Attack Detector:")
    print("="*60)
    
    for inp in test_inputs:
        result = detector.detect(inp)
        status = "🔴 MALICIOUS" if result['is_malicious'] else "🟢 SAFE"
        print(f"\nInput: {inp}")
        print(f"Status: {status}")
        print(f"Type: {result['label']}")
        print(f"Confidence: {result['confidence']:.2%}")
