#!/usr/bin/env python3
"""
Test script to verify ML detector RED/GREEN responses
"""

from detector import MLAttackDetector

def main():
    print("=" * 70)
    print("ML DETECTOR - RED/GREEN COLOR RESPONSE TEST")
    print("=" * 70)
    
    # Initialize detector
    detector = MLAttackDetector()
    detector.load()
    
    # Test cases
    test_cases = [
        # Safe inputs (should be GREEN)
        ("admin", "SAFE"),
        ("john.doe@example.com", "SAFE"),
        ("Password123!", "SAFE"),
        ("user123", "SAFE"),
        ("select_product", "SAFE"),
        ("john", "SAFE"),
        
        # SQL Injection (should be RED)
        ("' OR '1'='1", "MALICIOUS"),
        ("'; DROP TABLE users--", "MALICIOUS"),
        ("1' UNION SELECT NULL--", "MALICIOUS"),
        ("admin' --", "MALICIOUS"),
        ("' or 1=1; --", "MALICIOUS"),
        
        # XSS (should be RED)
        ("<script>alert(1)</script>", "MALICIOUS"),
        ("<img src=x onerror=alert(1)>", "MALICIOUS"),
        ("javascript:alert('xss')", "MALICIOUS"),
        ("<svg/onload=alert(1)>", "MALICIOUS"),
        ("onclick=alert(1)", "MALICIOUS"),
    ]
    
    print("\n🧪 Testing Detection Results:\n")
    
    correct = 0
    total = len(test_cases)
    
    for input_text, expected in test_cases:
        result = detector.detect(input_text)
        
        is_correct = (expected == "SAFE") == (not result['is_malicious'])
        status_icon = "✅" if is_correct else "❌"
        correct += is_correct
        
        print(f"{status_icon} Input: {input_text[:40]:40s}")
        print(f"   {result['color']:15s} | {result['status']:10s} | Confidence: {result['confidence']:.2%}")
        print(f"   Attack Type: {result['attack_type'] or 'None':20s} | Expected: {expected}")
        print()
    
    print("=" * 70)
    print(f"ACCURACY: {correct}/{total} = {(correct/total)*100:.1f}%")
    print("=" * 70)

if __name__ == "__main__":
    main()
