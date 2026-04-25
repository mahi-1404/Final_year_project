#!/usr/bin/env python3
"""
Quick test of ML detection with index.html integration
"""

from ml_detection.flask_integration import detector_manager

test_cases = [
    ('john_doe', 'SAFE'),
    ('admin', 'SAFE'),
    ("' OR '1'='1", 'ATTACK'),
    ('<script>alert(1)</script>', 'ATTACK')
]

print('Testing ML Detection Integration with index.html:')
print('=' * 60)

for inp, expected in test_cases:
    result = detector_manager.check_input(inp)
    print(f'Input: {inp[:40]:40s}')
    print(f'  {result["color"]:15s} | {result["status"]:10s} | Confidence: {result["confidence"]:.1%}')
    print()
