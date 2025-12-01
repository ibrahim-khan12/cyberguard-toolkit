#!/usr/bin/env python3
"""
Password Assessment Module for PayBuddy Cybersecurity Testing Toolkit
Password policy checking and offline hash testing simulation
"""

import hashlib
import string
import math
import re
import json
import argparse
import sys
import os
from datetime import datetime
from pathlib import Path
import secrets
import bcrypt

# Add src directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from identity_verifier import IdentityVerifier

class PasswordAssessment:
    def __init__(self):
        self.policy_rules = {
            'min_length': 8,
            'max_length': 128,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_digits': True,
            'require_special': True,
            'forbidden_patterns': [
                'password', '123456', 'qwerty', 'admin', 'login',
                'welcome', 'paybuddy', 'fintech', 'wallet'
            ],
            'min_entropy': 35.0  # bits of entropy
        }
        
        # Common weak passwords for simulation
        self.weak_passwords = [
            'password', '123456', 'password123', 'admin', 'qwerty',
            'letmein', 'welcome', 'monkey', 'dragon', 'shadow',
            'master', 'hello', 'falcon', 'freedom', 'whatever',
            'paybuddy123', 'fintech2024', 'wallet123', 'login123'
        ]
        
        # Pre-computed hashes for simulation (MD5, SHA256, bcrypt examples)
        self.sample_hashes = {
            'MD5': {
                '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8': 'password',
                'e10adc3949ba59abbe56e057f20f883e': '123456',
                '25d55ad283aa400af464c76d713c07ad': 'hello'
            },
            'SHA256': {
                '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8': 'password',
                '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918': 'admin',
                'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f': 'secret123'
            }
        }
    
    def check_policy_compliance(self, password):
        """Check password against policy rules"""
        results = {
            'compliant': True,
            'violations': [],
            'score': 100,
            'recommendations': []
        }
        
        # Length check
        if len(password) < self.policy_rules['min_length']:
            results['violations'].append(f"Password too short (minimum {self.policy_rules['min_length']} characters)")
            results['score'] -= 20
        
        if len(password) > self.policy_rules['max_length']:
            results['violations'].append(f"Password too long (maximum {self.policy_rules['max_length']} characters)")
            results['score'] -= 10
        
        # Character requirements
        if self.policy_rules['require_uppercase'] and not re.search(r'[A-Z]', password):
            results['violations'].append("Missing uppercase letter")
            results['score'] -= 15
        
        if self.policy_rules['require_lowercase'] and not re.search(r'[a-z]', password):
            results['violations'].append("Missing lowercase letter")
            results['score'] -= 15
        
        if self.policy_rules['require_digits'] and not re.search(r'\d', password):
            results['violations'].append("Missing digit")
            results['score'] -= 15
        
        if self.policy_rules['require_special'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            results['violations'].append("Missing special character")
            results['score'] -= 15
        
        # Forbidden patterns
        password_lower = password.lower()
        for pattern in self.policy_rules['forbidden_patterns']:
            if pattern in password_lower:
                results['violations'].append(f"Contains forbidden pattern: '{pattern}'")
                results['score'] -= 25
        
        # Common patterns
        if re.search(r'(.)\1{2,}', password):  # Repeated characters
            results['violations'].append("Contains repeated characters")
            results['score'] -= 10
        
        if re.search(r'(012|123|234|345|456|567|678|789)', password):
            results['violations'].append("Contains sequential numbers")
            results['score'] -= 10
        
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            results['violations'].append("Contains sequential letters")
            results['score'] -= 10
        
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        if entropy < self.policy_rules['min_entropy']:
            results['violations'].append(f"Low entropy: {entropy:.1f} bits (minimum {self.policy_rules['min_entropy']})")
            results['score'] -= 20
        
        # Determine compliance
        results['compliant'] = len(results['violations']) == 0
        results['score'] = max(0, results['score'])
        
        # Generate recommendations
        if not results['compliant']:
            results['recommendations'] = self._generate_recommendations(results['violations'])
        
        return results
    
    def calculate_entropy(self, password):
        """Calculate password entropy in bits"""
        if not password:
            return 0.0
        
        # Determine character space
        char_space = 0
        if re.search(r'[a-z]', password):
            char_space += 26
        if re.search(r'[A-Z]', password):
            char_space += 26
        if re.search(r'\d', password):
            char_space += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>\[\]\\\/\-_+=~`]', password):
            char_space += 32
        
        if char_space == 0:
            return 0.0
        
        # Basic entropy calculation
        entropy = len(password) * math.log2(char_space)
        
        # Reduce entropy for common patterns
        # Repeated characters
        unique_chars = len(set(password))
        if unique_chars < len(password):
            repetition_factor = unique_chars / len(password)
            entropy *= repetition_factor
        
        # Dictionary words (simple check)
        if password.lower() in self.weak_passwords:
            entropy *= 0.1
        
        return entropy
    
    def simulate_hash_cracking(self, hash_value, hash_type='MD5'):
        """Simulate hash cracking for educational purposes"""
        results = {
            'hash': hash_value,
            'hash_type': hash_type,
            'cracked': False,
            'plaintext': None,
            'method': 'Dictionary Attack Simulation',
            'time_simulated': '< 1 second'
        }
        
        # Check against known weak hashes
        if hash_type.upper() in self.sample_hashes:
            if hash_value in self.sample_hashes[hash_type.upper()]:
                results['cracked'] = True
                results['plaintext'] = self.sample_hashes[hash_type.upper()][hash_value]
                return results
        
        # Simulate checking against common passwords
        for password in self.weak_passwords:
            test_hash = None
            
            if hash_type.upper() == 'MD5':
                test_hash = hashlib.md5(password.encode()).hexdigest()
            elif hash_type.upper() == 'SHA256':
                test_hash = hashlib.sha256(password.encode()).hexdigest()
            elif hash_type.upper() == 'SHA1':
                test_hash = hashlib.sha1(password.encode()).hexdigest()
            
            if test_hash and test_hash == hash_value:
                results['cracked'] = True
                results['plaintext'] = password
                break
        
        return results
    
    def generate_secure_password(self, length=16):
        """Generate a secure password"""
        # Ensure we have characters from each required category
        password_chars = []
        
        # Add required character types
        password_chars.append(secrets.choice(string.ascii_uppercase))
        password_chars.append(secrets.choice(string.ascii_lowercase))
        password_chars.append(secrets.choice(string.digits))
        password_chars.append(secrets.choice('!@#$%^&*(),.?":{}|<>'))
        
        # Fill the rest randomly
        all_chars = string.ascii_letters + string.digits + '!@#$%^&*(),.?":{}|<>'
        for _ in range(length - 4):
            password_chars.append(secrets.choice(all_chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)
    
    def _generate_recommendations(self, violations):
        """Generate password improvement recommendations"""
        recommendations = []
        
        violation_text = ' '.join(violations).lower()
        
        if 'too short' in violation_text:
            recommendations.append("Increase password length to at least 12 characters")
        
        if 'uppercase' in violation_text:
            recommendations.append("Add uppercase letters (A-Z)")
        
        if 'lowercase' in violation_text:
            recommendations.append("Add lowercase letters (a-z)")
        
        if 'digit' in violation_text:
            recommendations.append("Add numbers (0-9)")
        
        if 'special' in violation_text:
            recommendations.append("Add special characters (!@#$%^&*)")
        
        if 'forbidden pattern' in violation_text:
            recommendations.append("Avoid common words and predictable patterns")
        
        if 'entropy' in violation_text:
            recommendations.append("Use more diverse character combinations")
        
        if 'repeated' in violation_text:
            recommendations.append("Avoid repeating characters")
        
        if 'sequential' in violation_text:
            recommendations.append("Avoid sequential numbers or letters")
        
        recommendations.append("Consider using a passphrase with random words")
        recommendations.append("Use a password manager for unique passwords")
        
        return recommendations

def main():
    parser = argparse.ArgumentParser(description='PayBuddy Password Assessment Tool')
    parser.add_argument('--check', help='Check password strength (use quotes for passwords with spaces)')
    parser.add_argument('--crack', help='Simulate hash cracking (provide hash value)')
    parser.add_argument('--hash-type', default='MD5', choices=['MD5', 'SHA1', 'SHA256'],
                       help='Hash type for cracking simulation')
    parser.add_argument('--generate', action='store_true', help='Generate secure password')
    parser.add_argument('--length', type=int, default=16, help='Password length for generation')
    parser.add_argument('--simulate', action='store_true', help='Run in simulation mode (no actual cracking)')
    parser.add_argument('--dry-run', action='store_true', help='Verify identity without performing tests')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    
    args = parser.parse_args()
    
    # Verify identity first
    verifier = IdentityVerifier()
    if not verifier.verify_identity(dry_run=args.dry_run):
        return 1
    
    if args.dry_run:
        print("✅ Dry run completed - no actual testing performed")
        return 0
    
    # Initialize password assessment
    assessor = PasswordAssessment()
    results = {}
    
    print("🔐 PayBuddy Password Assessment Tool")
    print("=" * 50)
    
    # Password strength check
    if args.check:
        print(f"🔍 Checking password strength...")
        policy_result = assessor.check_policy_compliance(args.check)
        entropy = assessor.calculate_entropy(args.check)
        
        print(f"\n📊 Password Analysis:")
        print(f"  Length: {len(args.check)} characters")
        print(f"  Entropy: {entropy:.1f} bits")
        print(f"  Policy Score: {policy_result['score']}/100")
        print(f"  Compliant: {'✅ Yes' if policy_result['compliant'] else '❌ No'}")
        
        if policy_result['violations']:
            print(f"\n⚠️  Policy Violations:")
            for violation in policy_result['violations']:
                print(f"    - {violation}")
        
        if policy_result['recommendations']:
            print(f"\n💡 Recommendations:")
            for rec in policy_result['recommendations']:
                print(f"    - {rec}")
        
        results['password_check'] = {
            'length': len(args.check),
            'entropy': entropy,
            'policy_result': policy_result
        }
    
    # Hash cracking simulation
    if args.crack:
        print(f"\n🔓 Simulating hash cracking...")
        print(f"  Hash: {args.crack}")
        print(f"  Type: {args.hash_type}")
        print(f"  ⚠️  SIMULATION MODE - Educational purposes only")
        
        crack_result = assessor.simulate_hash_cracking(args.crack, args.hash_type)
        
        print(f"\n📋 Cracking Results:")
        print(f"  Cracked: {'✅ Yes' if crack_result['cracked'] else '❌ No'}")
        if crack_result['cracked']:
            print(f"  Plaintext: {crack_result['plaintext']}")
            print(f"  Method: {crack_result['method']}")
            print(f"  Time: {crack_result['time_simulated']}")
        else:
            print(f"  Status: Hash not found in common password database")
        
        results['hash_crack'] = crack_result
    
    # Password generation
    if args.generate:
        print(f"\n🔐 Generating secure password...")
        secure_password = assessor.generate_secure_password(args.length)
        policy_check = assessor.check_policy_compliance(secure_password)
        entropy = assessor.calculate_entropy(secure_password)
        
        print(f"\n✨ Generated Password: {secure_password}")
        print(f"  Length: {len(secure_password)} characters")
        print(f"  Entropy: {entropy:.1f} bits")
        print(f"  Policy Score: {policy_check['score']}/100")
        
        results['generated_password'] = {
            'password': secure_password,
            'length': len(secure_password),
            'entropy': entropy,
            'policy_score': policy_check['score']
        }
    
    # Export results if requested
    if args.output and results:
        team_info = verifier.get_team_info()
        
        export_data = {
            'assessment_info': {
                'timestamp': datetime.now().isoformat(),
                'tool_version': 'PayBuddy PasswordAssessment v1.0',
                'mode': 'simulation' if args.simulate else 'assessment',
                'team_info': team_info
            },
            'results': results
        }
        
        try:
            # Include registration number in filename
            if team_info['members']:
                reg_num = team_info['members'][0]['reg'].split('-')[1] if '-' in team_info['members'][0]['reg'] else '000'
                name = team_info['members'][0]['name'].replace(' ', '')
                output_path = Path(args.output).parent / f"auth_test_{reg_num}_{name}.json"
            else:
                output_path = Path(args.output)
            
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            print(f"\n📄 Results exported to: {output_path}")
            
        except Exception as e:
            print(f"❌ Error exporting results: {e}")
    
    if not args.check and not args.crack and not args.generate:
        print("ℹ️  Use --help to see available options")
        print("   Example: python auth_test.py --check 'mypassword123'")
        print("   Example: python auth_test.py --generate --length 20")
        print("   Example: python auth_test.py --crack 'e10adc3949ba59abbe56e057f20f883e' --hash-type MD5")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())