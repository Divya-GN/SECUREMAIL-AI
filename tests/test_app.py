import unittest
import sys
import os

# Adjust path to find the app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app, db
from app.models import User, Scan
from app.ml.rules import RuleEngine
from app.ml.classifier import EmailClassifier

class SecureMailTestCase(unittest.TestCase):
    def setUp(self):
        # Configure app for testing
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.client = self.app.test_client()
        
        # Initialize test database
        with self.app.app_context():
            db.create_all()
            
    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
            
    def test_user_creation(self):
        """Test database User creation and password hashing."""
        with self.app.app_context():
            user = User(username='testuser', email='test@test.com')
            user.set_password('mysecurepassword')
            db.session.add(user)
            db.session.commit()
            
            queried = User.query.filter_by(username='testuser').first()
            self.assertIsNotNone(queried)
            self.assertEqual(queried.email, 'test@test.com')
            self.assertTrue(queried.check_password('mysecurepassword'))
            self.assertFalse(queried.check_password('wrongpassword'))
            
    def test_scan_creation(self):
        """Test database Scan creation and JSON serialization of indicators."""
        with self.app.app_context():
            user = User(username='testuser', email='test@test.com')
            user.set_password('pass')
            db.session.add(user)
            db.session.commit()
            
            scan = Scan(
                user_id=user.id,
                subject='Test Alert',
                body='Click here for millions of dollars.',
                prediction='Spam',
                confidence=95.0,
                risk_score=75.0,
                explanation='Spam words matched'
            )
            # Test JSON serialization property
            scan.indicators = {'warnings': ['Spam keywords matching'], 'score': 45}
            db.session.add(scan)
            db.session.commit()
            
            queried = Scan.query.first()
            self.assertIsNotNone(queried)
            self.assertEqual(queried.prediction, 'Spam')
            self.assertEqual(queried.indicators['score'], 45)
            self.assertIn('Spam keywords matching', queried.indicators['warnings'])

    def test_rule_engine(self):
        """Test that RuleEngine correctly identifies heuristic warnings."""
        # Phishing URL and urgent language email
        subject = "URGENT: Verify your bank account"
        body = "We noticed suspicious activity on your Chase account. Please reset your password immediately here: http://192.168.1.5/chase-security.xyz/login. Enter your OTP code received on your phone."
        sender = "Chase Security <alert@bank-update.xyz>"
        
        result = RuleEngine.analyze(subject, body, sender)
        
        self.assertGreaterEqual(result['score'], 50)
        self.assertIn("Chase", result['brand_impersonation'])
        self.assertTrue(len(result['suspicious_urls']) > 0)
        self.assertTrue(result['urgent_language_count'] > 0)
        self.assertTrue(result['credential_request_count'] > 0)
        self.assertTrue(result['suspicious_sender'])

    def test_routing_unauthorized(self):
        """Test that dashboard and scanner routes redirect unauthorized users to login."""
        response = self.client.get('/dashboard/home')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/auth/login', response.headers['Location'])
        
        response = self.client.get('/scanner/scan')
        self.assertEqual(response.status_code, 302)
        
    def test_static_routes_unauth(self):
        """Test landing page is accessible without authentication."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'SecureMail', response.data)

if __name__ == '__main__':
    unittest.main()
