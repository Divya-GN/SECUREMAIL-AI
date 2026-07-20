from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import json

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    scans = db.relationship('Scan', backref='user', lazy=True, cascade="all, delete-orphan")
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @property
    def is_admin(self):
        return self.role == 'admin'

class Scan(db.Model):
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    subject = db.Column(db.String(256), nullable=False)
    body = db.Column(db.Text, nullable=False)
    file_name = db.Column(db.String(256), nullable=True)
    prediction = db.Column(db.String(20), nullable=False)  # 'Safe', 'Spam', 'Phishing'
    confidence = db.Column(db.Float, nullable=False)  # in percent (e.g. 98.5)
    risk_score = db.Column(db.Float, nullable=False)  # 0 to 100
    explanation = db.Column(db.Text, nullable=False)
    indicators_json = db.Column(db.Text, nullable=False)  # stores JSON serialized dictionary of rules triggered
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def indicators(self):
        try:
            return json.loads(self.indicators_json)
        except Exception:
            return {}
            
    @indicators.setter
    def indicators(self, value):
        self.indicators_json = json.dumps(value)
