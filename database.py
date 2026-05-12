"""
Database models for CyberSafe India Portal
"""
from datetime import datetime
import random
import string
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """User model for authentication"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    aadhaar = db.Column(db.String(12), nullable=True)
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    complaints = db.relationship('Complaint', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Complaint(db.Model):
    """Complaint/Case model"""
    __tablename__ = 'complaints'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(120), nullable=True)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    evidence_file = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(30), default='Submitted')  # Submitted, Under Review, Investigating, Resolved, Closed
    priority = db.Column(db.String(20), default='Medium')  # Low, Medium, High, Critical
    officer_notes = db.Column(db.Text, nullable=True)
    amount_lost = db.Column(db.Float, default=0.0)
    amount_recovered = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @staticmethod
    def generate_case_id():
        """Generate unique case ID like CYBER-2026-XXXX"""
        year = datetime.utcnow().year
        random_part = ''.join(random.choices(string.digits, k=4))
        return f"CYBER-{year}-{random_part}"


class Alert(db.Model):
    """Live alerts model"""
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500), nullable=False)
    alert_type = db.Column(db.String(20), default='info')  # info, warning, danger
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Statistic(db.Model):
    """Portal statistics"""
    __tablename__ = 'statistics'

    id = db.Column(db.Integer, primary_key=True)
    total_reports = db.Column(db.Integer, default=0)
    amount_recovered = db.Column(db.Float, default=0.0)
    resolution_rate = db.Column(db.Float, default=0.0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


def init_db(app):
    """Initialize database with sample data"""
    with app.app_context():
        db.create_all()

        # Create admin user if not exists
        admin = User.query.filter_by(email='admin@cybersafe.gov.in').first()
        if not admin:
            admin = User(
                name='Admin Officer',
                email='admin@cybersafe.gov.in',
                phone='9999999999',
                role='admin',
                is_verified=True
            )
            admin.set_password('admin123')
            db.session.add(admin)

        # Create sample statistics
        stats = Statistic.query.first()
        if not stats:
            stats = Statistic(
                total_reports=15234,
                amount_recovered=2847500000,
                resolution_rate=78.5
            )
            db.session.add(stats)

        # Create sample alerts
        if Alert.query.count() == 0:
            alerts = [
                Alert(message="⚠️ New UPI fraud pattern detected — Never share OTP with anyone!", alert_type="warning"),
                Alert(message="🔒 12,450 cyber fraud cases resolved this month across India", alert_type="info"),
                Alert(message="🚨 Beware of fake loan apps — Report immediately on 1930", alert_type="danger"),
                Alert(message="✅ ₹284.75 Cr recovered for victims in FY 2025-26", alert_type="info"),
                Alert(message="⚠️ Rising cases of AI deepfake scams — Stay vigilant!", alert_type="warning"),
                Alert(message="📱 New WhatsApp investment scam targeting youth — Report suspicious links", alert_type="danger"),
            ]
            for alert in alerts:
                db.session.add(alert)

        # Create sample complaints for demo
        if Complaint.query.count() == 0:
            demo_user = User.query.filter_by(role='user').first()
            if not demo_user:
                demo_user = User(
                    name='Demo User',
                    email='demo@example.com',
                    phone='9876543210',
                    role='user',
                    is_verified=True
                )
                demo_user.set_password('demo123')
                db.session.add(demo_user)
                db.session.flush()

            sample_complaints = [
                Complaint(
                    case_id='CYBER-2026-1001',
                    user_id=demo_user.id,
                    name='Rahul Sharma',
                    mobile='9876543210',
                    category='Financial Fraud',
                    description='Received a phishing call claiming to be from SBI bank. Lost ₹50,000 via UPI.',
                    status='Investigating',
                    priority='High',
                    amount_lost=50000,
                    amount_recovered=30000
                ),
                Complaint(
                    case_id='CYBER-2026-1002',
                    user_id=demo_user.id,
                    name='Priya Patel',
                    mobile='9123456789',
                    category='Social Media',
                    description='Fake Instagram account created in my name posting defamatory content.',
                    status='Under Review',
                    priority='Medium'
                ),
                Complaint(
                    case_id='CYBER-2026-1003',
                    user_id=demo_user.id,
                    name='Amit Kumar',
                    mobile='9988776655',
                    category='Hacking',
                    description='Email account compromised. Unauthorized access to personal and financial data.',
                    status='Resolved',
                    priority='High',
                    amount_lost=0,
                    amount_recovered=0
                ),
                Complaint(
                    case_id='CYBER-2026-1004',
                    user_id=demo_user.id,
                    name='Sneha Reddy',
                    mobile='9111222333',
                    category='Phishing',
                    description='Clicked on fake Amazon link. Credit card details stolen. Unauthorized transactions of ₹1,20,000.',
                    status='Submitted',
                    priority='Critical',
                    amount_lost=120000
                ),
            ]
            for complaint in sample_complaints:
                db.session.add(complaint)

        db.session.commit()
