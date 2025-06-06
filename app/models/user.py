"""
User and authentication models
"""

from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from . import db

class User(db.Model):
    """Authenticated users with role-based access"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False, unique=True)
    email = db.Column(db.String(128), nullable=False, unique=True)
    password_hash = db.Column(db.String(256), nullable=False)
    display_name = db.Column(db.String(128))
    role = db.Column(db.String(32), default='analyst')  # analyst, expert, admin
    is_active = db.Column(db.Boolean, default=True)
    expertise_areas = db.Column(db.Text)  # JSON list
    contributions_count = db.Column(db.Integer, default=0)
    points = db.Column(db.Integer, default=0)
    level = db.Column(db.String(32), default='Analyst')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password"""
        return check_password_hash(self.password_hash, password)
    
    def can_access_admin(self):
        """Check admin access"""
        return self.role in ['admin']
    
    def can_verify_findings(self):
        """Check verification permissions"""
        return self.role in ['expert', 'admin']
    
    def award_points(self, points, action):
        """Award points and update level"""
        self.points += points
        self.contributions_count += 1
        self.level = self.calculate_level()
        self.last_activity = datetime.utcnow()
    
    def calculate_level(self):
        """Calculate user level based on points"""
        if self.points < 100:
            return 'Analyst'
        elif self.points < 500:
            return 'Expert'
        elif self.points < 1500:
            return 'Lead'
        else:
            return 'Master'
    
    def __repr__(self):
        return f'<User {self.username}>'
