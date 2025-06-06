#!/usr/bin/env python3
"""
Database initialization script
"""

from app import create_app
from app.models import db
from app.models.user import User
from app.models.finding import Vector

def init_database():
    """Initialize database with default data"""
    app = create_app()
    
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Create default admin user
        if User.query.count() == 0:
            admin = User(
                username='admin',
                email='admin@arweave-puzzle.local',
                display_name='Administrator',
                role='admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            print("Created default admin user: admin / admin123")
        
        # Create default vectors
        if Vector.query.count() == 0:
            vectors = [
                Vector(name='Image Steganography', description='Bitplane operations and image analysis', 
                      color='#ef4444', icon='🖼️'),
                Vector(name='Audio Steganography', description='MP3 and SysEx file analysis', 
                      color='#f97316', icon='🎵'),
                Vector(name='Software Steganography', description='VM analysis and executable reverse engineering', 
                      color='#eab308', icon='⚙️'),
                Vector(name='Text Steganography', description='Character substitution and linguistic analysis', 
                      color='#22c55e', icon='📝'),
                Vector(name='Encryption Steganography', description='GPG network and cryptographic analysis', 
                      color='#3b82f6', icon='🔐'),
                Vector(name='Digital Archaeology', description='Vintage systems and file format analysis', 
                      color='#8b5cf6', icon='🏛️')
            ]
            
            for vector in vectors:
                db.session.add(vector)
            
            print("Created default analysis vectors")
        
        db.session.commit()
        print("Database initialization complete!")

if __name__ == '__main__':
    init_database()
