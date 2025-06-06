#!/usr/bin/env python3
"""
Application entry point
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from app import create_app
from app.models import db


def create_default_admin():
    """Create default admin user if none exists"""
    from app.models.user import User

    if User.query.count() == 0:
        admin = User(
            username='admin',
            email='admin@arweave-puzzle.local',
            display_name='Administrator',
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("Created default admin user: admin / admin123")


def main():
    """Main application entry point"""
    app = create_app()

    with app.app_context():
        # Create database tables
        db.create_all()

        # Initialize default data
        create_default_admin()

        print("🎯 Arweave Puzzle #11 - Visual Steganography Tracker")
        print("📊 Login: http://localhost:5000/")
        print("👤 Default admin: admin / admin123")
        print("🔍 SHA-based file identification ready")
        print("📈 Visual relationship graph enabled")
        print("🔗 Interactive relationship mapping")
        print("📄 File content analysis with regions")
        print("🎨 Hex/text/image content viewing")
        print("📌 Region marking and annotation")
        print("📁 Bulk import with relationships")
        print("🛡️ Full audit trail enabled")

    app.run(debug=True, host='0.0.0.0', port=5000)


if __name__ == '__main__':
    main()