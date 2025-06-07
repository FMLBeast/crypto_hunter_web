#!/usr/bin/env python3
"""
Development Productivity Tools
Makes debugging and development much easier
"""

import os
import sys
import subprocess
import time
import threading
import signal
from pathlib import Path

class DevTools:
    """Collection of development tools"""
    
    @staticmethod
    def real_time_logs():
        """Stream real-time logs from Docker containers"""
        print("📺 Starting real-time log streaming...")
        print("🎯 Press Ctrl+C to stop\n")
        
        try:
            # Stream logs from all containers with colors
            cmd = ['docker', 'compose', 'logs', '-f', '--tail=50']
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                     universal_newlines=True, bufsize=1)
            
            for line in process.stdout:
                # Add color coding
                if 'ERROR' in line or 'CRITICAL' in line:
                    print(f"\033[91m{line.rstrip()}\033[0m")  # Red
                elif 'WARNING' in line:
                    print(f"\033[93m{line.rstrip()}\033[0m")  # Yellow
                elif 'INFO' in line:
                    print(f"\033[92m{line.rstrip()}\033[0m")  # Green
                else:
                    print(line.rstrip())
                    
        except KeyboardInterrupt:
            print("\n🛑 Log streaming stopped")
    
    @staticmethod
    def quick_restart():
        """Quickly restart the web service without full rebuild"""
        print("🔄 Quick restarting web service...")
        
        # For Docker setup
        try:
            subprocess.run(['docker', 'compose', 'restart', 'web'], check=True, timeout=30)
            print("✅ Web service restarted")
            time.sleep(2)
            DevTools.health_check()
        except subprocess.CalledProcessError:
            print("❌ Failed to restart web service")
        except subprocess.TimeoutExpired:
            print("⏰ Restart timed out")
    
    @staticmethod
    def health_check():
        """Quick health check"""
        print("🏥 Running quick health check...")
        
        try:
            import requests
            response = requests.get('http://localhost:8000/health', timeout=5)
            if response.status_code == 200:
                print("✅ Application is healthy")
                print(f"   Response time: {response.elapsed.total_seconds():.3f}s")
            else:
                print(f"⚠️ Application responding with status {response.status_code}")
        except requests.exceptions.ConnectionError:
            print("❌ Application not responding")
        except Exception as e:
            print(f"❌ Health check failed: {e}")
    
    @staticmethod
    def database_shell():
        """Open database shell for quick queries"""
        print("🗄️ Opening database shell...")
        print("💡 Try: SELECT * FROM users; or .tables or .exit")
        
        db_path = "instance/arweave_tracker.db"
        if os.path.exists(db_path):
            subprocess.run(['sqlite3', db_path])
        else:
            print(f"❌ Database not found at {db_path}")
    
    @staticmethod
    def flask_shell():
        """Open Flask shell with app context"""
        print("🐍 Opening Flask shell with app context...")
        
        shell_script = '''
import os
os.environ.update({
    "FLASK_ENV": "development",
    "DATABASE_URL": "sqlite:///instance/arweave_tracker.db",
    "REDIS_URL": "redis://localhost:6379/0"
})

from crypto_hunter_web import create_app, db
from crypto_hunter_web.models import *

app = create_app()
ctx = app.app_context()
ctx.push()

print("🎉 Flask shell ready!")
print("📚 Available: app, db, User, AnalysisFile, etc.")
print("💡 Try: User.query.all() or db.session.execute('SELECT * FROM users')")
'''
        
        with open('.flask_shell.py', 'w') as f:
            f.write(shell_script)
        
        subprocess.run([sys.executable, '-i', '.flask_shell.py'])
        os.remove('.flask_shell.py')
    
    @staticmethod
    def reset_database():
        """Reset database to clean state"""
        print("🗑️ Resetting database...")
        
        db_path = "instance/arweave_tracker.db"
        if os.path.exists(db_path):
            backup_path = f"{db_path}.backup.{int(time.time())}"
            os.rename(db_path, backup_path)
            print(f"✅ Database backed up to {backup_path}")
        
        # Recreate database
        reset_script = '''
from crypto_hunter_web import create_app, db
from crypto_hunter_web.models import User
import os

os.environ.update({
    "DATABASE_URL": "sqlite:///instance/arweave_tracker.db",
    "REDIS_URL": "redis://localhost:6379/0"
})

app = create_app()
with app.app_context():
    db.create_all()
    
    # Create admin user
    admin = User(username='admin', email='admin@example.com', is_admin=True)
    admin.set_password('admin123')
    admin.display_name = 'Administrator'
    admin.points = 1000
    admin.level = 'Master Analyst'
    
    db.session.add(admin)
    db.session.commit()
    
    print("✅ Database reset with admin user (admin/admin123)")
'''
        
        subprocess.run([sys.executable, '-c', reset_script])
    
    @staticmethod
    def show_menu():
        """Show development tools menu"""
        print("\n🛠️ Development Tools Menu")
        print("=" * 40)
        print("1. 📺 Real-time logs")
        print("2. 🔄 Quick restart web service") 
        print("3. 🏥 Health check")
        print("4. 🗄️ Database shell (SQLite)")
        print("5. 🐍 Flask shell")
        print("6. 🗑️ Reset database")
        print("7. 🚀 Setup local development")
        print("8. 🧹 Clean Docker cache")
        print("0. 🚪 Exit")
        print("=" * 40)
        
        while True:
            try:
                choice = input("\n🎯 Choose option (0-8): ").strip()
                
                if choice == '0':
                    print("👋 Goodbye!")
                    break
                elif choice == '1':
                    DevTools.real_time_logs()
                elif choice == '2':
                    DevTools.quick_restart()
                elif choice == '3':
                    DevTools.health_check()
                elif choice == '4':
                    DevTools.database_shell()
                elif choice == '5':
                    DevTools.flask_shell()
                elif choice == '6':
                    confirm = input("⚠️ This will delete your database. Continue? (y/N): ")
                    if confirm.lower() == 'y':
                        DevTools.reset_database()
                elif choice == '7':
                    DevTools.setup_local_dev()
                elif choice == '8':
                    DevTools.clean_docker()
                else:
                    print("❌ Invalid choice")
                    
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
    
    @staticmethod
    def setup_local_dev():
        """Quick setup for local development"""
        print("🚀 Setting up local development...")
        
        # Stop Docker containers
        subprocess.run(['docker', 'compose', 'down'], check=False)
        
        # Start only Redis
        subprocess.run(['docker', 'compose', 'up', '-d', 'redis'])
        
        print("✅ Redis started")
        print("💡 Now run: python run_local.py")
    
    @staticmethod
    def clean_docker():
        """Clean Docker cache and containers"""
        print("🧹 Cleaning Docker cache...")
        
        commands = [
            ['docker', 'compose', 'down'],
            ['docker', 'system', 'prune', '-f'],
            ['docker', 'volume', 'prune', '-f']
        ]
        
        for cmd in commands:
            try:
                subprocess.run(cmd, check=False)
            except:
                pass
        
        print("✅ Docker cache cleaned")

def main():
    """Main entry point"""
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == 'logs':
            DevTools.real_time_logs()
        elif command == 'restart':
            DevTools.quick_restart()
        elif command == 'health':
            DevTools.health_check()
        elif command == 'shell':
            DevTools.flask_shell()
        elif command == 'db':
            DevTools.database_shell()
        elif command == 'reset':
            DevTools.reset_database()
        elif command == 'local':
            DevTools.setup_local_dev()
        elif command == 'clean':
            DevTools.clean_docker()
        else:
            print(f"❌ Unknown command: {command}")
            print("💡 Available commands: logs, restart, health, shell, db, reset, local, clean")
    else:
        DevTools.show_menu()

if __name__ == '__main__':
    main()
