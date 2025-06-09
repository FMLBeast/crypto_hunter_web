#!/usr/bin/env python3
"""
Crypto Hunter Template Integration Script
Automatically integrates downloaded template files into the project structure
"""

import os
import shutil
import sys
from pathlib import Path
from datetime import datetime

class TemplateIntegrator:
    def __init__(self):
        self.script_dir = Path(__file__).parent
        self.project_root = self.find_project_root()
        self.templates_dir = self.project_root / "crypto_hunter_web" / "templates"
        
        # Template file mappings (source -> destination)
        self.template_mappings = {
            "base_template.html": "base.html",
            "dashboard_template.html": "dashboard/index.html", 
            "login_template.html": "auth/login.html",
            "file_list_template.html": "files/file_list.html",
            "file_detail_template.html": "files/file_detail.html",
            "file_content_template.html": "content/file_content.html",
            "upload_template.html": "files/upload.html",
            "visual_graph_template.html": "graph/visual_graph.html",
            "analysis_vectors_template.html": "analysis/vector_list.html",
            "search_results_template.html": "search/results.html",
            "admin_dashboard_template.html": "admin/dashboard.html",
            "system_logs_template.html": "admin/logs.html"
        }
        
        # Additional files to create (register template)
        self.additional_templates = {
            "auth/register.html": self.get_register_template_content()
        }
        
        # Directories to create
        self.required_dirs = [
            "auth", "dashboard", "files", "content", "graph", 
            "analysis", "search", "admin", "errors"
        ]

    def find_project_root(self):
        """Find the project root by looking for crypto_hunter_web directory"""
        current_dir = self.script_dir
        
        # Check current directory first
        if (current_dir / "crypto_hunter_web").exists():
            return current_dir
            
        # Check parent directories
        for parent in current_dir.parents:
            if (parent / "crypto_hunter_web").exists():
                return parent
                
        # If not found, assume current directory is the project root
        print("⚠️  Project root not found, using current directory")
        return current_dir

    def create_backup(self):
        """Create backup of existing templates"""
        if self.templates_dir.exists():
            backup_dir = self.project_root / f"templates_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            print(f"📦 Creating backup at: {backup_dir}")
            shutil.copytree(self.templates_dir, backup_dir)
            return backup_dir
        return None

    def create_directory_structure(self):
        """Create required directory structure"""
        print("📁 Creating directory structure...")
        
        for directory in self.required_dirs:
            dir_path = self.templates_dir / directory
            dir_path.mkdir(parents=True, exist_ok=True)
            print(f"   ✅ Created: {dir_path}")

    def integrate_template(self, source_file, destination_path):
        """Integrate a single template file"""
        source_path = self.script_dir / source_file
        dest_path = self.templates_dir / destination_path
        
        if not source_path.exists():
            print(f"   ❌ Source file not found: {source_file}")
            return False
            
        # Create destination directory if needed
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Read source content
            with open(source_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Apply any necessary transformations
            content = self.transform_template_content(content, destination_path)
            
            # Write to destination
            with open(dest_path, 'w', encoding='utf-8') as f:
                f.write(content)
                
            print(f"   ✅ Integrated: {source_file} → {destination_path}")
            return True
            
        except Exception as e:
            print(f"   ❌ Error integrating {source_file}: {e}")
            return False

    def transform_template_content(self, content, destination_path):
        """Apply any necessary transformations to template content"""
        
        # Fix template extends for auth templates
        if destination_path.startswith("auth/"):
            # Ensure auth templates extend the base template correctly
            content = content.replace('{% extends "base.html" %}', '{% extends "base.html" %}')
            
        # Fix any other path-specific transformations
        if "register.html" in destination_path:
            # Add register template specific fixes if needed
            pass
            
        return content

    def create_additional_templates(self):
        """Create additional required templates"""
        print("📝 Creating additional templates...")
        
        for template_path, content in self.additional_templates.items():
            dest_path = self.templates_dir / template_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            try:
                with open(dest_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"   ✅ Created: {template_path}")
            except Exception as e:
                print(f"   ❌ Error creating {template_path}: {e}")

    def create_error_templates(self):
        """Create error page templates"""
        print("🚨 Creating error page templates...")
        
        error_templates = {
            "errors/404.html": self.get_404_template(),
            "errors/403.html": self.get_403_template(), 
            "errors/500.html": self.get_500_template()
        }
        
        for template_path, content in error_templates.items():
            dest_path = self.templates_dir / template_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            try:
                with open(dest_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"   ✅ Created: {template_path}")
            except Exception as e:
                print(f"   ❌ Error creating {template_path}: {e}")

    def verify_integration(self):
        """Verify that all templates were integrated correctly"""
        print("\n🔍 Verifying integration...")
        
        total_files = 0
        success_files = 0
        
        for source_file, dest_path in self.template_mappings.items():
            total_files += 1
            dest_full_path = self.templates_dir / dest_path
            
            if dest_full_path.exists():
                success_files += 1
                print(f"   ✅ {dest_path}")
            else:
                print(f"   ❌ {dest_path} (missing)")
        
        print(f"\n📊 Integration Summary: {success_files}/{total_files} templates successfully integrated")
        return success_files == total_files

    def update_static_files(self):
        """Create any necessary static file directories"""
        print("🎨 Setting up static file structure...")
        
        static_dir = self.project_root / "crypto_hunter_web" / "static"
        static_dirs = ["css", "js", "img", "fonts"]
        
        for directory in static_dirs:
            dir_path = static_dir / directory
            dir_path.mkdir(parents=True, exist_ok=True)
            print(f"   ✅ Created static directory: {directory}")

    def run(self):
        """Main integration process"""
        print("🚀 Crypto Hunter Template Integration Starting...")
        print(f"📍 Project root: {self.project_root}")
        print(f"📂 Templates directory: {self.templates_dir}")
        
        # Create backup
        backup_dir = self.create_backup()
        if backup_dir:
            print(f"✅ Backup created: {backup_dir}")
        
        # Create directory structure
        self.create_directory_structure()
        
        # Integrate templates
        print("\n📥 Integrating template files...")
        success_count = 0
        
        for source_file, dest_path in self.template_mappings.items():
            if self.integrate_template(source_file, dest_path):
                success_count += 1
        
        # Create additional templates
        self.create_additional_templates()
        
        # Create error templates
        self.create_error_templates()
        
        # Setup static files
        self.update_static_files()
        
        # Verify integration
        success = self.verify_integration()
        
        # Final summary
        print(f"\n{'='*50}")
        if success:
            print("🎉 Integration completed successfully!")
            print("\n📋 Next steps:")
            print("   1. Review integrated templates in crypto_hunter_web/templates/")
            print("   2. Test all routes to ensure templates load correctly")
            print("   3. Update any route handlers if needed")
            print("   4. Restart your Flask application")
            print("\n🔧 Quick start:")
            print("   python run.py")
        else:
            print("⚠️  Integration completed with some issues.")
            print("   Please check the error messages above and retry.")
            
        if backup_dir:
            print(f"\n💾 Original templates backed up to: {backup_dir}")

    def get_register_template_content(self):
        """Get the register template content extracted from login template"""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Crypto Hunter</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        .auth-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .glass-effect {
            backdrop-filter: blur(20px);
            background: rgba(255, 255, 255, 0.25);
            border: 1px solid rgba(255, 255, 255, 0.18);
        }
        .strength-meter {
            height: 4px;
            border-radius: 2px;
            transition: all 0.3s ease;
        }
        .strength-weak { background-color: #ef4444; width: 25%; }
        .strength-fair { background-color: #f59e0b; width: 50%; }
        .strength-good { background-color: #10b981; width: 75%; }
        .strength-strong { background-color: #059669; width: 100%; }
    </style>
</head>
<body class="auth-bg min-h-screen flex items-center justify-center px-4 py-8">
    <div class="relative w-full max-w-md">
        <div class="text-center mb-8">
            <div class="bg-white rounded-full p-4 shadow-xl inline-block">
                <div class="text-4xl">🔍</div>
            </div>
            <h1 class="mt-6 text-3xl font-bold text-white">Join Crypto Hunter</h1>
            <p class="mt-2 text-blue-100">Start your steganography analysis journey</p>
        </div>

        <div class="glass-effect rounded-2xl shadow-2xl p-8">
            <form method="POST" class="space-y-6" onsubmit="return validateForm()">
                {{ csrf_token() }}
                
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label for="first_name" class="block text-sm font-medium text-white mb-2">First Name</label>
                        <input type="text" name="first_name" id="first_name"
                               class="w-full px-4 py-3 bg-white bg-opacity-20 border border-white border-opacity-30 rounded-lg text-white placeholder-blue-100 focus:outline-none focus:ring-2 focus:ring-white focus:ring-opacity-50"
                               placeholder="John">
                    </div>
                    <div>
                        <label for="last_name" class="block text-sm font-medium text-white mb-2">Last Name</label>
                        <input type="text" name="last_name" id="last_name"
                               class="w-full px-4 py-3 bg-white bg-opacity-20 border border-white border-opacity-30 rounded-lg text-white placeholder-blue-100 focus:outline-none focus:ring-2 focus:ring-white focus:ring-opacity-50"
                               placeholder="Doe">
                    </div>
                </div>

                <div>
                    <label for="username" class="block text-sm font-medium text-white mb-2">
                        <i class="fas fa-user mr-2"></i>Username *
                    </label>
                    <input type="text" name="username" id="username" required
                           class="w-full px-4 py-3 bg-white bg-opacity-20 border border-white border-opacity-30 rounded-lg text-white placeholder-blue-100 focus:outline-none focus:ring-2 focus:ring-white focus:ring-opacity-50"
                           placeholder="Choose a unique username">
                </div>

                <div>
                    <label for="email" class="block text-sm font-medium text-white mb-2">
                        <i class="fas fa-envelope mr-2"></i>Email Address *
                    </label>
                    <input type="email" name="email" id="email" required
                           class="w-full px-4 py-3 bg-white bg-opacity-20 border border-white border-opacity-30 rounded-lg text-white placeholder-blue-100 focus:outline-none focus:ring-2 focus:ring-white focus:ring-opacity-50"
                           placeholder="your.email@example.com">
                </div>

                <div>
                    <label for="password" class="block text-sm font-medium text-white mb-2">
                        <i class="fas fa-lock mr-2"></i>Password *
                    </label>
                    <input type="password" name="password" id="password" required
                           class="w-full px-4 py-3 bg-white bg-opacity-20 border border-white border-opacity-30 rounded-lg text-white placeholder-blue-100 focus:outline-none focus:ring-2 focus:ring-white focus:ring-opacity-50"
                           placeholder="Create a strong password">
                    <div class="mt-2">
                        <div class="bg-white bg-opacity-20 rounded-full h-1">
                            <div id="password-strength" class="strength-meter"></div>
                        </div>
                    </div>
                </div>

                <div>
                    <label for="confirm_password" class="block text-sm font-medium text-white mb-2">
                        <i class="fas fa-lock mr-2"></i>Confirm Password *
                    </label>
                    <input type="password" name="confirm_password" id="confirm_password" required
                           class="w-full px-4 py-3 bg-white bg-opacity-20 border border-white border-opacity-30 rounded-lg text-white placeholder-blue-100 focus:outline-none focus:ring-2 focus:ring-white focus:ring-opacity-50"
                           placeholder="Confirm your password">
                </div>

                <div class="space-y-3">
                    <label class="flex items-start text-sm text-blue-100">
                        <input type="checkbox" name="terms" required
                               class="mr-2 mt-1 rounded border-white border-opacity-30 bg-white bg-opacity-20 text-blue-600 focus:ring-white focus:ring-opacity-50">
                        <span>I agree to the <a href="/terms" class="text-white hover:underline">Terms of Service</a> and <a href="/privacy" class="text-white hover:underline">Privacy Policy</a></span>
                    </label>
                </div>

                <button type="submit" id="submit-btn"
                        class="w-full bg-white bg-opacity-90 hover:bg-opacity-100 text-gray-900 font-semibold py-3 px-4 rounded-lg transition-all duration-200 transform hover:scale-105 shadow-lg">
                    <i class="fas fa-user-plus mr-2"></i>Create Account
                </button>
            </form>

            <div class="mt-6 text-center">
                <p class="text-sm text-blue-100">
                    Already have an account?
                    <a href="{{ url_for('auth.login') }}" class="font-medium text-white hover:underline">
                        Sign in here
                    </a>
                </p>
            </div>
        </div>
    </div>

    <script>
        function validateForm() {
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            
            if (password !== confirmPassword) {
                alert('Passwords do not match');
                return false;
            }
            return true;
        }
    </script>
</body>
</html>'''

    def get_404_template(self):
        return '''{% extends "base.html" %}

{% block title %}Page Not Found - Crypto Hunter{% endblock %}

{% block content %}
<div class="min-h-screen flex items-center justify-center px-4">
    <div class="max-w-md w-full bg-white rounded-lg shadow-xl p-8 text-center">
        <div class="text-6xl mb-4">🎯</div>
        <h1 class="text-2xl font-bold text-gray-900 mb-2">Page Not Found</h1>
        <p class="text-gray-600 mb-6">The page you're looking for doesn't exist in our steganography tracker.</p>
        <div class="space-y-3">
            <a href="{{ url_for('dashboard.index') }}" class="block w-full bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md font-medium">
                Return to Dashboard
            </a>
            <a href="{{ url_for('files.file_list') }}" class="block w-full bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-md font-medium">
                Browse Files
            </a>
        </div>
    </div>
</div>
{% endblock %}'''

    def get_403_template(self):
        return '''{% extends "base.html" %}

{% block title %}Access Denied - Crypto Hunter{% endblock %}

{% block content %}
<div class="min-h-screen flex items-center justify-center px-4">
    <div class="max-w-md w-full bg-white rounded-lg shadow-xl p-8 text-center">
        <div class="text-6xl mb-4">🔒</div>
        <h1 class="text-2xl font-bold text-gray-900 mb-2">Access Denied</h1>
        <p class="text-gray-600 mb-6">You don't have permission to access this analysis resource.</p>
        <div class="space-y-3">
            <a href="{{ url_for('dashboard.index') }}" class="block w-full bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md font-medium">
                Return to Dashboard
            </a>
            <a href="{{ url_for('auth.logout') }}" class="block w-full bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-md font-medium">
                Logout & Login as Different User
            </a>
        </div>
    </div>
</div>
{% endblock %}'''

    def get_500_template(self):
        return '''{% extends "base.html" %}

{% block title %}Server Error - Crypto Hunter{% endblock %}

{% block content %}
<div class="min-h-screen flex items-center justify-center px-4">
    <div class="max-w-md w-full bg-white rounded-lg shadow-xl p-8 text-center">
        <div class="text-6xl mb-4">⚠️</div>
        <h1 class="text-2xl font-bold text-gray-900 mb-2">Server Error</h1>
        <p class="text-gray-600 mb-6">Something went wrong with our analysis engine. The error has been logged.</p>
        <div class="space-y-3">
            <a href="{{ url_for('dashboard.index') }}" class="block w-full bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md font-medium">
                Return to Dashboard
            </a>
            <button onclick="history.back()" class="block w-full bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-md font-medium">
                Go Back
            </button>
        </div>
    </div>
</div>
{% endblock %}'''


if __name__ == "__main__":
    print("🔍 Crypto Hunter Template Integration Script")
    print("=" * 50)
    
    integrator = TemplateIntegrator()
    
    # Confirm before proceeding
    print(f"📍 Project root detected: {integrator.project_root}")
    print(f"📂 Templates will be installed to: {integrator.templates_dir}")
    
    response = input("\n❓ Proceed with template integration? (y/N): ").strip().lower()
    
    if response in ['y', 'yes']:
        integrator.run()
    else:
        print("❌ Integration cancelled by user.")
        sys.exit(0)