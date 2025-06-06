#!/usr/bin/env python3
"""
Automatic database population script for Arweave Puzzle #11 Tracker
"""

import os
import csv
import sys
import hashlib
from datetime import datetime
from pathlib import Path
import mimetypes

# Add the app to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from app.models import db
from app.models.file import AnalysisFile, FileContent
from app.models.user import User
from app.models.finding import Vector
from app.services.auth_service import create_default_admin
from app.services.file_analyzer import FileAnalyzer


class AutoPopulator:
    """Automatically populate database from CSV files and directories"""
    
    def __init__(self):
        self.app = create_app()
        self.app_context = self.app.app_context()
        self.app_context.push()
        
        # Initialize database
        db.create_all()
        create_default_admin()
        
        # Get admin user
        self.admin_user = User.query.filter_by(username='admin').first()
        
        # Create default vectors
        self._create_default_vectors()
        
        print("🎯 Arweave Puzzle #11 - Auto Population Script")
        print("=" * 50)
    
    def _create_default_vectors(self):
        """Create default analysis vectors"""
        default_vectors = [
            {'name': 'Image Steganography', 'description': 'Hidden data in images', 'color': '#ef4444', 'icon': '🖼️'},
            {'name': 'Audio Steganography', 'description': 'Hidden data in audio files', 'color': '#f97316', 'icon': '🎵'},
            {'name': 'File Carving', 'description': 'Extracting embedded files', 'color': '#eab308', 'icon': '🔍'},
            {'name': 'Metadata Analysis', 'description': 'EXIF and metadata examination', 'color': '#22c55e', 'icon': '📋'},
            {'name': 'Binary Analysis', 'description': 'Raw binary data analysis', 'color': '#3b82f6', 'icon': '💾'},
            {'name': 'Text Analysis', 'description': 'String and text examination', 'color': '#8b5cf6', 'icon': '📝'},
        ]
        
        for vector_data in default_vectors:
            existing = Vector.query.filter_by(name=vector_data['name']).first()
            if not existing:
                vector = Vector(**vector_data)
                db.session.add(vector)
        
        db.session.commit()
    
    def populate_from_csv(self, csv_file_path):
        """Populate database from CSV file"""
        if not os.path.exists(csv_file_path):
            print(f"❌ CSV file not found: {csv_file_path}")
            return False
        
        print(f"📂 Processing CSV file: {csv_file_path}")
        
        try:
            with open(csv_file_path, 'r', encoding='utf-8') as f:
                # Detect delimiter
                sample = f.read(1024)
                f.seek(0)
                sniffer = csv.Sniffer()
                delimiter = sniffer.sniff(sample).delimiter
                
                reader = csv.DictReader(f, delimiter=delimiter)
                rows = list(reader)
                
                print(f"📊 Found {len(rows)} rows to process")
                
                # Process in batches
                batch_size = 1000
                for i in range(0, len(rows), batch_size):
                    batch = rows[i:i + batch_size]
                    self._process_batch(batch, i)
                    
                    if (i + batch_size) % 5000 == 0:
                        print(f"✅ Processed {min(i + batch_size, len(rows))}/{len(rows)} rows")
                
                print(f"🎉 Successfully imported {len(rows)} files")
                return True
                
        except Exception as e:
            print(f"❌ Error processing CSV: {e}")
            return False
    
    def _process_batch(self, batch, start_index):
        """Process a batch of CSV rows"""
        for i, row in enumerate(batch):
            try:
                self._process_csv_row(row)
                
                # Commit every 100 records
                if (start_index + i) % 100 == 0:
                    db.session.commit()
                    
            except Exception as e:
                print(f"⚠️ Error processing row {start_index + i}: {e}")
                db.session.rollback()
        
        # Final commit for the batch
        db.session.commit()
    
    def _process_csv_row(self, row):
        """Process a single CSV row"""
        # Extract data from row - handle various CSV formats
        sha256_hash = self._get_field(row, ['sha256', 'sha256_hash', 'hash', 'SHA256'])
        filepath = self._get_field(row, ['filepath', 'path', 'file_path', 'fullpath'])
        filename = self._get_field(row, ['filename', 'name', 'file_name', 'description'])
        file_type = self._get_field(row, ['file_type', 'type', 'mimetype', 'mime_type'])
        file_size = self._get_field(row, ['file_size', 'size', 'filesize'])
        
        # If no filename, use description or derive from path
        if not filename and filepath:
            filename = os.path.basename(filepath)
        
        # Generate SHA256 if not provided and file exists
        if not sha256_hash and filepath and os.path.exists(filepath):
            sha256_hash = self._calculate_sha256(filepath)
        elif not sha256_hash:
            # Generate a fake SHA256 for missing files
            fake_data = f"{filename}{filepath}{file_size}".encode()
            sha256_hash = hashlib.sha256(fake_data).hexdigest()
        
        # Skip if we already have this file
        existing = AnalysisFile.query.filter_by(sha256_hash=sha256_hash).first()
        if existing:
            return
        
        # Determine file type if not provided
        if not file_type and filepath:
            file_type, _ = mimetypes.guess_type(filepath)
        if not file_type:
            file_type = 'application/octet-stream'
        
        # Convert file size
        if file_size:
            try:
                file_size = int(file_size)
            except:
                file_size = 0
        else:
            file_size = 0
        
        # Create file record
        analysis_file = AnalysisFile(
            sha256_hash=sha256_hash,
            filename=filename or 'unknown',
            filepath=filepath or '',
            file_type=file_type,
            file_size=file_size,
            discovered_by=self.admin_user.id,
            is_root_file=False,  # We'll determine this later
            status='pending',
            node_color=self._get_file_type_color(file_type),
            extraction_method='bulk_import'
        )
        
        db.session.add(analysis_file)
        db.session.flush()  # Get the ID
        
        # Try to analyze content if file exists
        if filepath and os.path.exists(filepath):
            try:
                FileAnalyzer.analyze_file_content(filepath, analysis_file.id)
            except Exception as e:
                print(f"⚠️ Content analysis failed for {filename}: {e}")
    
    def _get_field(self, row, field_names):
        """Get field value from row using multiple possible field names"""
        for field_name in field_names:
            if field_name in row and row[field_name]:
                return row[field_name].strip()
        return None
    
    def _calculate_sha256(self, file_path):
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception:
            return None
    
    def _get_file_type_color(self, file_type):
        """Get color based on file type"""
        colors = {
            'image': '#ef4444',
            'audio': '#f97316', 
            'video': '#eab308',
            'text': '#22c55e',
            'application': '#3b82f6',
            'binary': '#8b5cf6'
        }
        
        file_type_lower = file_type.lower() if file_type else 'application'
        for key, color in colors.items():
            if key in file_type_lower:
                return color
        return colors['application']
    
    def populate_from_directory(self, directory_path, extensions=None):
        """Populate database by scanning a directory"""
        if not os.path.exists(directory_path):
            print(f"❌ Directory not found: {directory_path}")
            return False
        
        print(f"📁 Scanning directory: {directory_path}")
        
        if extensions is None:
            extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.wav', '.mp3', '.mp4', '.avi', '.zip', '.tar', '.gz'}
        
        file_count = 0
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = Path(file).suffix.lower()
                
                if extensions and file_ext not in extensions:
                    continue
                
                try:
                    # Calculate SHA256
                    sha256_hash = self._calculate_sha256(file_path)
                    if not sha256_hash:
                        continue
                    
                    # Skip duplicates
                    existing = AnalysisFile.query.filter_by(sha256_hash=sha256_hash).first()
                    if existing:
                        continue
                    
                    # Get file info
                    file_size = os.path.getsize(file_path)
                    file_type, _ = mimetypes.guess_type(file_path)
                    if not file_type:
                        file_type = 'application/octet-stream'
                    
                    # Create file record
                    analysis_file = AnalysisFile(
                        sha256_hash=sha256_hash,
                        filename=file,
                        filepath=file_path,
                        file_type=file_type,
                        file_size=file_size,
                        discovered_by=self.admin_user.id,
                        is_root_file=False,
                        status='pending',
                        node_color=self._get_file_type_color(file_type),
                        extraction_method='directory_scan'
                    )
                    
                    db.session.add(analysis_file)
                    file_count += 1
                    
                    # Commit in batches
                    if file_count % 100 == 0:
                        db.session.commit()
                        print(f"✅ Processed {file_count} files...")
                    
                    # Analyze content for smaller files
                    if file_size < 10 * 1024 * 1024:  # 10MB limit
                        try:
                            FileAnalyzer.analyze_file_content(file_path, analysis_file.id)
                        except:
                            pass
                    
                except Exception as e:
                    print(f"⚠️ Error processing {file_path}: {e}")
        
        db.session.commit()
        print(f"🎉 Successfully imported {file_count} files from directory")
        return True
    
    def create_sample_csv(self, output_path='sample_files.csv'):
        """Create a sample CSV file for testing"""
        sample_data = [
            {
                'sha256_hash': 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890',
                'filename': 'image1.jpg',
                'filepath': '/path/to/image1.jpg',
                'file_type': 'image/jpeg',
                'file_size': '2048576',
                'description': 'Sample JPEG image for steganography testing'
            },
            {
                'sha256_hash': 'b2c3d4e5f6789012345678901234567890123456789012345678901234567890a1',
                'filename': 'audio1.wav',
                'filepath': '/path/to/audio1.wav', 
                'file_type': 'audio/wav',
                'file_size': '8192000',
                'description': 'Sample WAV audio file'
            },
            {
                'sha256_hash': 'c3d4e5f6789012345678901234567890123456789012345678901234567890a1b2',
                'filename': 'document.pdf',
                'filepath': '/path/to/document.pdf',
                'file_type': 'application/pdf', 
                'file_size': '1024000',
                'description': 'Sample PDF document'
            }
        ]
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=sample_data[0].keys())
            writer.writeheader()
            writer.writerows(sample_data)
        
        print(f"📝 Created sample CSV: {output_path}")
    
    def cleanup(self):
        """Cleanup resources"""
        self.app_context.pop()


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Auto-populate Arweave Puzzle Tracker database')
    parser.add_argument('--csv', help='CSV file to import')
    parser.add_argument('--directory', help='Directory to scan for files')
    parser.add_argument('--create-sample', action='store_true', help='Create sample CSV')
    parser.add_argument('--extensions', help='File extensions to include (comma-separated)')
    
    args = parser.parse_args()
    
    populator = AutoPopulator()
    
    try:
        if args.create_sample:
            populator.create_sample_csv()
        
        if args.csv:
            populator.populate_from_csv(args.csv)
        
        if args.directory:
            extensions = None
            if args.extensions:
                extensions = {f'.{ext.strip()}' for ext in args.extensions.split(',')}
            populator.populate_from_directory(args.directory, extensions)
        
        if not any([args.csv, args.directory, args.create_sample]):
            print("Usage examples:")
            print("  python auto_populate.py --create-sample")
            print("  python auto_populate.py --csv sample_files.csv")
            print("  python auto_populate.py --directory /path/to/files")
            print("  python auto_populate.py --directory /path/to/files --extensions jpg,png,wav")
    
    finally:
        populator.cleanup()


if __name__ == '__main__':
    main()