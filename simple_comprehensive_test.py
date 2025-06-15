#!/usr/bin/env python3
"""
Simple Comprehensive Extraction Test
====================================

Tests the core comprehensive extraction system with your image.

Usage:
    python simple_comprehensive_test.py path/to/image.png
"""

import os
import sys
import time
import tempfile
import hashlib
import subprocess
from pathlib import Path
from typing import List, Dict, Any

class SimpleComprehensiveExtractor:
    """Simplified version of the comprehensive extractor for testing"""
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.processed_hashes = set()
        self.extracted_files = []
        self.stats = {
            'files_processed': 0,
            'files_extracted': 0,
            'start_time': time.time()
        }
    
    def extract_all_methods(self, file_path: str, output_dir: str) -> Dict[str, Any]:
        """Extract using all available methods"""
        print(f"🚀 Starting comprehensive extraction: {os.path.basename(file_path)}")
        print(f"📁 Output directory: {output_dir}")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Calculate file hash for deduplication
        file_hash = self._calculate_hash(file_path)
        self.processed_hashes.add(file_hash)
        self.stats['files_processed'] += 1
        
        # Run extraction methods
        extraction_results = []
        
        # 1. Steganography methods
        steg_results = self._run_steganography_extraction(file_path, output_dir)
        extraction_results.extend(steg_results)
        
        # 2. Binary analysis methods
        binary_results = self._run_binary_extraction(file_path, output_dir)
        extraction_results.extend(binary_results)
        
        # 3. Archive extraction (if advanced packages available)
        archive_results = self._run_archive_extraction(file_path, output_dir)
        extraction_results.extend(archive_results)
        
        # 4. String and metadata extraction
        string_results = self._run_string_extraction(file_path, output_dir)
        extraction_results.extend(string_results)
        
        # Collect all extracted files
        all_extracted = []
        for result in extraction_results:
            all_extracted.extend(result.get('extracted_files', []))
        
        self.extracted_files.extend(all_extracted)
        self.stats['files_extracted'] += len(all_extracted)
        
        # Process extracted files recursively (simplified - just one level)
        if all_extracted:
            print(f"🔄 Processing {len(all_extracted)} extracted files...")
            for extracted_file in all_extracted[:10]:  # Limit for testing
                if os.path.exists(extracted_file) and os.path.getsize(extracted_file) > 0:
                    sub_hash = self._calculate_hash(extracted_file)
                    if sub_hash not in self.processed_hashes:
                        sub_output = os.path.join(output_dir, f"sub_{os.path.basename(extracted_file)}")
                        os.makedirs(sub_output, exist_ok=True)
                        sub_results = self._run_basic_extraction(extracted_file, sub_output)
                        for result in sub_results:
                            all_extracted.extend(result.get('extracted_files', []))
        
        # Generate final report
        duration = time.time() - self.stats['start_time']
        
        report = {
            'success': True,
            'files_processed': self.stats['files_processed'],
            'files_extracted': len(all_extracted),
            'duration_seconds': duration,
            'extracted_files': all_extracted,
            'extraction_results': extraction_results,
            'output_directory': output_dir
        }
        
        print(f"\n📊 Extraction Summary:")
        print(f"   Files processed: {report['files_processed']}")
        print(f"   Files extracted: {report['files_extracted']}")
        print(f"   Duration: {duration:.1f} seconds")
        print(f"   Output: {output_dir}")
        
        return report
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return f"error_{int(time.time())}"
    
    def _run_steganography_extraction(self, file_path: str, output_dir: str) -> List[Dict]:
        """Run steganography extraction methods"""
        results = []
        
        # zsteg
        if subprocess.run(['which', 'zsteg'], capture_output=True).returncode == 0:
            result = self._run_zsteg(file_path, output_dir)
            results.append(result)
        
        # steghide
        if subprocess.run(['which', 'steghide'], capture_output=True).returncode == 0:
            result = self._run_steghide(file_path, output_dir)
            results.append(result)
        
        return results
    
    def _run_binary_extraction(self, file_path: str, output_dir: str) -> List[Dict]:
        """Run binary analysis extraction"""
        results = []
        
        # binwalk
        if subprocess.run(['which', 'binwalk'], capture_output=True).returncode == 0:
            result = self._run_binwalk(file_path, output_dir)
            results.append(result)
        
        # foremost
        if subprocess.run(['which', 'foremost'], capture_output=True).returncode == 0:
            result = self._run_foremost(file_path, output_dir)
            results.append(result)
        
        return results
    
    def _run_archive_extraction(self, file_path: str, output_dir: str) -> List[Dict]:
        """Run archive extraction using advanced packages"""
        results = []
        
        # Test if file might be an archive
        try:
            with open(file_path, 'rb') as f:
                header = f.read(10)
            
            # ZIP signature
            if header.startswith(b'PK'):
                result = self._extract_zip_advanced(file_path, output_dir)
                results.append(result)
            
            # RAR signature  
            elif header.startswith(b'Rar!'):
                result = self._extract_rar_advanced(file_path, output_dir)
                results.append(result)
        
        except Exception as e:
            results.append({
                'method': 'archive_detection',
                'success': False,
                'error': str(e),
                'extracted_files': []
            })
        
        return results
    
    def _run_string_extraction(self, file_path: str, output_dir: str) -> List[Dict]:
        """Extract strings and metadata"""
        results = []
        
        # strings
        result = self._run_strings(file_path, output_dir)
        results.append(result)
        
        # exiftool (if available)
        if subprocess.run(['which', 'exiftool'], capture_output=True).returncode == 0:
            result = self._run_exiftool(file_path, output_dir)
            results.append(result)
        
        return results
    
    def _run_basic_extraction(self, file_path: str, output_dir: str) -> List[Dict]:
        """Run basic extraction methods (for recursive processing)"""
        results = []
        
        # Just run strings and basic analysis
        result = self._run_strings(file_path, output_dir)
        results.append(result)
        
        return results
    
    def _run_zsteg(self, file_path: str, output_dir: str) -> Dict:
        """Run zsteg extraction"""
        try:
            print("  🔄 Running zsteg...")
            result = subprocess.run(
                ['zsteg', '-a', file_path],
                capture_output=True, text=True, timeout=60
            )
            
            extracted_files = []
            if result.returncode == 0 and result.stdout.strip():
                # Save zsteg output
                output_file = os.path.join(output_dir, 'zsteg_output.txt')
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                extracted_files.append(output_file)
                
                # Try to extract specific channels
                channels = ['b1,bgr,lsb,xy', 'b2,bgr,lsb,xy', 'b1,rgb,lsb,xy']
                for i, channel in enumerate(channels):
                    try:
                        extract_result = subprocess.run(
                            ['zsteg', '-E', channel, file_path],
                            capture_output=True, timeout=30
                        )
                        if extract_result.returncode == 0 and extract_result.stdout:
                            channel_file = os.path.join(output_dir, f'zsteg_channel_{i}.bin')
                            with open(channel_file, 'wb') as f:
                                f.write(extract_result.stdout)
                            extracted_files.append(channel_file)
                    except:
                        continue
            
            return {
                'method': 'zsteg',
                'success': len(extracted_files) > 0,
                'extracted_files': extracted_files,
                'details': f"Found {len(extracted_files)} files"
            }
        
        except Exception as e:
            return {
                'method': 'zsteg',
                'success': False,
                'error': str(e),
                'extracted_files': []
            }
    
    def _run_steghide(self, file_path: str, output_dir: str) -> Dict:
        """Run steghide extraction"""
        try:
            print("  🔄 Running steghide...")
            
            # Try with empty password
            output_file = os.path.join(output_dir, 'steghide_extracted.bin')
            result = subprocess.run(
                ['steghide', 'extract', '-sf', file_path, '-xf', output_file, '-p', ''],
                capture_output=True, timeout=30
            )
            
            extracted_files = []
            if result.returncode == 0 and os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                extracted_files.append(output_file)
            
            return {
                'method': 'steghide',
                'success': len(extracted_files) > 0,
                'extracted_files': extracted_files,
                'details': f"Extracted {len(extracted_files)} files"
            }
        
        except Exception as e:
            return {
                'method': 'steghide',
                'success': False,
                'error': str(e),
                'extracted_files': []
            }
    
    def _run_binwalk(self, file_path: str, output_dir: str) -> Dict:
        """Run binwalk extraction"""
        try:
            print("  🔄 Running binwalk...")
            
            binwalk_dir = os.path.join(output_dir, 'binwalk')
            os.makedirs(binwalk_dir, exist_ok=True)
            
            result = subprocess.run(
                ['binwalk', '-e', '--directory', binwalk_dir, file_path],
                capture_output=True, timeout=120
            )
            
            # Collect extracted files
            extracted_files = []
            if os.path.exists(binwalk_dir):
                for root, dirs, files in os.walk(binwalk_dir):
                    for file in files:
                        full_path = os.path.join(root, file)
                        if os.path.getsize(full_path) > 0:
                            extracted_files.append(full_path)
            
            return {
                'method': 'binwalk',
                'success': len(extracted_files) > 0,
                'extracted_files': extracted_files,
                'details': f"Extracted {len(extracted_files)} files"
            }
        
        except Exception as e:
            return {
                'method': 'binwalk',
                'success': False,
                'error': str(e),
                'extracted_files': []
            }
    
    def _run_foremost(self, file_path: str, output_dir: str) -> Dict:
        """Run foremost file carving"""
        try:
            print("  🔄 Running foremost...")
            
            foremost_dir = os.path.join(output_dir, 'foremost')
            os.makedirs(foremost_dir, exist_ok=True)
            
            result = subprocess.run(
                ['foremost', '-o', foremost_dir, file_path],
                capture_output=True, timeout=120
            )
            
            # Collect carved files
            extracted_files = []
            if os.path.exists(foremost_dir):
                for root, dirs, files in os.walk(foremost_dir):
                    for file in files:
                        full_path = os.path.join(root, file)
                        if os.path.getsize(full_path) > 0:
                            extracted_files.append(full_path)
            
            return {
                'method': 'foremost',
                'success': len(extracted_files) > 0,
                'extracted_files': extracted_files,
                'details': f"Carved {len(extracted_files)} files"
            }
        
        except Exception as e:
            return {
                'method': 'foremost',
                'success': False,
                'error': str(e),
                'extracted_files': []
            }
    
    def _run_strings(self, file_path: str, output_dir: str) -> Dict:
        """Extract strings from file"""
        try:
            print("  🔄 Running strings...")
            
            result = subprocess.run(
                ['strings', file_path],
                capture_output=True, text=True, timeout=60
            )
            
            extracted_files = []
            if result.returncode == 0 and result.stdout.strip():
                strings_file = os.path.join(output_dir, 'strings_output.txt')
                with open(strings_file, 'w') as f:
                    f.write(result.stdout)
                extracted_files.append(strings_file)
            
            return {
                'method': 'strings',
                'success': len(extracted_files) > 0,
                'extracted_files': extracted_files,
                'details': f"Extracted strings to {len(extracted_files)} files"
            }
        
        except Exception as e:
            return {
                'method': 'strings',
                'success': False,
                'error': str(e),
                'extracted_files': []
            }
    
    def _run_exiftool(self, file_path: str, output_dir: str) -> Dict:
        """Extract metadata with exiftool"""
        try:
            print("  🔄 Running exiftool...")
            
            result = subprocess.run(
                ['exiftool', file_path],
                capture_output=True, text=True, timeout=30
            )
            
            extracted_files = []
            if result.returncode == 0 and result.stdout.strip():
                metadata_file = os.path.join(output_dir, 'metadata.txt')
                with open(metadata_file, 'w') as f:
                    f.write(result.stdout)
                extracted_files.append(metadata_file)
            
            return {
                'method': 'exiftool',
                'success': len(extracted_files) > 0,
                'extracted_files': extracted_files,
                'details': f"Extracted metadata to {len(extracted_files)} files"
            }
        
        except Exception as e:
            return {
                'method': 'exiftool',
                'success': False,
                'error': str(e),
                'extracted_files': []
            }
    
    def _extract_zip_advanced(self, file_path: str, output_dir: str) -> Dict:
        """Extract ZIP using advanced Python packages"""
        try:
            print("  🔄 Running advanced ZIP extraction...")
            
            import zipfile
            zip_dir = os.path.join(output_dir, 'zip_extracted')
            os.makedirs(zip_dir, exist_ok=True)
            
            extracted_files = []
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                zip_file.extractall(zip_dir)
                
                for root, dirs, files in os.walk(zip_dir):
                    for file in files:
                        extracted_files.append(os.path.join(root, file))
            
            return {
                'method': 'zip_advanced',
                'success': len(extracted_files) > 0,
                'extracted_files': extracted_files,
                'details': f"Extracted {len(extracted_files)} files from ZIP"
            }
        
        except Exception as e:
            return {
                'method': 'zip_advanced',
                'success': False,
                'error': str(e),
                'extracted_files': []
            }
    
    def _extract_rar_advanced(self, file_path: str, output_dir: str) -> Dict:
        """Extract RAR using advanced Python packages"""
        try:
            print("  🔄 Running advanced RAR extraction...")
            
            import rarfile
            rar_dir = os.path.join(output_dir, 'rar_extracted')
            os.makedirs(rar_dir, exist_ok=True)
            
            extracted_files = []
            with rarfile.RarFile(file_path, 'r') as rar_file:
                rar_file.extractall(rar_dir)
                
                for root, dirs, files in os.walk(rar_dir):
                    for file in files:
                        extracted_files.append(os.path.join(root, file))
            
            return {
                'method': 'rar_advanced',
                'success': len(extracted_files) > 0,
                'extracted_files': extracted_files,
                'details': f"Extracted {len(extracted_files)} files from RAR"
            }
        
        except Exception as e:
            return {
                'method': 'rar_advanced',
                'success': False,
                'error': str(e),
                'extracted_files': []
            }

def main():
    """Main test function"""
    if len(sys.argv) < 2:
        print("Usage: python simple_comprehensive_test.py path/to/image.png")
        return 1
    
    image_path = sys.argv[1]
    
    if not os.path.exists(image_path):
        print(f"❌ Image file not found: {image_path}")
        return 1
    
    # Create output directory
    output_dir = f"./test_extraction_{int(time.time())}"
    
    print("🚀 Crypto Hunter Simple Comprehensive Test")
    print("=" * 50)
    print(f"Input: {image_path}")
    print(f"Output: {output_dir}")
    print()
    
    # Run extraction
    extractor = SimpleComprehensiveExtractor(max_workers=4)
    results = extractor.extract_all_methods(image_path, output_dir)
    
    # Print detailed results
    print("\n📋 Detailed Results:")
    for result in results['extraction_results']:
        status = "✅" if result['success'] else "❌"
        method = result['method']
        files = len(result.get('extracted_files', []))
        details = result.get('details', result.get('error', ''))
        print(f"  {status} {method}: {files} files - {details}")
    
    print(f"\n🎉 Test completed successfully!")
    print(f"Check results in: {output_dir}")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
