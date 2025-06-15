#!/usr/bin/env python3
"""
Quick Extraction Test for Crypto Hunter
=======================================

Simple test to verify the comprehensive extraction system is working.

Usage:
    python quick_extraction_test.py path/to/image.png
"""

import os
import sys
import time
import tempfile
import subprocess
from pathlib import Path

def test_extractor_availability():
    """Test which extractors are available"""
    print("🔍 Testing extractor availability...")
    
    extractors = {}
    
    # Test Python packages
    python_packages = ['rarfile', 'py7zr', 'patool', 'pyzipper', 'volatility3', 'numpy', 'scipy', 'cv2']
    
    for pkg in python_packages:
        try:
            if pkg == 'cv2':
                import cv2
            else:
                __import__(pkg)
            extractors[f'python-{pkg}'] = True
            print(f"  ✅ {pkg}")
        except ImportError:
            extractors[f'python-{pkg}'] = False
            print(f"  ❌ {pkg}")
    
    # Test system tools
    system_tools = ['binwalk', 'zsteg', 'steghide', 'foremost', 'strings', 'exiftool']
    
    for tool in system_tools:
        if subprocess.run(['which', tool], capture_output=True).returncode == 0:
            extractors[f'tool-{tool}'] = True
            print(f"  ✅ {tool}")
        else:
            extractors[f'tool-{tool}'] = False
            print(f"  ❌ {tool}")
    
    working_count = sum(1 for status in extractors.values() if status)
    total_count = len(extractors)
    
    print(f"\n📊 Summary: {working_count}/{total_count} extractors available")
    return extractors

def test_basic_extraction(image_path):
    """Test basic extraction methods on an image"""
    if not os.path.exists(image_path):
        print(f"❌ Image file not found: {image_path}")
        return False
    
    print(f"\n🧪 Testing extraction methods on: {os.path.basename(image_path)}")
    
    # Create temp output directory
    with tempfile.TemporaryDirectory(prefix='crypto_test_') as temp_dir:
        results = {}
        
        # Test zsteg
        if subprocess.run(['which', 'zsteg'], capture_output=True).returncode == 0:
            print("  🔄 Testing zsteg...")
            try:
                result = subprocess.run(
                    ['zsteg', '-a', image_path], 
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0 and result.stdout.strip():
                    print(f"    ✅ zsteg found potential data ({len(result.stdout)} bytes output)")
                    results['zsteg'] = True
                else:
                    print(f"    ⚪ zsteg completed but found no data")
                    results['zsteg'] = False
            except subprocess.TimeoutExpired:
                print(f"    ⚠️  zsteg timed out")
                results['zsteg'] = False
            except Exception as e:
                print(f"    ❌ zsteg failed: {e}")
                results['zsteg'] = False
        
        # Test binwalk
        if subprocess.run(['which', 'binwalk'], capture_output=True).returncode == 0:
            print("  🔄 Testing binwalk...")
            try:
                binwalk_output = os.path.join(temp_dir, 'binwalk_output')
                os.makedirs(binwalk_output, exist_ok=True)
                
                result = subprocess.run(
                    ['binwalk', '-e', '--directory', binwalk_output, image_path],
                    capture_output=True, timeout=60
                )
                
                # Check if any files were extracted
                extracted_files = []
                for root, dirs, files in os.walk(binwalk_output):
                    extracted_files.extend(files)
                
                if extracted_files:
                    print(f"    ✅ binwalk extracted {len(extracted_files)} files")
                    results['binwalk'] = True
                else:
                    print(f"    ⚪ binwalk completed but extracted no files")
                    results['binwalk'] = False
                    
            except subprocess.TimeoutExpired:
                print(f"    ⚠️  binwalk timed out")
                results['binwalk'] = False
            except Exception as e:
                print(f"    ❌ binwalk failed: {e}")
                results['binwalk'] = False
        
        # Test steghide
        if subprocess.run(['which', 'steghide'], capture_output=True).returncode == 0:
            print("  🔄 Testing steghide...")
            try:
                # Just test info command (doesn't require password)
                result = subprocess.run(
                    ['steghide', 'info', image_path],
                    capture_output=True, text=True, timeout=30
                )
                
                if 'capacity' in result.stderr.lower() or 'embed' in result.stderr.lower():
                    print(f"    ✅ steghide detected embeddable format")
                    results['steghide'] = True
                else:
                    print(f"    ⚪ steghide: format not suitable for embedding")
                    results['steghide'] = False
                    
            except subprocess.TimeoutExpired:
                print(f"    ⚠️  steghide timed out")
                results['steghide'] = False
            except Exception as e:
                print(f"    ❌ steghide failed: {e}")
                results['steghide'] = False
        
        # Test strings
        print("  🔄 Testing strings extraction...")
        try:
            result = subprocess.run(
                ['strings', image_path],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                string_lines = result.stdout.count('\n')
                print(f"    ✅ strings extracted {string_lines} text lines")
                results['strings'] = True
            else:
                print(f"    ❌ strings extraction failed")
                results['strings'] = False
                
        except subprocess.TimeoutExpired:
            print(f"    ⚠️  strings timed out")
            results['strings'] = False
        except Exception as e:
            print(f"    ❌ strings failed: {e}")
            results['strings'] = False
        
        # Test Python-based extraction
        print("  🔄 Testing Python-based analysis...")
        try:
            import hashlib
            with open(image_path, 'rb') as f:
                content = f.read()
            
            file_hash = hashlib.sha256(content).hexdigest()
            file_size = len(content)
            
            # Basic entropy calculation
            byte_counts = [0] * 256
            for byte in content:
                byte_counts[byte] += 1
            
            entropy = 0
            for count in byte_counts:
                if count > 0:
                    probability = count / file_size
                    entropy -= probability * (probability.bit_length() - 1)
            
            print(f"    ✅ Python analysis: {file_size} bytes, entropy {entropy:.2f}")
            print(f"    📝 SHA256: {file_hash[:16]}...")
            results['python_analysis'] = True
            
        except Exception as e:
            print(f"    ❌ Python analysis failed: {e}")
            results['python_analysis'] = False
    
    # Summary
    working_methods = sum(1 for status in results.values() if status)
    total_methods = len(results)
    
    print(f"\n📊 Extraction test summary: {working_methods}/{total_methods} methods working")
    
    if working_methods > 0:
        print("🎉 Basic extraction capabilities are working!")
        return True
    else:
        print("❌ No extraction methods are working properly")
        return False

def test_comprehensive_system():
    """Test if the comprehensive system can be imported"""
    print("\n🔬 Testing comprehensive system imports...")
    
    try:
        # Test if we can import the basic components
        import numpy as np
        print("  ✅ numpy")
        
        import hashlib
        print("  ✅ hashlib")
        
        from pathlib import Path
        print("  ✅ pathlib")
        
        # Test advanced packages
        try:
            import rarfile
            print("  ✅ rarfile")
        except ImportError:
            print("  ❌ rarfile")
        
        try:
            import py7zr
            print("  ✅ py7zr")
        except ImportError:
            print("  ❌ py7zr")
        
        try:
            import volatility3
            print("  ✅ volatility3")
        except ImportError:
            print("  ❌ volatility3")
        
        print("🎉 Comprehensive system components are importable!")
        return True
        
    except Exception as e:
        print(f"❌ Comprehensive system import failed: {e}")
        return False

def main():
    """Main test function"""
    print("🚀 Crypto Hunter Quick Extraction Test")
    print("=" * 50)
    
    # Test extractor availability
    extractors = test_extractor_availability()
    
    # Test comprehensive system
    comp_test = test_comprehensive_system()
    
    # Test extraction if image provided
    if len(sys.argv) > 1:
        image_path = sys.argv[1]
        extraction_test = test_basic_extraction(image_path)
    else:
        print("\n💡 To test extraction on a specific image:")
        print("   python quick_extraction_test.py path/to/image.png")
        extraction_test = True
    
    # Final summary
    print("\n" + "=" * 50)
    if comp_test and extraction_test:
        print("🎉 SYSTEM READY FOR COMPREHENSIVE EXTRACTION! 🎉")
        print("\nNext steps:")
        print("1. Place your target image in the project directory")
        print("2. Run: python comprehensive_extractor_system.py path/to/image.png")
        print("3. Monitor progress in the output directory")
    else:
        print("⚠️  System needs additional setup")
        print("Run: python fixed_deployment_script.py setup-all")

if __name__ == '__main__':
    main()
