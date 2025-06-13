"""
Simplified steganography and file carving script for image.png
This script performs steganography and file carving analysis on the image.png file
and prints the results without storing them in a database.
"""

import os
import sys
import logging
import time
from datetime import datetime
from typing import Dict, Any, List

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from crypto_hunter_web.services.extractors import (
    analyze_png_file, extract_png_metadata, get_extractor
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
IMAGE_PATH = "uploads/image.png"

def main():
    """Main function to orchestrate the analysis"""
    logger.info("Starting comprehensive steganography and file carving analysis")
    
    # Verify the image exists
    if not os.path.exists(IMAGE_PATH):
        logger.error(f"Image file not found at {IMAGE_PATH}")
        return
    
    # Step 1: Analyze PNG structure
    logger.info("Step 1: Analyzing PNG structure")
    analyze_png_structure(IMAGE_PATH)
    
    # Step 2: Extract metadata
    logger.info("Step 2: Extracting PNG metadata")
    extract_metadata(IMAGE_PATH)
    
    # Step 3: Run steganography extractors
    logger.info("Step 3: Running steganography extractors")
    run_steganography_extractors(IMAGE_PATH)
    
    # Step 4: Run file carving tools
    logger.info("Step 4: Running file carving tools")
    run_file_carving_tools(IMAGE_PATH)
    
    # Step 5: Run string analysis
    logger.info("Step 5: Running string analysis")
    run_string_analysis(IMAGE_PATH)
    
    logger.info("Analysis complete!")

def analyze_png_structure(file_path: str):
    """Analyze PNG structure and print results"""
    try:
        # Analyze PNG file
        analysis_results = analyze_png_file(file_path)
        
        if 'error' in analysis_results:
            logger.error(f"PNG analysis error: {analysis_results['error']}")
            return
        
        # Print analysis results
        print("\n=== PNG Structure Analysis ===")
        print(f"File type: {analysis_results.get('file_type', 'Unknown')}")
        print(f"File size: {analysis_results.get('file_size', 0)} bytes")
        print(f"Dimensions: {analysis_results.get('dimensions', 'Unknown')}")
        print(f"Bit depth: {analysis_results.get('bit_depth', 'Unknown')}")
        print(f"Color type: {analysis_results.get('color_type', 'Unknown')}")
        print(f"Compression: {analysis_results.get('compression', 'Unknown')}")
        print(f"Filter method: {analysis_results.get('filter_method', 'Unknown')}")
        print(f"Interlace method: {analysis_results.get('interlace_method', 'Unknown')}")
        print(f"Has text data: {analysis_results.get('has_text_data', False)}")
        print(f"Has transparency: {analysis_results.get('has_transparency', False)}")
        
        # Print chunk information
        print("\nChunk Information:")
        print(f"Total chunks: {analysis_results.get('chunk_count', 0)}")
        print(f"Standard chunks: {', '.join(analysis_results.get('standard_chunks', []))}")
        print(f"Non-standard chunks: {', '.join(analysis_results.get('non_standard_chunks', []))}")
        
        # Print suspicious chunks
        if 'suspicious_chunks' in analysis_results and analysis_results['suspicious_chunks']:
            print("\nSuspicious Chunks:")
            for chunk in analysis_results['suspicious_chunks']:
                print(f"  - Type: {chunk['type']}, Length: {chunk['length']} bytes, Reason: {chunk.get('reason', 'Non-standard chunk')}")
        
        logger.info("PNG structure analysis complete")
        
    except Exception as e:
        logger.error(f"Error analyzing PNG structure: {str(e)}")

def extract_metadata(file_path: str):
    """Extract PNG metadata and print results"""
    try:
        # Extract metadata
        metadata_results = extract_png_metadata(file_path)
        
        if 'error' in metadata_results:
            logger.error(f"PNG metadata extraction error: {metadata_results['error']}")
            return
        
        # Print metadata results
        print("\n=== PNG Metadata ===")
        
        # Print image header information
        if 'image_header' in metadata_results:
            header = metadata_results['image_header']
            print("\nImage Header:")
            print(f"Width: {header.get('width', 'Unknown')}")
            print(f"Height: {header.get('height', 'Unknown')}")
            print(f"Bit depth: {header.get('bit_depth', 'Unknown')}")
            print(f"Color type: {header.get('color_type', 'Unknown')} ({header.get('color_type_name', 'Unknown')})")
            print(f"Compression: {header.get('compression', 'Unknown')}")
            print(f"Filter method: {header.get('filter_method', 'Unknown')}")
            print(f"Interlace method: {header.get('interlace_method', 'Unknown')} ({header.get('interlace_name', 'Unknown')})")
        
        # Print text data
        if 'text_data' in metadata_results and metadata_results['text_data']:
            print("\nText Data:")
            for text_item in metadata_results['text_data']:
                print(f"  - Keyword: {text_item.get('keyword', 'Unknown')}")
                print(f"    Text: {text_item.get('text', 'Unknown')}")
                print(f"    Type: {text_item.get('type', 'Unknown')}")
                print()
        
        # Print time data
        if 'time_data' in metadata_results and metadata_results['time_data']:
            time_data = metadata_results['time_data']
            print("\nTime Data:")
            print(f"Timestamp: {time_data.get('timestamp', 'Unknown')}")
        
        logger.info("PNG metadata extraction complete")
        
    except Exception as e:
        logger.error(f"Error extracting PNG metadata: {str(e)}")

def run_steganography_extractors(file_path: str):
    """Run steganography extractors on the image"""
    # Get recommended extractors for PNG
    extractors = ['zsteg', 'zsteg_bitplane_1', 'zsteg_bitplane_2', 'zsteg_bitplane_3', 'zsteg_bitplane_4', 'steghide']
    
    print("\n=== Steganography Analysis ===")
    
    for extractor_name in extractors:
        try:
            logger.info(f"Running {extractor_name} extractor")
            
            # Get extractor
            extractor = get_extractor(extractor_name)
            if not extractor:
                logger.warning(f"Extractor {extractor_name} not found")
                continue
            
            # Run extraction
            result = extractor.extract(file_path, {})
            
            # Print results
            print(f"\n{extractor_name.upper()} Results:")
            print(f"Success: {result['success']}")
            print(f"Details: {result['details']}")
            print(f"Confidence: {result['confidence']}")
            
            # If extraction was successful and data was found
            if result['success'] and result['data']:
                print(f"Extracted data size: {len(result['data'])} bytes")
                
                # Try to decode as text if it looks like text
                try:
                    text_data = result['data'].decode('utf-8', errors='replace')
                    if len(text_data) < 1000:  # Only print if it's not too long
                        print(f"Extracted text: {text_data}")
                    else:
                        print(f"Extracted text: {text_data[:1000]}... (truncated)")
                except:
                    print("Extracted data is binary (not showing)")
                
                # Print metadata if available
                if 'metadata' in result:
                    print("\nMetadata:")
                    for key, value in result['metadata'].items():
                        if key == 'findings' and isinstance(value, list):
                            print(f"  Findings: {len(value)} items")
                            for i, finding in enumerate(value[:5]):  # Show first 5 findings
                                print(f"    Finding {i+1}: {finding}")
                            if len(value) > 5:
                                print(f"    ... and {len(value) - 5} more findings")
                        else:
                            print(f"  {key}: {value}")
            
            logger.info(f"{extractor_name} extraction complete")
            
        except Exception as e:
            logger.error(f"Error running {extractor_name}: {str(e)}")

def run_file_carving_tools(file_path: str):
    """Run file carving tools on the image"""
    # Use binwalk and foremost
    carving_tools = ['binwalk', 'foremost']
    
    print("\n=== File Carving Analysis ===")
    
    for tool_name in carving_tools:
        try:
            logger.info(f"Running {tool_name} extractor")
            
            # Get extractor
            extractor = get_extractor(tool_name)
            if not extractor:
                logger.warning(f"Extractor {tool_name} not found")
                continue
            
            # Run extraction
            result = extractor.extract(file_path, {})
            
            # Print results
            print(f"\n{tool_name.upper()} Results:")
            print(f"Success: {result['success']}")
            print(f"Details: {result['details']}")
            print(f"Confidence: {result['confidence']}")
            
            # If extraction was successful and data was found
            if result['success'] and result['data']:
                print(f"Extracted data size: {len(result['data'])} bytes")
                
                # Print metadata if available
                if 'metadata' in result:
                    print("\nMetadata:")
                    
                    # Print extracted files
                    if 'extracted_files' in result['metadata']:
                        files = result['metadata']['extracted_files']
                        print(f"  Extracted files: {len(files)} files")
                        for i, file_info in enumerate(files[:5]):  # Show first 5 files
                            print(f"    File {i+1}: {file_info.get('name', 'Unknown')} ({file_info.get('size', 0)} bytes, {file_info.get('type', 'Unknown')})")
                        if len(files) > 5:
                            print(f"    ... and {len(files) - 5} more files")
                    
                    # Print signatures found
                    if 'signatures_found' in result['metadata']:
                        signatures = result['metadata']['signatures_found']
                        print(f"  Signatures found: {len(signatures)} signatures")
                        for i, sig in enumerate(signatures[:5]):  # Show first 5 signatures
                            print(f"    Signature {i+1}: {sig.get('description', 'Unknown')} at offset {sig.get('offset', 'Unknown')}")
                        if len(signatures) > 5:
                            print(f"    ... and {len(signatures) - 5} more signatures")
            
            logger.info(f"{tool_name} extraction complete")
            
        except Exception as e:
            logger.error(f"Error running {tool_name}: {str(e)}")

def run_string_analysis(file_path: str):
    """Run string analysis on the image"""
    try:
        logger.info("Running strings extractor")
        
        # Get extractor
        extractor = get_extractor('strings')
        if not extractor:
            logger.warning("Strings extractor not found")
            return
        
        # Run extraction
        result = extractor.extract(file_path, {'min_length': 4})
        
        # Print results
        print("\n=== String Analysis ===")
        print(f"Success: {result['success']}")
        print(f"Details: {result['details']}")
        print(f"Confidence: {result['confidence']}")
        
        # If extraction was successful and data was found
        if result['success'] and result['data']:
            print(f"Extracted strings size: {len(result['data'])} bytes")
            
            # Print interesting strings if available
            if 'metadata' in result and 'analysis' in result['metadata']:
                analysis = result['metadata']['analysis']
                
                print(f"\nTotal strings found: {analysis.get('total_strings', 0)}")
                print(f"Interesting strings found: {len(analysis.get('interesting_strings', []))}")
                
                # Print interesting strings
                if 'interesting_strings' in analysis and analysis['interesting_strings']:
                    print("\nInteresting Strings:")
                    for i, string_info in enumerate(analysis['interesting_strings'][:10]):  # Show first 10 interesting strings
                        print(f"  {i+1}. Type: {string_info.get('type', 'Unknown')}")
                        print(f"     String: {string_info.get('string', 'Unknown')}")
                        if 'keywords' in string_info:
                            print(f"     Keywords: {', '.join(string_info['keywords'])}")
                        print()
                    if len(analysis['interesting_strings']) > 10:
                        print(f"  ... and {len(analysis['interesting_strings']) - 10} more interesting strings")
                
                # Print pattern counts
                if 'patterns' in analysis:
                    print("\nPattern Counts:")
                    for pattern_name, pattern_list in analysis['patterns'].items():
                        if pattern_list:
                            print(f"  {pattern_name}: {len(pattern_list)} found")
        
        logger.info("String analysis complete")
        
    except Exception as e:
        logger.error(f"Error running string analysis: {str(e)}")

if __name__ == "__main__":
    main()