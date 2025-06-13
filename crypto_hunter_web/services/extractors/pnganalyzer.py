"""
PNG file analyzer for Crypto Hunter
Provides specialized analysis for PNG files to detect steganography and hidden data
"""

import os
import struct
import logging
import zlib
from typing import Dict, Any, List, Tuple

# Setup logging
logger = logging.getLogger(__name__)

def analyze_png_file(file_path: str) -> Dict[str, Any]:
    """
    Analyze a PNG file for potential hidden data and steganography
    
    Args:
        file_path: Path to the PNG file
        
    Returns:
        Dictionary with analysis results
    """
    try:
        if not os.path.exists(file_path):
            return {'error': 'Analysis failed: File not found'}
            
        # Verify PNG signature
        with open(file_path, 'rb') as f:
            signature = f.read(8)
            if signature != b'\x89PNG\r\n\x1a\n':
                return {'error': 'Analysis failed: Not a valid PNG file'}
            
            # Extract chunks
            chunks = _extract_chunks(f)
            
        # Analyze chunks
        chunk_analysis = _analyze_chunks(chunks)
        
        # Get basic file info
        file_size = os.path.getsize(file_path)
        
        return {
            'file_type': 'PNG',
            'file_size': file_size,
            'chunks': chunk_analysis['chunks'],
            'chunk_count': len(chunks),
            'standard_chunks': chunk_analysis['standard_chunks'],
            'non_standard_chunks': chunk_analysis['non_standard_chunks'],
            'suspicious_chunks': chunk_analysis['suspicious_chunks'],
            'has_text_data': chunk_analysis['has_text_data'],
            'has_transparency': chunk_analysis['has_transparency'],
            'dimensions': chunk_analysis['dimensions'],
            'color_type': chunk_analysis['color_type'],
            'bit_depth': chunk_analysis['bit_depth'],
            'compression': chunk_analysis['compression'],
            'filter_method': chunk_analysis['filter_method'],
            'interlace_method': chunk_analysis['interlace_method'],
            'analysis_complete': True
        }
    except Exception as e:
        logger.error(f"PNG analysis error: {str(e)}")
        return {'error': f'Analysis failed: {str(e)}'}

def extract_png_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract metadata from a PNG file
    
    Args:
        file_path: Path to the PNG file
        
    Returns:
        Dictionary with extracted metadata
    """
    try:
        if not os.path.exists(file_path):
            return {'error': 'Metadata extraction failed: File not found'}
            
        # Verify PNG signature
        with open(file_path, 'rb') as f:
            signature = f.read(8)
            if signature != b'\x89PNG\r\n\x1a\n':
                return {'error': 'Metadata extraction failed: Not a valid PNG file'}
            
            # Extract chunks
            chunks = _extract_chunks(f)
        
        # Extract text chunks
        text_data = _extract_text_chunks(chunks)
        
        # Extract IHDR data
        ihdr_data = _extract_ihdr_data(chunks)
        
        # Extract time data
        time_data = _extract_time_data(chunks)
        
        return {
            'text_data': text_data,
            'image_header': ihdr_data,
            'time_data': time_data,
            'metadata_extracted': True
        }
    except Exception as e:
        logger.error(f"PNG metadata extraction error: {str(e)}")
        return {'error': f'Metadata extraction failed: {str(e)}'}

def _extract_chunks(file_obj) -> List[Dict[str, Any]]:
    """Extract all chunks from a PNG file"""
    chunks = []
    
    while True:
        # Read chunk length and type
        chunk_data = file_obj.read(8)
        if not chunk_data or len(chunk_data) < 8:
            break
            
        length = struct.unpack('>I', chunk_data[:4])[0]
        chunk_type = chunk_data[4:8].decode('ascii')
        
        # Read chunk data and CRC
        data = file_obj.read(length)
        crc = file_obj.read(4)
        
        # Verify CRC
        calculated_crc = zlib.crc32(chunk_data[4:8] + data) & 0xffffffff
        actual_crc = struct.unpack('>I', crc)[0]
        crc_valid = calculated_crc == actual_crc
        
        chunks.append({
            'type': chunk_type,
            'length': length,
            'data': data,
            'crc_valid': crc_valid
        })
        
        # IEND chunk signals the end of the PNG file
        if chunk_type == 'IEND':
            break
            
    return chunks

def _analyze_chunks(chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze PNG chunks for suspicious content"""
    standard_chunks = ['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'cHRM', 'gAMA', 'iCCP', 'sBIT', 'sRGB', 'tEXt', 'zTXt', 'iTXt', 'bKGD', 'hIST', 'pHYs', 'sPLT', 'tIME']
    
    result = {
        'chunks': [],
        'standard_chunks': [],
        'non_standard_chunks': [],
        'suspicious_chunks': [],
        'has_text_data': False,
        'has_transparency': False,
        'dimensions': None,
        'color_type': None,
        'bit_depth': None,
        'compression': None,
        'filter_method': None,
        'interlace_method': None
    }
    
    for chunk in chunks:
        chunk_type = chunk['type']
        chunk_info = {
            'type': chunk_type,
            'length': chunk['length']
        }
        
        # Add to appropriate lists
        result['chunks'].append(chunk_info)
        
        if chunk_type in standard_chunks:
            result['standard_chunks'].append(chunk_type)
        else:
            result['non_standard_chunks'].append(chunk_type)
            # Non-standard chunks might be suspicious
            result['suspicious_chunks'].append({
                'type': chunk_type,
                'length': chunk['length'],
                'reason': 'Non-standard chunk type'
            })
        
        # Check for text data
        if chunk_type in ['tEXt', 'zTXt', 'iTXt']:
            result['has_text_data'] = True
        
        # Check for transparency
        if chunk_type == 'tRNS':
            result['has_transparency'] = True
        
        # Extract IHDR information
        if chunk_type == 'IHDR' and len(chunk['data']) >= 13:
            width = struct.unpack('>I', chunk['data'][0:4])[0]
            height = struct.unpack('>I', chunk['data'][4:8])[0]
            bit_depth = chunk['data'][8]
            color_type = chunk['data'][9]
            compression = chunk['data'][10]
            filter_method = chunk['data'][11]
            interlace_method = chunk['data'][12]
            
            result['dimensions'] = (width, height)
            result['bit_depth'] = bit_depth
            result['color_type'] = color_type
            result['compression'] = compression
            result['filter_method'] = filter_method
            result['interlace_method'] = interlace_method
    
    return result

def _extract_text_chunks(chunks: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Extract text data from tEXt, zTXt, and iTXt chunks"""
    text_data = []
    
    for chunk in chunks:
        if chunk['type'] == 'tEXt':
            # Extract keyword and text from tEXt chunk
            try:
                data = chunk['data']
                null_pos = data.find(b'\0')
                if null_pos > 0:
                    keyword = data[:null_pos].decode('latin1')
                    text = data[null_pos+1:].decode('latin1')
                    text_data.append({
                        'keyword': keyword,
                        'text': text,
                        'type': 'tEXt'
                    })
            except Exception as e:
                logger.warning(f"Failed to parse tEXt chunk: {e}")
        
        elif chunk['type'] == 'zTXt':
            # Extract compressed text from zTXt chunk
            try:
                data = chunk['data']
                null_pos = data.find(b'\0')
                if null_pos > 0 and len(data) > null_pos + 2:
                    keyword = data[:null_pos].decode('latin1')
                    compression_method = data[null_pos+1]
                    compressed_text = data[null_pos+2:]
                    
                    if compression_method == 0:  # zlib compression
                        text = zlib.decompress(compressed_text).decode('latin1')
                        text_data.append({
                            'keyword': keyword,
                            'text': text,
                            'type': 'zTXt'
                        })
            except Exception as e:
                logger.warning(f"Failed to parse zTXt chunk: {e}")
    
    return text_data

def _extract_ihdr_data(chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract and interpret IHDR chunk data"""
    for chunk in chunks:
        if chunk['type'] == 'IHDR' and len(chunk['data']) >= 13:
            width = struct.unpack('>I', chunk['data'][0:4])[0]
            height = struct.unpack('>I', chunk['data'][4:8])[0]
            bit_depth = chunk['data'][8]
            color_type = chunk['data'][9]
            compression = chunk['data'][10]
            filter_method = chunk['data'][11]
            interlace_method = chunk['data'][12]
            
            # Interpret color type
            color_type_name = {
                0: 'Grayscale',
                2: 'RGB',
                3: 'Palette',
                4: 'Grayscale with alpha',
                6: 'RGB with alpha'
            }.get(color_type, 'Unknown')
            
            # Interpret interlace method
            interlace_name = {
                0: 'No interlace',
                1: 'Adam7 interlace'
            }.get(interlace_method, 'Unknown')
            
            return {
                'width': width,
                'height': height,
                'bit_depth': bit_depth,
                'color_type': color_type,
                'color_type_name': color_type_name,
                'compression': compression,
                'filter_method': filter_method,
                'interlace_method': interlace_method,
                'interlace_name': interlace_name
            }
    
    return {}

def _extract_time_data(chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract time information from tIME chunk"""
    for chunk in chunks:
        if chunk['type'] == 'tIME' and len(chunk['data']) >= 7:
            year = struct.unpack('>H', chunk['data'][0:2])[0]
            month = chunk['data'][2]
            day = chunk['data'][3]
            hour = chunk['data'][4]
            minute = chunk['data'][5]
            second = chunk['data'][6]
            
            return {
                'year': year,
                'month': month,
                'day': day,
                'hour': hour,
                'minute': minute,
                'second': second,
                'timestamp': f"{year}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
            }
    
    return {}