# Recursive Extraction Guide

This guide explains how to perform recursive extraction on image files in the Crypto Hunter project.

## What is Recursive Extraction?

Recursive extraction is a process that:
1. Extracts hidden data from an initial file
2. Analyzes any extracted files for further hidden data
3. Continues this process recursively until no more data can be extracted or a maximum depth is reached

This is particularly useful for CTF challenges and steganography puzzles where data may be hidden in multiple layers.

## Using the Recursive Extraction Script

The project includes a dedicated script for recursive extraction:

```bash
./run_recursive_extraction.py
```

This script will:
1. Process the file at `uploads/image.png`
2. Save all extracted data to the `production` directory
3. Recursively analyze any extracted files
4. Create database records for all processed files and their relationships

## How It Works

The recursive extraction process:

1. Identifies the file type of the input file
2. Applies appropriate extractors based on the file type:
   - PNG files: zsteg, pngcheck, exiftool, etc.
   - JPEG files: steghide, exiftool, etc.
   - Archives: binwalk, foremost, etc.
   - Text files: base64 decoding, hex decoding, etc.
3. Runs binwalk and strings analysis on all files
4. Tries exotic extraction methods on files that don't match common patterns
5. Recursively processes any extracted files

## Customization

If you need to customize the recursive extraction process:

1. Edit `crypto_hunter_web/scripts/recursive_extract.py` to modify:
   - `IMAGE_PATH`: Path to the input file (default: "uploads/image.png")
   - `OUTPUT_DIR`: Directory to save extracted files (default: "production")
   - `MAX_DEPTH`: Maximum recursion depth (default: 10)

## Viewing Results

After running the recursive extraction:

1. Check the `production` directory for extracted files
2. Each file will have its own subdirectory with extracted data
3. The database will contain records of all files and their relationships
4. You can view the extraction graph in the web interface