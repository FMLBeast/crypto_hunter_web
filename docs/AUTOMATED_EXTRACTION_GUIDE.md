# Automated Extraction Guide for Crypto Hunter

This guide explains how to perform automated extraction from a base image file using the Crypto Hunter system. It covers three approaches: CLI, API/programmatic, and web interface.

## 1. Overview of Extraction Functionality

Crypto Hunter provides a powerful extraction system that can automatically extract hidden data from files, particularly images. The system includes:

1. **Standard Extraction**: Extract data using specific methods like zsteg, binwalk, strings, etc.
2. **Comprehensive Extraction**: Run all recommended extraction methods on a file
3. **Production Extraction**: Extract data and save to the production directory with a clean structure
4. **LLM Orchestrated Recursive Extraction**: Use LLM to optimize extraction parameters and recursively extract from all derived files

## 2. CLI Approach

### 2.1 Using run_extraction.py

The `run_extraction.py` script provides a command-line interface for running extraction tasks.

#### Basic Usage

```bash
python crypto_hunter_web/scripts/run_extraction.py /path/to/image.png
```

This will run all recommended extraction methods on the image file.

#### Specific Extraction Method

```bash
python crypto_hunter_web/scripts/run_extraction.py /path/to/image.png --method zsteg
```

Available methods include: zsteg, binwalk, strings, exiftool, steghide, etc.

#### Production Extraction

```bash
python crypto_hunter_web/scripts/run_extraction.py /path/to/image.png --method production --output-dir production
```

This will extract data from the image and save it to the production directory with a clean structure.

#### Additional Options

- `--background` or `-b`: Run extraction in the background using Celery
- `--wait` or `-w`: Wait for background task to complete
- `--parameters` or `-p`: JSON string of parameters for the extraction method
- `--user-id` or `-u`: User ID to attribute the extraction to (default: 1)

### 2.2 Using run_llm_extraction.py

The `run_llm_extraction.py` script provides LLM orchestrated recursive extraction.

#### Basic Usage

```bash
python crypto_hunter_web/scripts/run_llm_extraction.py
```

This will start the extraction process from the beginning, using the image at `uploads/image.png`.

#### Resuming an Interrupted Extraction

```bash
python crypto_hunter_web/scripts/run_llm_extraction.py --resume
```

This will resume an extraction that was previously interrupted, continuing from where it left off.

### 2.3 Using CLI Commands

Crypto Hunter also provides CLI commands for extraction operations.

#### Forensics Commands

```bash
# Check status of forensics tools
flask forensics check

# Install forensics tools
flask forensics install --all
flask forensics install --tool zsteg

# Test forensics tools
flask forensics test
```

#### Analysis Commands

```bash
# Run analysis on a file
flask analysis run <file_hash> --type comprehensive

# Check analysis status
flask analysis status <task_id>

# List recent analyses
flask analysis list --limit 10

# Show analysis results
flask analysis results <file_hash> --format json
```

## 3. API/Programmatic Approach

### 3.1 Using ExtractionService

The `ExtractionService` class provides a programmatic interface for extraction operations.

```python
from crypto_hunter_web.services.extraction import ExtractionService

# Extract from file using specific method
result = ExtractionService.extract_from_file(
    file_id=file_id,
    extraction_method='zsteg',
    parameters={},
    user_id=user_id,
    async_mode=True,
    use_llm=True
)

# Extract using all recommended methods
result = ExtractionService.extract_all_methods(
    file_id=file_id,
    user_id=user_id,
    async_mode=True,
    use_llm=True
)

# Extract to production directory
result = ExtractionService.extract_to_production(
    file_id=file_id,
    output_dir='production',
    user_id=user_id,
    async_mode=True,
    use_llm=True
)

# Get task status
status = ExtractionService.get_task_status(task_id)

# Get available extractors
extractors = ExtractionService.get_available_extractors()

# Get recommended extractors for a file type
recommended = ExtractionService.get_recommended_extractors(file_type)

# Get extraction history for a file
history = ExtractionService.get_extraction_history(file_id)

# Get file content records
content = ExtractionService.get_file_content(file_id, content_type='extracted_data')
```

### 3.2 Using ExtractionEngine

The `ExtractionEngine` class provides lower-level access to extraction operations.

```python
from crypto_hunter_web.services.extraction_engine import ExtractionEngine

# Check if LLM mode is enabled
llm_enabled = ExtractionEngine.is_llm_mode_enabled()

# Extract from file
result = ExtractionEngine.extract_from_file(
    source_file=file_obj,
    extraction_method='zsteg',
    parameters={},
    user_id=user_id
)

# Get suggested extraction methods
methods = ExtractionEngine.suggest_extraction_methods(file_type)
```

### 3.3 Using LLMRecursiveExtractor

The `LLMRecursiveExtractor` class provides programmatic access to LLM orchestrated recursive extraction.

```python
from crypto_hunter_web.scripts.run_llm_extraction import LLMRecursiveExtractor

# Initialize extractor
extractor = LLMRecursiveExtractor(resume=False)

# Run extraction
extractor.run()

# Process a specific file
file_record = extractor.process_file(
    file_path='/path/to/image.png',
    output_dir='production',
    depth=0
)
```

## 4. Web Interface Approach

The Crypto Hunter web interface provides a user-friendly way to perform extraction operations.

### 4.1 Uploading a File

1. Navigate to the Crypto Hunter web interface
2. Click on "Upload" in the navigation menu
3. Drag and drop your image file or click to select it
4. Click "Upload" to upload the file

### 4.2 Running Extraction

1. Navigate to the "Files" section
2. Find your uploaded file in the list
3. Click on the file to view its details
4. In the file details page, click on "Extract" to see extraction options
5. Choose an extraction method or click "Extract All" to run all recommended methods
6. Click "Run Extraction" to start the extraction process

### 4.3 Viewing Extraction Results

1. Navigate to the "Files" section
2. Find your file in the list
3. Click on the file to view its details
4. In the file details page, click on "Extractions" to see extraction results
5. Click on an extraction to view its details
6. You can also view the extraction graph by clicking on "Graph View"

## 5. Extraction Output Format

### 5.1 Standard Output Format

The standard output format for extraction is a directory structure with extracted files:

```
production/
├── 3_image.png/
│   ├── zsteg_20250614_185958_image.png.bin
│   └── binwalk_20250614_185959_image.png.bin
├── 4_zsteg_20250614_185958_image.png.bin/
│   └── strings_20250614_185958_zsteg_20250614_185958_image.png.bin.bin
└── 6_binwalk_20250614_185959_image.png.bin/
    └── strings_20250614_185959_binwalk_20250614_185959_image.png.bin.bin
```

### 5.2 LLM Orchestrated Output Format

The LLM orchestrated output format is more organized and cleaner:

#### Flat Structure Example
```
production/
├── 1/
│   ├── zsteg_1_123045.bin
│   └── binwalk_1_123049.bin
├── 2/
│   ├── str_123048.bin
│   └── bin_123046.bin
└── 3/
    └── str_123047.bin
```

#### Hierarchical Structure Example
```
production/
├── depth_0/
│   └── 1/
│       ├── d0_zsteg_1.bin
│       └── d0_binwalk_1.bin
├── depth_1/
│   └── 2/
│       ├── d1_strings_2.bin
│       └── d1_binwalk_2.bin
└── depth_2/
    └── 3/
        └── d2_strings_3.bin
```

## 6. Interpreting Extraction Results

### 6.1 Understanding Extraction Methods

- **zsteg**: Extracts data hidden using LSB steganography in PNG and BMP files
- **binwalk**: Extracts embedded files and executable code from firmware images
- **strings**: Extracts printable strings from binary files
- **exiftool**: Extracts metadata from image files
- **steghide**: Extracts data hidden using steganography in JPEG, BMP, WAV, and AU files

### 6.2 Analyzing Extracted Files

1. **Check file type**: Use `file` command or the web interface to determine the type of extracted file
2. **Examine content**: Use appropriate tools to examine the content of the extracted file
3. **Look for patterns**: Look for patterns or signatures that might indicate the presence of hidden data
4. **Check for additional layers**: Some extracted files might contain additional hidden data

### 6.3 Using the Extraction Graph

The extraction graph provides a visual representation of the extraction process:

1. **Nodes**: Represent files in the extraction process
2. **Edges**: Represent extraction relationships between files
3. **Colors**: Indicate the type of file or extraction method
4. **Size**: Indicates the importance or depth of the file in the extraction tree

## 7. Example: Full Automated Extraction Workflow

Here's a complete example of an automated extraction workflow using the CLI approach:

```bash
# Step 1: Upload the image file
cp image.png uploads/

# Step 2: Run LLM orchestrated recursive extraction
python crypto_hunter_web/scripts/run_llm_extraction.py

# Step 3: Check the extraction results
ls -la production/

# Step 4: Analyze the extracted files
for dir in production/*/; do
    echo "Contents of $dir:"
    ls -la "$dir"
    echo ""
done

# Step 5: Examine specific extracted files
file production/3_image.png/zsteg_20250614_185958_image.png.bin
strings production/3_image.png/zsteg_20250614_185958_image.png.bin | head -20
```

## 8. Troubleshooting

### 8.1 Common Issues

- **Missing dependencies**: Ensure all required extraction tools are installed
- **Permission issues**: Ensure you have write permission to the output directory
- **Database connection issues**: Verify database connection settings
- **LLM API limits**: Check LLM API rate limits and budgets

### 8.2 Logs

Check the logs for detailed information about the extraction process:

- **Flask logs**: Located in the Flask application log directory
- **Celery logs**: Located in the Celery log directory
- **Extraction logs**: Printed to the console when running extraction scripts

## 9. Conclusion

The Crypto Hunter system provides powerful tools for automated extraction from image files. By using the CLI, API/programmatic, or web interface approaches, you can extract hidden data from files and analyze the results to uncover hidden information.

The LLM Orchestrated Recursive Extraction system enhances this capability by using LLM to optimize extraction parameters and recursively extract from all derived files, creating a comprehensive extraction tree with clear naming, origin, and content information.