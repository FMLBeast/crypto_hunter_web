# Extraction System Documentation

This document provides an overview of the extraction system in the Crypto Hunter project, including how to use it and how it integrates with the rest of the application.

## Overview

The extraction system is responsible for extracting hidden data from files using various steganography and file carving techniques. It consists of several components:

1. **Extractors**: Individual extractors for different techniques (zsteg, binwalk, steghide, etc.)
2. **Extraction Engine**: Core engine for performing extractions
3. **Extraction Service**: High-level service for extraction operations
4. **Extraction Tasks**: Background tasks for asynchronous extraction
5. **Command-line Interface**: Script for running extractions from the command line

## Directory Structure

```
crypto_hunter_web/
├── services/
│   ├── extractors/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── binwalk.py
│   │   ├── custom.py
│   │   ├── forensics_extractor.py
│   │   ├── pnganalyzer.py
│   │   ├── steghide.py
│   │   └── zsteg.py
│   ├── extraction/
│   │   ├── __init__.py
│   │   └── extraction_service.py
│   └── extraction_engine.py
├── tasks/
│   ├── extraction/
│   │   ├── __init__.py
│   │   └── extraction_tasks.py
│   └── ...
└── scripts/
    └── run_extraction.py
```

## Database Integration

The extraction system integrates with the database through several models:

1. **AnalysisFile**: Represents a file in the system
2. **FileContent**: Stores the content of extracted data
3. **ExtractionRelationship**: Tracks relationships between source files and extracted files
4. **Finding**: Stores analysis findings from extractions

## Using the Extraction Service

The `ExtractionService` provides a high-level interface for extraction operations:

```python
from crypto_hunter_web.services.extraction import ExtractionService

# Extract from a file using a specific method
result = ExtractionService.extract_from_file(
    file_id=123,
    extraction_method='zsteg',
    parameters={'param1': 'value1'},
    user_id=1,
    async_mode=True  # Run asynchronously using Celery
)

# Extract using all recommended methods
result = ExtractionService.extract_all_methods(
    file_id=123,
    user_id=1,
    async_mode=True
)

# Extract to production directory
result = ExtractionService.extract_to_production(
    file_id=123,
    output_dir='production',
    user_id=1,
    async_mode=True
)

# Get task status
status = ExtractionService.get_task_status(task_id)

# Get available extractors
extractors = ExtractionService.get_available_extractors()

# Get recommended extractors for a file type
recommended = ExtractionService.get_recommended_extractors('image/png')

# Get extraction history for a file
history = ExtractionService.get_extraction_history(file_id=123)

# Get file content records for a file
content = ExtractionService.get_file_content(file_id=123, content_type='extracted_data')
```

## Command-line Interface

The `run_extraction.py` script provides a command-line interface for running extractions:

```bash
# Extract using all recommended methods
./crypto_hunter_web/scripts/run_extraction.py /path/to/file.png

# Extract using a specific method
./crypto_hunter_web/scripts/run_extraction.py /path/to/file.png --method zsteg

# Extract to a specific output directory
./crypto_hunter_web/scripts/run_extraction.py /path/to/file.png --output-dir /path/to/output

# Run in the background using Celery
./crypto_hunter_web/scripts/run_extraction.py /path/to/file.png --background

# Wait for background task to complete
./crypto_hunter_web/scripts/run_extraction.py /path/to/file.png --background --wait

# Specify parameters for the extraction method
./crypto_hunter_web/scripts/run_extraction.py /path/to/file.png --method zsteg --parameters '{"param1": "value1"}'
```

## Background Tasks

The extraction system uses Celery for background processing. The following tasks are available:

1. `extract_from_file`: Extract hidden data from a file using a specified method
2. `extract_all_methods`: Extract hidden data from a file using all recommended methods
3. `extract_to_production`: Extract hidden data from a file and save to production directory

These tasks are defined in `crypto_hunter_web/tasks/extraction/extraction_tasks.py` and are registered with Celery in `crypto_hunter_web/services/celery_app.py`.

## Adding New Extractors

To add a new extractor:

1. Create a new extractor class in `crypto_hunter_web/services/extractors/` that inherits from `BaseExtractor`
2. Implement the required methods: `_get_tool_name` and `extract`
3. Register the extractor in `crypto_hunter_web/services/extractors/__init__.py`

Example:

```python
from .base import BaseExtractor

class MyExtractor(BaseExtractor):
    """My custom extractor"""
    
    def _get_tool_name(self):
        return 'my_tool'
    
    def extract(self, file_path, parameters=None):
        # Implement extraction logic
        return {
            'success': True,
            'data': b'extracted data',
            'error': '',
            'details': 'Extraction successful',
            'command_line': 'my_tool command',
            'confidence': 0.8
        }
```

Then register it in `__init__.py`:

```python
EXTRACTORS = {
    # ...
    'my_extractor': MyExtractor,
    # ...
}
```

## Progress Tracking

The extraction system tracks progress using the `BackgroundService`:

1. Tasks update their progress using `self.update_state` and `BackgroundService.update_task_status`
2. Progress can be monitored using `BackgroundService.get_task_status`
3. The command-line script can wait for task completion using `task.get()`

## Error Handling

The extraction system handles errors at multiple levels:

1. Individual extractors handle tool-specific errors
2. The `ExtractionEngine` handles extraction errors
3. The `ExtractionService` handles service-level errors
4. The `extraction_tasks` module handles task-level errors
5. The command-line script handles script-level errors

## Integration with Web Interface

The extraction system can be integrated with the web interface by:

1. Using the `ExtractionService` in route handlers
2. Displaying task status and progress in the UI
3. Showing extraction history and results in the UI