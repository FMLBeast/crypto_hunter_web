# LLM Orchestrated Recursive Extraction

This document explains the LLM Orchestrated Recursive Extraction system, which combines the power of LLM (Large Language Model) orchestration with recursive extraction to create a comprehensive file extraction and analysis pipeline.

## Overview

The LLM Orchestrated Recursive Extraction system:

1. Starts with the root image at `uploads/image.png`
2. Uses LLM to analyze and optimize extraction parameters
3. Extracts files recursively, creating a tree of all derivable files
4. Maintains clear naming, origin, and content information
5. Writes everything to the database as it runs
6. Supports resume capabilities to continue interrupted extractions

This approach combines the intelligence of LLM orchestration with the thoroughness of recursive extraction to provide the most comprehensive analysis possible.

## How It Works

### Initialization

The system initializes by:
- Creating a Flask application context
- Setting up the LLM orchestrator
- Creating the output directory
- Loading previous extraction state (if resuming)
- **Consulting LLM for initial extraction strategy** (new feature)

### Initial LLM Consultation

At the very beginning of the extraction process, the system consults the LLM to:
- Determine the overall extraction strategy
- Get recommendations for organizing the extraction tree structure
- Establish naming conventions for extracted files
- Identify initial extraction methods to try
- Set the maximum recursion depth

This initial consultation helps optimize the extraction process and avoid extremely long paths.

### Recursive Extraction Process

For each file, the system:

1. **Analyzes the file with LLM**:
   - Reads a preview of the file content
   - Sends this to the LLM for analysis
   - Determines appropriate extraction methods based on file type and LLM recommendations

2. **Applies extraction methods with LLM optimization**:
   - For each extraction method, uses LLM to optimize parameters
   - Performs extraction with optimized parameters
   - Saves extracted content to the output directory using LLM-recommended naming conventions

3. **Processes extracted files recursively**:
   - For each extracted file, repeats the process
   - Maintains a clean tree structure based on LLM recommendations
   - Tracks extraction depth to prevent infinite recursion

4. **Maintains database records**:
   - Creates records for all files
   - Tracks relationships between source and extracted files
   - Creates graph nodes and edges for visualization
   - Stores LLM analysis results

### Resume Capability

The system implements resume capability by:
- Tracking processed files by their SHA-256 hash
- Periodically saving the extraction state to a JSON file
- Loading the state when resuming an interrupted extraction
- Skipping already processed files

## Usage

### Basic Usage

```bash
python run_llm_extraction.py
```

This will start the extraction process from the beginning, using the image at `uploads/image.png`.

### Resuming an Interrupted Extraction

```bash
python run_llm_extraction.py --resume
```

This will resume an extraction that was previously interrupted, continuing from where it left off.

## Key Components

### LLMRecursiveExtractor Class

The main class that orchestrates the extraction process:

- **Initialization**: Sets up the environment and loads state if resuming
- **Process File**: Processes a single file with LLM orchestration
- **Determine Extraction Methods**: Uses LLM to determine appropriate extraction methods
- **Extract With Method**: Applies an extraction method with LLM-optimized parameters
- **Database Integration**: Creates and maintains database records for files and relationships

### Database Models Used

- **AnalysisFile**: Represents a file in the system
- **FileContent**: Stores file content and analysis results
- **ExtractionRelationship**: Tracks relationships between source and extracted files
- **FileNode**: Represents files as nodes in a graph for visualization
- **GraphEdge**: Represents relationships between file nodes
- **FileDerivation**: Tracks derivation relationships between files

### Output Structure

The system creates a structured output directory based on LLM recommendations:

#### Tree Structure Options:
- **Flat structure**: `production/{file_id}/`
- **Hierarchical structure**: `production/depth_{depth}/{file_id}/`
- **Default structure**: `production/{file_id}_{short_filename}/`

#### File Naming Convention Options:
- **Short**: `{method_abbrev}_{timestamp}.bin`
- **Descriptive**: `{method}_{file_id}_{timestamp}.bin`
- **Hierarchical**: `d{depth}_{method}_{file_id}.bin`
- **Default**: `{method}_{file_id}_{short_filename}.bin`

This flexible structure allows the system to adapt to different extraction scenarios and avoid extremely long paths while maintaining clarity and traceability.

## Advantages Over Previous Approaches

### Compared to Standard Recursive Extraction

- **Initial LLM Consultation**: Consults LLM at the beginning to optimize the entire extraction process
- **Intelligent Parameter Selection**: Uses LLM to optimize extraction parameters
- **Adaptive Method Selection**: Chooses extraction methods based on file content analysis
- **Clean Tree Structure**: Creates a clean, organized tree structure based on LLM recommendations
- **Smart Naming Conventions**: Uses LLM-recommended naming conventions to avoid long paths
- **Resume Capability**: Can resume interrupted extractions
- **Enhanced Database Integration**: Creates more comprehensive relationship records

### Compared to Standard LLM Extraction

- **Depth of Analysis**: Recursively processes all extracted files
- **Comprehensive Tree Creation**: Builds a complete tree of all derivable files
- **Relationship Tracking**: Maintains clear lineage of all extracted files
- **Visualization Support**: Creates graph nodes and edges for visualization
- **Path Length Management**: Intelligently manages path lengths to avoid extremely long paths

## Example Extraction Tree

### Old Structure (Before Improvement)
```
uploads/image.png
├── zsteg_20230615_123045_image.png.bin
│   ├── binwalk_20230615_123046_zsteg_20230615_123045_image.png.bin
│   │   └── strings_20230615_123047_binwalk_20230615_123046_zsteg_20230615_123045_image.png.bin
│   └── strings_20230615_123048_zsteg_20230615_123045_image.png.bin
└── binwalk_20230615_123049_image.png.bin
    └── strings_20230615_123050_binwalk_20230615_123049_image.png.bin
```

### New Structure (With LLM Recommendations)

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

The new structure creates much cleaner and shorter paths while maintaining clarity and traceability.

## Troubleshooting

### Common Issues

- **Missing Image**: Ensure `uploads/image.png` exists
- **Database Connection**: Verify database connection settings
- **LLM API Limits**: Check LLM API rate limits and budgets
- **Extraction Tools**: Ensure all required extraction tools are installed

### Logs

The system logs detailed information to the console, including:
- Files being processed
- Extraction methods being applied
- LLM recommendations
- Database operations
- Errors and warnings

## Future Enhancements

Potential future enhancements include:
- Parallel processing of extraction methods
- More sophisticated LLM prompting for better extraction guidance
- Integration with additional extraction tools
- Enhanced visualization of the extraction tree
- Automatic report generation
