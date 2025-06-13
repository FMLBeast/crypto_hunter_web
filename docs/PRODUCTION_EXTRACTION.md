# Production Extraction Guide

This guide explains how to set up and run the production extraction process for the crypto_hunter project.

## Prerequisites

The extraction process requires several tools to be installed on your system:

- **zsteg**: For extracting data from PNG files
- **binwalk**: For file carving and analysis
- **foremost**: For file carving
- **steghide**: For extracting hidden data from images
- **exiftool**: For extracting metadata from files

## Installation

### Automatic Installation

We've provided a script to automatically install all the required tools:

```bash
sudo ./scripts/install_tools.py
```

This script will check if each tool is already installed and install any missing tools.

### Manual Installation

If the automatic installation fails, you can install the tools manually:

#### Ubuntu/Debian:

```bash
# Update package lists
sudo apt-get update

# Install binwalk, foremost, steghide, and exiftool
sudo apt-get install -y binwalk foremost steghide libimage-exiftool-perl

# Install Ruby (required for zsteg)
sudo apt-get install -y ruby ruby-dev

# Install zsteg
sudo gem install zsteg
```

#### macOS:

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install binwalk, foremost, steghide, and exiftool
brew install binwalk foremost steghide exiftool

# Install Ruby (required for zsteg)
brew install ruby

# Install zsteg
gem install zsteg
```

## Running the Extraction

Once all the required tools are installed, you can run the extraction process using the orchestrator script:

```bash
./extraction/orchestrate_extraction.py
```

This script will:

1. Check if all required tools are installed
2. Prepare the necessary directories for extraction
3. Run the extraction process using all available extractors
4. Verify that the extraction was successful
5. Print a summary of the extraction results

## Output

The extraction results will be saved in the `production` directory:

- `production/image.png`: The original image file (marked as root)
- `production/zsteg_extracted/`: Files extracted using zsteg
- `production/binwalk_extracted/`: Files extracted using binwalk
- `production/foremost_extracted/`: Files extracted using foremost
- `production/steghide_extracted/`: Files extracted using steghide

Each extractor-specific directory will contain:
- `<extractor>_data.bin`: The raw extracted data
- Any files that were extracted from the image

## Troubleshooting

### Missing Tools

If the orchestrator script reports that some tools are missing, you can install them using the installation script:

```bash
sudo ./scripts/install_tools.py
```

### Extraction Failures

If an extractor fails, check the error message in the extraction summary. Common issues include:

- **File format not supported**: Some extractors only work with specific file formats. For example, steghide doesn't support PNG files.
- **No data found**: The extractor didn't find any hidden data in the file.
- **Tool not available**: The tool is not installed or not properly configured.

### Database Connection Issues

The orchestrator script attempts to initialize the Flask app context, which requires a database connection. If this fails, the script will continue without the Flask app context, but some functionality may be limited.

If you need the full functionality, make sure the database is properly configured and accessible.

## Using as an Orchestrator

The orchestrator script is designed to be used as a central coordinator for the extraction process. It handles:

1. Tool availability checking
2. Directory preparation
3. Extraction coordination
4. Result verification and reporting

You can modify the script to add additional extractors or customize the extraction process as needed.
