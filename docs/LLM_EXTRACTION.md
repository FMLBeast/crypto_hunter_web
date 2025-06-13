# LLM Orchestrated Extraction Guide

This guide explains how to use the LLM (Large Language Model) orchestrated extraction functionality in the Crypto Hunter project.

## What is LLM Orchestrated Extraction?

LLM orchestrated extraction uses artificial intelligence to enhance the extraction process by:

1. Analyzing file content to determine optimal extraction parameters
2. Selecting the most appropriate extraction methods based on file characteristics
3. Providing intelligent guidance on how to interpret extracted data
4. Suggesting follow-up analysis steps based on initial findings

This approach can significantly improve extraction success rates, especially for complex steganography and cryptographic challenges.

## Using the LLM Orchestrated Extraction Script

The project includes a dedicated script for LLM orchestrated extraction:

```bash
./run_llm_extraction.py
```

This script will:
1. Enable LLM orchestration mode by setting the `USE_LLM_ORCHESTRATOR` environment variable
2. Process the file at `uploads/image.png`
3. Apply all appropriate extraction methods with LLM-optimized parameters
4. Save extracted data to the `production` directory
5. Create database records for all findings and extraction results

## How It Works

The LLM orchestrated extraction process:

1. Reads a preview of the file content
2. Sends this content to an LLM (GPT-4 or Claude) for analysis
3. The LLM identifies potential patterns, encodings, and hidden data
4. Based on the LLM's analysis, optimal extraction parameters are determined
5. The extraction is performed with these optimized parameters
6. Results are enhanced with LLM-generated insights and recommendations

## Benefits Over Standard Extraction

LLM orchestration provides several advantages:

1. **Adaptive Parameters**: The LLM can suggest optimal parameters for each extraction method based on file content
2. **Pattern Recognition**: LLMs excel at recognizing subtle patterns that might indicate steganography or encryption
3. **Contextual Understanding**: The LLM can interpret findings in the context of common CTF challenges and cryptographic techniques
4. **Intelligent Recommendations**: After extraction, the LLM can suggest next steps for further analysis

## Cost Management

LLM API calls incur costs, so the system includes budget management:

1. Daily and hourly budget limits prevent excessive spending
2. Cost tracking for all LLM operations
3. Fallback to standard extraction if budget limits are reached

## Viewing Results

After running the LLM orchestrated extraction:

1. Check the `production` directory for extracted files
2. The database will contain records of all findings with LLM-enhanced analysis
3. LLM-generated recommendations will be stored with each extraction result
4. High-confidence findings will be automatically created in the system

## Comparison with Recursive Extraction

While recursive extraction (`run_recursive_extraction.py`) focuses on depth by extracting data from files and then analyzing those extracted files, LLM orchestrated extraction (`run_llm_extraction.py`) focuses on intelligence by using AI to optimize the extraction process itself.

For the most comprehensive analysis, consider running both:
1. First use LLM orchestrated extraction to optimize the initial extraction
2. Then use recursive extraction to thoroughly process all extracted files