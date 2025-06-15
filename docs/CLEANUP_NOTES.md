# Cleanup of Redundant Extraction Files

This document describes the cleanup of redundant extraction files that were superseded by the new LLM Orchestrated Recursive Extraction system.

## Files Removed

The following files were removed as they are now redundant with the new LLM Orchestrated Recursive Extraction system:

1. `run_recursive_extraction.py` - A simple wrapper script that called the main recursive extraction implementation
2. `docs/RECURSIVE_EXTRACTION.md` - Documentation for the recursive extraction functionality
3. `docs/LLM_EXTRACTION.md` - Documentation for the LLM orchestrated extraction functionality

## Files Modified

The following files were modified:

1. `crypto_hunter_web/scripts/recursive_extract.py` - Added a deprecation notice to indicate that it's being replaced by the new LLM Orchestrated Recursive Extraction system

## Reason for Cleanup

The new LLM Orchestrated Recursive Extraction system (`run_llm_extraction.py`) combines the functionality of both the recursive extraction and LLM orchestrated extraction systems, making the separate implementations redundant. The new system:

1. Uses LLM to analyze and optimize extraction parameters
2. Extracts files recursively, creating a tree of all derivable files
3. Maintains clear naming, origin, and content information
4. Writes everything to the database as it runs
5. Supports resume capabilities to continue interrupted extractions

## Compatibility Notes

The `crypto_hunter_web/scripts/recursive_extract.py` file was not removed because it's still being imported by `crypto_hunter_web/services/engine_service.py`. Instead, a deprecation notice was added to indicate that it will be removed in a future version.

## Documentation

The new LLM Orchestrated Recursive Extraction system is documented in `docs/LLM_RECURSIVE_EXTRACTION.md`, which provides comprehensive information about the system's capabilities, how it works, and how to use it.