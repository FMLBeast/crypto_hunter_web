#!/usr/bin/env python3
"""
LLM Orchestrated Recursive Extraction Script

This script combines LLM orchestration with recursive extraction to:
1. Start with the root image at uploads/image.png
2. Use LLM to analyze and optimize extraction parameters
3. Extract files recursively, creating a tree of all derivable files
4. Maintain clear naming, origin, and content information
5. Write everything to the database as it runs
6. Support resume capabilities to continue interrupted extractions

Usage:
    python run_llm_extraction.py [--resume]
"""

import os
import sys
import time
import logging
import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
from sqlalchemy import text, create_engine

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import Flask app and database models
from crypto_hunter_web import create_app, db
from crypto_hunter_web.models import (
    AnalysisFile, FileContent, Finding, ExtractionRelationship,
    FileNode, GraphEdge, FileStatus, FileDerivation
)
from crypto_hunter_web.services.extractors import (
    analyze_png_file, extract_png_metadata, get_extractor
)
from crypto_hunter_web.services.extraction_engine import ExtractionEngine
from crypto_hunter_web.services.llm_crypto_orchestrator import LLMCryptoOrchestrator

# Constants
IMAGE_PATH = "../../uploads/image.png"
OUTPUT_DIR = "../../production"
MAX_DEPTH = 10  # Maximum recursion depth
PROCESSED_FILES = set()  # Keep track of processed files by hash
ADMIN_USER_ID = 1  # Admin user ID for attribution
DB_FILE_RECORDS = {}  # Cache of file records by hash
EXTRACTION_STATE_FILE = "extraction_state.json"  # File to store extraction state for resume

class LLMRecursiveExtractor:
    """
    LLM Orchestrated Recursive Extractor

    This class combines LLM orchestration with recursive extraction to create
    a comprehensive extraction system with resume capabilities.
    """

    def __init__(self, resume: bool = False):
        """Initialize the extractor"""
        self.resume = resume
        self.processed_files = set()  # Track processed files by hash
        self.db_file_records = {}  # Cache of file records by hash
        self.extraction_state = self._load_extraction_state() if resume else {}
        self.llm_orchestrator = LLMCryptoOrchestrator()

        # Create Flask app and application context
        self.app = create_app()
        self.app_context = self.app.app_context()
        self.app_context.push()

        # Create output directory
        os.makedirs(OUTPUT_DIR, exist_ok=True)

        # Ensure instance directory exists
        instance_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
        os.makedirs(instance_dir, exist_ok=True)

        # Use an in-memory SQLite database
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        logger.info("Using in-memory SQLite database")

        # Flag to track if database is available
        self.db_available = False

        # Try to create a direct SQLite connection to test if SQLite is working
        try:
            # Create a direct SQLite engine
            direct_engine = create_engine('sqlite:///:memory:')
            # Test the connection
            with direct_engine.connect() as conn:
                conn.execute(text('SELECT 1'))
            logger.info("Direct SQLite connection successful")

            # Now try the Flask-SQLAlchemy connection
            db.session.execute(text('SELECT 1'))
            logger.info("Database connection successful")
            self.db_available = True
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            logger.info("Creating a new database file if it doesn't exist")
            try:
                # Try to create database tables
                db.create_all()
                logger.info("Database tables created successfully")
                self.db_available = True
            except Exception as e:
                logger.error(f"Failed to create database tables: {e}")
                # Continue without database
                logger.warning("Continuing without database support - some features will be limited")
                self.db_available = False

    def __del__(self):
        """Clean up resources"""
        try:
            self.app_context.pop()
        except:
            pass

    def _load_extraction_state(self) -> Dict[str, Any]:
        """Load extraction state from file for resume capability"""
        if os.path.exists(EXTRACTION_STATE_FILE):
            try:
                with open(EXTRACTION_STATE_FILE, 'r') as f:
                    state = json.load(f)
                logger.info(f"Loaded extraction state with {len(state.get('processed_files', []))} processed files")
                return state
            except Exception as e:
                logger.error(f"Failed to load extraction state: {e}")
        return {}

    def _save_extraction_state(self):
        """Save extraction state to file for resume capability"""
        state = {
            'processed_files': list(self.processed_files),
            'timestamp': datetime.utcnow().isoformat(),
            'last_file_id': max([0] + [r.id for r in self.db_file_records.values()]) if self.db_file_records else 0
        }

        try:
            with open(EXTRACTION_STATE_FILE, 'w') as f:
                json.dump(state, f, indent=2)
            logger.info(f"Saved extraction state with {len(state['processed_files'])} processed files")
        except Exception as e:
            logger.error(f"Failed to save extraction state: {e}")

    def consult_llm_for_extraction_strategy(self, file_path: str) -> Dict[str, Any]:
        """Consult LLM for initial extraction strategy and tree structure recommendations"""
        logger.info("Consulting LLM for initial extraction strategy and tree structure recommendations")

        try:
            # Read file preview for LLM analysis
            with open(file_path, 'rb') as f:
                content = f.read(8192)  # Read first 8KB for LLM analysis
                content_preview = content.decode('utf-8', errors='ignore')

            # Create a prompt for the LLM
            prompt = f"""
You are an expert in digital forensics and steganography extraction. You're starting a recursive extraction process 
on a file that may contain hidden data. Please provide recommendations for:

1. The overall extraction strategy
2. How to organize the extraction tree structure to avoid extremely long paths
3. Naming conventions for extracted files to maintain clarity while keeping paths short
4. Initial extraction methods to try

File information:
- Path: {file_path}
- Size: {os.path.getsize(file_path)} bytes
- Content preview:
```
{content_preview[:1000]}
```

Respond with a JSON object containing:
- "strategy": Overall extraction strategy
- "tree_structure": Recommendations for organizing the extraction tree
- "naming_convention": Recommended naming convention for extracted files
- "initial_methods": List of initial extraction methods to try
- "max_depth": Recommended maximum recursion depth
"""

            # Get LLM response
            response = self.llm_orchestrator._call_openai(
                self.llm_orchestrator.using_openai_v1 and 
                LLMProvider.OPENAI_GPT4 or 
                LLMProvider.OPENAI_GPT35, 
                prompt
            )

            # Parse the response
            try:
                # Try to parse as JSON
                if '{' in response['content'] and '}' in response['content']:
                    json_start = response['content'].find('{')
                    json_end = response['content'].rfind('}') + 1
                    json_str = response['content'][json_start:json_end]
                    strategy = json.loads(json_str)
                    logger.info("Successfully parsed LLM extraction strategy")
                    return strategy
            except Exception as e:
                logger.error(f"Failed to parse LLM response as JSON: {e}")

            # Fallback to default strategy
            return {
                "strategy": "Standard recursive extraction with LLM optimization",
                "tree_structure": "Use a flat structure with unique IDs",
                "naming_convention": "Use short, descriptive names with method and ID",
                "initial_methods": ["binwalk", "strings", "exiftool"],
                "max_depth": 5
            }

        except Exception as e:
            logger.error(f"Failed to consult LLM for extraction strategy: {e}")
            # Return default strategy
            return {
                "strategy": "Standard recursive extraction with LLM optimization",
                "tree_structure": "Use a flat structure with unique IDs",
                "naming_convention": "Use short, descriptive names with method and ID",
                "initial_methods": ["binwalk", "strings", "exiftool"],
                "max_depth": 5
            }

    def run(self):
        """Run the LLM orchestrated recursive extraction"""
        logger.info("Starting LLM orchestrated recursive extraction")

        # Verify the image exists
        if not os.path.exists(IMAGE_PATH):
            logger.error(f"Image file not found at {IMAGE_PATH}")
            return

        # Initialize from resume state if needed
        if self.resume and 'processed_files' in self.extraction_state:
            self.processed_files = set(self.extraction_state.get('processed_files', []))
            logger.info(f"Resuming extraction with {len(self.processed_files)} previously processed files")

        # Consult LLM for initial extraction strategy
        extraction_strategy = self.consult_llm_for_extraction_strategy(IMAGE_PATH)
        logger.info(f"LLM recommended strategy: {extraction_strategy.get('strategy')}")
        logger.info(f"LLM recommended tree structure: {extraction_strategy.get('tree_structure')}")
        logger.info(f"LLM recommended naming convention: {extraction_strategy.get('naming_convention')}")

        # Update MAX_DEPTH if recommended by LLM
        global MAX_DEPTH
        if 'max_depth' in extraction_strategy and isinstance(extraction_strategy['max_depth'], int):
            MAX_DEPTH = extraction_strategy['max_depth']
            logger.info(f"Setting maximum recursion depth to {MAX_DEPTH} as recommended by LLM")

        # Process the initial file
        root_file_record = self.process_file(IMAGE_PATH, OUTPUT_DIR, 0, extraction_strategy)

        if root_file_record:
            # Create root node in graph
            self.create_file_node(root_file_record, node_type='root', graph_level=0)
            logger.info(f"Created root node for {root_file_record.filename}")

        logger.info("LLM orchestrated recursive extraction completed")

        # Print summary
        self.print_summary()

    def process_file(self, file_path: str, output_dir: str, depth: int, extraction_strategy: Dict[str, Any] = None) -> Optional[AnalysisFile]:
        """Process a file with LLM orchestration and recursive extraction"""
        if depth > MAX_DEPTH:
            logger.warning(f"Maximum recursion depth reached for {file_path}")
            return None

        # Calculate file hash
        file_hash = self.calculate_file_hash(file_path)

        # Skip if already processed
        if file_hash in self.processed_files:
            logger.info(f"Skipping already processed file: {os.path.basename(file_path)}")
            return self.db_file_records.get(file_hash)

        # Get or create file record
        file_record = self.get_or_create_file_record(file_path)

        # Mark as processed
        self.processed_files.add(file_hash)

        # Save state periodically
        if len(self.processed_files) % 5 == 0:
            self._save_extraction_state()

        # Create file-specific output directory based on LLM recommendations
        if extraction_strategy and 'tree_structure' in extraction_strategy:
            # Use LLM recommended tree structure
            if 'flat' in extraction_strategy['tree_structure'].lower():
                # Flat structure with just ID
                file_output_dir = os.path.join(output_dir, f"{file_record.id}")
            elif 'hierarchical' in extraction_strategy['tree_structure'].lower():
                # Hierarchical structure with depth
                file_output_dir = os.path.join(output_dir, f"depth_{depth}", f"{file_record.id}")
            else:
                # Default to a clean structure with just ID and short name
                basename = os.path.basename(file_path)
                short_name = basename[:20] if len(basename) > 20 else basename
                file_output_dir = os.path.join(output_dir, f"{file_record.id}_{short_name}")
        else:
            # Default to a clean structure with just ID and short name
            basename = os.path.basename(file_path)
            short_name = basename[:20] if len(basename) > 20 else basename
            file_output_dir = os.path.join(output_dir, f"{file_record.id}_{short_name}")

        os.makedirs(file_output_dir, exist_ok=True)

        logger.info(f"Processing file: {os.path.basename(file_path)} (depth: {depth})")

        # Use LLM to analyze file and determine extraction strategies
        if depth == 0 and extraction_strategy and 'initial_methods' in extraction_strategy:
            # Use LLM recommended initial methods for the root file
            extraction_methods = extraction_strategy['initial_methods']
            logger.info(f"Using LLM recommended initial methods: {extraction_methods}")
        else:
            # For non-root files or if no recommendations, determine methods as usual
            extraction_methods = self.determine_extraction_methods(file_record, file_path)

        # Apply each extraction method with LLM optimization
        for method in extraction_methods:
            extracted_files = self.extract_with_method(file_record, file_path, method, file_output_dir, depth, extraction_strategy)

            # Process each extracted file recursively
            for extracted_file in extracted_files:
                child_record = self.process_file(extracted_file, output_dir, depth + 1, extraction_strategy)

                if child_record and file_record:
                    # Create relationship between files
                    self.create_file_relationship(file_record, child_record, method)

        # Mark file as analyzed
        if file_record and self.db_available:
            file_record.status = FileStatus.ANALYZED
            file_record.analyzed_at = datetime.utcnow()
            db.session.commit()
        elif file_record:
            # For mock file records when database is not available
            if hasattr(file_record, 'status'):
                file_record.status = "ANALYZED"  # Use string instead of enum
            if hasattr(file_record, 'analyzed_at'):
                file_record.analyzed_at = datetime.utcnow()

        return file_record

    def determine_extraction_methods(self, file_record: AnalysisFile, file_path: str) -> List[str]:
        """Use LLM to determine appropriate extraction methods for the file"""
        # Default extraction methods based on file type
        default_methods = []

        # Read file preview for LLM analysis
        try:
            with open(file_path, 'rb') as f:
                content = f.read(8192)  # Read first 8KB for LLM analysis
                content_preview = content.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Failed to read file content: {e}")
            content_preview = ""

        # Get file type
        file_type = file_record.file_type.lower() if file_record.file_type else ""

        # Add default methods based on file type
        if "png" in file_type:
            default_methods.extend(["zsteg", "binwalk", "strings", "exiftool"])
        elif "jpeg" in file_type or "jpg" in file_type:
            default_methods.extend(["steghide", "binwalk", "strings", "exiftool"])
        elif "text" in file_type or "ascii" in file_type:
            default_methods.extend(["base64", "hex", "strings"])
        elif "zip" in file_type or "archive" in file_type:
            default_methods.extend(["unzip", "binwalk"])
        else:
            default_methods.extend(["binwalk", "strings", "hexdump"])

        # Use LLM to enhance extraction methods if content is available
        if content_preview:
            try:
                # Get existing analysis if available
                existing_content = FileContent.query.filter_by(
                    file_id=file_record.id,
                    content_type='crypto_background_complete'
                ).first()

                existing_analysis = {}
                if existing_content:
                    try:
                        existing_analysis = json.loads(existing_content.content_text or '{}')
                    except:
                        pass

                # Use LLM to analyze and suggest extraction methods
                llm_results = self.llm_orchestrator.analyze_file_with_llm(
                    file_record.id,
                    content_preview,
                    existing_analysis
                )

                # Store LLM analysis results
                self.store_llm_results(file_record.id, llm_results)

                # Extract recommended methods from LLM results
                llm_methods = []
                for result in llm_results.get('analysis_results', []):
                    for rec in result.get('recommendations', []):
                        # Extract method names from recommendations
                        rec_lower = rec.lower()
                        for method in ["zsteg", "binwalk", "strings", "exiftool", "steghide", 
                                      "base64", "hex", "xor", "aes", "unzip", "hexdump"]:
                            if method in rec_lower and method not in llm_methods:
                                llm_methods.append(method)

                # Combine default and LLM-suggested methods, prioritizing LLM suggestions
                methods = llm_methods + [m for m in default_methods if m not in llm_methods]

                logger.info(f"LLM suggested extraction methods: {llm_methods}")
                return methods

            except Exception as e:
                logger.error(f"LLM analysis failed: {e}")

        logger.info(f"Using default extraction methods: {default_methods}")
        return default_methods

    def extract_with_method(self, file_record: AnalysisFile, file_path: str, 
                           method: str, output_dir: str, depth: int, extraction_strategy: Dict[str, Any] = None) -> List[str]:
        """Extract content using a specific method with LLM optimization"""
        logger.info(f"Extracting from {os.path.basename(file_path)} using {method}")

        extracted_files = []

        try:
            # Get the extractor
            extractor = get_extractor(method)
            if not extractor:
                logger.warning(f"Extractor not found for method: {method}")
                return extracted_files

            # Read file preview for LLM optimization
            try:
                with open(file_path, 'rb') as f:
                    content = f.read(8192)  # Read first 8KB for LLM analysis
                    content_preview = content.decode('utf-8', errors='ignore')
            except:
                content_preview = ""

            # Default parameters
            parameters = {}

            # Use LLM to optimize extraction parameters
            if content_preview:
                try:
                    # LLM-optimized extraction
                    llm_result = self.llm_orchestrator.extract_with_llm(
                        file_record.id,
                        content_preview,
                        method,
                        parameters
                    )

                    # Use optimized parameters if available
                    if llm_result.get('success') and llm_result.get('optimized_parameters'):
                        parameters = llm_result.get('optimized_parameters', {})
                        logger.info(f"Using LLM-optimized parameters for {method}: {parameters}")
                except Exception as e:
                    logger.error(f"LLM parameter optimization failed: {e}")

            # Perform extraction
            result = extractor.extract(file_path, parameters)

            if result.get('success'):
                # Handle extracted data
                if result.get('data'):
                    # Create output file with naming convention based on LLM recommendations
                    if extraction_strategy and 'naming_convention' in extraction_strategy:
                        naming_convention = extraction_strategy['naming_convention'].lower()

                        # Generate a short timestamp (last 6 digits)
                        short_timestamp = datetime.now().strftime("%H%M%S")

                        # Get a short version of the original filename
                        basename = os.path.basename(file_path)
                        short_name = basename[:10] if len(basename) > 10 else basename

                        # Apply naming convention based on LLM recommendation
                        if 'short' in naming_convention:
                            # Very short names with just essential info
                            output_filename = f"{method[:3]}_{short_timestamp}.bin"
                        elif 'descriptive' in naming_convention:
                            # More descriptive but still concise
                            output_filename = f"{method}_{file_record.id}_{short_timestamp}.bin"
                        elif 'hierarchical' in naming_convention:
                            # Include depth information
                            output_filename = f"d{depth}_{method}_{file_record.id}.bin"
                        else:
                            # Default to a balanced approach
                            output_filename = f"{method}_{file_record.id}_{short_name[:10]}.bin"
                    else:
                        # Default naming convention (shorter than original)
                        short_timestamp = datetime.now().strftime("%H%M%S")
                        basename = os.path.basename(file_path)
                        short_name = basename[:10] if len(basename) > 10 else basename
                        output_filename = f"{method}_{file_record.id}_{short_timestamp}.bin"

                    output_path = os.path.join(output_dir, output_filename)

                    with open(output_path, 'wb') as f:
                        f.write(result['data'])

                    logger.info(f"Extracted data saved to {output_path}")
                    extracted_files.append(output_path)

                    # Create extraction relationship
                    self.create_extraction_relationship(
                        file_record,
                        output_path,
                        method,
                        result.get('command_line', ''),
                        depth
                    )

                # Handle extracted files (if extractor returns file paths)
                if result.get('extracted_files'):
                    for ext_file in result.get('extracted_files', []):
                        if os.path.exists(ext_file):
                            logger.info(f"Found extracted file: {ext_file}")
                            extracted_files.append(ext_file)

                            # Create extraction relationship
                            self.create_extraction_relationship(
                                file_record,
                                ext_file,
                                method,
                                result.get('command_line', ''),
                                depth
                            )
            else:
                logger.warning(f"Extraction failed with {method}: {result.get('error', 'Unknown error')}")

        except Exception as e:
            logger.error(f"Error during extraction with {method}: {e}")

        return extracted_files

    def create_extraction_relationship(self, source_file: AnalysisFile, 
                                      extracted_path: str, method: str, 
                                      command: str, depth: int):
        """Create extraction relationship in database"""
        # Get or create file record for extracted file
        extracted_file = self.get_or_create_file_record(extracted_path)

        if not extracted_file:
            logger.error(f"Failed to create file record for {extracted_path}")
            return

        # Skip database operations if database is not available
        if not self.db_available:
            logger.info(f"Skipping database operation (create_extraction_relationship): {source_file.filename} -> {extracted_file.filename}")
            return

        try:
            # Create relationship
            relationship = ExtractionRelationship(
                source_file_id=source_file.id,
                source_file_sha=source_file.sha256_hash,
                extracted_file_id=extracted_file.id,
                extracted_file_sha=extracted_file.sha256_hash,
                extraction_method=method,
                extraction_command=command,
                extraction_depth=depth,
                created_at=datetime.utcnow()
            )

            db.session.add(relationship)
            db.session.commit()

            # Create file nodes and edge for visualization
            source_node = self.create_file_node(source_file, 'source', depth)
            target_node = self.create_file_node(extracted_file, 'extracted', depth + 1)

            if source_node and target_node:
                self.create_graph_edge(source_node, target_node, method)

            # Create file derivation record
            derivation = FileDerivation(
                parent_sha=source_file.sha256_hash,
                child_sha=extracted_file.sha256_hash,
                operation=method,
                tool=method,
                parameters=command,
                confidence=1.0
            )

            db.session.add(derivation)
            db.session.commit()

            logger.info(f"Created extraction relationship: {source_file.filename} -> {extracted_file.filename} via {method}")

        except Exception as e:
            logger.error(f"Failed to create extraction relationship: {e}")
            if hasattr(db, 'session') and db.session:
                db.session.rollback()

    def create_file_node(self, file: AnalysisFile, node_type: str, graph_level: int) -> Optional[FileNode]:
        """Create or get file node for visualization"""
        # Skip database operations if database is not available
        if not self.db_available:
            # Create a mock node
            class MockNode:
                def __init__(self, **kwargs):
                    for key, value in kwargs.items():
                        setattr(self, key, value)

            # Create a mock node with a unique ID
            mock_id = hash(f"{file.sha256_hash}_{node_type}_{graph_level}") % 10000
            node = MockNode(
                id=mock_id,
                file_id=file.id,
                file_sha=file.sha256_hash,
                node_type=node_type,
                graph_level=graph_level,
                node_color='#ff0000' if node_type == 'root' else '#0000ff',
                node_size=15 if node_type == 'root' else 10,
                extra_data={'extraction_depth': graph_level}
            )

            logger.info(f"Created mock file node for {file.filename} (no database)")
            return node

        try:
            # Check if node already exists
            node = FileNode.query.filter_by(file_sha=file.sha256_hash).first()

            if not node:
                # Create new node
                node = FileNode(
                    file_id=file.id,
                    file_sha=file.sha256_hash,
                    node_type=node_type,
                    graph_level=graph_level,
                    node_color='#ff0000' if node_type == 'root' else '#0000ff',
                    node_size=15 if node_type == 'root' else 10,
                    extra_data={'extraction_depth': graph_level}
                )

                db.session.add(node)
                db.session.commit()

            return node

        except Exception as e:
            logger.error(f"Failed to create file node: {e}")
            if hasattr(db, 'session') and db.session:
                db.session.rollback()
            return None

    def create_graph_edge(self, source_node: FileNode, target_node: FileNode, edge_type: str) -> Optional[GraphEdge]:
        """Create graph edge between nodes"""
        # Skip database operations if database is not available
        if not self.db_available:
            # Create a mock edge
            class MockEdge:
                def __init__(self, **kwargs):
                    for key, value in kwargs.items():
                        setattr(self, key, value)

            # Create a mock edge with a unique ID
            mock_id = hash(f"{source_node.id}_{target_node.id}_{edge_type}") % 10000
            edge = MockEdge(
                id=mock_id,
                source_node_id=source_node.id,
                target_node_id=target_node.id,
                edge_type=f"extracted_via_{edge_type}",
                weight=1.0,
                edge_color='#00ff00',
                extra_data={'extraction_method': edge_type}
            )

            logger.info(f"Created mock graph edge (no database)")
            return edge

        try:
            # Check if edge already exists
            edge = GraphEdge.query.filter_by(
                source_node_id=source_node.id,
                target_node_id=target_node.id
            ).first()

            if not edge:
                # Create new edge
                edge = GraphEdge(
                    source_node_id=source_node.id,
                    target_node_id=target_node.id,
                    edge_type=f"extracted_via_{edge_type}",
                    weight=1.0,
                    edge_color='#00ff00',
                    extra_data={'extraction_method': edge_type}
                )

                db.session.add(edge)
                db.session.commit()

            return edge

        except Exception as e:
            logger.error(f"Failed to create graph edge: {e}")
            if hasattr(db, 'session') and db.session:
                db.session.rollback()
            return None

    def create_file_relationship(self, parent: AnalysisFile, child: AnalysisFile, method: str):
        """Create relationship between parent and child files"""
        # Skip database operations if database is not available
        if not self.db_available:
            logger.info(f"Skipping database operation (create_file_relationship): {parent.filename} -> {child.filename}")
            return

        try:
            # Create extraction relationship
            relationship = ExtractionRelationship(
                source_file_id=parent.id,
                source_file_sha=parent.sha256_hash,
                extracted_file_id=child.id,
                extracted_file_sha=child.sha256_hash,
                extraction_method=method,
                created_at=datetime.utcnow()
            )

            db.session.add(relationship)
            db.session.commit()

            logger.info(f"Created file relationship: {parent.filename} -> {child.filename}")

        except Exception as e:
            logger.error(f"Failed to create file relationship: {e}")
            if hasattr(db, 'session') and db.session:
                db.session.rollback()

    def get_or_create_file_record(self, file_path: str) -> Optional[AnalysisFile]:
        """Get or create a file record in the database"""
        # Calculate file hash
        file_hash = self.calculate_file_hash(file_path)

        # Check if we already have this file in our cache
        if file_hash in self.db_file_records:
            return self.db_file_records[file_hash]

        # If database is not available, create a mock file record
        if not self.db_available:
            # Create a mock file record with basic information
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)
            file_type = self.identify_file_type(file_path)

            # Create a simple class to mimic AnalysisFile
            class MockFileRecord:
                def __init__(self, **kwargs):
                    for key, value in kwargs.items():
                        setattr(self, key, value)

            # Create a mock file record with a unique ID
            mock_id = len(self.db_file_records) + 1
            file_record = MockFileRecord(
                id=mock_id,
                filename=filename,
                filepath=file_path,
                file_size=file_size,
                file_type=file_type,
                mime_type=file_type,
                sha256_hash=file_hash,
                status="PROCESSING",
                is_root_file=(file_path == IMAGE_PATH),
                created_at=datetime.utcnow()
            )

            logger.info(f"Created mock file record for {filename} with ID {mock_id} (no database)")
            self.db_file_records[file_hash] = file_record
            return file_record

        # If database is available, use it
        try:
            # Check if file exists in database
            file_record = AnalysisFile.query.filter_by(sha256_hash=file_hash).first()

            if not file_record:
                # Create new file record
                file_size = os.path.getsize(file_path)
                filename = os.path.basename(file_path)
                file_type = self.identify_file_type(file_path)

                file_record = AnalysisFile(
                    filename=filename,
                    filepath=file_path,
                    file_size=file_size,
                    file_type=file_type,
                    mime_type=file_type,
                    sha256_hash=file_hash,
                    status=FileStatus.PROCESSING,
                    is_root_file=(file_path == IMAGE_PATH),
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow()
                )
                db.session.add(file_record)
                db.session.commit()
                logger.info(f"Created new file record for {filename} with ID {file_record.id}")
            else:
                logger.info(f"Found existing file record for {os.path.basename(file_path)} with ID {file_record.id}")

            # Cache the file record
            self.db_file_records[file_hash] = file_record

            return file_record

        except Exception as e:
            logger.error(f"Failed to get or create file record: {e}")
            if hasattr(db, 'session') and db.session:
                db.session.rollback()
            return None

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()

        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()

    def identify_file_type(self, file_path: str) -> str:
        """Identify file type using magic"""
        try:
            import magic
            mime = magic.Magic(mime=True)
            return mime.from_file(file_path)
        except:
            # Fallback to extension-based identification
            ext = os.path.splitext(file_path)[1].lower()
            if ext == '.png':
                return 'image/png'
            elif ext in ['.jpg', '.jpeg']:
                return 'image/jpeg'
            elif ext == '.txt':
                return 'text/plain'
            elif ext == '.zip':
                return 'application/zip'
            else:
                return 'application/octet-stream'

    def store_llm_results(self, file_id: int, results: Dict):
        """Store LLM analysis results"""
        # Skip database operations if database is not available
        if not self.db_available:
            logger.info(f"Skipping database operation (store_llm_results) for file_id: {file_id}")
            return True

        try:
            content = FileContent(
                file_id=file_id,
                content_type='llm_analysis_complete',
                content_text=json.dumps(results, indent=2),
                content_size=len(json.dumps(results)),
                created_at=datetime.utcnow()
            )
            db.session.add(content)
            db.session.commit()
            logger.info(f"Stored LLM results for file_id: {file_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to store LLM results: {e}")
            if hasattr(db, 'session') and db.session:
                db.session.rollback()
            return False

    def print_summary(self):
        """Print summary of extraction results"""
        try:
            total_files = len(self.processed_files)

            logger.info("=" * 50)
            logger.info("LLM ORCHESTRATED RECURSIVE EXTRACTION SUMMARY")
            logger.info("=" * 50)
            logger.info(f"Total files processed: {total_files}")

            # If database is available, get additional statistics
            if self.db_available:
                try:
                    total_relationships = db.session.query(ExtractionRelationship).count()
                    total_nodes = db.session.query(FileNode).count()
                    total_edges = db.session.query(GraphEdge).count()

                    logger.info(f"Total extraction relationships: {total_relationships}")
                    logger.info(f"Total graph nodes: {total_nodes}")
                    logger.info(f"Total graph edges: {total_edges}")
                except Exception as e:
                    logger.error(f"Failed to get database statistics: {e}")
            else:
                logger.info("Database not available - no additional statistics")

            logger.info("=" * 50)

        except Exception as e:
            logger.error(f"Failed to print summary: {e}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='LLM Orchestrated Recursive Extraction')
    parser.add_argument('--resume', action='store_true', help='Resume from previous state')
    args = parser.parse_args()

    # Run the extractor
    extractor = LLMRecursiveExtractor(resume=args.resume)
    extractor.run()

if __name__ == "__main__":
    main()
