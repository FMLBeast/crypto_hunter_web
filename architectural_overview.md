# Crypto Hunter - Architectural Overview

## 1. System Architecture

### 1.1 High-Level Architecture

The Crypto Hunter system is a comprehensive platform for analyzing files for cryptographic puzzles and steganography challenges. It serves as a backbone tool for complex puzzle solving, where files are extracted from different sources and analyzed for hidden content, patterns, and cryptographic elements. The system consists of the following main components:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Crypto Hunter System                          │
│                                                                     │
│  ┌───────────┐    ┌───────────┐    ┌───────────┐    ┌───────────┐   │
│  │   Web     │    │   CLI     │    │  API      │    │ Background │   │
│  │ Interface │    │ Interface │    │ Endpoints │    │ Processing │   │
│  └─────┬─────┘    └─────┬─────┘    └─────┬─────┘    └─────┬─────┘   │
│        │                │                │                │         │
│        └────────────────┼────────────────┼────────────────┘         │
│                         │                │                          │
│                         ▼                ▼                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Core Services                             │   │
│  │                                                             │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐ │   │
│  │  │   File    │  │ Background │  │   Crypto  │  │    AI     │ │   │
│  │  │  Service  │  │  Service   │  │  Analyzer │  │  Service  │ │   │
│  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘ │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      Data Layer                              │   │
│  │                                                             │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐ │   │
│  │  │ Database  │  │   Redis   │  │ File      │  │ Vector    │ │   │
│  │  │  (SQL)    │  │  Cache    │  │ Storage   │  │ Storage   │ │   │
│  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘ │   │
│  │                                                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 Component Overview

1. **User Interfaces**:
   - Web Interface: Flask-based web application
   - CLI Interface: Command-line tools for administration
   - API Endpoints: REST API for programmatic access

2. **Core Services**:
   - File Service: File upload, storage, and management
   - Background Service: Task scheduling and monitoring
   - Crypto Analyzer: Cryptocurrency pattern detection and analysis
   - AI Service: AI-powered analysis and insights

3. **Data Layer**:
   - Database: SQL database (SQLite for development, PostgreSQL for production)
   - Redis: Caching and task queue management
   - File Storage: Physical storage of uploaded files
   - Vector Storage: Storage of vector embeddings for semantic search

## 2. Data Flow

### 2.1 File Analysis Flow

```
┌──────────┐     ┌───────────┐     ┌────────────────┐     ┌───────────┐
│  Upload  │     │  Initial  │     │  Background    │     │  Results  │
│   File   │────▶│  Analysis │────▶│  Processing    │────▶│  Storage  │
└──────────┘     └───────────┘     └────────────────┘     └───────────┘
                                           │                     │
                                           ▼                     ▼
                                    ┌────────────┐        ┌────────────┐
                                    │  Finding   │        │   User     │
                                    │ Generation │        │ Interface  │
                                    └────────────┘        └────────────┘
```

1. **File Upload**: Puzzle solver uploads a file through web interface or API
2. **Initial Analysis**: Basic file information is extracted (size, type, hashes)
3. **Background Processing**: File is queued for comprehensive analysis including steganography detection, cryptographic pattern analysis, and hidden data extraction
4. **Finding Generation**: Analysis results are processed to generate findings about hidden content, cryptographic patterns, and potential puzzle solutions
5. **Results Storage**: Results are stored in the database with cross-references to related files and findings
6. **User Interface**: Results are displayed to the puzzle solver with interactive tools for further investigation

### 2.2 Task Processing Flow

```
┌──────────┐     ┌───────────┐     ┌────────────────┐     ┌───────────┐
│  Queue   │     │  Task     │     │   Worker       │     │  Status   │
│   Task   │────▶│  Tracking │────▶│   Processing   │────▶│  Updates  │
└──────────┘     └───────────┘     └────────────────┘     └───────────┘
                                           │                     │
                                           ▼                     ▼
                                    ┌────────────┐        ┌────────────┐
                                    │  Result    │        │ Notification│
                                    │ Processing │        │    System   │
                                    └────────────┘        └────────────┘
```

1. **Queue Task**: Task is queued for processing
2. **Task Tracking**: Task is tracked in Redis
3. **Worker Processing**: Celery worker processes the task
4. **Status Updates**: Task status is updated in Redis
5. **Result Processing**: Task results are processed and stored
6. **Notification System**: User is notified of task completion

## 3. Core Services

### 3.1 File Service

Responsible for file upload, storage, and basic analysis.

**Key Components**:
- File upload handling
- File storage management
- File metadata extraction
- File type detection
- Hash calculation

### 3.2 Background Service

Manages background tasks and provides status tracking.

**Key Components**:
- Task queuing
- Task status tracking
- Task result storage
- System status monitoring
- Task cleanup

### 3.3 Crypto Analyzer

Analyzes files for cryptographic patterns, steganography, and hidden content.

**Key Components**:
- Pattern detection and analysis
- Steganography detection and extraction
- Cryptographic key identification
- Cipher detection and decryption
- Hidden data extraction and analysis
- Confidence scoring

### 3.4 AI Service

Provides AI-powered analysis and insights for puzzle solving.

**Key Components**:
- LLM integration for pattern recognition and insight generation
- Vector embedding generation for semantic relationships between files and findings
- Cross-linking of data across different puzzle elements
- AI-powered recommendations for next steps in puzzle solving
- Automated documentation of puzzle-solving progress
- Cost tracking for AI resource usage

## 4. Data Models

### 4.1 Core Models

- **User**: User accounts with authentication and profiles
- **AnalysisFile**: Files uploaded for analysis
- **FileContent**: Different types of content extracted from files
- **Finding**: Analysis findings with classification and validation
- **Vector**: Vector embeddings for semantic search

### 4.2 Relationship Models

- **ExtractionRelationship**: Relationships between files and extracted content
- **FileNode** and **GraphEdge**: Graph representation of files
- **RegionOfInterest**: Specific regions within file content
- **FileDerivation**: File derivation relationships
- **CombinationRelationship**: File combination relationships

## 5. Agent-Based Architecture

### 5.1 Overview

The Crypto Hunter system is evolving toward a more specialized agent-based architecture for comprehensive file analysis, steganography extraction, and cryptographic intelligence. This approach employs dedicated task agents that each focus on a specific aspect of the analysis pipeline, passing results to the next agent in the chain.

```
┌──────────────────┐
│                  │
│   Import Agent   │
│                  │
└────────┬─────────┘
         │
         │ File metadata, initial classification
         ▼
┌──────────────────┐
│                  │
│ Steganography    │
│     Agent        │◄───────────┐
│                  │            │
└────────┬─────────┘            │
         │                      │
         │ Extracted files      │ New files
         ▼                      │ for analysis
┌──────────────────┐            │
│                  │            │
│  File Analysis   │────────────┘
│     Agent        │◄───────────┐
│                  │            │
└────────┬─────────┘            │
         │                      │
         │ Analysis results     │ New strings
         ▼                      │ for analysis
┌──────────────────┐            │
│                  │            │
│ String Detection │────────────┘
│     Agent        │◄───────────┐
│                  │            │
└────────┬─────────┘            │
         │                      │
         │ Decoded strings      │ Crypto
         ▼                      │ patterns
┌──────────────────┐            │
│                  │            │
│  Cryptographic   │────────────┘
│ Intelligence Agent│◄──────────┐
│                  │            │
└────────┬─────────┘            │
         │                      │
         │ Crypto findings      │ Analysis
         ▼                      │ guidance
┌──────────────────┐            │
│                  │            │
│  LLM Orchestration─────────────┘
│     Agent        │
│                  │
└────────┬─────────┘
         │
         │ Comprehensive results
         ▼
┌──────────────────┐
│                  │
│  Summarization   │
│     Agent        │
│                  │
└────────┬─────────┘
         │
         │ Final report
         ▼
┌──────────────────┐
│                  │
│  Visualization   │
│     Layer        │
│                  │
└──────────────────┘
```

### 5.2 Agent Descriptions

1. **Import Agent**
   - Handles file ingestion, initial classification, and preparation
   - Validates and sanitizes input files
   - Calculates file hashes and checks for duplicates
   - Performs initial file type detection
   - Creates database records for tracking
   - Queues files for analysis

2. **Steganography Agent**
   - Specializes in extracting hidden data using various steganography techniques
   - Supports multiple extraction tools (zsteg, steghide, outguess, etc.)
   - Handles different file formats (images, audio, video)
   - Maintains extraction relationships and provenance
   - Passes extracted files back into the pipeline

3. **File Analysis Agent**
   - Performs deep analysis on files to identify patterns, structures, and anomalies
   - Identifies file structures and formats
   - Detects anomalies and suspicious patterns
   - Extracts metadata and embedded information
   - Generates analysis reports
   - Identifies regions of interest for further analysis

4. **String Detection Agent**
   - Extracts and analyzes strings, applying various decoding/decryption techniques
   - Identifies encoded strings (base64, hex, etc.)
   - Applies various decoders and converters
   - Detects natural language patterns
   - Identifies potential passwords, keys, or other sensitive information
   - Passes decoded strings to other agents for further analysis

5. **Cryptographic Intelligence Agent**
   - Identifies and analyzes cryptographic artifacts and patterns
   - Detects encryption algorithms and techniques
   - Identifies key material and cryptographic artifacts
   - Analyzes entropy and randomness patterns
   - Suggests decryption approaches
   - Provides cryptographic context for findings

6. **LLM Orchestration Agent**
   - Uses AI to guide the analysis process and make intelligent decisions
   - Analyzes file content to determine optimal extraction strategies
   - Identifies potential cryptographic patterns
   - Suggests next steps in the analysis pipeline
   - Provides natural language explanations of findings
   - Coordinates the overall analysis strategy

7. **Summarization Agent**
   - Collects results from other agents and provides comprehensive summaries
   - Aggregates findings from all agents
   - Identifies relationships between findings
   - Generates comprehensive reports
   - Suggests next steps for human analysts
   - Maintains the knowledge graph of all findings

### 5.3 Agent Communication

Agents communicate through a combination of:

1. **Database Records**: Structured data stored in the PostgreSQL database
2. **Task Queue**: Celery tasks for asynchronous processing
3. **File System**: Shared access to extracted files and artifacts
4. **Event System**: Publish-subscribe pattern for real-time notifications
5. **Direct API Calls**: Synchronous communication between agents

### 5.4 Integration with Existing Architecture

The agent-based architecture integrates with the existing system as follows:

1. **Core Services**: Each agent leverages the existing core services (File Service, Background Service, etc.)
2. **Data Layer**: All agents share the same data layer (Database, Redis, File Storage)
3. **User Interfaces**: Results from all agents are accessible through the existing interfaces
4. **Task Processing**: Agents use the existing task processing infrastructure

## 6. Potential Refactoring Opportunities

### 6.1 Code Organization

1. **Service Consolidation**: Some services have overlapping functionality that could be consolidated:
   - Background service and background crypto manager could be merged
   - File analyzer and crypto analyzer have similar pattern detection logic

2. **Error Handling**: Implement more consistent error handling across services

3. **Configuration Management**: Centralize configuration management

### 6.2 Performance Improvements

1. **Caching Strategy**: Implement more comprehensive caching for analysis results

2. **Task Prioritization**: Enhance task prioritization system for better resource allocation

3. **Batch Processing**: Implement batch processing for large file sets

### 6.3 Architectural Improvements

1. **Microservices Approach**: Consider splitting some services into microservices for better scalability

2. **Event-Driven Architecture**: Implement event-driven architecture for better decoupling

3. **API Versioning**: Implement API versioning for better backward compatibility

## 7. End-to-End Testing Recommendations

### 7.1 Test Scenarios

1. **Puzzle File Upload and Analysis**:
   - Upload various file types (text, binary, images, audio, archives)
   - Verify steganography detection and extraction
   - Check cryptographic pattern analysis
   - Test hidden data extraction
   - Verify cross-referencing between related files and findings

2. **Puzzle Session Management**:
   - Create and manage puzzle sessions
   - Document findings and progress
   - Collaborate with other puzzle solvers
   - Track puzzle-solving progress

3. **Advanced Analysis Features**:
   - Test steganography tools integration
   - Verify cryptographic analysis tools
   - Check file carving and metadata extraction
   - Test LLM-powered insight generation

4. **Background Processing**:
   - Task queuing and execution
   - Continuous monitoring of files for new patterns
   - Automated cross-referencing of findings
   - Task result retrieval and visualization

### 7.2 Testing Approach

1. **Manual Testing Checklist**:
   - Puzzle solver interface functionality
   - File upload and steganography analysis workflow
   - Cryptographic pattern detection and decryption
   - Hidden data extraction and visualization
   - Cross-referencing of findings across files
   - Puzzle session management and collaboration
   - LLM-powered insight generation and documentation

2. **Automated Testing**:
   - Unit tests for core cryptographic and steganography services
   - Integration tests for file extraction and analysis pipelines
   - Validation tests for pattern detection accuracy
   - Performance tests for large puzzle datasets
   - Regression tests for puzzle-solving workflows

### 7.3 Testing Environment

1. **Local Development Environment**:
   - SQLite database
   - Local Redis instance
   - Local file storage

2. **Staging Environment**:
   - PostgreSQL database
   - Redis instance
   - S3-compatible storage
   - Celery workers

## 8. Conclusion

The Crypto Hunter system is a comprehensive platform for analyzing files for cryptographic puzzles and steganography challenges. It serves as a backbone tool for puzzle solvers to document findings, extract hidden content, and analyze complex patterns. The system has a well-structured architecture with clear separation of concerns between different components. There are some opportunities for refactoring to improve code organization, performance, and architecture. The recommended end-to-end testing approach will help ensure the system functions correctly and meets user requirements.
