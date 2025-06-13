# Puzzle Solving System Documentation

This document provides an overview of the puzzle solving system in the Crypto Hunter project, including how to use it and how it integrates with the rest of the application.

## Overview

The puzzle solving system is designed to help users track their progress in solving cryptographic puzzles. It provides a structured way to document steps, findings, and regions of interest in files, making it easier to retrace the path to a solution and collaborate with others.

Key features include:

1. **Puzzle Sessions**: Create and manage puzzle solving sessions
2. **Steps Timeline**: Track the progression of steps taken to solve a puzzle
3. **Region Tagging**: Highlight and tag regions of interest in files
4. **Collaboration**: Work with others on solving puzzles
5. **Real-time Updates**: See changes made by collaborators instantly

## Components

The puzzle solving system consists of several components:

1. **Models**: Database models for puzzle sessions, steps, and relationships
2. **Routes**: Controllers for handling HTTP requests
3. **Templates**: User interface for interacting with puzzle sessions
4. **Services**: Business logic for analysis and extraction
5. **Tasks**: Background processing for long-running operations

## Database Models

### PuzzleSession

The main model representing a puzzle solving session:

- `name`: Name of the session
- `description`: Description of the puzzle and approach
- `owner_id`: User who created the session
- `is_public`: Whether the session is publicly visible
- `status`: Current status (active, paused, completed, archived)
- `tags`: Tags for categorizing the session

### PuzzleStep

Represents a step in the puzzle solving process:

- `session_id`: Session this step belongs to
- `title`: Title of the step
- `description`: Description of what was done in this step
- `is_active`: Whether this is the currently active step
- `created_by`: User who created the step
- `files`: Files associated with this step
- `findings`: Findings associated with this step
- `regions`: Regions of interest associated with this step

### PuzzleCollaborator

Represents a user collaborating on a puzzle session:

- `session_id`: Session they're collaborating on
- `user_id`: The collaborating user
- `role`: Their role (viewer, editor, admin)
- `is_online`: Whether they're currently online
- `last_active`: When they were last active

### Junction Models

- `PuzzleStepFile`: Links files to steps
- `PuzzleStepFinding`: Links findings to steps
- `PuzzleStepRegion`: Links regions of interest to steps

## Using the Puzzle Solving System

### Creating a Puzzle Session

1. Navigate to the Puzzles section in the main navigation
2. Click "New Session"
3. Fill in the session details:
   - Name
   - Description
   - Privacy setting (public or private)
   - Tags (optional)
4. Click "Create Session"

### Adding Steps

1. Open a puzzle session
2. Click "Add Step"
3. Enter the step title and description
4. Click "Add Step"

### Working with Files

1. Upload files through the main Files section
2. In your puzzle session, click "Upload File" or select a file from an existing step
3. The file will be added to the active step
4. You can view the file content, findings, and add regions of interest

### Tagging Regions of Interest

1. Open a file in your puzzle session
2. Select text in the file content
3. Click "Tag Region"
4. Fill in the region details:
   - Title
   - Description
   - Type (text, crypto, binary, etc.)
   - Color
5. Click "Tag Region"

### Collaborating with Others

1. Open a puzzle session
2. Click "Add Collaborator"
3. Enter the username of the person you want to collaborate with
4. Select their role (viewer, editor, admin)
5. Click "Add Collaborator"
6. Collaborators will see changes in real-time

## Integration with Other Systems

The puzzle solving system integrates with several other components of the Crypto Hunter application:

### File Analysis

Files added to puzzle steps are analyzed using the AnalysisService, which provides:

- Basic file analysis (metadata, content extraction)
- Cryptographic pattern detection
- Steganography and file carving

### Extraction System

The puzzle solving system uses the ExtractionService to extract hidden data from files:

- Steganography extraction (zsteg, steghide, etc.)
- File carving (binwalk, etc.)
- Custom extraction methods

### Caching

The system uses Redis for caching and real-time updates:

- Session data is cached for quick access
- Real-time updates are pushed to collaborators
- Analysis results are cached to avoid redundant processing

## Background Processing

Long-running operations are handled by Celery tasks:

- File analysis
- Crypto pattern detection
- Region tagging
- Batch operations

## API Endpoints

The puzzle solving system provides several API endpoints for programmatic access:

- `GET /api/puzzle/sessions`: List puzzle sessions
- `POST /api/puzzle/sessions`: Create a new session
- `GET /api/puzzle/sessions/<id>`: Get session details
- `POST /api/puzzle/sessions/<id>/steps`: Add a step to a session
- `POST /api/puzzle/sessions/<id>/collaborators`: Add a collaborator
- `POST /api/puzzle/sessions/<id>/regions`: Tag a region of interest

## Example Workflow

1. Create a new puzzle session for "Arweave Puzzle #11"
2. Upload initial files (images, text files, etc.)
3. Add a step "Initial Analysis" describing your first observations
4. Run analysis on the files to detect patterns
5. Tag interesting regions in the files
6. Add a step "Steganography Extraction" describing your findings
7. Extract hidden data from images
8. Add the extracted files to the step
9. Continue adding steps as you progress
10. Invite collaborators to help with specific aspects
11. Document the solution in the final step

## Best Practices

1. **Create clear steps**: Each step should represent a distinct phase or approach
2. **Document your reasoning**: Include your thought process in step descriptions
3. **Tag regions thoroughly**: Use descriptive titles and appropriate colors
4. **Organize files logically**: Group related files in the same step
5. **Use appropriate roles**: Assign viewer roles for observers, editor roles for active collaborators
6. **Update regularly**: Keep the session updated with your latest findings
7. **Use tags**: Tag sessions with relevant categories for easier searching

## Troubleshooting

### Common Issues

1. **Session not updating**: Try refreshing the page or check your internet connection
2. **File analysis failing**: Check the file format and size
3. **Region tagging not working**: Ensure you've selected text before clicking "Tag Region"
4. **Collaborator can't access**: Check their role and ensure the session is shared correctly

### Getting Help

If you encounter issues with the puzzle solving system, contact the system administrator or refer to the API documentation for more details.