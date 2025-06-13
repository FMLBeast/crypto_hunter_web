"""
Base extractor interface for steganography tools
"""

from abc import ABC, abstractmethod
import os
import subprocess
import tempfile

class BaseExtractor(ABC):
    """Base class for all steganography extractors"""

    def __init__(self, method_name):
        self.method_name = method_name
        self.tool_name = self._get_tool_name()

    @abstractmethod
    def _get_tool_name(self):
        """Return the name of the underlying tool"""
        pass

    @abstractmethod
    def extract(self, file_path, parameters=None):
        """
        Extract hidden data from file

        Args:
            file_path: Path to the file to analyze
            parameters: Dictionary of extraction parameters

        Returns:
            Dictionary with:
            - success: Boolean indicating if extraction succeeded
            - data: Extracted binary data (if successful)
            - error: Error message (if failed)
            - details: Additional details about the extraction
            - command_line: Command that was executed
            - confidence: Confidence level (1-10)
        """
        pass

    def _run_command(self, command, input_data=None, timeout=None):
        """
        Run external command and capture output

        Args:
            command: List of command arguments
            input_data: Optional input data to pipe to command
            timeout: Command timeout in seconds (None for no timeout)

        Returns:
            Dictionary with stdout, stderr, returncode
        """
        try:
            process = subprocess.run(
                command,
                input=input_data,
                capture_output=True,
                timeout=timeout,
                text=False  # Handle binary data
            )

            return {
                'stdout': process.stdout,
                'stderr': process.stderr,
                'returncode': process.returncode,
                'command_line': ' '.join(command)
            }

        except subprocess.TimeoutExpired:
            return {
                'stdout': b'',
                'stderr': b'Command timed out',
                'returncode': -1,
                'command_line': ' '.join(command)
            }
        except FileNotFoundError:
            return {
                'stdout': b'',
                'stderr': f'Command not found: {command[0]}'.encode(),
                'returncode': -1,
                'command_line': ' '.join(command)
            }
        except Exception as e:
            return {
                'stdout': b'',
                'stderr': str(e).encode(),
                'returncode': -1,
                'command_line': ' '.join(command)
            }

    def _create_temp_file(self, data, suffix=''):
        """Create temporary file with data"""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        temp_file.write(data)
        temp_file.close()
        return temp_file.name

    def _cleanup_temp_file(self, file_path):
        """Clean up temporary file"""
        try:
            os.unlink(file_path)
        except:
            pass

    def is_available(self):
        """Check if the extractor tool is available on the system"""
        try:
            result = self._run_command([self.tool_name, '--version'], timeout=None)
            return result['returncode'] == 0
        except:
            return False
