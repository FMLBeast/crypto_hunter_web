# OpenAI Version Compatibility

This document explains the changes made to ensure compatibility with different versions of the OpenAI Python library.

## Issue

The LLM extraction script was failing with the following error:

```
AttributeError: module 'openai' has no attribute 'OpenAI'
```

This error occurred because the code was using the newer OpenAI client initialization method (`openai.OpenAI()`) but an older version of the OpenAI library (0.28.1) was installed.

## Solution

The code has been modified to handle both versions of the OpenAI library:

1. **Version Detection**: The code now tries to initialize the client using the new method first, and falls back to the old method if that fails.

2. **API Call Adaptation**: The `_call_openai` method has been updated to use the appropriate API call based on which version of the library is being used.

3. **Error Handling**: Added robust error handling for both OpenAI and Anthropic client initialization.

4. **Strategy Generation**: Updated the strategy generation to avoid using providers that aren't available.

## Implementation Details

### Client Initialization

```python
# Initialize OpenAI client - handle both new and old API versions
try:
    # Try to use the new OpenAI client (v1.0.0+)
    self.openai_client = openai.OpenAI()
    self.using_openai_v1 = True
except (AttributeError, TypeError):
    # Fall back to the old API (pre-v1.0.0)
    # Make sure API key is set
    if not openai.api_key and os.environ.get("OPENAI_API_KEY"):
        openai.api_key = os.environ.get("OPENAI_API_KEY")
    self.openai_client = openai
    self.using_openai_v1 = False
```

### API Call Adaptation

```python
if self.using_openai_v1:
    # New OpenAI API (v1.0.0+)
    response = self.openai_client.chat.completions.create(...)
    usage = response.usage
    content = response.choices[0].message.content
else:
    # Old OpenAI API (pre-v1.0.0)
    response = self.openai_client.ChatCompletion.create(...)
    usage = response['usage']
    content = response['choices'][0]['message']['content']
```

## Anthropic Compatibility

Similar changes were made to handle potential issues with the Anthropic client:

1. **Initialization with Error Handling**: The Anthropic client initialization is now wrapped in a try-except block.

2. **Availability Flag**: A flag `anthropic_available` is set to track whether the Anthropic client is available.

3. **Strategy Filtering**: The strategy generation now checks if Anthropic is available before generating strategies that use it.

4. **Method Guards**: The `_call_anthropic` method now checks if the Anthropic client is available before trying to use it.

## Testing

The changes have been tested with:

1. A simple test script that initializes the OpenAI client directly
2. A test script that initializes the LLMCryptoOrchestrator class
3. A test script that initializes the full LLMRecursiveExtractor class

All tests confirm that the code now works correctly with the installed version of the OpenAI library (0.28.1).

## Future Considerations

For future development, consider:

1. Updating to the latest version of the OpenAI library (v1.0.0+)
2. Adding version checks to the documentation
3. Adding a requirements.txt entry with a specific version constraint