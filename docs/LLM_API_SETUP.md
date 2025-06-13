# LLM API Keys Setup Guide

This guide explains how to set up the API keys required for the LLM (Large Language Model) orchestrated extraction functionality in the Crypto Hunter project.

## Required API Keys

The LLM orchestrator uses two AI providers:

1. **OpenAI** (GPT-4 and GPT-3.5)
2. **Anthropic** (Claude and Claude Sonnet)

You need to obtain API keys from at least one of these providers to use the LLM orchestration functionality.

## Setting Up API Keys

### Step 1: Obtain API Keys

#### OpenAI API Key
1. Go to [OpenAI's platform](https://platform.openai.com/)
2. Sign up or log in to your account
3. Navigate to the API section
4. Create a new API key
5. Copy the API key (it starts with "sk-")

#### Anthropic API Key
1. Go to [Anthropic's console](https://console.anthropic.com/)
2. Sign up or log in to your account
3. Navigate to the API keys section
4. Create a new API key
5. Copy the API key

### Step 2: Configure API Keys in the Project

There are two ways to set up the API keys:

#### Option 1: Using the .env File (Recommended for Development)

1. Open the `.env` file in the project root
2. Replace the placeholder values with your actual API keys:
   ```
   OPENAI_API_KEY=your_actual_openai_api_key
   ANTHROPIC_API_KEY=your_actual_anthropic_api_key
   ```

#### Option 2: Setting Environment Variables Directly

For production environments, you can set the environment variables directly:

```bash
export OPENAI_API_KEY=your_actual_openai_api_key
export ANTHROPIC_API_KEY=your_actual_anthropic_api_key
```

Or add them to your system's environment configuration.

### Step 3: Configure Budget Controls (Optional)

You can also configure budget controls to limit API usage costs:

```
LLM_DAILY_BUDGET=100.0  # Maximum daily spending in USD
LLM_HOURLY_BUDGET=20.0  # Maximum hourly spending in USD
```

## Verifying API Key Setup

To verify that your API keys are properly configured:

1. Set `USE_LLM_ORCHESTRATOR=true` in your `.env` file
2. Run the LLM extraction script:
   ```bash
   ./run_llm_extraction.py
   ```
3. Check the logs for any API key errors

If the extraction runs without API key errors, your setup is correct.

## Troubleshooting

If you encounter API key errors:

1. Verify that the API keys are correctly copied without any extra spaces
2. Ensure the environment variables are properly set and accessible to the application
3. Check that your API keys have not expired or been revoked
4. Verify that your API keys have sufficient permissions and quota

For OpenAI-specific issues, check your usage and billing status on the OpenAI platform.
For Anthropic-specific issues, check your usage and billing status on the Anthropic console.