#!/usr/bin/env python3
"""
Example script showing how to use the new AI extraction system
"""
import asyncio
import sys
from ai_orchestrated_extraction import AIOrchestrator

async def main():
    if len(sys.argv) != 2:
        print("Usage: python run_ai_extraction_example.py <input_file>")
        return 1
    
    input_file = sys.argv[1]
    
    # Initialize AI orchestrator
    orchestrator = AIOrchestrator(output_dir="./ai_results")
    
    # Run comprehensive analysis
    try:
        print(f"🚀 Starting AI analysis of {input_file}...")
        result = await orchestrator.extract_and_analyze(input_file, analysis_mode="comprehensive")
        
        print(f"✅ Analysis completed!")
        print(f"📁 Results in: {result['output_directory']}")
        print(f"🔍 Key findings: {len(result.get('intelligence_synthesis', {}).get('key_findings', []))}")
        
        return 0
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
