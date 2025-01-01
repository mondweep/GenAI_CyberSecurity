# Challenge 4: Advanced NLP Security Analysis

## Overview
This challenge implements a past tense-based attack on AWS Bedrock LLMs to test their security responses. The system:
- Transforms security-related prompts from present to past tense
- Analyzes differences in LLM responses
- Evaluates potential security implications

## Architecture

### Components
1. **PastTenseAttackModel**
   - Core class for tense transformation and LLM interaction
   - Uses spaCy and NLTK for NLP processing
   - Implements custom verb dictionary for reliable transformations

2. **NLP Processing**
   - spaCy: Verb tense transformations and POS tagging
   - NLTK: Text tokenization and analysis
   - Custom verb dictionary for security-specific terms

3. **LLM Integration**
   - AWS Bedrock API integration
   - Response analysis and comparison
   - Timestamp tracking for response changes

### Data Flow
1. Input prompt processing
2. Present to past tense transformation
3. LLM query generation
4. Response analysis and comparison
5. Results logging and visualization

## Setup
1. Install dependencies:
```bash
pip install -r requirements.txt
python -m nltk.downloader punkt averaged_perceptron_tagger
```

2. Configure credentials:
   - Set up AWS Bedrock credentials
   - Create .env file with API keys

3. Run tests:
```bash
pytest tests/
```

4. Start analysis:
```bash
jupyter notebook notebooks/past_tense_attack.ipynb
```

## Implementation Details
- Uses custom verb dictionary for reliable transformations
- Implements detailed logging for debugging
- Provides DataFrame output for response analysis
- Tracks response length differences and timestamps

## Results Analysis
- Compares original vs modified prompt responses
- Analyzes length differences
- Evaluates security implications of tense changes
- Provides detailed response comparisons
