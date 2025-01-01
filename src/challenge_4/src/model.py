import google.generativeai as genai
import spacy
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from datetime import datetime
import json
from pyinflect import getInflection
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class PastTenseAttackModel:
    def __init__(self, api_key):
        # Configure Gemini
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-pro')
        
        # Load NLP tools for tense transformation
        self.nlp = spacy.load('en_core_web_sm')
        
    def get_llm_response(self, prompt):
        """Get response from Gemini"""
        response = self.model.generate_content(prompt)
        return response.text
    
    def transform_to_past_tense(self, text):
        """Convert text from present to past tense"""
        # Dictionary of common verbs and their past tense forms
        verb_dict = {
            'controls': 'controlled',
            'control': 'controlled',
            'monitors': 'monitored',
            'monitor': 'monitored',
            'access': 'accessed',
            'accesses': 'accessed'
        }
        
        doc = self.nlp(text)
        logger.debug(f"Processing text: {text}")
        logger.debug("Token analysis:")
        
        transformed = []
        for token in doc:
            logger.debug(f"Token: {token.text}, Tag: {token.tag_}")
            # First check our dictionary, then try getInflection
            if token.text.lower() in verb_dict:
                past_form = verb_dict[token.text.lower()]
                logger.debug(f"Converting {token.text} to {past_form}")
                transformed.append(past_form)
            elif token.tag_ in ["VBP", "VBZ"]:
                past_form = getInflection(token.text, tag='VBD')
                if past_form:
                    logger.debug(f"Converting {token.text} to {past_form[0]}")
                    transformed.append(past_form[0])
                else:
                    logger.debug(f"No past form found for: {token.text}")
                    transformed.append(token.text)
            else:
                transformed.append(token.text)
        
        result = " ".join(transformed)
        logger.debug(f"Final result: {result}")
        return result
    
    def analyze_responses(self, original_response, modified_response):
        """Analyze differences between original and modified responses"""
        return {
            'original_prompt': original_response,
            'modified_prompt': modified_response,
            'length_diff': len(modified_response) - len(original_response),
            'timestamp': datetime.now().isoformat()
        }