# Challenge 2: Cybersecurity Incident Analysis

This challenge focuses on analyzing cybersecurity incidents using machine learning and implementing secure data handling practices.

## Project Structure
challenge_2/

├── results/ # Analysis results and visualizations

│ ├── analysis_results.txt # Text output of analysis

│ ├── confusion_matrix.png # Model performance visualization

│ ├── correlation_matrix.png # Feature correlation analysis

│ ├── model.pkl # Saved ML model

│ ├── monthly_incidents.png # Time-based incident analysis

│ ├── text_length_distribution.png # Text analysis visualization

│ ├── vectorizer.pkl # Saved text vectorizer

│ ├── vulnerability_distribution.png # Vulnerability type analysis

│ └── vulnerability_vs_label.png # Vulnerability vs label analysis

├── security_results/ # Security testing outputs

│ ├── encryption_test_results.txt # Encryption workflow test results

│ └── security_test_results.txt # Basic security test results

├── analysis.py # Main analysis script

└── PBKDF2HMAC_explanation.md # Documentation for encryption



## Features

1. **Data Analysis**
   - Preprocessing of incident data
   - Vulnerability type distribution analysis
   - Time-based incident analysis
   - Text length analysis
   - Correlation analysis

2. **Machine Learning**
   - Text vectorization using TF-IDF
   - Incident classification using Logistic Regression
   - Model performance evaluation
   - Model persistence for future use

3. **Security Implementation**
   - PBKDF2HMAC-based key derivation
   - AES-CBC encryption/decryption
   - Secure data handling
   - Integration with Voyager project

## Usage

1. Ensure the input data is present:

bash
input/cyber-security-incidents/incidents.csv


2. Install required packages:
   bash
pip install -r requirements.txt

   
3. Run the analysis:

   bash
python analysis.py


## Output

The script generates various visualizations and analysis results:
- Vulnerability distribution plots
- Monthly incident trends
- Text length distribution
- Correlation matrices
- Model performance metrics
- Encryption test results

## Security Features

- Implements PBKDF2HMAC for key derivation
- Uses AES-CBC for encryption
- Includes IV rotation
- Implements secure padding
- Provides data integrity verification

## Dependencies

- pandas
- numpy
- matplotlib
- seaborn
- scikit-learn
- nltk
- cryptography

## Notes

- For headless environments (like servers), the script automatically configures matplotlib
- NLTK data is downloaded automatically on first run
- All results are saved in their respective directories for future reference

## Author
[Mondweep Chakravorty]

## License
[MIT]
