# GenAI and Cyber Security Project

## Overview
This project is part of the RMIT GenAI and Cyber Security Hackathon. It integrates with SkywardAI's Voyager platform for advanced AI capabilities.

## Project Structure
- `src/`: Core project source code
- `voyager_files/`: Contains the Voyager integration
  - `voyager/`: Submodule linked to [SkywardAI/voyager](https://github.com/SkywardAI/voyager)
- `local-swagger.json`: API documentation and specifications
- `requirements.txt`: Python dependencies

## Setup Instructions

1. Clone the repository with submodules:
bash
git clone --recursive https://github.com/mondweep/GenAI_CyberSecurity.git
cd GenAI_CyberSecurity

2. Set up Python virtual environment:
bash
python -m venv venv
source venv/bin/activate # On Windows: venv\Scripts\activate
pip install -r requirements.txt

3. Configure API Keys:
- Place your AWS credentials in `developer_accessKeys.csv`
- Set up Voyager API key in `voyager-api-key.pem`

## Voyager Integration
This project uses SkywardAI's Voyager platform for AI capabilities. The integration is maintained as a Git submodule in `voyager_files/voyager/`.

To update the Voyager submodule:
bash
git submodule update --remote voyager_files/voyager

## Competition Details
This project is part of the [RMIT GenAI and Cyber Security Hackathon](https://www.kaggle.com/competitions/rmit-gen-ai-and-cyber-security-hackathon/overview).

## License
This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
