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

I have modified some of the configuration file from within voyager_files/voyager and kept them in the voyager_files/ folder. you may have to use those (ie overwrite the ones you get from voyager) to get the API end points to work correctly. I will include a video recording of how the end points work after I conffgured it.

## Competition Details
This project is part of the [RMIT GenAI and Cyber Security Hackathon](https://www.kaggle.com/competitions/rmit-gen-ai-and-cyber-security-hackathon/overview).

## A record of the attempt at Challenge 1 (https://www.kaggle.com/code/aisuko/challenge-1-foundational-level?scriptVersionId=204101404)
https://youtube.com/live/R32JnJFwOWk

## License
This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
