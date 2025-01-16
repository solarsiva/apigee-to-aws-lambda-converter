# Apigee to AWS Converter

A Python tool that converts Apigee API proxies to AWS Lambda functions and Step Functions state machines.

## Features

- Converts Apigee policies to AWS Lambda functions
- Transforms Apigee flows into Step Functions state machines
- Supports multiple policy types:
  - AssignMessage
  - JavaScript
  - ServiceCallout
- Maintains original flow sequence and logic
- Uses AWS Bedrock Claude 3.5 Sonnet for generating complex sample policies

## Prerequisites

- Python 3.7+
- pip (Python package installer)
- AWS SSO access configured

## Installation

1. Clone the repository:

bash
git clone <your-repository-url>
cd apigee-aws-converter

2. Create a virtual environment:

bash
python -m venv venv
source venv/bin/activate

# On Windows:

venv\Scripts\activate

3. Install the dependencies:

bash
pip install -r requirements.txt

4. Configure AWS SSO:

```bash
aws sso login --profile [Profile Name]
```

5. Update configuration (optional):

Edit `config.yaml` to customize:

- AWS profile and region
- Bedrock model settings
- Token limits and temperature

## Usage

### Generate Sample Apigee Project (Optional)

To create a sample Apigee project structure for testing:

bash
python create_sample_apigee.py

This will:

- Generate multiple policy types using AI
- Create complex flows with conditions
- Set up a complete project structure

### Convert Apigee Project

To convert an existing Apigee project:

bash
python convert.py <path_to_apigee_project>

When prompted, enter the path to your Apigee project directory.

### Output Structure

The converter generates AWS resources in the `aws_output` directory:

aws_output/
├── lambda/
│ ├── AssignMessage-1/
│ │ └── index.js
│ ├── JavaScript-1/
│ │ └── index.js
│ └── ServiceCallout-1/
│ └── index.js
└── state_machine.json

## Supported Policy Types

1. **AssignMessage**

   - Converts to Lambda function that handles response modification
   - Maintains payload and status code settings

2. **JavaScript**

   - Converts JavaScript policies to Lambda functions
   - Preserves original JavaScript code logic

3. **ServiceCallout**
   - Transforms into Lambda functions that make HTTP requests
   - Maintains endpoint configurations

## Project Structure

README.md
.
├── convert.py # Main converter script
├── create_sample_apigee.py # Sample project generator
├── config.yaml # AWS and Bedrock configuration
├── requirements.txt # Python dependencies
└── README.md # This file

## Limitations

- Basic policy conversion (limited policy types)
- Simple flow conversion (sequential steps only)
- No support for complex conditions or branching
- Assumes Node.js runtime for Lambda functions

## Contributing

## License

This project is licensed under the MIT License - see the LICENSE file for details.
