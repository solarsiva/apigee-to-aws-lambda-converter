import os
import json
import boto3
import yaml
import re
from pathlib import Path
from typing import Dict, List, Optional
import time


def load_config():
    """Load configuration from config.yaml"""
    with open('config.yaml', 'r') as f:
        return yaml.safe_load(f)


class ApigeeDigest:
    """Creates a digestible summary of Apigee project structure and dependencies"""

    def __init__(self, source_dir: Path):
        self.source_dir = source_dir
        self.policies: Dict[str, dict] = {}
        self.flows: Dict[str, dict] = {}
        self.resources: Dict[str, str] = {}
        self.dependencies: Dict[str, List[str]] = {}

    def analyze_policy(self, policy_file: Path) -> dict:
        """Analyze a policy file and extract key information"""
        content = policy_file.read_text()
        policy_type = self._detect_policy_type(content)

        return {
            'type': policy_type,
            'name': policy_file.stem,
            'path': str(policy_file.relative_to(self.source_dir)),
            'dependencies': self._extract_dependencies(content),
            'content': content
        }

    def _detect_policy_type(self, content: str) -> str:
        """Detect the type of Apigee policy from content"""
        type_patterns = {
            'AssignMessage': r'<AssignMessage.*?>',
            'JavaScript': r'<Javascript.*?>',
            'ServiceCallout': r'<ServiceCallout.*?>',
            'OAuth': r'<OAuthV2.*?>',
            'SpikeArrest': r'<SpikeArrest.*?>',
            'Cache': r'<Cache.*?>',
            'Extension': r'<ExtensionBundle.*?>',
            'Authentication': r'<AuthenticationPolicy.*?>',
            'RateLimiting': r'<RateLimitingPolicy.*?>',
            'Caching': r'<CachingPolicy.*?>',
            'Logging': r'<LoggingPolicy.*?>'
        }

        for policy_type, pattern in type_patterns.items():
            if re.search(pattern, content, re.DOTALL):
                return policy_type
        return 'Unknown'

    def _extract_dependencies(self, content: str) -> List[str]:
        """Extract policy dependencies from content"""
        deps = []
        # Find referenced policies
        refs = re.findall(r'<Name>(.*?)</Name>', content)
        deps.extend(refs)
        # Find resource references
        resources = re.findall(r'<ResourceURL>(.*?)</ResourceURL>', content)
        deps.extend(resources)
        return deps

    def create_digest(self) -> dict:
        """Create a complete digest of the Apigee project"""
        # Process policies
        policies_dir = self.source_dir / 'apiproxy' / 'policies'
        if policies_dir.exists():
            for policy_file in policies_dir.glob('*.xml'):
                policy_info = self.analyze_policy(policy_file)
                self.policies[policy_file.stem] = policy_info
                self.dependencies[policy_file.stem] = policy_info['dependencies']

        # Process resources
        resources_dir = self.source_dir / 'apiproxy' / 'resources'
        if resources_dir.exists():
            for resource_type in ['jsc', 'properties', 'certificates']:
                type_dir = resources_dir / resource_type
                if type_dir.exists():
                    for resource_file in type_dir.glob('*'):
                        self.resources[resource_file.stem] = str(
                            resource_file.relative_to(self.source_dir))

        return {
            'policies': self.policies,
            'resources': self.resources,
            'dependencies': self.dependencies
        }


class BedrockConverter:
    """Handles AI-powered conversion using AWS Bedrock"""

    def __init__(self, config_path: str = 'config.yaml'):
        self.config = load_config()
        session = boto3.Session(
            profile_name=self.config['aws']['profile_name'])
        self.bedrock = session.client(
            'bedrock-runtime', region_name=self.config['aws']['region'])
        self._last_request_time = 0
        self._requests_this_minute = 0
        # Default to Claude 3.5 Sonnet quota of 2 requests/min
        self._max_requests_per_minute = 2

    def _wait_for_rate_limit(self):
        """Implement token bucket rate limiting"""
        current_time = time.time()

        # Reset counter if a minute has passed
        if current_time - self._last_request_time >= 60:
            self._requests_this_minute = 0
            self._last_request_time = current_time

        # Wait if we've hit the limit
        if self._requests_this_minute >= self._max_requests_per_minute:
            sleep_time = 60 - (current_time - self._last_request_time)
            if sleep_time > 0:
                print(f"\nRate limit reached. Waiting {
                      sleep_time:.1f} seconds...")
                time.sleep(sleep_time)
            self._requests_this_minute = 0
            self._last_request_time = time.time()

        self._requests_this_minute += 1

    def get_base_layer(self):
        """Return the base layer code"""
        return """/**
 * Base layer for Apigee policy conversions
 */

const AWS = require('aws-sdk');

class ApigeeBaseLayer {
    constructor() {
        this.cloudwatch = new AWS.CloudWatch();
        this.apiGateway = new AWS.APIGateway();
    }

    // Common authentication handling
    async validateAuth(event) {
        const cognitoIdentityId = event.requestContext?.identity?.cognitoIdentityId;
        if (!cognitoIdentityId) {
            throw new Error('Unauthorized');
        }
        return cognitoIdentityId;
    }

    // Common rate limiting using API Gateway
    async checkRateLimit(event) {
        const apiKey = event.requestContext?.identity?.apiKey;
        if (!apiKey) {
            throw new Error('API Key required');
        }
        // Rate limit check is handled by API Gateway usage plans
        return true;
    }

    // Common logging
    async logRequest(event, context) {
        const logEvent = {
            requestId: context.awsRequestId,
            path: event.path,
            method: event.httpMethod,
            sourceIp: event.requestContext?.identity?.sourceIp,
            userAgent: event.requestContext?.identity?.userAgent
        };
        
        await this.cloudwatch.putMetricData({
            Namespace: 'ApigeeConverted',
            MetricData: [{
                MetricName: 'RequestCount',
                Value: 1,
                Unit: 'Count',
                Dimensions: [
                    {
                        Name: 'Path',
                        Value: event.path
                    }
                ]
            }]
        }).promise();
        
        console.log('Request:', JSON.stringify(logEvent));
    }

    // Common error handling
    handleError(error) {
        console.error('Error:', error);
        return {
            statusCode: error.statusCode || 500,
            body: JSON.stringify({
                message: error.message || 'Internal Server Error',
                requestId: context.awsRequestId
            })
        };
    }

    // Common response formatting
    formatResponse(data, statusCode = 200) {
        return {
            statusCode,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        };
    }
}

module.exports = ApigeeBaseLayer;
"""

    def _format_lambda_code(self, code: str, policy_info: dict) -> str:
        """Format the Lambda code with proper structure and comments"""
        # Extract comments if present in the response
        comments = []
        code_lines = []
        in_comment_block = False

        for line in code.split('\n'):
            if line.strip().startswith('This Lambda function') or line.strip().startswith('The function'):
                in_comment_block = True
                comments.append(line.strip())
            elif in_comment_block and line.strip():
                if line.strip().startswith('```') or line.strip().startswith('/*'):
                    in_comment_block = False
                else:
                    comments.append(line.strip())
            else:
                code_lines.append(line)

        # Format the actual code
        formatted_code = '\n'.join(code_lines)

        # Create structured comments
        header = f"""/**
 * @fileoverview Converted from Apigee {policy_info['type']} Policy
 * Original policy: {policy_info['path']}
 *
 * Conversion Notes:
 * ----------------
 * {chr(10) + ' * '.join(comments) if comments else 'Direct conversion of Apigee policy to AWS Lambda'}
 *
 * Dependencies Required:
 * --------------------
 * - aws-sdk
 * - axios (for HTTP calls)
 * - xml2js (for XML processing)
 */

"""

        # Extract actual Lambda implementation from Bedrock response
        implementation_code = ""
        in_code_block = False
        for line in code.split('\n'):
            if line.strip().startswith('```'):
                in_code_block = not in_code_block
                continue
            if in_code_block:
                implementation_code += line + '\n'

        # Create implementation using base layer
        implementation = f"""
const ApigeeBaseLayer = require('../shared/ApigeeBaseLayer');

class {policy_info['name'].replace('-', '_')}Handler extends ApigeeBaseLayer {{
    constructor() {{
        super();
        this.initialize();
    }}

    initialize() {{
        // Policy-specific initialization
    }}

    async handle(event, context) {{
        try {{
            await this.logRequest(event, context);
            await this.validateAuth(event);
            await this.checkRateLimit(event);

            {implementation_code}
        }} catch (error) {{
            return this.handleError(error);
        }}
    }}
}}

const handler = new {policy_info['name'].replace('-', '_')}Handler();
exports.handler = (event, context) => handler.handle(event, context);
"""

        return {
            'index.js': implementation,
            'package.json': json.dumps({
                "name": policy_info['name'],
                "version": "1.0.0",
                "description": f"Converted from Apigee {policy_info['type']} Policy",
                "main": "index.js",
                "dependencies": {
                    "apigee-base-layer": "file:../shared"
                }
            }, indent=2)
        }

    def convert_policy(self, policy_info: dict, project_context: dict) -> dict:
        """Convert a single policy using Bedrock"""
        prompt = self._create_policy_prompt(policy_info, project_context)

        try:
            self._wait_for_rate_limit()
            response = self.bedrock.invoke_model(
                modelId=self.config['bedrock']['model_id'],
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": self.config['bedrock']['policy_max_tokens'],
                    "temperature": self.config['bedrock']['temperature'],
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                })
            )
            response_body = json.loads(response['body'].read())
            lambda_code = response_body['content'][0]['text'].strip()

            # Format the code and create package.json
            formatted_files = self._format_lambda_code(
                lambda_code, policy_info)

            return {
                'runtime': 'nodejs18.x',
                'handler': 'index.handler',
                'files': formatted_files
            }
        except Exception as e:
            raise Exception(f"Error converting policy: {str(e)}")

    def _create_policy_prompt(self, policy_info: dict, project_context: dict) -> str:
        """Create a detailed prompt for policy conversion"""
        base_prompt = f"""Convert this Apigee {policy_info['type']} policy to an AWS Lambda function.
        Include error handling, logging, and maintain the original functionality.

        Policy Content:
        {policy_info['content']}

        Dependencies:
        {json.dumps(policy_info['dependencies'], indent=2)}

        Project Context:
        {json.dumps(project_context, indent=2)}"""

        # Add specific handling for extension policies
        if policy_info['type'] in ['Extension', 'Authentication', 'RateLimiting', 'Caching', 'Logging']:
            base_prompt += """
            
            For this extension policy, please:
            1. Create separate Lambda functions for each sub-policy
            2. Use appropriate AWS services:
               - Authentication: Use AWS Cognito/IAM
               - Rate Limiting: Use API Gateway usage plans
               - Caching: Use API Gateway caching
               - Logging: Use CloudWatch Logs
            3. Include proper IAM permissions in comments
            4. Add integration instructions with API Gateway
            """

        return base_prompt + """
        
        Generate a complete Node.js Lambda function that:
        1. Handles the same functionality
        2. Includes proper error handling
        3. Uses AWS best practices
        4. Maintains any dependencies
        5. Returns appropriate responses
        
        Format the response as a complete Lambda function without explanation."""


class ApigeeConverter:
    """Main converter class orchestrating the conversion process"""

    def __init__(self, source_dir: str = None):
        config = load_config()
        self.source_dir = Path(config['paths']['source_dir'])
        self.output_dir = Path('aws_output')
        self.digest_file = Path('aws_output/project_digest.json')
        self.shared_layer_dir = self.output_dir / 'shared'
        self.digest = ApigeeDigest(self.source_dir)
        self.bedrock = BedrockConverter()
        self.state_machine = {
            "Comment": "Converted from Apigee",
            "StartAt": "Initial",
            "States": {}
        }

    def _create_shared_layer(self):
        """Create shared base layer for all Lambda functions"""
        self.shared_layer_dir.mkdir(exist_ok=True)

        # Write base layer code
        with open(self.shared_layer_dir / 'ApigeeBaseLayer.js', 'w') as f:
            f.write(self.bedrock.get_base_layer())

        # Write package.json for shared layer
        package_json = {
            "name": "apigee-base-layer",
            "version": "1.0.0",
            "description": "Shared base layer for converted Apigee policies",
            "main": "ApigeeBaseLayer.js",
            "dependencies": {
                "aws-sdk": "^2.1001.0",
                "axios": "^0.24.0",
                "xml2js": "^0.4.23"
            }
        }
        with open(self.shared_layer_dir / 'package.json', 'w') as f:
            json.dump(package_json, f, indent=2)

    def _load_cached_digest(self) -> Optional[dict]:
        """Load digest from cache if available and not stale"""
        if self.digest_file.exists():
            cached_digest = json.loads(self.digest_file.read_text())
            # Check if source files are newer than cache
            cache_time = self.digest_file.stat().st_mtime
            policies_dir = self.source_dir / 'apiproxy' / 'policies'
            for policy_file in policies_dir.glob('*.xml'):
                if policy_file.stat().st_mtime > cache_time:
                    return None
            print("Using cached project digest")
            return cached_digest
        return None

    def process_directory(self):
        """Process the Apigee directory and convert to AWS resources"""
        print(f"Processing Apigee directory: {self.source_dir}")

        # Create shared base layer first
        print("\nCreating shared base layer...")
        self._create_shared_layer()

        # Try to load cached digest first
        project_context = self._load_cached_digest()
        if not project_context:
            print("Creating new project digest...")
            project_context = self.digest.create_digest()
            # Cache the digest
            self.output_dir.mkdir(exist_ok=True)
            self.digest_file.write_text(json.dumps(project_context, indent=2))

        print("\nFound policies:")
        for policy_name in project_context['policies'].keys():
            print(f"- {policy_name}")

        # Create output directories
        self.output_dir.mkdir(exist_ok=True)

        # Convert policies to Lambda functions
        for policy_name, policy_info in project_context['policies'].items():
            print(f"\nConverting policy: {
                  policy_name} (Type: {policy_info['type']})")
            try:
                lambda_code = self.bedrock.convert_policy(
                    policy_info, project_context)

                # Save Lambda function
                lambda_dir = self.output_dir / 'lambda' / policy_name
                lambda_dir.mkdir(parents=True, exist_ok=True)
                # Save all generated files
                for filename, content in lambda_code['files'].items():
                    with open(lambda_dir / filename, 'w') as f:
                        f.write(content)
                print(f"✓ Successfully converted and saved to {
                      lambda_dir}/index.js")
            except Exception as e:
                print(f"✗ Failed to convert: {str(e)}")

        # Generate Step Functions state machine
        self._create_state_machine(project_context)

        # Save Step Functions definition
        with open(self.output_dir / 'state_machine.json', 'w') as f:
            json.dump(self.state_machine, f, indent=2)

    def _create_state_machine(self, project_context: dict):
        """Create Step Functions state machine based on flow dependencies"""
        # Create states based on policy dependencies
        states = {}
        for policy_name, deps in project_context['dependencies'].items():
            state = {
                "Type": "Task",
                "Resource": f"arn:aws:lambda:${{AWS::Region}}:${{AWS::AccountId}}:function:{policy_name}",
                "Next": deps[0] if deps else "End",
                "Catch": [{
                    "ErrorEquals": ["States.ALL"],
                    "Next": "ErrorHandler"
                }]
            }
            states[policy_name] = state

        # Add error handler
        states["ErrorHandler"] = {
            "Type": "Task",
            "Resource": f"arn:aws:lambda:${{AWS::Region}}:${{AWS::AccountId}}:function:error-handler",
            "End": True
        }

        states["End"] = {"Type": "Succeed"}

        self.state_machine["States"] = states
        self.state_machine["StartAt"] = next(iter(states.keys()))


def main():
    try:
        converter = ApigeeConverter()
        converter.process_directory()
        print("Conversion completed. Check 'aws_output' directory for results.")
    except Exception as e:
        print(f"Error during conversion: {str(e)}")


if __name__ == "__main__":
    main()
