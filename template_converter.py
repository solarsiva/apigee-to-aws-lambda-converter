import os
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional
import re
import xml.etree.ElementTree as ET


def load_config():
    """Load configuration from config.yaml"""
    with open('config.yaml', 'r') as f:
        return yaml.safe_load(f)


class PolicyTemplate:
    """Base class for policy templates"""

    def __init__(self, policy_content: str):
        self.content = policy_content
        self.tree = ET.fromstring(policy_content)
        self.variables = {}
        self.extract_variables()

    def extract_variables(self):
        """Extract variables from policy XML"""
        pass

    def generate_lambda(self) -> dict:
        """Generate Lambda function code"""
        raise NotImplementedError


class AssignMessageTemplate(PolicyTemplate):
    def extract_variables(self):
        """Extract AssignMessage specific variables"""
        self.variables['set_variables'] = []
        self.variables['remove_variables'] = []
        self.variables['payload'] = None

        # Extract Set variables
        for set_var in self.tree.findall('.//AssignVariable'):
            name = set_var.find('Name').text
            value = set_var.find('Value').text if set_var.find(
                'Value') is not None else None
            self.variables['set_variables'].append({
                'name': name,
                'value': value
            })

        # Extract Remove variables
        for remove_var in self.tree.findall('.//RemoveVariable'):
            name = remove_var.find('Name').text
            self.variables['remove_variables'].append(name)

        # Extract Payload
        payload = self.tree.find('.//Payload')
        if payload is not None:
            self.variables['payload'] = payload.text

    def generate_lambda(self) -> dict:
        """Generate Lambda function for AssignMessage policy"""
        code = """
const ApigeeBaseLayer = require('../shared/ApigeeBaseLayer');

class AssignMessageHandler extends ApigeeBaseLayer {
    constructor() {
        super();
        this.initialize();
    }

    initialize() {
        this.setVariables = {
"""
        # Add set variables
        for var in self.variables['set_variables']:
            code += f"            '{var['name']}': '{var['value']}',\n"

        code += """        };
    }

    async handle(event, context) {
        try {
            await this.logRequest(event, context);
            
            // Create response object
            const response = {
                statusCode: 200,
                headers: {},
                body: {}
            };

            // Set variables
            Object.entries(this.setVariables).forEach(([key, value]) => {
                if (value.startsWith('request.')) {
                    response.body[key] = event[value.split('.')[1]];
                } else {
                    response.body[key] = value;
                }
            });
"""

        if self.variables['payload']:
            code += f"""
            // Set payload
            response.body = {self.variables['payload']};
"""

        code += """
            return this.formatResponse(response.body, response.statusCode);
        } catch (error) {
            return this.handleError(error);
        }
    }
}

const handler = new AssignMessageHandler();
exports.handler = (event, context) => handler.handle(event, context);
"""
        return {
            'runtime': 'nodejs18.x',
            'handler': 'index.handler',
            'files': {
                'index.js': code,
                'package.json': json.dumps({
                    "name": "assign-message-handler",
                    "version": "1.0.0",
                    "description": "Converted from Apigee AssignMessage Policy",
                    "main": "index.js",
                    "dependencies": {
                        "apigee-base-layer": "file:../shared"
                    }
                }, indent=2)
            }
        }


class ServiceCalloutTemplate(PolicyTemplate):
    def extract_variables(self):
        """Extract ServiceCallout specific variables"""
        self.variables['url'] = self.tree.find('.//URL').text
        self.variables['timeout'] = self.tree.find('.//Timeout').text
        self.variables['method'] = 'GET'  # Default
        method = self.tree.find('.//Verb')
        if method is not None:
            self.variables['method'] = method.text

    def generate_lambda(self) -> dict:
        """Generate Lambda function for ServiceCallout policy"""
        code = f"""
const ApigeeBaseLayer = require('../shared/ApigeeBaseLayer');
const axios = require('axios');

class ServiceCalloutHandler extends ApigeeBaseLayer {{
    constructor() {{
        super();
        this.initialize();
    }}

    initialize() {{
        this.endpoint = '{self.variables['url']}';
        this.timeout = {self.variables['timeout']};
        this.method = '{self.variables['method']}';
    }}

    async handle(event, context) {{
        try {{
            await this.logRequest(event, context);

            const response = await axios({{
                method: this.method,
                url: this.endpoint,
                timeout: this.timeout,
                headers: event.headers || {{}},
                data: event.body
            }});

            return this.formatResponse(response.data, response.status);
        }} catch (error) {{
            return this.handleError(error);
        }}
    }}
}}

const handler = new ServiceCalloutHandler();
exports.handler = (event, context) => handler.handle(event, context);
"""
        return {
            'runtime': 'nodejs18.x',
            'handler': 'index.handler',
            'files': {
                'index.js': code,
                'package.json': json.dumps({
                    "name": "service-callout-handler",
                    "version": "1.0.0",
                    "description": "Converted from Apigee ServiceCallout Policy",
                    "main": "index.js",
                    "dependencies": {
                        "apigee-base-layer": "file:../shared",
                        "axios": "^0.24.0"
                    }
                }, indent=2)
            }
        }


class ProxyEndpointTemplate:
    def __init__(self, content: str):
        self.tree = ET.fromstring(content)
        self.variables = {}
        self.extract_variables()

    def extract_variables(self):
        """Extract proxy endpoint configuration"""
        self.variables['base_path'] = self.tree.find('.//BasePath').text
        self.variables['flows'] = []
        self.variables['route_rules'] = []

        # Extract flows
        for flow in self.tree.findall('.//Flow'):
            flow_info = {
                'name': flow.get('name'),
                'condition': flow.find('Condition').text if flow.find('Condition') is not None else None,
                'steps': []
            }
            for step in flow.findall('.//Step'):
                flow_info['steps'].append({
                    'name': step.find('Name').text,
                    'condition': step.find('Condition').text if step.find('Condition') is not None else None
                })
            self.variables['flows'].append(flow_info)

        # Extract route rules
        for rule in self.tree.findall('.//RouteRule'):
            self.variables['route_rules'].append({
                'name': rule.get('name'),
                'condition': rule.find('Condition').text if rule.find('Condition') is not None else None,
                'target': rule.find('TargetEndpoint').text if rule.find('TargetEndpoint') is not None else None
            })

    def generate_api_gateway_config(self) -> dict:
        """Generate API Gateway configuration"""
        openapi = {
            'openapi': '3.0.1',
            'info': {
                'title': 'Converted Apigee API',
                'version': '1.0.0'
            },
            'paths': {},
            'components': {
                'schemas': {}
            }
        }

        # Add base path
        base_path = self.variables['base_path'].strip('/')

        # Create paths from flows
        for flow in self.variables['flows']:
            path = f'/{base_path}/{flow["name"].lower()}'
            method = 'get'  # Default method
            if 'POST' in str(flow.get('condition', '')):
                method = 'post'
            elif 'PUT' in str(flow.get('condition', '')):
                method = 'put'
            elif 'DELETE' in str(flow.get('condition', '')):
                method = 'delete'

            openapi['paths'][path] = {
                method: {
                    'x-amazon-apigateway-integration': {
                        'type': 'aws_proxy',
                        'httpMethod': 'POST',
                        'uri': f'${{stageVariables.lambdaArn}}',
                        'passthroughBehavior': 'when_no_match',
                        'contentHandling': 'CONVERT_TO_TEXT'
                    },
                    'responses': {
                        '200': {
                            'description': 'Successful operation'
                        }
                    }
                }
            }

        return openapi


class TargetEndpointTemplate:
    def __init__(self, content: str):
        self.tree = ET.fromstring(content)
        self.variables = {}
        self.extract_variables()

    def extract_variables(self):
        """Extract target endpoint configuration"""
        self.variables['servers'] = []
        for server in self.tree.findall('.//Server'):
            self.variables['servers'].append({
                'name': server.get('name'),
                'base_url': server.find('BaseURL').text if server.find('BaseURL') is not None else None
            })

    def generate_api_gateway_config(self) -> dict:
        """Generate API Gateway VPC Link configuration"""
        return {
            'vpcLink': {
                'name': 'ConvertedVPCLink',
                'targets': [server['base_url'] for server in self.variables['servers'] if server['base_url']]
            }
        }


class ExtensionTemplate(PolicyTemplate):
    def extract_variables(self):
        """Extract Extension policy variables"""
        self.variables['name'] = self.tree.get('name')
        self.variables['flows'] = []
        for flow in self.tree.findall('.//Flow'):
            self.variables['flows'].append({
                'name': flow.get('name'),
                'steps': [step.find('Name').text for step in flow.findall('.//Step')]
            })

    def generate_lambda(self) -> dict:
        code = """
const ApigeeBaseLayer = require('../shared/ApigeeBaseLayer');

class ExtensionHandler extends ApigeeBaseLayer {
    constructor() {
        super();
        this.initialize();
    }

    initialize() {
        // Extension-specific initialization
    }

    async handle(event, context) {
        try {
            await this.logRequest(event, context);
            
            // Process each flow step
            const result = await this.processFlows(event);
            return this.formatResponse(result);
        } catch (error) {
            return this.handleError(error);
        }
    }

    async processFlows(event) {
        // Implementation would handle each flow's logic
        return { processed: true };
    }
}

const handler = new ExtensionHandler();
exports.handler = (event, context) => handler.handle(event, context);
"""
        return {
            'runtime': 'nodejs18.x',
            'handler': 'index.handler',
            'files': {
                'index.js': code,
                'package.json': json.dumps({
                    "name": "extension-handler",
                    "version": "1.0.0",
                    "description": "Converted from Apigee Extension Policy",
                    "main": "index.js",
                    "dependencies": {
                        "apigee-base-layer": "file:../shared"
                    }
                }, indent=2)
            }
        }


class MediationTemplate(PolicyTemplate):
    def extract_variables(self):
        """Extract Mediation policy variables"""
        self.variables['flows'] = []
        for flow in self.tree.findall('.//Flow'):
            self.variables['flows'].append({
                'name': flow.get('name'),
                'request_steps': [step.find('Name').text for step in flow.findall('.//Request/Step')],
                'response_steps': [step.find('Name').text for step in flow.findall('.//Response/Step')]
            })

    def generate_lambda(self) -> dict:
        code = """
const ApigeeBaseLayer = require('../shared/ApigeeBaseLayer');

class MediationHandler extends ApigeeBaseLayer {
    constructor() {
        super();
        this.initialize();
    }

    initialize() {
        // Mediation-specific initialization
    }

    async handle(event, context) {
        try {
            await this.logRequest(event, context);
            
            // Process request and response mediation
            const result = await this.processMediation(event);
            return this.formatResponse(result);
        } catch (error) {
            return this.handleError(error);
        }
    }

    async processMediation(event) {
        // Implementation would handle request/response transformation
        return { mediated: true };
    }
}

const handler = new MediationHandler();
exports.handler = (event, context) => handler.handle(event, context);
"""
        return {
            'runtime': 'nodejs18.x',
            'handler': 'index.handler',
            'files': {
                'index.js': code,
                'package.json': json.dumps({
                    "name": "mediation-handler",
                    "version": "1.0.0",
                    "description": "Converted from Apigee Mediation Policy",
                    "main": "index.js",
                    "dependencies": {
                        "apigee-base-layer": "file:../shared"
                    }
                }, indent=2)
            }
        }


class SecurityTemplate(PolicyTemplate):
    def extract_variables(self):
        """Extract Security policy variables"""
        self.variables['policies'] = []
        for policy in self.tree.findall('.//policy'):
            self.variables['policies'].append({
                'name': policy.get('name'),
                'type': policy.get('type', 'unknown')
            })

    def generate_lambda(self) -> dict:
        code = """
const ApigeeBaseLayer = require('../shared/ApigeeBaseLayer');

class SecurityHandler extends ApigeeBaseLayer {
    constructor() {
        super();
        this.initialize();
    }

    initialize() {
        // Security-specific initialization
    }

    async handle(event, context) {
        try {
            await this.logRequest(event, context);
            
            // Process security checks
            const result = await this.processSecurity(event);
            return this.formatResponse(result);
        } catch (error) {
            return this.handleError(error);
        }
    }

    async processSecurity(event) {
        // Implementation would handle security checks
        return { secured: true };
    }
}

const handler = new SecurityHandler();
exports.handler = (event, context) => handler.handle(event, context);
"""
        return {
            'runtime': 'nodejs18.x',
            'handler': 'index.handler',
            'files': {
                'index.js': code,
                'package.json': json.dumps({
                    "name": "security-handler",
                    "version": "1.0.0",
                    "description": "Converted from Apigee Security Policy",
                    "main": "index.js",
                    "dependencies": {
                        "apigee-base-layer": "file:../shared"
                    }
                }, indent=2)
            }
        }


class TrafficManagementTemplate(PolicyTemplate):
    def extract_variables(self):
        """Extract Traffic Management policy variables"""
        self.variables['quota'] = {}
        self.variables['spike_arrest'] = {}

        # Extract Quota settings
        quota = self.tree.find('.//Quota')
        if quota is not None:
            self.variables['quota'] = {
                'interval': quota.find('.//Interval').text if quota.find('.//Interval') is not None else '1',
                'time_unit': quota.find('.//TimeUnit').text if quota.find('.//TimeUnit') is not None else 'hour',
                'allow': quota.find('.//Allow').text if quota.find('.//Allow') is not None else '1000'
            }

        # Extract SpikeArrest settings
        spike = self.tree.find('.//SpikeArrest')
        if spike is not None:
            self.variables['spike_arrest'] = {
                'rate': spike.find('.//Rate').text if spike.find('.//Rate') is not None else '10pm',
                'identifier': spike.find('.//IdentifierRef').text if spike.find('.//IdentifierRef') is not None else None
            }

    def generate_lambda(self) -> dict:
        code = """
const ApigeeBaseLayer = require('../shared/ApigeeBaseLayer');
const Redis = require('ioredis');

class TrafficManagementHandler extends ApigeeBaseLayer {
    constructor() {
        super();
        this.initialize();
    }

    initialize() {
        this.redis = new Redis(process.env.REDIS_URL);
    }

    async handle(event, context) {
        try {
            await this.logRequest(event, context);
            
            // Check quota and rate limits
            await this.checkLimits(event);
            
            return this.formatResponse({ allowed: true });
        } catch (error) {
            if (error.message === 'Rate limit exceeded' || error.message === 'Quota exceeded') {
                return {
                    statusCode: 429,
                    body: JSON.stringify({
                        error: error.message
                    })
                };
            }
            return this.handleError(error);
        }
    }

    async checkLimits(event) {
        const clientId = event.requestContext?.identity?.apiKey || 'default';
        const now = Date.now();
        
        // Check quota
        const quotaKey = `quota:${clientId}`;
        const quotaCount = await this.redis.incr(quotaKey);
        if (quotaCount === 1) {
            await this.redis.expire(quotaKey, 3600); // 1 hour
        }
        if (quotaCount > 1000) {
            throw new Error('Quota exceeded');
        }

        // Check spike arrest
        const spikeKey = `spike:${clientId}`;
        const spikeCount = await this.redis.incr(spikeKey);
        if (spikeCount === 1) {
            await this.redis.expire(spikeKey, 60); // 1 minute
        }
        if (spikeCount > 10) {
            throw new Error('Rate limit exceeded');
        }
    }
}

const handler = new TrafficManagementHandler();
exports.handler = (event, context) => handler.handle(event, context);
"""
        return {
            'runtime': 'nodejs18.x',
            'handler': 'index.handler',
            'files': {
                'index.js': code,
                'package.json': json.dumps({
                    "name": "traffic-management-handler",
                    "version": "1.0.0",
                    "description": "Converted from Apigee Traffic Management Policy",
                    "main": "index.js",
                    "dependencies": {
                        "apigee-base-layer": "file:../shared",
                        "ioredis": "^5.0.0"
                    }
                }, indent=2)
            }
        }


class TemplateConverter:
    """Rule-based converter using templates"""

    def __init__(self, source_dir: str = None):
        config = load_config()
        self.source_dir = Path(config['paths']['source_dir'])
        self.output_dir = Path('aws_output_template')
        self.shared_layer_dir = self.output_dir / 'shared'
        self.resources_dir = self.output_dir / 'resources'
        self.templates = {
            'AssignMessage': AssignMessageTemplate,
            'ServiceCallout': ServiceCalloutTemplate,
            'Extension': ExtensionTemplate,
            'JavaScript': JavaScriptTemplate,
            'TrafficManagement': TrafficManagementTemplate,
            'Mediation': MediationTemplate,
            'Security': SecurityTemplate
        }

    def _create_shared_layer(self):
        """Create shared base layer for all Lambda functions"""
        self.shared_layer_dir.mkdir(parents=True, exist_ok=True)

        # Write base layer code - reuse the same base layer from convert.py
        with open(self.shared_layer_dir / 'ApigeeBaseLayer.js', 'w') as f:
            f.write("""/**
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
""")

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

    def _detect_policy_type(self, content: str) -> Optional[str]:
        """Detect policy type from XML content"""
        type_patterns = {
            'AssignMessage': r'<AssignMessage.*?>',
            'ServiceCallout': r'<ServiceCallout.*?>',
            'Extension': r'<ExtensionBundle.*?>',
            'JavaScript': r'<Javascript.*?>|<Script.*?>',
            'TrafficManagement': r'<TrafficManagementPolicy.*?>',
            'Mediation': r'<MediationPolicy.*?>',
            'Security': r'<SecurityPolicy.*?>|<VerifyAPIKey.*?>|<OAuth.*?>'
        }

        for policy_type, pattern in type_patterns.items():
            if re.search(pattern, content, re.DOTALL):
                return policy_type
        return None

    def convert_policy(self, policy_file: Path) -> dict:
        """Convert a single policy using templates"""
        content = policy_file.read_text()
        policy_type = self._detect_policy_type(content)

        if policy_type and policy_type in self.templates:
            template = self.templates[policy_type](content)
            return template.generate_lambda()
        else:
            raise ValueError(f"Unsupported policy type in {policy_file}")

    def _process_resources(self):
        """Process resource files (JavaScript, properties, etc.)"""
        resources_dir = self.source_dir / 'apiproxy' / 'resources'
        if not resources_dir.exists():
            return

        print("\nProcessing resources...")
        for resource_type in ['jsc', 'properties', 'certificates']:
            src_dir = resources_dir / resource_type
            if src_dir.exists():
                dst_dir = self.resources_dir / resource_type
                dst_dir.mkdir(parents=True, exist_ok=True)

                for resource_file in src_dir.glob('*'):
                    print(f"Copying resource: {resource_file.name}")
                    with open(resource_file, 'r') as src, open(dst_dir / resource_file.name, 'w') as dst:
                        dst.write(src.read())

    def _process_proxies(self):
        """Process proxy endpoint configurations"""
        proxies_dir = self.source_dir / 'apiproxy' / 'proxies'
        if not proxies_dir.exists():
            return

        print("\nProcessing proxy endpoints...")
        proxy_dir = self.output_dir / 'api_gateway'
        proxy_dir.mkdir(parents=True, exist_ok=True)

        for proxy_file in proxies_dir.glob('*.xml'):
            print(f"Processing proxy endpoint: {proxy_file.name}")
            content = proxy_file.read_text()
            template = ProxyEndpointTemplate(content)
            config = template.generate_api_gateway_config()

            output_file = proxy_dir / f'{proxy_file.stem}_openapi.json'
            with open(output_file, 'w') as f:
                json.dump(config, f, indent=2)
            print(f"✓ Generated API Gateway config: {output_file}")

    def _process_targets(self):
        """Process target endpoint configurations"""
        targets_dir = self.source_dir / 'apiproxy' / 'targets'
        if not targets_dir.exists():
            return

        print("\nProcessing target endpoints...")
        target_dir = self.output_dir / 'api_gateway'
        target_dir.mkdir(parents=True, exist_ok=True)

        for target_file in targets_dir.glob('*.xml'):
            print(f"Processing target endpoint: {target_file.name}")
            content = target_file.read_text()
            template = TargetEndpointTemplate(content)
            config = template.generate_api_gateway_config()

            output_file = target_dir / f'{target_file.stem}_vpc_link.json'
            with open(output_file, 'w') as f:
                json.dump(config, f, indent=2)
            print(f"✓ Generated VPC Link config: {output_file}")

    def process_directory(self):
        """Process the Apigee directory and convert to AWS resources"""
        print(f"Processing Apigee directory: {self.source_dir}")

        # Create shared base layer first
        print("\nCreating shared base layer...")
        self._create_shared_layer()

        # Create output directories
        self.output_dir.mkdir(exist_ok=True)

        # Process all components
        self._process_resources()
        self._process_proxies()
        self._process_targets()

        # Process policies
        policies_dir = self.source_dir / 'apiproxy' / 'policies'
        if policies_dir.exists():
            print("\nProcessing policies...")
            for policy_file in policies_dir.glob('*.xml'):
                print(f"\nConverting policy: {policy_file.stem}")
                try:
                    lambda_code = self.convert_policy(policy_file)

                    # Save Lambda function
                    lambda_dir = self.output_dir / 'lambda' / policy_file.stem
                    lambda_dir.mkdir(parents=True, exist_ok=True)

                    for filename, content in lambda_code['files'].items():
                        with open(lambda_dir / filename, 'w') as f:
                            f.write(content)
                    print(f"✓ Successfully converted and saved to {
                          lambda_dir}/index.js")
                except Exception as e:
                    print(f"✗ Failed to convert: {str(e)}")

        print(f"\nTemplate-based conversion completed. Check '{
              self.output_dir}' directory for results.")


class JavaScriptTemplate(PolicyTemplate):
    def extract_variables(self):
        """Extract JavaScript specific variables"""
        resource_url = self.tree.find('.//ResourceURL')
        if resource_url is None:
            raise ValueError("JavaScript policy must have a ResourceURL")
        self.variables['resource_url'] = resource_url.text
        self.variables['include_url'] = self.tree.find(
            './/IncludeURL').text if self.tree.find('.//IncludeURL') is not None else None

    def generate_lambda(self) -> dict:
        """Generate Lambda function for JavaScript policy"""
        code = f"""
        const ApigeeBaseLayer = require('../shared/ApigeeBaseLayer');
        const fs = require('fs');
        const path = require('path');

        class JavaScriptHandler extends ApigeeBaseLayer {{
            constructor() {{
                super();
                this.initialize();
            }}

            initialize() {{
                // Load JavaScript resources
                this.mainScript = fs.readFileSync(path.join(__dirname, '../resources/jsc/{self.variables['resource_url'].split('/')[-1]}'), 'utf8');
                {f"this.helperScript = fs.readFileSync(path.join(__dirname, '../resources/jsc/{self.variables['include_url'].split('/')[-1]}'), 'utf8');" if self.variables['include_url'] else ''}
            }}

            async handle(event, context) {{
                try {{
                    await this.logRequest(event, context);

                    // Execute JavaScript in VM
                    const vm = require('vm');
                    const sandbox = {{
                        request: event,
                        context: context,
                        response: {{}}
                    }};

                    {f"vm.runInNewContext(this.helperScript, sandbox);" if self.variables['include_url'] else ''}
                    vm.runInNewContext(this.mainScript, sandbox);

                    return this.formatResponse(sandbox.response);
                }} catch (error) {{
                    return this.handleError(error);
                }}
            }}
        }}

        const handler = new JavaScriptHandler();
        exports.handler = (event, context) => handler.handle(event, context);
        """
        return {
            'runtime': 'nodejs18.x',
            'handler': 'index.handler',
            'files': {
                'index.js': code,
                'package.json': json.dumps({
                    "name": "javascript-handler",
                    "version": "1.0.0",
                    "description": "Converted from Apigee JavaScript Policy",
                    "main": "index.js",
                    "dependencies": {
                        "apigee-base-layer": "file:../shared"
                    }
                }, indent=2)
            }
        }


def main():
    try:
        converter = TemplateConverter()
        converter.process_directory()
        print("Conversion completed. Check 'aws_output' directory for results.")
    except Exception as e:
        print(f"Error during conversion: {str(e)}")


if __name__ == "__main__":
    main()
