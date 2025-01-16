import os
import json
import boto3
import yaml
import time
from pathlib import Path


def load_config():
    """Load configuration from config.yaml"""
    with open('config.yaml', 'r') as f:
        return yaml.safe_load(f)


# Load configuration
config = load_config()


class BedrockClient:
    def __init__(self):
        session = boto3.Session(profile_name=config['aws']['profile_name'])
        self.client = session.client(
            'bedrock-runtime', region_name=config['aws']['region'])
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

    def converse(self, **kwargs):
        """Rate-limited wrapper for Bedrock converse"""
        self._wait_for_rate_limit()
        return self.client.converse(**kwargs)


# Initialize rate-limited Bedrock client
bedrock = BedrockClient()

POLICY_CATEGORIES = [
    "security",
    "traffic-management",
    "mediation",
    "extension"
]


def generate_policy_with_bedrock(category):
    """Use Bedrock to generate complex Apigee policies based on category"""
    conversation = [
        {
            "role": "user",
            "content": [
                {
                    "text": f"Generate a complex Apigee {category} policy XML. Include realistic settings and configurations that would be used in production. The policy should follow Apigee best practices and include detailed comments. Format as valid XML without explanation."
                }
            ]
        }
    ]

    try:
        response = bedrock.converse(
            modelId=config['bedrock']['model_id'],
            messages=conversation,
            inferenceConfig={
                "maxTokens": config['bedrock']['policy_max_tokens'],
                "temperature": config['bedrock']['temperature'],
                "topP": 0.9
            }
        )
        return response["output"]["message"]["content"][0]["text"].strip()
    except Exception as e:
        raise Exception(f"Error generating policy: {str(e)}")


def generate_complex_flow():
    """Generate complex flow with conditional logic and error handling"""
    conversation = [
        {
            "role": "user",
            "content": [
                {
                    "text": "Generate an Apigee ProxyEndpoint XML with: 1. Multiple flows with conditions 2. Error handling 3. Flow hooks 4. Route rules. Format as valid XML without explanation."
                }
            ]
        }
    ]

    try:
        response = bedrock.converse(
            modelId=config['bedrock']['model_id'],
            messages=conversation,
            inferenceConfig={
                "maxTokens": config['bedrock']['flow_max_tokens'],
                "temperature": config['bedrock']['temperature'],
                "topP": 0.9
            }
        )
        return response["output"]["message"]["content"][0]["text"].strip()
    except Exception as e:
        raise Exception(f"Error generating flow: {str(e)}")


def create_sample_apigee_project():
    base_dir = Path("sample_apigee_project")

    # Create directory structure
    dirs = [
        base_dir / "apiproxy" / "policies",
        base_dir / "apiproxy" / "proxies",
        base_dir / "apiproxy" / "targets",
        base_dir / "apiproxy" / "resources" / "jsc",
        base_dir / "apiproxy" / "resources" / "properties",
        base_dir / "apiproxy" / "resources" / "certificates"
    ]

    for dir_path in dirs:
        dir_path.mkdir(parents=True, exist_ok=True)

    # Generate and create policy files for each category
    policies_dir = base_dir / "apiproxy" / "policies"
    for category in POLICY_CATEGORIES:
        # Generate multiple policies per category
        for i in range(2):
            policy_name = f"{category}-policy-{i+1}.xml"
            policy_content = generate_policy_with_bedrock(category)

            with open(policies_dir / policy_name, 'w') as f:
                f.write(policy_content)
            print(f"Created {category} policy: {policy_name}")

    # Generate and create complex proxy endpoints
    proxies_dir = base_dir / "apiproxy" / "proxies"
    for endpoint in ['default', 'alternative']:
        flow_content = generate_complex_flow()
        with open(proxies_dir / f"{endpoint}.xml", 'w') as f:
            f.write(flow_content)
        print(f"Created proxy endpoint: {endpoint}.xml")

    # Create target endpoint
    target_content = generate_policy_with_bedrock("target-endpoint")
    with open(base_dir / "apiproxy" / "targets" / "default.xml", 'w') as f:
        f.write(target_content)

    print(f"Sample Apigee project created in {base_dir}")
    return str(base_dir)


def main():
    try:
        project_dir = create_sample_apigee_project()
        print(f"\nSuccessfully created complex Apigee project in: {
              project_dir}")
        print("\nGenerated files include:")
        print("- Multiple policy categories (security, traffic-management, etc.)")
        print("- Complex flows with conditions and error handling")
        print("- Target endpoints with realistic configurations")
    except Exception as e:
        print(f"Error creating sample project: {str(e)}")


if __name__ == "__main__":
    main()
