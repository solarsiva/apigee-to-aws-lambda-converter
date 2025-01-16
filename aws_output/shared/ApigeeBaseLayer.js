/**
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
