
const ApigeeBaseLayer = require('../shared/ApigeeBaseLayer');

class AssignMessageHandler extends ApigeeBaseLayer {
    constructor() {
        super();
        this.initialize();
    }

    initialize() {
        this.setVariables = {
        };
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

            // Set payload
            response.body = {"message": "Hello from Apigee"};

            return this.formatResponse(response.body, response.statusCode);
        } catch (error) {
            return this.handleError(error);
        }
    }
}

const handler = new AssignMessageHandler();
exports.handler = (event, context) => handler.handle(event, context);
