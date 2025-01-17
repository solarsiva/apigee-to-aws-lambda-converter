
const ApigeeBaseLayer = require('../shared/ApigeeBaseLayer');
const axios = require('axios');

class ServiceCalloutHandler extends ApigeeBaseLayer {
    constructor() {
        super();
        this.initialize();
    }

    initialize() {
        this.endpoint = 'https://api.example.com/data';
        this.timeout = 30000;
        this.method = 'GET';
    }

    async handle(event, context) {
        try {
            await this.logRequest(event, context);

            const response = await axios({
                method: this.method,
                url: this.endpoint,
                timeout: this.timeout,
                headers: event.headers || {},
                data: event.body
            });

            return this.formatResponse(response.data, response.status);
        } catch (error) {
            return this.handleError(error);
        }
    }
}

const handler = new ServiceCalloutHandler();
exports.handler = (event, context) => handler.handle(event, context);
