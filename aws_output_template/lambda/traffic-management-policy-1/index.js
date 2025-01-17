
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
