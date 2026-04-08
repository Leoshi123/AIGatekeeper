
/**
 * Decorators, Proxies, and Reflective Metadata Stress Test
 */
function Logger(target, key, descriptor) {
    console.log(`Logging ${key}`);
    return descriptor;
}

class SecurityService {
    @Logger
    processPayload(payload: any) {
        // CRITICAL: child_process exec with concatenation
        const { exec } = require('child_process');
        exec("echo " + payload, (err) => {
            if (err) console.error(err);
        });
    }
}

const proxy = new Proxy(new SecurityService(), {
    get(target, prop) {
        return target[prop];
    }
});
