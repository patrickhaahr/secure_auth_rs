/**
 * Browser Fingerprinting for Rate Limiting
 * Generates a unique fingerprint based on browser characteristics
 */

async function generateFingerprint() {
    const components = [];

    // User Agent
    components.push(navigator.userAgent || '');

    // Language
    components.push(navigator.language || navigator.userLanguage || '');

    // Screen resolution
    components.push(`${screen.width}x${screen.height}x${screen.colorDepth}`);

    // Timezone
    components.push(Intl.DateTimeFormat().resolvedOptions().timeZone || '');

    // Platform
    components.push(navigator.platform || '');

    // Hardware concurrency (CPU cores)
    components.push(navigator.hardwareConcurrency || '');

    // Device memory (if available)
    if (navigator.deviceMemory) {
        components.push(navigator.deviceMemory);
    }

    // Canvas fingerprint (more advanced)
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (ctx) {
            canvas.width = 200;
            canvas.height = 50;
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(100, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('Browser Fingerprint', 2, 15);
            components.push(canvas.toDataURL());
        }
    } catch (e) {
        // Canvas fingerprinting might be blocked
        components.push('canvas-blocked');
    }

    // WebGL fingerprint
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (debugInfo) {
                components.push(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || '');
                components.push(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || '');
            }
        }
    } catch (e) {
        components.push('webgl-blocked');
    }

    // Touch support
    components.push(navigator.maxTouchPoints || 0);

    // Plugins (deprecated in modern browsers, but still useful)
    if (navigator.plugins) {
        const plugins = Array.from(navigator.plugins)
            .map(p => p.name)
            .sort()
            .join(',');
        components.push(plugins);
    }

    // Combine all components and hash
    const fingerprint = await hashString(components.join('|||'));
    return fingerprint;
}

async function hashString(str) {
    // Use SubtleCrypto API for SHA-256
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

// Attach fingerprint to all fetch requests
let cachedFingerprint = null;

async function getFingerprint() {
    if (!cachedFingerprint) {
        cachedFingerprint = await generateFingerprint();
    }
    return cachedFingerprint;
}

// Override fetch to automatically include fingerprint
const originalFetch = window.fetch;
window.fetch = async function(...args) {
    const fingerprint = await getFingerprint();
    
    // Modify options to include fingerprint header
    let [url, options = {}] = args;
    options.headers = options.headers || {};
    
    // Handle Headers object
    if (options.headers instanceof Headers) {
        options.headers.set('X-Browser-Fingerprint', fingerprint);
    } else {
        options.headers['X-Browser-Fingerprint'] = fingerprint;
    }
    
    return originalFetch(url, options);
};

// Generate fingerprint on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => getFingerprint());
} else {
    getFingerprint();
}
