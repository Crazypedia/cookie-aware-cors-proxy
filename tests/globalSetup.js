const express = require('express');
const os = require('os');

// The proxy now enforces the CRIT-2 SSRF blocklist, which always rejects
// loopback targets. The dummy backend used by the test suite therefore can't
// bind to 127.0.0.1 anymore - it needs to listen on a real network interface
// address instead so requests to it pass the SSRF check like a normal target
// would. That address is typically RFC 1918 private in CI/sandbox
// environments, so SSRF_ALLOW_PRIVATE is enabled for the test run (dev/test
// only - loopback and link-local stay blocked regardless of this flag).
process.env.SSRF_ALLOW_PRIVATE = 'true';

function findNonLoopbackAddress() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    console.warn('No non-loopback IPv4 interface found; falling back to 127.0.0.1 (SSRF tests against the dummy backend will fail).');
    return '127.0.0.1';
}

const bindAddress = findNonLoopbackAddress();

    // Starts the proxy server
const testedServer = require('../src/server');


module.exports = async () => {

        // Starts a dummy server to use for testing
    let server;
    const app = express();

    await new Promise(function(resolve) {
        server = app.listen(0,bindAddress,function() {
            console.log('Running express on ',server.address());
            resolve();
        });
    });

    let address = server.address().address;
    global.server = server;
    global.testedServer = testedServer.getProxyServer();
    //console.log("Setup:", (global.testedServer==null));
    process.env.SERVER_ADDRESS = 'http://'+address+':'+server.address().port;

    app.all('/**', async (req, res, next) => {
        let path=req.path;
        if( path.startsWith('/redirect')) {
            res.redirect(process.env.SERVER_ADDRESS+path.substring('/redirect'.length));
            return;
        }else if( path.startsWith('/headertest')) {
            res.set('X-Internal-Secret', 'super-secret-value');
            res.set('Content-Type', 'text/html');
            path=path.substring('/headertest'.length);
        }else if( path.startsWith('/cookie')) {
            res.cookie("domain-cookie", "value-of-domain-cookie",{
                domain:req.hostname,
                sameSite: 'Lax'
            });
            res.cookie("strict-cookie", "value-of-subdomain-cookie", {
                domain:req.hostname,
                sameSite: 'Strict'
            });
            res.cookie("path-cookie","value-of-path-cookie", {
                domain:req.hostname,
                sameSite: 'Lax',
                path: '/cookie/path'
            });
            path=path.substring('/cookie'.length);
        }
        
        res.sendFile(process.cwd()+'/tests/files'+path);

    });


};
