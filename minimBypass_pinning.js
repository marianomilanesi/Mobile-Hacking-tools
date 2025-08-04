Java.perform(function () {
    // TrustManagerImpl (Conscrypt)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (chain, anchors, host, authType, ocsp, sct) {
            console.log('[+] Bypassed TrustManagerImpl.verifyChain for host: ' + host);
            return chain;
        };
        console.log('[+] Hooked TrustManagerImpl.verifyChain');
    } catch (err) {
        console.log('[-] TrustManagerImpl not found: ' + err);
    }

    // X509TrustManager custom implementations
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

    var classes = Java.enumerateLoadedClassesSync();
    classes.forEach(function(className) {
        if (className.includes('TrustManager')) {
            try {
                var clazz = Java.use(className);
                if (clazz.checkServerTrusted) {
                    clazz.checkServerTrusted.implementation = function (chain, authType) {
                        console.log('[+] Bypassed checkServerTrusted in: ' + className);
                    };
                }
            } catch (e) {}
        }
    });

    // OkHTTP3 CertificatePinner (resiliente)
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');

        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
            console.log('[+] Bypassed OkHTTPv3 check(List) for: ' + hostname);
        };

        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (hostname, peerCertificates) {
            console.log('[+] Bypassed OkHTTPv3 check(Cert[]) for: ' + hostname);
        };

        console.log('[+] Hooked OkHTTPv3 CertificatePinner');
    } catch (err) {
        console.log('[-] OkHTTPv3 CertificatePinner not found or not active yet.');
    }
});
