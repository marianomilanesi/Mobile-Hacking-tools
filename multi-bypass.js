Java.perform(function() {
 
    var array_list = Java.use("java.util.ArrayList");
    var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
 
    ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
        // console.log('Bypassing SSL Pinning');
        var k = array_list.$new();
        return k;
    }
 
}, 0);
 
 
Java.perform(function() {
 
    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com", "com.android.vending.billing.InAppBillingService.COIN","com.topjohnwu.magisk"
    ];
 
    var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk","magisk"];
 
    var RootProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    };
 
    var RootPropertiesKeys = [];
 
    for (var k in RootProperties) RootPropertiesKeys.push(k);
 
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
 
    var Runtime = Java.use('java.lang.Runtime');
 
    var NativeFile = Java.use('java.io.File');
 
    var String = Java.use('java.lang.String');
 
    var SystemProperties = Java.use('android.os.SystemProperties');
 
    var BufferedReader = Java.use('java.io.BufferedReader');
 
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
 
    var StringBuffer = Java.use('java.lang.StringBuffer');
 
    var loaded_classes = Java.enumerateLoadedClassesSync();
 
    send("Loaded " + loaded_classes.length + " classes!");
 
    var useKeyInfo = false;
 
    var useProcessManager = false;
 
    send("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));
 
    if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
        try {
            //useProcessManager = true;
            //var ProcessManager = Java.use('java.lang.ProcessManager');
        } catch (err) {
            send("ProcessManager Hook failed: " + err);
        }
    } else {
        send("ProcessManager hook not loaded");
    }
 
    var KeyInfo = null;
 
    if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
        try {
            //useKeyInfo = true;
            //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
        } catch (err) {
            send("KeyInfo Hook failed: " + err);
        }
    } else {
        send("KeyInfo hook not loaded");
    }
 
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
        if (shouldFakePackage) {
            send("Bypass root check for package: " + pname);
            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
        }
        return this.getPackageInfo.call(this, pname, flags);
    };
 
    NativeFile.exists.implementation = function() {
        var name = NativeFile.getName.call(this);
        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
        if (shouldFakeReturn) {
            send("Bypass return value for binary: " + name);
            return false;
        } else {
            return this.exists.call(this);
        }
    };
 
    var exec = Runtime.exec.overload('[Ljava.lang.String;');
    var exec1 = Runtime.exec.overload('java.lang.String');
    var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
    var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
    var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
    var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');
 
    exec5.implementation = function(cmd, env, dir) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "which") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass which command");
            return exec1.call(this, fakeCmd);
        }
        return exec5.call(this, cmd, env, dir);
    };
 
    exec4.implementation = function(cmdarr, env, file) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
 
            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec4.call(this, cmdarr, env, file);
    };
 
    exec3.implementation = function(cmdarr, envp) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
 
            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec3.call(this, cmdarr, envp);
    };
 
    exec2.implementation = function(cmd, env) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec2.call(this, cmd, env);
    };
 
    exec.implementation = function(cmd) {
        for (var i = 0; i < cmd.length; i = i + 1) {
            var tmp_cmd = cmd[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
 
            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
        }
 
        return exec.call(this, cmd);
    };
 
    exec1.implementation = function(cmd) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec1.call(this, cmd);
    };
 
    String.contains.implementation = function(name) {
        if (name == "test-keys") {
            send("Bypass test-keys check");
            return false;
        }
        return this.contains.call(this, name);
    };
 
    var get = SystemProperties.get.overload('java.lang.String');
 
    get.implementation = function(name) {
        if (RootPropertiesKeys.indexOf(name) != -1) {
            send("Bypass " + name);
            return RootProperties[name];
        }
        return this.get.call(this, name);
    };
 
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var path1 = Memory.readCString(args[0]);
            var path = path1.split("/");
            var executable = path[path.length - 1];
            var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
            if (shouldFakeReturn) {
                Memory.writeUtf8String(args[0], "/ggezxxx");
                send("Bypass native fopen >> "+path1);
            }
        },
        onLeave: function(retval) {
 
        }
    });
 
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var path1 = Memory.readCString(args[0]);
            var path = path1.split("/");
            var executable = path[path.length - 1];
            var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
            if (shouldFakeReturn) {
                Memory.writeUtf8String(args[0], "/ggezxxx");
                send("Bypass native fopen >> "+path1);
            }
        },
        onLeave: function(retval) {
 
        }
    });
 
    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
        onEnter: function(args) {
            var cmd = Memory.readCString(args[0]);
            send("SYSTEM CMD: " + cmd);
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "grep");
            }
            if (cmd == "su") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
            }
        },
        onLeave: function(retval) {
 
        }
    });

 
    BufferedReader.readLine.overload().implementation = function() {
        var text = this.readLine.call(this);
        if (text === null) {
            // just pass , i know it's ugly as hell but test != null won't work :(
        } else {
            var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
            if (shouldFakeRead) {
                send("Bypass build.prop file read");
                text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
            }
        }
        return text;
    };
 
    var executeCommand = ProcessBuilder.command.overload('java.util.List');
 
    ProcessBuilder.start.implementation = function() {
        var cmd = this.command.call(this);
        var shouldModifyCommand = false;
        for (var i = 0; i < cmd.size(); i = i + 1) {
            var tmp_cmd = cmd.get(i).toString();
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                shouldModifyCommand = true;
            }
        }
        if (shouldModifyCommand) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["grep"]);
            return this.start.call(this);
        }
        if (cmd.indexOf("su") != -1) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
            return this.start.call(this);
        }
 
        return this.start.call(this);
    };
 
    if (useProcessManager) {
        var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
        var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');
 
        ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }
 
                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
        };
 
        ProcManExecVariant.implementation = function(cmd, env, directory, stdin, stdout, stderr, redirect) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }
 
                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
        };
    }
 
    if (useKeyInfo) {
        KeyInfo.isInsideSecureHardware.implementation = function() {
            send("Bypass isInsideSecureHardware");
            return true;
        }
    }
 
});
setTimeout(function() {

    Java.perform(function () {

        var okhttp3_CertificatePinner_class = null;
        try {
            okhttp3_CertificatePinner_class = Java.use('okhttp3.CertificatePinner');    
        } catch (err) {
            console.log('[-] OkHTTPv3 CertificatePinner class not found. Skipping.');
            okhttp3_CertificatePinner_class = null;
        }

        if(okhttp3_CertificatePinner_class != null) {

            try{
                okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.util.List').implementation = function (str,list) {
                    console.log('[+] Bypassing OkHTTPv3 1: ' + str);
                    return true;
                };
                console.log('[+] Loaded OkHTTPv3 hook 1');
            } catch(err) {
                console.log('[-] Skipping OkHTTPv3 hook 1');
            }

            try{
                okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (str,cert) {
                    console.log('[+] Bypassing OkHTTPv3 2: ' + str);
                    return true;
                };
                console.log('[+] Loaded OkHTTPv3 hook 2');
            } catch(err) {
                console.log('[-] Skipping OkHTTPv3 hook 2');
            }

            try {
                okhttp3_CertificatePinner_class.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (str,cert_array) {
                    console.log('[+] Bypassing OkHTTPv3 3: ' + str);
                    return true;
                };
                console.log('[+] Loaded OkHTTPv3 hook 3');
            } catch(err) {
                console.log('[-] Skipping OkHTTPv3 hook 3');
            }

            try {
                okhttp3_CertificatePinner_class['check$okhttp'].implementation = function (str,obj) {
                    console.log('[+] Bypassing OkHTTPv3 4 (4.2+): ' + str);
                };
                console.log('[+] Loaded OkHTTPv3 hook 4 (4.2+)');
            } catch(err) {
                console.log('[-] Skipping OkHTTPv3 hook 4 (4.2+)');
            }

        }

    });
    
}, 0);

/*
    Bypass fingerprint authentication if the app accept NULL cryptoObject in onAuthenticationSucceeded(...).
    This script should automatically bypass fingerprint when authenticate(...) method will be called.
*/

console.log("Fingerprint hooks loaded!");

Java.perform(function () {
    //Call in try catch as Biometric prompt is supported since api 28 (Android 9)
    try { hookBiometricPrompt_authenticate(); }
    catch (error) { console.log("hookBiometricPrompt_authenticate not supported on this android version") }
    try { hookBiometricPrompt_authenticate2(); }
    catch (error) { console.log("hookBiometricPrompt_authenticate not supported on this android version") }
    try { hookFingerprintManagerCompat_authenticate(); }
    catch (error) { console.log("hookFingerprintManagerCompat_authenticate failed"); }
    try { hookFingerprintManager_authenticate(); }
    catch (error) { console.log("hookFingerprintManager_authenticate failed"); }
});



var cipherList = [];
var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');


});

function getAuthResult(resultObj, cryptoInst) {
    try {
        var authenticationResultInst = resultObj.$new(cryptoInst, null, 0, false);
    } catch (error) {
        try {
            var authenticationResultInst = resultObj.$new(cryptoInst, null, 0);
        } catch (error) {
            try {
                var authenticationResultInst = resultObj.$new(cryptoInst, null);
            }
            catch (error) {
                var authenticationResultInst = resultObj.$new(cryptoInst);
            }
        }
    }
    console.log("cryptoInst:, " + cryptoInst + " class: " + cryptoInst.$className);
    return authenticationResultInst;
}

function getBiometricPromptAuthResult() {
    var sweet_cipher = null;
    var cryptoObj = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
    var cryptoInst = cryptoObj.$new(sweet_cipher);
    var authenticationResultObj = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
    var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
    return authenticationResultInst
}

function hookBiometricPrompt_authenticate() {
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    console.log("Hooking BiometricPrompt.authenticate()...");
    biometricPrompt.implementation = function (cancellationSignal, executor, callback) {
        console.log("[BiometricPrompt.BiometricPrompt()]: cancellationSignal: " + cancellationSignal + ", executor: " + ", callback: " + callback);
        var authenticationResultInst = getBiometricPromptAuthResult();
        callback.onAuthenticationSucceeded(authenticationResultInst);
    }
}

function hookBiometricPrompt_authenticate2() {
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    console.log("Hooking BiometricPrompt.authenticate2()...");
    biometricPrompt.implementation = function (crypto, cancellationSignal, executor, callback) {
        console.log("[BiometricPrompt.BiometricPrompt2()]: crypto:" + crypto + ", cancellationSignal: " + cancellationSignal + ", executor: " + ", callback: " + callback);
        var authenticationResultInst = getBiometricPromptAuthResult();
        callback.onAuthenticationSucceeded(authenticationResultInst);
    }
}

function hookFingerprintManagerCompat_authenticate() {
    /*
    void authenticate (FingerprintManagerCompat.CryptoObject crypto, 
                    int flags, 
                    CancellationSignal cancel, 
                    FingerprintManagerCompat.AuthenticationCallback callback, 
                    Handler handler)
    */
    var fingerprintManagerCompat = null;
    var cryptoObj = null;
    var authenticationResultObj = null;
    try {
        fingerprintManagerCompat = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat');
        cryptoObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
        authenticationResultObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
    } catch (error) {
        try {
            fingerprintManagerCompat = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat');
            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
        }
        catch (error) {
            console.log("FingerprintManagerCompat class not found!");
            return
        }
    }
    console.log("Hooking FingerprintManagerCompat.authenticate()...");
    var fingerprintManagerCompat_authenticate = fingerprintManagerCompat['authenticate'];
    fingerprintManagerCompat_authenticate.implementation = function (crypto, flags, cancel, callback, handler) {
        console.log("[FingerprintManagerCompat.authenticate()]: crypto: " + crypto + ", flags: " + flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: " + handler);
        //console.log(enumMethods(callback.$className));
        callback['onAuthenticationFailed'].implementation = function () {
            console.log("[onAuthenticationFailed()]:");
            var sweet_cipher = null;
            var cryptoInst = cryptoObj.$new(sweet_cipher);
            var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
            callback.onAuthenticationSucceeded(authenticationResultInst);
        }
        return this.authenticate(crypto, flags, cancel, callback, handler);
    }
}

function hookFingerprintManager_authenticate() {
    /*
    public void authenticate (FingerprintManager.CryptoObject crypto, 
                    CancellationSignal cancel, 
                    int flags, 
                    FingerprintManager.AuthenticationCallback callback, 
                    Handler handler)
Error: authenticate(): has more than one overload, use .overload(<signature>) to choose from:
    .overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler')
    .overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler', 'int')


    */
    var fingerprintManager = null;
    var cryptoObj = null;
    var authenticationResultObj = null;
    try {
        fingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
        cryptoObj = Java.use('android.hardware.fingerprint.FingerprintManager$CryptoObject');
        authenticationResultObj = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
    } catch (error) {
        try {
            fingerprintManager = Java.use('androidx.core.hardware.fingerprint.FingerprintManager');
            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$CryptoObject');
            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$AuthenticationResult');
        }
        catch (error) {
            console.log("FingerprintManager class not found!");
            return
        }
    }
    console.log("Hooking FingerprintManager.authenticate()...");

    var fingerprintManager_authenticate = fingerprintManager['authenticate'].overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler');
    fingerprintManager_authenticate.implementation = function (crypto, cancel, flags, callback, handler) {
        console.log("[FingerprintManager.authenticate()]: crypto: " + crypto + ", flags: " + flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: " + handler);
        var sweet_cipher = null;
        var cryptoInst = cryptoObj.$new(sweet_cipher);
        var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
        callback.onAuthenticationSucceeded(authenticationResultInst);
        return this.authenticate(crypto, cancel, flags, callback, handler);
    }
}


function enumMethods(targetClass) {
    var hook = Java.use(targetClass);
    var ownMethods = hook.class.getDeclaredMethods();

    return ownMethods;
}
