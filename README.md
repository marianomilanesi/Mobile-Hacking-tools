***Execution commands multibypass***

frida -U -f '<com.apk>' -l .\multipass.js

***Execution commands minimalist_bypass***

frida -U -p '<PID>' -l minimBypass_pinning.js
