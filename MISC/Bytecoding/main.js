const vm = require('vm');
const fs = require('fs');
const path = require('path');

const flag = process.env.FLAG || "FLAG{real_flag_would_be_here}";
delete process.env.FLAG;


// Don't you have checker.js? Oh, we're so sorry... 
const checkerCode = fs.readFileSync(path.join(__dirname, 'checker.js'), 'utf8');
const checkerCtx = {};
vm.runInNewContext(checkerCode, checkerCtx);
const checkForbidden = checkerCtx.checkForbidden;

const CHECKER_CACHE = 'VgbewElxuZj0AQAAw7yUqsunv6YYAwAAAAAAAAAAAAABJFQDLAe0YAAAAAATAAAAAQgHuQoEBB8DEAeJAWIAAAAADAAAAAEEDwAK+AQJAAbYCgAAAAAfByUNHwMQB4EBYAAAAAACAAAAARBMYAAAAAACAAAAASRUAwwHKQtJYIABAADzAQAAYAAAAAD/////ARBSYgbi5VEOAAAAY2hlY2tGb3JiaWRkZW4AAAEoU2RAMAAEAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAD0AQAAARBSYlLNzB4JAAAARk9SQklEREVOAAAAAAAAAGAAAAAAwf8/AElgAAAAAP////8BSAf9CggAARRSY16dPCoXAAAAZXZhbG1hY2hpbmUuPGFub255bW91cz4AYQAAAAAAAAAAAAAAAAAAAABEYgAAAAACAAAAAAAAAAAAAAAAAAAAVAAAAERgAAAAAAAAAAABEAdpAWAAAAAAAgAAABgEABgEGERgAAAAAAoAAACARF1EYgEAAgAXAAAAABEAAAEAAAB5DAAAAAAAAGAAAAAAAAAAAAEMB6UKYAAAAAACAAAAAThNYAAAAAAMAAAAAQxSYYZQErYHAAAAcmVxdWlyZQABDFJhqhYUJAcAAABwcm9jZXNzAAdhBgEQUmJiHlGXDAAAAHJlYWRGaWxlU3luYwAAAAABDFJhitCbFQgAAABleGVjU3luYwEQUmK+0b7kCQAAAHNwYXduU3luYwAAAAAAAAABEFJiDixjaQ0AAAB3cml0ZUZpbGVTeW5jAAAAARBSYqJGonkKAAAAbWFpbk1vZHVsZQAAAAAAAAEMUmHClDl2BwAAAGJpbmRpbmcAAQxSYVqCh7oIAAAAb3BlblN5bmMBEFJi1sSFfQ0AAABjcmVhdGVSZXF1aXJlAAAAAQxSYfJujtQDAAAAZW52AAAAAABkGAAAAAEAAAAAAAAAAAAAABMAyRn+92hkAfgCfgEAJSUDDq8AAAAAAGAAAAAA/////wQkAQwHpGEBAAAAAQAAABMAAAACAAAABCxiAAABAAAAAgAAEAAIAAAAAHgMAAAAAAAACwoKCgoKCgo=';

// â”€â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const getCompiledCode = (code) => {
    const script = new vm.Script(code);
    const cachedData = script.createCachedData();
    return { script, cachedData };
};

// â”€â”€â”€ Main sandbox â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const runUntrustedCode = (codeString) => {

    const blocked = checkForbidden(codeString);
    if (blocked) {
        return 'Security Error';
    }

    const ctx = {};
    try {
        const { script } = getCompiledCode(codeString);
        script.runInNewContext(ctx, { timeout: 1000 });
        return ctx;
    } catch (e) {
        return "Runtime Error: " + e.message;
    }
};

// â”€â”€â”€ Entry point â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

try {
    const userCode = fs.readFileSync(0, 'utf8');
    if (!userCode) {
        console.log("Send your javascript payload via stdin.");
    } else {
        const result = runUntrustedCode(userCode);
        const response = {
            cache: CHECKER_CACHE,
            result: result
        };
        process.stdout.write(JSON.stringify(response) + "\n", () => {
            process.exit(0);
        });
    }
} catch (error) {
    console.error("CRASH:", error);
    process.stdout.write("Internal Error\n", () => process.exit(1));
}