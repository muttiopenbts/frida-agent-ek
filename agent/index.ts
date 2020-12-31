import { type } from "os";
import { log } from "./logger";
 
/*  Example of how to parse command line parameters
    Using eval is dangerous so do not use this in production code unless you know what you're doing.
    e.g. 
    frida -f ~/my_binary -l _agent.js -P '{"call":["do_get_exports","\"libSystem.B.dylib\""]}' --no-pause --runtime=v8

 */ 
rpc.exports = {
    init: function (stage, cmdline_json) {
        console.log('[init]', stage, JSON.stringify(cmdline_json));
        rpc.exports.cmdline_json = cmdline_json;

        Object.keys(rpc.exports.cmdline_json).forEach(key => {
                if (key === 'call') {
                    // Function call type parameter
                    let call_func = (rpc.exports.cmdline_json as any)[key]
                    console.log(`Calling function ${call_func} and typeof ${typeof call_func}`)

                    if (Array.isArray(call_func)) {
                        // Check if user has passed function within json array.
                        console.log(`Parameter option is array.`)

                        let temp_array = call_func

                        let func_name = temp_array.shift()
                        let func_params = temp_array

                        if (is_allowed(func_name)) {
                            call_func = `${func_name}(${func_params})`
                        } else {
                            // Cause invocation to fail. Better to raise exception?
                            console.log(`Can't run: Function doesn't exist or not approved`)
                            throw 'Function not authorized!';
                        }

                    } else if (typeof call_func === 'string') {
                        if (is_allowed(call_func)) {
                            call_func = `${call_func}()`
                        } else {
                            // Cause invocation to fail. Better to raise exception?
                            console.log(`Can't run: Function doesn't exist or not approved`)
                            throw 'Function not authorized!';
                        }
                    }

                    if (typeof call_func !== 'undefined' && call_func !== '') { 
                        console.log(`Running ${call_func}`)
                        // Function name should have been validated for safety.
                        eval(call_func)
                    } else {
                        console.log(`Can't run: Function doesn't exist or not approved`)
                    }
                }
            });
    },
    dispose: function () {
        console.log('[dispose]');
    }
};

function is_allowed(func_name:string) {
    /*  Validate authorized function names that can be specified
        from agent process invocation
     */
    switch (func_name) {
        case "do_get_exports": return true;
    }
}

function do_get_exports(module_name: string){
    // e.g. Param: "libSystem.B.dylib"
    Process.getModuleByName(module_name)
        .enumerateExports()
        .slice(0, 16)
        .forEach((exp, index) => {
            log(`export ${index}: ${exp.name}`);
        });
}

function do_intercept(export_name: string){
    // e.g. Param: "open"
    Interceptor.attach(Module.getExportByName(null, export_name), {
        onEnter(args) {
            const path = args[0].readUtf8String();
            log(`open() path="${path}"`);
        }
    });       
}
