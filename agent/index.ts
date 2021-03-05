import { log } from "./logger";
import { 
    do_intercept,
    do_get_exports,
    do_find_functions
} from "../libs/frida_process";
import { 
    net_hooks_backtrace,
    enumerate_all_exports
} from "../libs/frida-net";
const os = require('os');

console.log(`Agent running on ${os.release()} ${os.type()} ${os.platform()}`)
 
rpc.exports = {
    /*  Example of how to parse command line parameters
     *
     * Using eval is dangerous so do not use this in production code unless you know what you're doing.
     * e.g. 
     * frida -f ~/my_binary -l _agent.js -P '{"call":["do_get_exports","\"libSystem.B.dylib\""]}' --no-pause --runtime=v8
     */ 
    init: function (stage, cmdline_json) {
        /* Init is automatically run with frida.
         */
        console.log(`[init], ${stage}, ${JSON.stringify(cmdline_json)}`);
        rpc.exports.cmdline_json = cmdline_json;

        Object.keys(rpc.exports.cmdline_json).forEach(key => {
            /* Expect following json:
                    "call": ["function name","parameter"]
                    "appname": string 
             */
                if (key === 'appname') {
                    rpc.exports.appname = (rpc.exports.cmdline_json as any)[key]
                    console.log(`App name is  ${rpc.exports.appname}`)
                }

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
                        rpc.exports.call_func_name = func_name
                        rpc.exports.call_func_params = func_params as any
                        rpc.exports.call_func = `${func_name}(${func_params})` as any
                    } else if (typeof call_func === 'string') {
                        rpc.exports.call_func_name = call_func as any
                        rpc.exports.call_func = `${call_func}()` as any
                    }
                }
            });
    },
    dispose: function () {
        console.log('[dispose]');
    }
};


/* Main
 * Avoid java.lang.ClassNotFoundException by using setTimeout().
 */
(function main() {
    setTimeout(async () => {
            if (typeof rpc.exports.call_func !== 'undefined' && `${rpc.exports.call_func}` !== '') { 
                console.log(`Running ${rpc.exports.call_func_name}: ${JSON.stringify(rpc.exports.call_func_params)} ${typeof rpc.exports.call_func_params}`)
                // Validate user function call for safety.
                switch (`${rpc.exports.call_func_name}`) {
                    case "do_get_exports":  do_get_exports(`${rpc.exports.call_func_params}`); return;
                    case "do_intercept":    do_intercept(`${rpc.exports.call_func_params}`); return;
                    case "net_hooks_backtrace":    
                        const funcs_params = rpc.exports.call_func_params as any
                        net_hooks_backtrace(funcs_params[0], funcs_params[1]); 
                        return;
                    case "enumerate_all_exports": enumerate_all_exports(); return;
                    case "do_find_functions":
                        const func_params = rpc.exports.call_func_params as any
                        do_find_functions(func_params[0]); return;
                    default: console.log(`Failed to run. No matching function.`); return;
                }
            } else {
                console.log(`Can't run, Must specify function to call.`)
            }
        }, 1000);
})();