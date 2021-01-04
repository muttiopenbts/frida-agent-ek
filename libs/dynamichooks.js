/* MobSF Android API Monitor
 * Inspired from: https://github.com/realgam3/ReversingAutomation/blob/master/Frida/Android-DynamicHooks/DynamicHooks.js
 *
 * Need setTimeout() to delay execution of frida so that app has time to fully load
 * all classes. Too soon and we get java.lang.ClassNotFoundException
 */

import { get_class_methods } from "../libs/android-full-class-methods";
var debug = false;

// Example
var _apis = [{
    class: 'com.unity3d.player.WWW',
    method: 'runSafe',
    name: 'runSafe'
}]

export function log_to_file(data, filename) {
    if (filename == undefined || filename === '') {
        console.log(`No filename specified.`)
        return
    }

    Java.perform(function () {
        // a,w,r,w+,r+ modes, same as fopen in c
        var file = new File(filename,"a");
        file.write(data);
        file.close();
    });
}

function stack_trace() {
    var ThreadDef = Java.use('java.lang.Thread');
    var ThreadObj = ThreadDef.$new();

    var stack = ThreadObj.currentThread().getStackTrace();
    let trace_info = ''

    for (var i = 0; i < stack.length; i++) {
        trace_info += `${i} => ${stack[i].toString()}\n`;
    }

    return trace_info;
}

// Get All Method Implementations
function get_implementations(toHook) {
    var imp_args = []
    toHook.overloads.forEach(function (impl, _) {
        if (impl.argumentTypes) {
            var args = [];
            var argTypes = impl.argumentTypes
            argTypes.forEach(function (arg_type, __) {
                args.push(arg_type.className)
            });
            imp_args.push(args);
        }
    });
    return imp_args;
}

// Dynamic Hooks
function _hook(api, callback) {
    /*  Params
        api = {class:, method:}
            class = string
            method = string
     */
    var Exception = Java.use('java.lang.Exception');
    var toHook;
    try {
        var clazz = api.class;
        var method = api.method;
        var name = api.name;
        try {
            if (api.target && parseInt(Java.androidVersion, 10) < api.target) {
                // send('[API Monitor] Not Hooking unavailable class/method - ' + clazz + '.' + method)
                return
            }
            
            // Check if class and method is available
            toHook = Java.use(clazz)[method];

            if (!toHook) {
                let msg = `Nohook [API Monitor] Cannot find ${clazz}.${method}\n${name}`;
                send(msg);
                console.log(msg)
                return
            }
        } catch (err) {
            let msg = `Exception [API Monitor] Cannot find ${clazz}.${method}\n${name}\n${err}`;
            send(msg);
            console.log(msg)
            return
        }

        var overloadCount = toHook.overloads.length;
        for (var i = 0; i < overloadCount; i++) {
            toHook.overloads[i].implementation = function () {
                var argz = [].slice.call(arguments);
                // Call original function
                var retval = this[method].apply(this, arguments);
                let argz_stringed = [];

                // Try to convert any objects into a printable string
                argz.forEach(x => { x !== null && argz_stringed.push(JSON.stringify(x, null, 2)) })

                if (callback) {
                    var calledFrom = Exception.$new().getStackTrace().toString().split(',')[1];
                    var message = {
                        name: name,
                        class: clazz,
                        method: method,
                        arguments: argz,
                        arguments_stringed: argz_stringed,
                        result: retval ? JSON.stringify(retval, null, 2) : null,
                        calledFrom: calledFrom
                    };
                    retval = callback(retval, message);
                }
                return retval;
            }
        }
    } catch (err) {
        send('[API Monitor] - ERROR: ' + clazz + "." + method + " [\"Error\"] => " + err);
    }
}

function countProperties(obj) {
    return Object.keys(obj).length;
}

function hook(api, callback) {
    /*  Params
        api = {class:, method:}
            class = string
            method = string | [string,]
     */
    var clazz = api.class;
    var method = api.method;
    var name = api.name;

    // Do we have a class defined with a single method?
    if (typeof(api.method) === 'string') {
        debug && console.log(`Would be string: ${clazz}`)
        // Some hooks might never be reached so we need to add an initial count of 0.
        hook_stats[api.class + '.' + api.method] = 0

        _hook(api, callback);
    }
    else if (Array.isArray(api.method) ) {
        debug && console.log(`Would be array: ${clazz}`)
        method.forEach( method_name => {
            debug && console.log(`array: ${method_name}`)
            
            // Some hooks might never be reached so we need to add an initial count of 0.
            hook_stats[api.class + '.' + method_name] = 0

            if (api.name == undefined || api.name === '') {
                name = clazz + '.' + method_name;
            }
                _hook( {class: clazz, method: method_name, name: name} , callback);
        })
    }
    else {
        console.log(`Would be ${typeof(api.method)}, ${clazz}`)
    }

}

/* Variable is accessible from outside. Pupose is to keep count of num times
 * a hook is called.
 */
export var hook_stats = {};

function incre_stat(class_and_method) {
    // Used to keep count on number of times hooked function is called.
    // TODO: fix overloaded methods. Some class+methods will dup.
    // Increment
    if (hook_stats[class_and_method]) {
        hook_stats[class_and_method] += 1;
    }
    // Create new key
    else{
        hook_stats[class_and_method] = 1;
    }
}


function do_dynamichooking() {
    /*  Hook android api calls methods.
        Prints to console hooked functions.
        Logs function name and parameters to file on Frida agent host.
        TODO: add params
     */
    let class_regex = /my_class/ // e.g. /ReflectionHelper/;
    let methods_regex = /my_method/ // e.g. /nativeProxyInvoke/; // Works when settimeout = 100

    const log_filename = `/data/data/${APP_NAME}/files/dump-classes-${get_timestamp()}.txt`;

    // Populate with list of classes and their method names for hooking.
    let api_list = []

    for (let [clazz, methods] of Object.entries(get_class_methods(class_regex, methods_regex)) ) {
        api_list.push({
            class: clazz,
            method: methods
        });
    }

    deploy_hooks({ api_list: api_list, log_file: log_filename});
    
    (async function display_loop() {
        while (true) {
            console.log(JSON.stringify(hook_stats, null, 2));
            console.log(`Hooks total: ${get_length(hook_stats)}`);
            log_to_file(JSON.stringify(hook_stats, null, 2) + '\n' + get_length(hook_stats), log_filename);

            await sleep(20000);
        }
    })();
}


export function deploy_hooks({api_list = [], log_file = ''}) {
    Java.performNow(function () {
        api_list.forEach(function (api, _) {

            hook(api, function (originalResult, message) {
                message.returnValue = originalResult

                if (originalResult && typeof originalResult === 'object') {
                    var s = [];

                    for (var k = 0, l = originalResult.length; k < l; k++) {
                        s.push(originalResult[k]);
                    }
                    message.returnValue = '' + s.join('');
                }

                if (!message.result) {
                    message.result = undefined;
                }

                if (!message.returnValue) {
                    message.returnValue = undefined;
                }

                let msg = `MobSF-API-Monitor: ${JSON.stringify(message, null, 2)}, `;
                debug && send(msg);
                debug && console.log(`${msg}, `);

                incre_stat(message.class + '.' + message.method);

                if (log_file) {
                    log_to_file(msg, log_file)
                    log_to_file(stack_trace(), log_file)
                }

                return originalResult;
            });
        });
    });
}


export function load_library_hook() {
    /* Taken from https://awakened1712.github.io/hacking/hacking-frida/
     */
    Java.perform(function() {
        const System = Java.use('java.lang.System');
        const Runtime = Java.use('java.lang.Runtime');
        const VMStack = Java.use('dalvik.system.VMStack');
    
        System.loadLibrary.implementation = function(library) {
            try {
                console.log('System.loadLibrary("' + library + '")');
                const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
                return loaded;
            } catch(ex) {
                console.log(ex);
            }
        };
        
        System.load.implementation = function(library) {
            try {
                console.log('System.load("' + library + '")');
                const loaded = Runtime.getRuntime().load0(VMStack.getCallingClassLoader(), library);
                return loaded;
            } catch(ex) {
                console.log(ex);
            }
        };
    });    
}


export function intercept_dlopen(address) {
    try {
        Interceptor.attach(address, {
            onEnter: function(args) {
                this.lib = Memory.readUtf8String(args[0]);
	        console.log("dlopen called with: " + this.lib);
            },
            onLeave: function(ignored) {}
        });
    } catch (e) {
        console.error(e);
    }
}
 
export function find_dlopen_symbol() {
	var dlopenSymbol;
	symbols.forEach(function(symbol){
		if (symbol.name == '__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv') {
			 dlopenSymbol = symbol;			 
		 } else if (symbol.name == '__dl__Z9do_dlopenPKciPK17android_dlextinfoPv') {
			 dlopenSymbol = symbol;
		 } else if (symbol.name == '__dl__ZL10dlopen_extPKciPK17android_dlextinfoPv') {
			 dlopenSymbol = symbol;
		 } else if (symbol.name == '__dl__Z20__android_dlopen_extPKciPK17android_dlextinfoPKv') {
			 dlopenSymbol = symbol;
		 } else if (symbol.name == '__dl___loader_android_dlopen_ext') {
			 dlopenSymbol = symbol;
		 } else if (symbol.name == '__dl__Z9do_dlopenPKciPK17android_dlextinfo') {
			 dlopenSymbol = symbol;
		 } else if (symbol.name == '__dl__Z8__dlopenPKciPKv') {
			 dlopenSymbol = symbol;
		 } else if (symbol.name == '__dl___loader_dlopen') {
			 dlopenSymbol = symbol;
		 } else if (symbol.name == '__dl_dlopen') {
			 dlopenSymbol = symbol;
		 }
		 
	});
	return dlopenSymbol;
}


// Main
function main() {
    setTimeout(function(apis) {
        deploy_hooks();
    }, 1000);
}
