/* Test
 * $ frida -l <this script's name>.js -o ftrace-output-`date +%m%d%Y-%T`.txt -p `pgrep <proc name>` --runtime=v8 --no-pause
 * Searches through every module's export list looking for functions that starts with a particular name and hooks.
 * Experimental code. Needs to be examined and cleaned.
 */

import { get_backtrace, getBase } from "../libs/memo-intercept";
import { stringify } from "querystring";

var saved_hosts = [];


export function enumerate_all_exports() {
    Process
    .enumerateModules()
    .forEach(mod => 
        Process
        .getModuleByName(mod.name)
        .enumerateExports()
        .forEach(ex => {   
             console.log(`${mod.name}: ${ex.name}`)
        }))
}

export function net_hooks_backtrace(hooked_funcs, details) {
    /* Hooks network functions and displays new sockets only.
     * Backtrace will impact performance and in my experience, cause app to stop.
     * 
     * Params
     * hooked_funcs = ['recv','recvmsg'];
     * 
     * Optional
     * details =       array of k,v. [{'port':number, 'buffer':boolean, 'backtrace':boolean, 'protocol':boolean},]
     *                port is port number. buffer determines if caller wants to display buffer data.
     *
     * net_hooks_backtrace(['recv',], [
     *        {'protocol': 'udp', 'port':5056, 'buffer':false, 'backtrace':true, 'bt_sample_size': 5},
     * ]);
     */
    // To help reduce slow down in backtraces, only collect bt on every nth
    let bt_count = 0;
    console.log(`Hooking ${hooked_funcs}`)

    // Validate params
    if (! Array.isArray(hooked_funcs)) {
        console.log(`${hooked_funcs}`)
        return console.log(`Must specify hooked functions in array and not ${typeof hooked_funcs}. End app.`)
    }

    if (! Array.isArray(details) || (typeof details[0] !== 'object')) {
        console.log(`${details}`)
        return console.log(`Must specify hooked function's details in array and not ${typeof details}. End app.`)
    }

    Process
    .enumerateModules()
    .forEach(mod => 
        Process
        .getModuleByName(mod.name)
        .enumerateExports().filter(ex => ex.type === 'function' && hooked_funcs.some(prefix => ex.name.indexOf(prefix) === 0) )
        .forEach(ex => {
            Interceptor.attach(ex.address, {
                    onEnter: function (this, args) {
                        // Tested with https://linux.die.net/man/2/recv 
                        var fd = args[0].toInt32();
                        var buff = args[1];
                        var len = args[2].toInt32();
                
                        if ((fd != undefined) && (fd != null) && Socket.type(fd) != null) {
                            let message = `${ex.address} ${ex.name}`;
                            let protocol = `${Socket.type(fd)}`;
                            let address = Socket.peerAddress(fd);

                            if (address === null) {
                                return;
                            }

                            //if (details === undefined) {
                            //    return console.log(`Must specify hook details.`)
                            //}

                            // Examine if socket meets caller's criteria and what to track
                            details.forEach( detail => {
                                // Does port and protocol match
                                if (detail.port === address.port
                                        && detail.protocol === protocol) {

                                    let connection = `${protocol}:${address.ip}:${address.port}`;

                                    // Keep a record of new sockets.
                                    if (!saved_hosts.includes(connection)) {
                                        saved_hosts.push(`${connection}`);
                                        message += `--\t${protocol}\n${fd} ${ex.name} ${connection}`;
                                    }
                
                                    if (detail.backtrace === true) {
                                        // Take sample backtrace now?
                                        if (detail.bt_sample_size !== undefined && bt_count <= detail.bt_sample_size) {
                                            bt_count += 1;
                                        }
                                        else {
                                            let backtrace = get_backtrace(this.context);
                                            message +=  `\n${mod.name}\n${backtrace.accurate_sysmbols}`; 

                                            //reset counter
                                            bt_count = 0;
                                        }
                                    }

                                    // Check if caller wants to read function buffer
                                    if (detail.buffer === true) {
                                        // Save buffer pointer so we can retrieve contents once filled on exit.
                                        this.save = {'buffer': buff, 'len': len}
                                    }

                                    console.log(message);
                                    console.log(JSON.stringify(saved_hosts));    
                                }
                            })
                        }
                    },
                    onLeave: function (retval) {
                        if (this.save !== undefined) {
                            //Short hexdump
                            this.save.len = 64;

                            console.log(hexdump(this.save.buffer, {length: this.save.len, ansi: true}));
                            this.save = {};
                        }
                    }
            })
        })
);
} 


export function net_hooks_optimized(hooked_funcs, port_nos) {
    /* Working experiment.
     * Implements CModule for better performance.
     * net_hooks_backtrace_optimized(['recvfrom',], [{'num':5056, 'buffer':true, 'backtrace':false},]);
     */
    const cmodule = new CModule(`
    #include <gum/guminterceptor.h>
  
    extern void onMessageSocket (int * fd);
    extern void onMessageText (const gchar * message);
  
    static void log (const gchar * format, ...);
    static void send_fd (int * fd, ...);
  

    void 
    onEnter (GumInvocationContext * ic)
    {
        int fd;
        fd = (int) gum_invocation_context_get_nth_argument (ic, 0);

        if (fd) {
            send_fd (&fd);
        }
    }
  
    static void send_fd(int *fd, ...)
    {
        onMessageSocket (fd);
    }

    static void
    log (const gchar * format,
         ...)
    {
        gchar * message;
        va_list args;

        va_start (args, format);
        message = g_strdup_vprintf (format, args);
        va_end (args);

        onMessageText (message);

        g_free (message);
    }
    `, {
        onMessageSocket: new NativeCallback(messagePtr => {
            const fd = messagePtr.readPointer().toInt32();
            let protocol = Socket.type(fd);
            let address = Socket.peerAddress(fd);

            if (protocol === 'udp' && address.port === 5056) {
                console.log(`onMessage ${typeof(fd)}: fd ${fd}, ${protocol}, ${address.ip}, ${address.port}`);
            }
        }, 'void', ['pointer']),
        onMessageText: new NativeCallback(messagePtr => {
            const message = messagePtr.readUtf8String();
            console.log('onMessageText:', message);
            }, 'void', ['pointer'])       
    });

    Process
    .enumerateModules()
    .forEach(mod => 
        Process
        .getModuleByName(mod.name)
        .enumerateExports().filter(ex => ex.type === 'function' && hooked_funcs.some(prefix => ex.name.indexOf(prefix) === 0) )
        .forEach(ex => {
            console.log(`enum ${mod.name}->${ex.name} addr: ${ex.address}`);
            Interceptor.attach(ex.address,  cmodule);
        })
    );
}