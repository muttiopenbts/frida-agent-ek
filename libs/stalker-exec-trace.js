/* stalker-exec-trace.js
 * Experimental code. Needs to be examined and cleaned.
 */
"use strict";
const SEARCH_MODULE_NAME = "hello_frida";
var modules = Process.enumerateModules();

var module_name = null;
// Search all loaded modules for matching name specified
for (var i = 0; i < modules.length; i++) {
    if (modules[i].name.indexOf(SEARCH_MODULE_NAME) > -1) {
        module_name = modules[i].name;
    }
}
// Will use base address in combination with any offset addresses
const BASE = Module.findBaseAddress(module_name);


function StalkerExeample() 
{
    var threadIds = [];
    
	Process.enumerateThreads({
		onMatch: function (thread) {
			threadIds.push(thread.id);
			console.log("Thread ID: " + thread.id.toString());
		},
		onComplete: function () {
			threadIds.forEach(function (threadId) {
                Stalker.follow(threadId, {
                    events: {call: true, exec: false, ret: false},
					
					onReceive: function (events) {
                        var log = []
                        var mm = new ModuleMap;
                        /*
                        var stalker_evts = Stalker.parse(events, {
                            annotate    : true,
                            stringify   : true
                        });
                        */

                        var stalker_evts = Stalker.parse(events);

                        for (var evt in stalker_evts) {
                            //log.push(`Event: ${evt}\n`);
                        }

                        for (var i = 0; i < stalker_evts.length; i++) {
                            // https://github.com/frida/frida-gum/blob/master/gum/gumevent.h
                            const ev = stalker_evts[i];
                            const type = ev[0];
                            const location = ev[1];
                            const target = ev[2];
                            const symbol = DebugSymbol.fromAddress(target);
                            const instr = Instruction.parse(target).toString()
                            var stalked_module = mm.find(target);
                  
                            /* This code will highlight the fileExists call in the stack */
                            //if (!!symbol && !!symbol.name && (symbol.name.indexOf('fileExists') >= 0)) {
                            //  console.warn('fileExists');
                            //  found_at = i;
                            //  break;
                            //}
                            
                            /* This code will display a frame that belongs to our module */
                            if (!!symbol) {
                                if (stalked_module.name == SEARCH_MODULE_NAME) {
                            const instr = Instruction.parse(target).toString()
                                    log.push(`Stalker: ${type}\t${location}\t${target}\t${symbol}\t${instr}\n`);
                                    //log.push(`Instru: ${instr}\n`);
                                    //log.push(`Symbol: ${symbol}\n`);
                                    //log.push(`Stalked module name: ${stalked_module.name}\n`);
                                }
                            }
                        }

                        //log.push(`Event: ${stalker_evts}\n`);
                        console.log(`onReceive called:\n${log}\n`);
                    },
                    /*
					onCallSummary: function (summary) {
                        var log = []
                        var mm = new ModuleMap;
    
                        for (i in summary) {
                            var addr = ptr(i);
                            var stalked_func = mm.find(addr);
                            
                            log.push(`Stalked addr ${addr}\n`);

                            if (stalked_func) {
                                log.push(`Stalked symbol for ${addr}: ${DebugSymbol.fromAddress(addr)}\n`);
                                log.push(`Stalked instruc for ${addr}: ${Instruction.parse(addr).toString()}\n`);
                                
                                log.push(`Stalked path for ${addr}: ${stalked_func.path}\n`);
                                log.push(`Stalked name for ${addr}: ${stalked_func.name}\n`);
                                log.push(`Stalked size for ${addr}: ${stalked_func.size}\n`);
                            }
                        }
                        console.log(`onCallSummary called.\n${log}`);
                    }
                    */
				});
			});
		}
	});
}

StalkerExeample();