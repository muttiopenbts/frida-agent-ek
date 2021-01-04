/* Experimental code. Needs to be examined and cleaned.
 */
"use strict";

const JSON5 = require('json5')

export function get_previous_instr(addr: NativePointer) {
    /**
     * Returns previous machine instruction from addr.
     * TODO: this is a hack and not accurate. Better to add a disassembler
     * like capstone.
     *
     * @param: {NativePointer} addr.
     * Returns: {object} Frida Instruction.parse
     */
    let current_instr: any = Instruction.parse(addr);
    let prev_addr:any = current_instr;

    var i;
    var max_instr_size = 30; //x86 is 15 bytes. 30 more than enough

    for (i = 1; i < max_instr_size; i++) {
        let sub_addr = addr.sub(i);
        //console.log(`${sub_addr}`);
        let guess_prev_addr;
        let guess_next_addr: any;

        try {
            guess_prev_addr = Instruction.parse(sub_addr);

            guess_next_addr = Instruction.parse(guess_prev_addr.next)
            /*
             * console.log(`get_previous_instr guess_next_addr\t @${guess_next_addr.address}\t${guess_next_addr.toString()}`);
             * console.log(`guess next address ${guess_next_addr.address}`);
             * console.log(`real next address ${current_instr.address}`);
             * console.log(`Does previous next match known current? = ${current_instr.toString() === guess_next_addr.toString()}`);
             * console.log(`Do they size match? = ${current_instr.size === guess_next_addr.size}`);
             * console.log(`Do they address match? = ${current_instr.address === guess_next_addr.address}`);
             * console.log(`Diff? = ${current_instr.address - guess_next_addr.address}`);
             */
        }
        catch (err) {
            //console.log(`Bad Instruction.parse() for ${sub_addr}`);
            continue;
        }
        

        if (current_instr.toString() === guess_next_addr.toString()
            && (current_instr.address - guess_next_addr.address == 0)) {
            /* Real and guess must match assembly instruction and address.
             * Couldn't get addresses to match, but substraction did.
             */

            prev_addr = guess_prev_addr;
            //console.log('Found a match.');
            break;
        }
    }

    return prev_addr;
}

export function get_backtrace(context: any) {
    /*
    Thread.backtrace([context, backtracer]): generate a backtrace for the current
    thread, returned as an array of NativePointer objects.

    If you call this from Interceptor’s onEnter or onLeave callbacks you should
    provide this.context for the optional context argument, as it will give you a
    more accurate backtrace.
    */

    let result_fuzzy: object[] = [];
    let result_accurate: object[] = [];

    let backtrace_fuzzy_symbols = Thread.backtrace(context, Backtracer.FUZZY)
        .map(function(x) {
            let line = `${DebugSymbol.fromAddress(x)}\t`;
            line += `${Instruction.parse(x).toString()}\t`;
            line += `${get_previous_instr(x).address}\t`;
            line += `${get_previous_instr(x).toString()}`;

            result_fuzzy.push({'address': x});

            return line;
        })
        .join("\n\t");

    let backtrace_accurate_symbols = Thread.backtrace(context, Backtracer.ACCURATE)
        .map(function (x) {
            let line = `Symbol: ${DebugSymbol.fromAddress(x).toString()}\t`;

            try {
                line += `Instr: ${Instruction.parse(x).toString()}\t`;
                line += `Prev instr address: ${get_previous_instr(x).address}\t`;
                line += `Prev instr: ${get_previous_instr(x).toString()}`;
            }
            catch (err) {
                //pass
            }
            result_accurate.push({'address': x});

            return line;
        })
        .join("\n");

    return {'fuzzy':result_fuzzy, 
            'accurate':result_accurate, 
            'fuzzy_symbols': backtrace_fuzzy_symbols, 
            'accurate_sysmbols': backtrace_accurate_symbols};
}

export function memo_intercept(module: string, addr: string, cb: void) {
    /*
     * Params:
     * module  Name of module where addr is offset to. Can be main binary or library.
     * addr    Offset address within module where hook will be applied.
     * cb      Not used.
     *
     * .e.g    var monitor_addr = "0x116d"; // Linux
     *         var monitor_addr = "0xee1"; //Mac
     */
    var searchModule = module;
    var modules = Process.enumerateModules();
    let moduleName: string = '';
    var monitor_addr = addr;
    var return_addr_list;

    for (var i = 0; i < modules.length; i++) {
        if (modules[i].name.indexOf(searchModule) > -1) {
            moduleName = modules[i].name;
        }
    }
    
    var base: NativePointer | null = Module.findBaseAddress(moduleName);

    if (base === null) {
        return
    }
    
    var monitor_addr_real = new NativePointer(base.add(ptr(monitor_addr)))
    
    console.log("moduleName: " + moduleName);
    console.log("Base value: " + base);
    
    var callback = {
        onEnter: function(this: any, args: any) {
            console.log("Callback for memory monitor hit on: ", JSON.stringify(monitor_addr_real));
            var backtrace = get_backtrace(this.context);
            let result = {'sub_type': 'backtrace', 'data': backtrace};
            send(JSON5.stringify(result));
        }
    }
    
    let mon_instruction = Instruction.parse(monitor_addr_real);
    console.log(`Monitor: ${monitor_addr_real} \t ${mon_instruction.toString()}`);
    let prev_inst = get_previous_instr(monitor_addr_real);
    console.log(`Previous instruction of monitored address: ${prev_inst.address} \t ${prev_inst.toString()}`);
    Interceptor.attach(monitor_addr_real, callback);
}

export function getBase(module: string) {
    var searchModule = module;
    var modules = Process.enumerateModules();
    var moduleName = '';

    for (var i = 0; i < modules.length; i++) {
        if (modules[i].name.indexOf(searchModule) > -1) {
            moduleName = modules[i].name;
        }
    }
    
    var base = Module.findBaseAddress(moduleName);
    
    return base;
}