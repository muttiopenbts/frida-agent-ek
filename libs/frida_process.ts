/*
 * Experimental code for now.
 * agent.ts should use this file to interface with libs.
 */

import { log } from "../agent/logger";

const fs = require('fs');
const ffs = require("frida-fs");
const JSON5 = require('json5');
const APP_NAME = ``; // e.g. com.some.android.app

function log_to_read(log_filename:string) {
    fs.readFile(`${log_filename}`, 'utf8', function (err: string, data: string) {
        if (err) {
            console.log(err);
        }
        console.log(data);
    });    
}


function sleep(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function get_length(obj: any) {
    return Object.keys(obj).length;
}

function get_timestamp() {
    let date_ob = new Date();

    // current date
    // adjust 0 before single digit date
    let date = ("0" + date_ob.getDate()).slice(-2);
    
    // current month
    let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
    
    // current year
    let year = date_ob.getFullYear();
    
    // current hours
    let hours = date_ob.getHours();
    
    // current minutes
    let minutes = date_ob.getMinutes();
    
    // current seconds
    let seconds = date_ob.getSeconds();
    
    // prints date & time in YYYY-MM-DD HH:MM:SS format
    return year + "-" + month + "-" + date + "_" + hours + ":" + minutes + ":" + seconds;
}


export function do_find_functions(func_glob: string) {
    /*
     * e.g. func_glob = *Http*setCookiesForDomain*
     */
    console.log(`do_find_functions called.`)
    DebugSymbol.findFunctionsMatching(func_glob)
        .forEach(function (sym_addr: NativePointer) {
            console.log(`${DebugSymbol.fromAddress(ptr(sym_addr as any)).name}`)
        });
}

export function do_get_exports(module_name: string){
    // e.g. Param: "libSystem.B.dylib"
    Process.getModuleByName(module_name)
        .enumerateExports()
        .slice(0, 16)
        .forEach((exp, index) => {
            log(`export ${index}: ${exp.name}`);
        });
}

export function do_intercept(export_name: string){
    console.log(`Intercepting=${export_name}`);
    // e.g. Param: "open"
    Interceptor.attach(Module.getExportByName(null, export_name), {
        onEnter(args) {
            const path = args[0].readUtf8String();
            log(`${export_name} path="${path}"`);
        }
    });       
}
