/*
 * Experimential code.
 * Example use of MemoryAccessMonitor
 * 
 * $ frida --runtime=v8 -f ~/SynologyDrive/Dev/c/mac/hello_frida -l ~/SynologyDrive/Dev/binary_analysis/freedom/memo.js --no-pause
*/
var searchModule = "hello_frida";
var modules = Process.enumerateModules();
var moduleName = null;
var monitor_addr = "0x116e"; //Linux
//var monitor_addr = "0xee0"; //Mac

for (var i = 0; i < modules.length; i++) {
    if (modules[i].name.indexOf(searchModule) > -1) {
        moduleName = modules[i].name;
    }
}

var base = Module.findBaseAddress(moduleName);
var range = {base: base.add(ptr(monitor_addr)), size:1};

console.log("moduleName: " + moduleName);
console.log("Base value: " + base);
console.log("Address: " + range.base);
console.log("Range: ", JSON.stringify(range));

var callback = {
    onAccess: function(details) {
        console.log("Callback for memory monitor hit on ", JSON.stringify(range));
        console.log("Callback for memory monitor hit address ", JSON.stringify(details.address));
        console.log("Callback for memory monitor hit on operation ", JSON.stringify(details.operation));
        console.log("Callback for memory monitor hit on from ", JSON.stringify(details.from));
        console.log("Callback for memory monitor hit on pagestotal ", JSON.stringify(details.pagesTotal));
        console.log("Callback for memory monitor real page size ", Process.pageSize);

        let instruction = Instruction.parse(details.from);
        console.log("Callback for memory monitor from real instruction ", instruction.toString());

        let mon_instruction = Instruction.parse(details.address);
        console.log("Callback for memory monitor triggered on real instruction ", mon_instruction.toString());

//        MemoryAccessMonitor.disable(range);
//        MemoryAccessMonitor.enable(range, callback);
    }
}

let mon_instruction = Instruction.parse(base.add(ptr(monitor_addr)));
console.log("monitor address contains instruction ", mon_instruction.toString());

MemoryAccessMonitor.enable(range, callback);
