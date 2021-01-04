/*
 * Based off  * https://github.com/0xdea/frida-scripts/
 *
 * Example usage:
 * $ frida-compile <this script name> -o <new name>.js
 * # frida -U -f <Android app name> -l <new name> --no-pause
 *
 * Experimental code. Needs to be examined and cleaned.
 */
'use strict';

var debug = false;


// enumerate all Java classes
function enumAllClasses()
{
	let classes = Java.enumerateLoadedClassesSync();

	let allClasses = classes.map( aClass => {
        let className;
        
        try {
            className = aClass;

            /* Not sure what the purpose of this filter is for, but
            it prevented many classes from returning.

			className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
             */

            return className;
        }
        catch(err) { 
            debug && console.log(`Error enumAllClasses ${className}: ${err}`) 
        } // avoid TypeError: cannot read property 1 of null        
	});

	return allClasses;
}

// find all Java classes that match a pattern
function findClasses(pattern)
{
	let allClasses = enumAllClasses();

	let foundClasses = allClasses.filter( aClass => {
		try {
			if (aClass && aClass.match(pattern)) {
                debug && console.log(`\t\tfindClasses: ${aClass}`);
                return true;
			}
		}
        catch(err) { // avoid TypeError: cannot read property 'match' of undefined
            console.log(`Error findClasses: ${err}`);
        } 
	});

	return foundClasses;
}

function extract_method(class_name, declared_method_instance) {
    /*
    Extract the method name of java class.
    e.g. params
        class_name = 'com.android.okhttp.HttpUrl$Builder$ParseResult'
        declared_method_instance = '<instance> public static com.android.okhttp.HttpUrl$Builder$ParseResult com.android.okhttp.HttpUrl$Builder$ParseResult.valueOf(java.lang.String)'

        Return 'valueOf'
     */
    class_name += '.'
    // Cleanup methods names without class name
    // Change . and $ to literal in class name
    class_name = class_name.replace(/\./g, '\\.').
            replace(/\$/g, '\\$');
    // Add space and regex group to match
    class_name = `\\s${class_name}(.+)?\\(`;

    let declared_method_string = declared_method_instance.toString();

    let myRe = new RegExp(class_name);

    let match = declared_method_string.match(myRe);

    if (match) {
        return match[1];
        debug && console.log(`\t${match[1]}`);
    }
}

// enumerate all methods declared in a Java class
function enumMethods(targetClass) {
    if (!targetClass) {
        return;
    }

    try {
        var hook = Java.use(targetClass);
        var ownMethods = hook.class.getDeclaredMethods();
        hook.$dispose;
    }
    catch(err) { console.log(`Error enumMethods ${targetClass}: ${err}`) }

    return ownMethods;
}

export function get_class_methods(class_regex, methods_regex) {
    /*
    Params:
    class_regex         Filter for class names
    methods_regex       Filter for method names

    Return [{"com.android.okhttp.HttpUrl$Builder$ParseResult":["valueOf","values"]}
    ,{"com.android.okhttp.Protocol":["get","valueOf","values","toString"]}]

     */
    let return_classes = {};

	Java.perform(function() {
        // find classes that match a pattern
		let classes = findClasses(class_regex);
        
        classes.forEach( clazz => {
            let methodz = enumMethods(clazz)

            debug && console.log(`Class ${clazz}:`);

            if (methodz && methodz.length > 0) {
                debug && console.log(`\tMethods:`);
                    
                // Strip method names down
                let simple_methodz = methodz.map(declared_method => {
                    return extract_method(clazz, declared_method);
                });

                debug && console.log(`\t${simple_methodz}`);

                if (simple_methodz) {
                    // Remove methods don't meet callers regex
                    simple_methodz = simple_methodz.filter(enum_method => enum_method.match(methods_regex));

                    return_classes[clazz] = simple_methodz;
                }
            }
        });

        debug && console.log(`${return_classes}`);
    });
    
    return return_classes;
}

function main() {
    /* Main
    Avoid java.lang.ClassNotFoundException by using setTimeout().
    */
    setTimeout(function() { 
        let class_regex = /okhttp/i;

        console.log('[');

        for (let [key, value] of Object.entries(get_class_methods(class_regex)) ) {
            console.log(`{
            class: '${key}',
            method: [${value.map( x => {return "'" + x + "'" })}],
            name: 'http'\n},`);
        }

        console.log(']');
    }, 10);
}