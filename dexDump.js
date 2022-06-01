'use strict';

/**
 * Author: guoqiangck & enovella
 * Created: 2019/6/11
 * Dump dex file for packed apks
 * Hook art/runtime/dex_file.cc OpenMemory or OpenCommon
 * Support Version: Android 4.4 up to Android 11.0
 */

/* Read a C++ std string (basic_string) to a nomal string */
function readStdString(ptr_str) {
    const isTiny = (ptr_str.readU8() & 1) === 0;
    if (isTiny) {
      return ptr_str.add(1).readUtf8String();
    }

    return ptr_str.add(2 * Process.pointerSize).readPointer().readUtf8String();
}


function logPrint(log) {
    var theDate = new Date();
    var hour = theDate.getHours();
    var minute = theDate.getMinutes();
    var second = theDate.getSeconds();
    var mSecond = theDate.getMilliseconds()

    hour < 10 ? hour = "0" + hour : hour;
    minute < 10 ? minute = "0" + minute : minute;
    second < 10 ? second = "0" + second : second;
    mSecond < 10 ? mSecond = "00" + mSecond : mSecond < 100 ? mSecond = "0" + mSecond : mSecond;

    var time = hour + ":" + minute + ":" + second + ":" + mSecond;
    console.log("[" + time + "] " + log);
}

function getAndroidVersion(){
    var version = 0;

    if(Java.available){
        var version = parseInt(Java.androidVersion);
    }else{
        logPrint("Error: cannot get android version");
    }
    logPrint("[*] Android version: " + version);

    return version;
}

function getFunctionName(){
    var i = 0;
    var functionName = "";

    // Android 4: hook dvmDexFileOpenPartial
    // Android 5: hook OpenMemory
    // after Android 5: hook OpenCommon
    if (g_AndroidOSVersion > 4){ // android 5 and later version
        // OpenCommon is in libdexfile.so in android 10 and later
        var soName = g_AndroidOSVersion >= 10 ? "libdexfile.so" : "libart.so";
        var artExports =  Module.enumerateExportsSync(soName);
        for(i = 0; i< artExports.length; i++){
            if(artExports[i].name.indexOf("OpenMemory") !== -1){
                functionName = artExports[i].name;
                logPrint("[*] Export index: " + i + " -> "+ functionName);
                break;
            }else if(artExports[i].name.indexOf("OpenCommon") !== -1){
                if (g_AndroidOSVersion >= 10 && artExports[i].name.indexOf("ArtDexFileLoader") !== -1)
                    continue;
                functionName = artExports[i].name;
                logPrint("[*] Export index: " + i + " -> "+ functionName);
                break;
            }
        }
    }else{ //android 4
        var dvmExports =  Module.enumerateExportsSync("libdvm.so");
        if (dvmExports.length !== 0) {
            for(i = 0; i< dvmExports.length; i++){
                if(dvmExports[i].name.indexOf("dexFileParse") !== -1){
                    functionName = dvmExports[i].name;
                    logPrint("[*] Export index: " + i + " -> "+ functionName);
                    break;
                }
            }
        }else {
            dvmExports = Module.enumerateExportsSync("libart.so");
            for(i = 0; i< dvmExports.length; i++){
                if(dvmExports[i].name.indexOf("OpenMemory") !== -1){
                    functionName = dvmExports[i].name;
                    logPrint("[*] Export index: " + i + " -> "+ functionName);
                    break;
                }
            }
        }
    }
    return functionName;
}

function getg_processName(){
    var g_processName = "";

    var fopenPtr = Module.findExportByName("libc.so", "fopen");
    var fgetsPtr = Module.findExportByName("libc.so", "fgets");
    var fclosePtr = Module.findExportByName("libc.so", "fclose");

    var fopenFunc = new NativeFunction(fopenPtr, 'pointer', ['pointer', 'pointer']);
    var fgetsFunc = new NativeFunction(fgetsPtr, 'int', ['pointer', 'int', 'pointer']);
    var fcloseFunc = new NativeFunction(fclosePtr, 'int', ['pointer']);

    var pathPtr = Memory.allocUtf8String("/proc/self/cmdline");
    var openFlagsPtr = Memory.allocUtf8String("r");

    var fp = fopenFunc(pathPtr, openFlagsPtr);
    if(fp.isNull() === false){
        var buffData = Memory.alloc(128);
        var ret = fgetsFunc(buffData, 128, fp);
        if(ret !== 0){
            g_processName = Memory.readCString(buffData);
            logPrint("[*] ProcessName: " + g_processName);
        }
        fcloseFunc(fp);
    }
    return g_processName;
}

function arraybuffer2hexstr(buffer)
{
    var hexArr = Array.prototype.map.call(
        new Uint8Array(buffer),
        function (bit) {
            return ('00' + bit.toString(16)).slice(-2)
        }
    );
    return hexArr.join(' ');
}

function checkMagic(dataAddr) { // Throws access violation errors, not handled at all.
    let dexMagic = 'dex\n'; // [0x64, 0x65, 0x78, 0x0a]
    let dexVersions = ['035', '037', '038', '039', '040']; // Same as above (hex -> ascii)
    let odexVersions = ['036'];
    let kDexMagic = 'cdex'; // [0x63, 0x64, 0x65, 0x78]
    let kDexVersions = ['001'];
    let magicTrailing = 0x00;

    let readData
    try {
        readData = ptr(dataAddr).readByteArray(8)
    } catch (e) {
        logPrint('Error reading memory at address' + dataAddr);
        return {found: false, wrongMagic: 0xDEADBEEF};
    }
    let magic = Array.from( new Uint8Array( readData ) );

    let foundStart = magic.slice(0,4).map(i => String.fromCharCode(i)).join('');
    let foundVersion = magic.slice(4,7).map(i => String.fromCharCode(i)).join('');
    let foundMagicString = foundStart.replace('\n', '') + foundVersion; // Printable string

    if (foundStart === dexMagic && dexVersions.includes(foundVersion) && magic[7] === magicTrailing) {
        // Found a dex
        return {found: true, ext: 'dex', sizeOffset: 0x20, magicString: foundMagicString};
    } else if (foundStart === dexMagic && odexVersions.includes(foundVersion) && magic[7] === magicTrailing) {
        // Found an odex (only version number differs, same magic)
        return {found: true, ext: 'odex', sizeOffset: 0x1C, magicString: foundMagicString};
    } else if (foundStart === kDexMagic && kDexVersions.includes(foundVersion) && magic[7] === magicTrailing) {
        // Found a compact dex
        return {found: true, ext: 'cdex', sizeOffset: 0x20, magicString: foundMagicString};
    } else {
        return {found: false, wrongMagic: magic};
    }
}

function dumpDexToFile(begin, dexInfo, processName, location) {
    let dexSize = ptr(begin).add(dexInfo.sizeOffset).readInt();
    let dexPath = "/data/data/" + processName + "/" + dexSize + "." + dexInfo.ext;
    var dexFile = new File(dexPath, "wb");

    dexFile.write(ptr(begin).readByteArray(dexSize));
    dexFile.flush();
    dexFile.close();

    logPrint("magic        : " + dexInfo.magicString);
    logPrint("size         : " + dexSize);
    logPrint("orig location: " + location);
    logPrint("dumped " + dexInfo.ext + " @ " + dexPath + "\n");
}

function dumpDex(moduleFuncName, g_processName){
    if (moduleFuncName == "") {
        logPrint("Error: cannot find correct module function.");
        return;
    }

    var hookFunction;
    if (g_AndroidOSVersion > 4) {
        hookFunction = Module.findExportByName("libart.so", moduleFuncName);
    } else {
        hookFunction = Module.findExportByName("libdvm.so", moduleFuncName);
        if(hookFunction == null) {
            hookFunction = Module.findExportByName("libart.so", moduleFuncName);
        }
    }

    Interceptor.attach(hookFunction,{
        onEnter: function(args){
            let begin, dexInfo, location;

            dexInfo = checkMagic(args[0]);
            begin = args[0];
            if (!dexInfo.found) {
                wrongMagic0 = dexInfo.wrongMagic
                dexInfo = checkMagic(args[1]);
                begin = args[1];
            }
            if (!dexInfo.found) {
                throw new Error(
                    'Could not identify magic, found invalid values ' +
                    wrongMagic0.map(i => i.toString(16).padStart(2, '0')).join('') +
                    ' ' +
                    dexInfo.wrongMagic.map(i => i.toString(16).padStart(2, '0')).join('')
                )
            }

            for (let i = 0; i < 10; i++) {
            // Try all parameters
                try {
                    location = readStdString(ptr(args[i]));
                } catch {} // Illegal memory access
                if (location != null && location.length > 0 && location.includes('/')) {
                    // != null catches both undefined and null
                    break;
                }
            }

            dumpDexToFile(begin, dexInfo, g_processName, location);
        },
    });
}

// Main code
var g_AndroidOSVersion = getAndroidVersion();
var g_moduleFunctionName = getFunctionName();
var g_processName = getg_processName();

if(g_moduleFunctionName !== "" && g_processName !== ""){
    dumpDex(g_moduleFunctionName, g_processName);
}
