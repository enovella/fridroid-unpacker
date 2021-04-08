# fridroid-unpacker

Defeat Java packers via Frida instrumentation


Description
-----------
Use the method `OpenMemory` or `OpenCommon` (after Android N) in `libart.so`/`libdexfile.so` to get the address of the dex in memory, calculate the size of the dex file, and dump the dex from memory.

Usage
-----

```sh
$ frida -U -f com.package.target -l dexDump.js --no-pause
```

References
----------
- https://www.frida.re/docs/home/
- frida-unpack (dstmath) https://github.com/dstmath/frida-unpack
- Frida-Android-unpack (xiaokanghub) https://github.com/xiaokanghub/Frida-Android-unpack

Supported OS: Android 4.4 - Android 11

Tested Packers
---------------

- Jiagu
- DexProtector
- DexGuard
- Yidun
- Tencent Legu 
- Mobile Tencent Protect
