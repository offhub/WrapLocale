# WrapLocale

### A plugin for [Sandboxie](https://github.com/sandboxie-plus/Sandboxie) to properly emulate different locales.  

This is based on [Locale Remulator](https://github.com/InWILL/Locale_Remulator) and [SbieHide](https://github.com/VeroFess/SbieHide) as a template, but uses local [MinHook](https://github.com/TsudaKageyu/minhook) instead of Detours.  

Just like LR it's very basic and doesn't cover internal window messaging, registry and some of the other APIs fully like [Locale Emulator](https://github.com/xupefei/Locale-Emulator) does so it may show `?`s in normal dialog windows or produce other artifacts. However, it covers more than what the native Sandboxie implementation currently does with Custom Locale/LangID option.

## How to use?

Compile this plugin in both x86 and x64 versions.  

Open the configuration of a sandbox that needs the emulation and add these lines:

```
InjectDll64=X:\path\to\WrapLocale_x64.dll
InjectDll=X:\path\to\WrapLocale_x86.dll
```

By default it emulates Japanese locale. See what other sandbox config options are available in the source for now.

-----

## LICENSE
WrapLocale is licensed under the MIT License.  
Dependencies are under their respective licenses.