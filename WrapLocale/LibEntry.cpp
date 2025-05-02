#include "HookFunc.h"
#include "CommonLibrary.h"
#ifdef ENABLE_HIDING
#include "HideProcessInformation.h"
#endif

// Function pointers
SbieApi_QueryConf_t pSbieApi_QueryConf = NULL;
SbieApi_QueryConfBool_t pSbieApi_QueryConfBool = NULL;
SbieApi_QueryProcess_t pSbieApi_QueryProcess = NULL;
SbieApi_Log_t Log = NULL;

// Global profile
GLOBAL_CONFIG settings = {
    932,                    // CodePage
    0x0411,                 // LCID
    540,                    // Bias
    true,                   // HookIME
    false,                   // SingleLCID
    false,                   // UseFontSubstitution
    false,                  // SubstituteAllFonts
    L"MS Gothic",           // SubstituteFontName
    {                       // FontsToSubstitute
            L"MS Sans Serif",
            L"Verdana",
            L"Tahoma",
            L"Times New Roman"
    },
    {                       // ExcludedProcesses
        L"WerFault.exe",
        L"SandboxieRpcSs.exe",
        L"SandboxieDcomLaunch.exe",
        L"SandboxieCrypto.exe",
        L"SandboxieBITS.exe",
        L"Firefox.exe",
        L"Chrome.exe",
        L"explorer.exe",
        L"vsjitdebugger.exe"
    }
};

INITIAL_STATE Initial;

// Function to clean up allocated memory in config
void CleanupLRProfile(GLOBAL_CONFIG& profile)
{
    if (profile.SubstituteFontName)
        delete[] profile.SubstituteFontName;

    profile.FontsToSubstitute.clear();
    profile.ExcludedProcesses.clear();
}

// Function to read local config from Sandboxie ini config
bool ReadLRProfileConfig(const WCHAR* boxName, GLOBAL_CONFIG& profile)
{
    WCHAR buffer[4096];
    LONG rc;

    // Read CodePage
    rc = pSbieApi_QueryConf(boxName, L"EmulateCodePage", 0, buffer, sizeof(buffer));
    if (rc >= 0) profile.CodePage = _wtoi(buffer);

    // Read LCID
    rc = pSbieApi_QueryConf(boxName, L"EmulateLCID", 0, buffer, sizeof(buffer));
    if (rc >= 0) profile.LCID = _wtoi(buffer);

    // Read Bias
    rc = pSbieApi_QueryConf(boxName, L"EmulateBias", 0, buffer, sizeof(buffer));
    if (rc >= 0) profile.Bias = _wtol(buffer);

    // Read boolean values
    profile.HookIME = pSbieApi_QueryConfBool(boxName, L"EmulatorHooksIME", profile.HookIME);
    profile.SingleLCID = pSbieApi_QueryConfBool(boxName, L"EmulatorUsesSingleLCID", profile.SingleLCID);
    profile.UseFontSubstitution = pSbieApi_QueryConfBool(boxName, L"EmulatorSubstitutesFonts", profile.UseFontSubstitution);
    profile.SubstituteAllFonts = pSbieApi_QueryConfBool(boxName, L"EmulatorSubstituteAllFonts", profile.SubstituteAllFonts);

    // Read SubstituteFontName (needs memory allocation)
    rc = pSbieApi_QueryConf(boxName, L"SubstituteFontName", 0, buffer, sizeof(buffer));
    if (rc >= 0 && buffer[0] != L'\0') {
        WCHAR* fontName = new WCHAR[wcslen(buffer) + 1];
        wcscpy(fontName, buffer);
        profile.SubstituteFontName = fontName;
    }

    // Read FontsToSubstitute (comma-separated list)
    rc = pSbieApi_QueryConf(boxName, L"EmulatorFontsToSubstitute", 0, buffer, sizeof(buffer));
    if (rc >= 0 && buffer[0] != L'\0') {
        WCHAR* context = NULL;
        WCHAR* token = wcstok_s(buffer, L",", &context);

        profile.FontsToSubstitute.clear();
        while (token != NULL) {
            // Trim whitespace
            while (*token == L' ') token++;
            WCHAR* end = token + wcslen(token) - 1;
            while (end > token && *end == L' ') *end-- = L'\0';
            if (token && *token)
                profile.FontsToSubstitute.push_back(token);
            else
                break;
            token = wcstok_s(NULL, L",", &context);
        }
    }

    // Read FontsToSubstitute (comma-separated list)
    rc = pSbieApi_QueryConf(boxName, L"EmulatorExcludedProcesses", 0, buffer, sizeof(buffer));
    if (rc >= 0 && buffer[0] != L'\0') {
        WCHAR* context = NULL;
        WCHAR* token = wcstok_s(buffer, L",", &context);

        while (token != NULL) {
            // Trim whitespace
            while (*token == L' ') token++;
            WCHAR* end = token + wcslen(token) - 1;
            while (end > token && *end == L' ') *end-- = L'\0';

            // Add to vector (with memory allocation)
            if (token && *token)
                profile.ExcludedProcesses.push_back(token);
            else
                break;
            token = wcstok_s(NULL, L",", &context);
        }
    }
    return true;
}


// Load Sandboxie API functions from its module handle
bool LoadSandboxieFunctions(HINSTANCE hSbieDll)
{
    if (!hSbieDll)
        return false;

    // Get function addresses
    pSbieApi_QueryConf = (SbieApi_QueryConf_t)GetProcAddress(hSbieDll, "SbieApi_QueryConf");
    pSbieApi_QueryConfBool = (SbieApi_QueryConfBool_t)GetProcAddress(hSbieDll, "SbieApi_QueryConfBool");
    pSbieApi_QueryProcess = (SbieApi_QueryProcess_t)GetProcAddress(hSbieDll, "SbieApi_QueryProcess");
    Log = (SbieApi_Log_t)GetProcAddress(hSbieDll, "SbieApi_Log");

    // Check if all functions were loaded
    if (!pSbieApi_QueryConf || !pSbieApi_QueryConfBool || !pSbieApi_QueryProcess || !Log)
        return false;

    return true;
}

BOOL IsWrongProcess() {
    wchar_t processName[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, processName, MAX_PATH);
    wchar_t* fileName = wcsrchr(processName, L'\\');
    fileName = fileName ? fileName + 1 : processName;
    for (const auto& excluded : settings.ExcludedProcesses) {
        if (_wcsicmp(fileName, excluded.c_str()) == 0)
            return TRUE;
    }
    return FALSE;
}

// Sandboxie will automatically call this when loading the DLL
// But this is called _after_ DLL_PROCESS_ATTACH
extern "C" __declspec(dllexport) void WINAPI InjectDllMain(
    HINSTANCE hSbieDll,
    ULONG_PTR UnusedParameter
) {
    if (!Initial.hModule)
        return;

    if (!LoadSandboxieFunctions(hSbieDll)) // Failed to load functions
        return;

    WCHAR boxName[256];
    WCHAR imageName[256];
    WCHAR sid[96];
    ULONG sessionId;

    LONG rc = pSbieApi_QueryProcess((HANDLE)GetCurrentProcessId(), boxName, imageName, sid, &sessionId);
    if (rc != 0)
        return;

    ReadLRProfileConfig(boxName, settings);

#ifdef ENABLE_HIDING
    InitMemoryImageHideInformation();
    EraseModuleNameFromPeb();
#endif
    EnableApiHooks();

#ifdef SET_CODEPAGE
    // Set the code page
    if (settings.CodePage != 0) {
        SetConsoleOutputCP(settings.CodePage);
        SetConsoleCP(settings.CodePage);
    }

    // Set the locale
    if (settings.LCID != 0 && settings.HookLCID) {
        SetThreadLocale(settings.LCID);
        SetThreadUILanguage(settings.LCID);
    }

    //SetUserGeoID(122);
#endif

    // Log that we've applied the settings
#ifdef _DEBUG
    Log(2, L"Applied locale settings {CodePage=%d, LCID=0x%X, Bias=%d}",
        settings.CodePage, settings.LCID, settings.Bias);
#endif // DEBUG
}

// Regular DLL entry point - still needed for proper initialization/cleanup
BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason) {
    case DLL_PROCESS_ATTACH: {
        if (IsWrongProcess())
            return FALSE; // Don't load in these

        Initial.hModule = hInstance;
        Initial.CodePage = GetACP();

        MAP_CODEPAGE_TO_CHARSET(Initial.CodePage, Initial.Charset);

        Initial.hHeap = GetProcessHeap();

        DisableThreadLibraryCalls(hInstance);
        break;
    }
    case DLL_PROCESS_DETACH:
        //CleanupLRProfile(settings);
        break;
    }

    return TRUE;
}