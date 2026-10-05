/*
 * Source of the delay-load test fixtures next to this file. It is not a pet
 * and does nothing worth running: it exists so that the linker emits a
 * delay-load import directory (data directory 13) naming user32.dll, with
 * one function the published mapping table describes and one it does not.
 * build.cmd rebuilds both fixtures; see it for the exact toolchain flags.
 *
 * There is no C runtime, so the entry point is named explicitly, and the
 * helper the linker calls on a delay-loaded function's first use is the
 * short one below rather than delayimp.lib's, which needs runtime support
 * this program does not link. The linker's output for the import directory
 * itself is the same either way: /DELAYLOAD decides that, not the helper.
 */
#include <windows.h>
#include <delayimp.h>

extern IMAGE_DOS_HEADER __ImageBase;

FARPROC WINAPI __delayLoadHelper2(PCImgDelayDescr descriptor, FARPROC *slot)
{
    BYTE *base = (BYTE *)&__ImageBase;
    HMODULE *module = (HMODULE *)(base + descriptor->rvaHmod);
    PImgThunkData iat = (PImgThunkData)(base + descriptor->rvaIAT);
    PCImgThunkData names = (PCImgThunkData)(base + descriptor->rvaINT);
    PCImgThunkData name = names + ((PImgThunkData)slot - iat);
    FARPROC resolved;

    if (*module == NULL) {
        *module = LoadLibraryA((LPCSTR)(base + descriptor->rvaDLLName));
    }
    resolved = GetProcAddress(*module, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)(base + name->u1.AddressOfData))->Name);
    *slot = resolved;
    return resolved;
}

int WINAPI start(void)
{
    if (GetAsyncKeyState(VK_LBUTTON) < 0) {
        MessageBeep(MB_OK);
    }
    return 0;
}
