
+++
date = '2026-08-03T18:36:07-06:00'
title = 'DLL Sideloading'
+++
Proxificando DLLs sobre aplicaciones legitimas para evadir detecciones y obtener un implant.
<!--more-->

## Overview
Esta tecnica permite utilizar un binario legitimo, ya sea firmado por Microsoft o simplemente inofensivo para cargar una DLL controlada por nosotros, permitiendonos ejecutar, por ejemplo, un loader que posteriormente aloje shellcode en memoria para obtener un implant en nuestro C2 preferido.
Por comodidad en este articulo(o como sea que quieras llamarle al post xD) estare utilizando AdaptixC2 y su agente como shellcode.
## DLLs
Para entender la tecnica primero hay que aondar en la base principal sobre la que funciona. Alguna vez te has preguntado **que es una DLL?**, ese componente que vemos comunmente dentro de Windows cada que monitoreamos el sistema. Bueno, pues si no lo has hecho, yo si xd, y para ahorrarte tiempo explicare las bases de este objeto.
> La siguiente explicacion esta meramente hecha para que se entienda la tecnica posterior, te recomiendo investigar por tu cuenta para tener el concepto mas claro.

Una DLL es un componente de Windows(omg que buena explicacion) utilizado en ambitos de desarrollo para alojar codigo que sera compartido por distintos programas durante su ejecucion, esto permite, por ejemplo, no tener que reescribir la misma funcion una y otra, y otra, y otra, y otra, y otra vez(se entiende el concepto xd).

Las DLLs tienen que ser importadas en las aplicaciones para poder acceder a sus funciones, un ejemplo en codigo de esto puede lucir como el siguiente snippet:
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
Ahora, en la vida todo tiene un orden, y la busqueda de DLLs en Windows no es la excepcion. Windows por defecto buscara en el siguiente orden por la libreria `my_library.dll`:
- The directory where the application runs
- The system folder (`C:\Windows\System32`)
- The 16-bit system folder (`C:\Windows\System`)
- The Windows folder (`C:\Windows`)
- The current working directory

So, ahora, quizas te hayas preguntado, **que pasa si logro escribir una DLL sobre alguno de estos directorios?**, bueno, pues alguien ya lo hizo alguien, y de hecho gracias a esta pregunta es que existe la base de nuestra tecnica, el **DLL Hijacking**.
## DLL Hijacking
Este es el primitivo para la tecnica de evasion que se explica en este articulo, basicamente una aplicacion es vulnerable a **secuestro de librerias** si se cumplen ciertos requisitos:
- La aplicacion no especifica el path completo donde la DLL se encuentra
- Se tiene *Write Access* sobre algun directorio incluido en el search order 
- La libreria requerida no existe o puede ser interceptada, es decir, puede estar en `C:\Windows`, pero nosotros tenemos *Write* en el directorio donde la aplicacion corre, so, nuestra DLL sera encontrada antes de la "legitima".
Para encontrar programas vulnerables a este ataque podemos utilizar la herramienta [Process Monitor - Sysinternals | Microsoft Learn](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon), simplemente hay que implementar los siguientes filtros:
![Filtros Process Monitor](/images/pm-filters.png)
*Imagen 1 ~ Filtros aplicados en **Process Monitor***

El siguiente paso seria buscar por intentos de carga de librerias inexistentes sobre algun directorio donde sea posible escribir:
![Ejemplo Process Monitor](/images/pm-example.png)
*Imagen 2 ~ Librerias inexistentes*

Pero como podras deducir, actualmente es algo dificil encontrar alguna aplicacion utilizada constantemente la cual sea vulnerable a este ataque. Aqui es donde entra la tecnica de la cual trata el articulo.
## DLL Sideloading
Esta tecnica es mayoritariamente usada en la fase de acceso inicial, de hecho, hay registro de su uso en operaciones leakeadas de APTs bastante reconocidas:
- https://www.cybereason.com/blog/threat-analysis-report-dll-side-loading-widely-abused
- https://unit42.paloaltonetworks.com/dll-hijacking-techniques/

Basicamente consta de tomar un binario legitimo(si es posible que este sea firmado por Microsoft ;b), analizar su carga de DLLs y tomar alguno que nos de estabilidad para poder utilizarlo como injector para nuestro beacon. 

Ahora, hay un problema, puede que la aplicacion crashee si simplemente suplantamos la DLL original con alguna creada por nuestro C2, por lo tanto tenemos que realizar el llamado **DLL Proxying**, este termino es bastante simple de entender, basicamente consta de al mismo tiempo que ejecutamos nuestro payload malicioso una vez se importe nuestra DLL sobre la aplicacion, redireccionemos las funciones originales de la DLL suplantada, de tal forma que la aplicacion tiene todas las funciones necesarias para continuar con su ejecucion y nosotros tenemos nuestro codigo malicioso siendo ejecutado sin ninguna interferencia.
![Ejemplo de ejecucion](/images/DLL-Sideloading-Execution-Flow(Fortra).png)
*Imagen 3 ~ DLL Sideloading Attack Flow - From [Cobalt Strike Blog](https://www.cobaltstrike.com/blog/create-a-proxy-dll-with-artifact-kit)*

Ya que se entienden las bases de la tecnica, procedere a explicar como podemos implementar **DLL Sideloading** en un payload de nuestra autoria, para posteriormente llevarlo al mundo real fungiendo como parte de nuestro initial access.
## Implementacion
Lo primero que tenemos que hacer es seleccionar el binario que queremos utilizar para nuestra implementacion, recomiendo que sea alguno firmado por Microsoft, dado que estos causan menos ruido, pero si no es posible puedes utilizar cualquier programa legitimo. *Notepad++* por ejemplo.

Una vez tengamos nuestro binario tenemos que localizar alguna DLL sobre la cual generar nuestro template, simplemente hay que implementar los mismos filtros que utilizamos en la *imagen 1*, en mi caso utilizare la siguiente libreria requerida por Notepad++
![Notepad++ Targeted DLL](/images/pm-targeted-dll.png)
*Imagen 4 Libreria utilizada*

Ahora, debemos encontrar esta libreria en el sistema para poder resolver todas las funciones exportadas, para esto podemos utilizar herramientas manuales y crear nuestro template en C paso por paso o podemos utilizar herramientas automatizadas como [sadreck/Spartacus: Spartacus DLL/COM Hijacking Toolkit](https://github.com/sadreck/Spartacus).
Esta herramienta contiene varias funciones, algunas bastante utiles, como la generacion automatica de librerias pasandole como input un *.csv* generado por *Process Monitor*, y la que estamos buscando nosotros en especifico, generar un template de proxy para la libreria especifica que buscamos utilizar.
```powershell
.\Spartacus --mode proxy --dll C:\Windows\System32\cryptbase.dll --solution "C:\data\tmp\dllout" --overwrite --verbose --external-resources
```
Esto nos devolvera un proyecto de Visual Studio, el cual contiene un template como el siguiente:
```c
#pragma once

#pragma comment(linker,"/export:SystemFunction001=c:\\windows\\system32\\cryptbase.SystemFunction001,@1")
#pragma comment(linker,"/export:SystemFunction002=c:\\windows\\system32\\cryptbase.SystemFunction002,@2")
#pragma comment(linker,"/export:SystemFunction003=c:\\windows\\system32\\cryptbase.SystemFunction003,@3")
#pragma comment(linker,"/export:SystemFunction004=c:\\windows\\system32\\cryptbase.SystemFunction004,@4")
#pragma comment(linker,"/export:SystemFunction005=c:\\windows\\system32\\cryptbase.SystemFunction005,@5")
#pragma comment(linker,"/export:SystemFunction028=c:\\windows\\system32\\cryptbase.SystemFunction028,@6")
#pragma comment(linker,"/export:SystemFunction029=c:\\windows\\system32\\cryptbase.SystemFunction029,@7")
#pragma comment(linker,"/export:SystemFunction034=c:\\windows\\system32\\cryptbase.SystemFunction034,@8")
#pragma comment(linker,"/export:SystemFunction036=c:\\windows\\system32\\cryptbase.SystemFunction036,@9")
#pragma comment(linker,"/export:SystemFunction040=c:\\windows\\system32\\cryptbase.SystemFunction040,@10")
#pragma comment(linker,"/export:SystemFunction041=c:\\windows\\system32\\cryptbase.SystemFunction041,@11")

#include "windows.h"
#include "ios"
#include "fstream"



// Remove this line if you aren't proxying any functions.
HMODULE hModule = LoadLibrary(L"c:\\windows\\system32\\cryptbase.dll");

// Remove this function if you aren't proxying any functions.
VOID DebugToFile(LPCSTR szInput)
{
    std::ofstream log("spartacus-proxy-cryptbase.log", std::ios_base::app | std::ios_base::out);
    log << szInput;
    log << "\n";
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```
Ya con este template podemos realizar una funcion que se encargue de cargar nuestro shellcode en algun otro proceso como ***msedge.exe***. A continuacion dejo mi implementacion:
```c
# Trabajando en el codigo, sera subido en proximos commits
```
### En proceso de terminar...