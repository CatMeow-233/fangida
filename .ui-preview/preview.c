#include <Python.h>
#include <unistd.h>
int main(void) {
    if (chdir("/Users/meow233/Desktop/ai/fangida-0.4.0") != 0) return 2;
    PyConfig config; PyConfig_InitPythonConfig(&config);
    PyStatus status=PyConfig_SetString(&config, &config.home, L"/Library/Frameworks/Python.framework/Versions/3.13");
    if (PyStatus_Exception(status)) Py_ExitStatusException(status);
    char *args[]={"fangida-preview","-m","fangida.gui","--open-database","/Users/meow233/Desktop/ai/fangida-0.4.0/analysis-databases/challenge-verified.fdb"};
    status=PyConfig_SetBytesArgv(&config,5,args);
    if (PyStatus_Exception(status)) Py_ExitStatusException(status);
    status=Py_InitializeFromConfig(&config); PyConfig_Clear(&config);
    if (PyStatus_Exception(status)) Py_ExitStatusException(status);
    return Py_RunMain();
}
