#include <dlfcn.h>
#include <stdio.h>


int main()
{
  char *lib = "./QTSSIcecastAuthModule";
  char *sym = "QTSSIcecastAuthModule_Main";

  void *lp = NULL;
  void *sp = NULL;

  lp = dlopen(lib, RTLD_NOW | RTLD_GLOBAL);
  if(!lp) { fprintf (stderr, "err: %s\n", dlerror()); return 1; }

  sp = dlsym(lp, sym);
  if(!lp) { fprintf (stderr, "err: %s\n", dlerror()); return 1; }

  return 0;
}