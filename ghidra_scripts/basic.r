# Basic R demo
#@category Ghidraal

currentProgram$getFunctionManager()$getFunctions(TRUE)$forEach( function(f) {
  printf('%s %s\n', f$getEntryPoint(), f$getName());
});

