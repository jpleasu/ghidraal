currentProgram.getFunctionManager().getFunctions(true).forEach( f => {
  printf('%s %s\n', f.getEntryPoint(), f.getName());
});
