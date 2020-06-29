#attach(_ghidra_api)

for(n in names(_ghidra_api)) {
  if(!exists(n,envir=.GlobalEnv))
    assign(n, _ghidra_api[n] ,envir=.GlobalEnv);
}
