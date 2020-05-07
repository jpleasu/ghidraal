for(n in names(gs)) {
  if(!exists(n,envir=.GlobalEnv))
    assign(n, gs[n] ,envir=.GlobalEnv);
}
