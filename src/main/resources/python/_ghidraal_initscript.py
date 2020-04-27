# make GhidraScript methods global, unless they'd overwrite something already defined
g=globals()
for m in dir(gs):
  if m=='print':
    continue
  if not m in g:
    v=getattr(gs,m)
    g[m]=v

