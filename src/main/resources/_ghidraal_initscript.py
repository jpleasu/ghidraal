g=globals()
for m in dir(_ghidra_api):
  if m=='print':
    continue
  if not m in g:
    v=getattr(_ghidra_api,m)
    g[m]=v
