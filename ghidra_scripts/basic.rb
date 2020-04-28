print <<"foo", <<"bar"  # you can stack them
  I said foo.
foo
  I said bar.
bar

#s=$gs.askString("gimme string","for ruby")
#puts "got #{s}"

$currentProgram.getFunctionManager.getFunctions(true).forEach(-> f {
  puts "#{f.getEntryPoint.toString} #{f.getName}"
})
