# Basic R graphics demo
#@category Ghidraal

library(grid)

# install from R repl with
#    install.packages('ggplot2')
library(ggplot2)

# create image and register graphics
imageClass <- java.type('java.awt.image.BufferedImage')
image <- new(imageClass, 1024, 1024, imageClass$TYPE_INT_RGB);
graphics <- image$getGraphics()
graphics$setBackground(java.type('java.awt.Color')$white);
grDevices:::awt(image$getWidth(), image$getHeight(), graphics)

# draw the image
df <- data.frame(name=character(0), addr=integer(0), size=integer(0), stringsAsFactors=FALSE)
it<-currentProgram$getFunctionManager()$getFunctions(TRUE)$iterator()

while(it$hasNext()) {
  f<-it['next']();
  df[nrow(df)+1,]<-list(f$getName(), f$getEntryPoint()$getOffset(), f$getBody()$getNumAddresses())
}

p <- ggplot(df, aes(x=size)) + geom_histogram()

print(p)

# open frame with image
imageIcon <- new("javax.swing.ImageIcon", image)
label <- new("javax.swing.JLabel", imageIcon)
panel <- new("javax.swing.JPanel")
panel$add(label)
frame <- new("javax.swing.JFrame")
frame$setMinimumSize(new("java.awt.Dimension",
             image$getWidth()+20, image$getHeight()+40))
frame$add(panel)
frame$setVisible(T)

