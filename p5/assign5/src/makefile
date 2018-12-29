JC = javac
JFLAGS = -g

default: SimpleDNS.class

SimpleDNS.class: edu/wisc/cs/sdn/simpledns/SimpleDNS.java
	$(JC) $(JFLAGS) edu/wisc/cs/sdn/simpledns/packet/*.java
	$(JC) $(JFLAGS) edu/wisc/cs/sdn/simpledns/SimpleDNS.java

run:
	java edu.wisc.cs.sdn.simpledns.SimpleDNS -r a.root-servers.net -e ../ec2.csv

clean:
	$(RM) ./edu/wisc/cs/sdn/simpledns/*.class
	$(RM) ./edu/wisc/cs/sdn/simpledns/packet/*.class