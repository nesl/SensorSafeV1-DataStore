from guppy import hpy
import cProfile
import hotshot

def hoo():
	s = 0
	for i in xrange(1,100):
		s += i
	print 'another sum = ' + str(s)
	

def foo():
	hoo()
	s = 0
	for i in xrange(1,100):
		s += i
	print 'sum = ' + str(s)


h=hpy()
foo()
h.heap()

#cProfile.run('foo()')
#prof = hotshot.Profile('foo_prof_log')
#prof.runcall(foo)
#prof.close()
