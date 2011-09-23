from guppy import hpy
import cProfile

def foo():
	s = 0
	for i in xrange(1,100):
		s += i
	print 'sum = ' + str(s)


h=hpy()
foo()
h.heap()

#cProfile.run('foo()')
