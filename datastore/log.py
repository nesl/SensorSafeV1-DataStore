import sys

def log(object):
	if type(object) is str:
		print >> sys.stderr, object
	else:
		print >> sys.stderr, str(object)
	sys.stderr.flush()



