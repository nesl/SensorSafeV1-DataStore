import sys

def logp(prefix, object):
	if type(object) is str:
		print >> sys.stderr, prefix + ': ' + object
	else:
		print >> sys.stderr, prefix + ': ' + str(object)
	sys.stderr.flush()

def log(object):
	if type(object) is str:
		print >> sys.stderr, object
	else:
		print >> sys.stderr, str(object)
	sys.stderr.flush()



