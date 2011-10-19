import hotshot
from guppy import hpy
import os
import time
import settings
import hashlib, random
from log import log


try:
	PROFILE_LOG_BASE = settings.PROFILE_LOG_BASE
except:
	PROFILE_LOG_BASE = '/var/log/django-profile-logs'



# This is django decorator.
def hotshot_heapy_profile(log_file):
	"""Profile some callable

	This decorator uses the hotshot profiler to profile some callable (like
	a view function or method) and dumps the profile data somewhere sensible
	for later processing and examination.
	It takes one argument, the profile log name. If it's a relative path, it
	places it under the PROFILE_LOG_BASE. It also inserts a time stamp into the 
	file name, such that 'my_view.prof' become 'my_view-20100211T170321.prof', 
	where the time stamp is in UTC. This makes it easy to run and compare 
	multiple trials.
	"""

	def _outer(f):
		def _inner(*args, **kwargs):
			if os.path.isabs(log_file):
				assert False # log_file should not be absolute path name.
			else:
				hotshot_log_file = os.path.join(PROFILE_LOG_BASE, log_file + '.hotshot')
				heapy_before_log_file = os.path.join(PROFILE_LOG_BASE, log_file + '_before.heapy')
				heapy_after_log_file = os.path.join(PROFILE_LOG_BASE, log_file + '_after.heapy')
				#heapy_log_file = os.path.join(PROFILE_LOG_BASE, log_file + '.heapy')

			# Add hash to the filename for multithread execution.
			hash = '_' + hashlib.sha1(str(random.random())).hexdigest()
			
			# Add a timestamp to the profile output when the callable is actually called.
			timestamp = time.strftime("_%Y%m%d-%H%M%S", time.localtime())
					
			(base, ext) = os.path.splitext(hotshot_log_file)
			base += hash
			#base += timestamp
			hotshot_log_file = base + ext
			
			(base, ext) = os.path.splitext(heapy_before_log_file)
			base += hash
			#base += timestamp
			heapy_before_log_file = base + ext

			(base, ext) = os.path.splitext(heapy_after_log_file)
			base += hash
			#base += timestamp
			heapy_after_log_file = base + ext

			prof = hotshot.Profile(hotshot_log_file)
			h = hpy()
			hpyresult = h.heap()
			hpyresult.dump(heapy_before_log_file)
			try:
				ret = prof.runcall(f, *args, **kwargs)
			finally:
				prof.close()
				hpyresult = h.heap()
				hpyresult.dump(heapy_after_log_file)
			return ret

		return _inner

	return _outer


