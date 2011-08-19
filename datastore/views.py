import sys
import time
from datetime import datetime, timedelta
import httplib, urllib
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect
from django.shortcuts import render_to_response
import json
import pymongo, bson
from django.contrib.auth.decorators import login_required
from sensorsafe.datastore.forms import *
from django.core.exceptions import *
from django.contrib.auth.models import User as authUser
from django.contrib.auth import authenticate, login, logout
import hashlib, random 
from sensorsafe.datastore.models import *
from django.template import RequestContext
from googlemaps import GoogleMaps
from threading import Lock
from copy import copy, deepcopy
import math

BROKER_ADDRESS = 'fieldstream.nesl.ucla.edu'
GOOGLE_APIKEY = 'ABQIAAAA-BHV3Z55zCdo4z_ley123xT2yXp_ZAY8_ufC3CFXhHIE1NvwkxTGit_DA3cmLDETSlrEJ5l9J2xRaQ'

gmaps = GoogleMaps(GOOGLE_APIKEY)
db = pymongo.Connection()['sensorsafe_database']

def print_error_context():
	print 'Caught: sys.exc_type =', sys.exc_type, 'sys.exc_value =', sys.exc_value
	print 'sys.exc_traceback =', sys.exc_traceback
	print sys.exc_info()

def json_dump_pretty_html(data):
	return '<pre>' + json.dumps(data, sort_keys=True, indent=4) + '</pre>'



@login_required
def status(request):
	userinfo = UserProfile.objects.get(userID__exact = request.user)
	return render_to_response('status.html', { 'apikey': userinfo.apiKey }, context_instance=RequestContext(request))



def check_post_request(postdata):
	if not 'apikey' in postdata:
		return False, None, HttpResponseBadRequest("No 'apikey' in post data")

	if not 'data' in postdata:
		return False, None, HttpResponseBadRequest("No 'data' in post data")

	try:
		userinfo = UserProfile.objects.get(apiKey__exact = postdata['apikey'])
	except ObjectDoesNotExist:
		return False, None, HttpResponseBadRequest("Bad API key.")

	return True, userinfo, None



def check_post_request_apikey(postdata):
	if not 'apikey' in postdata:
		return False, None, HttpResponseBadRequest("No 'apikey' in post data")

	try:
		userinfo = UserProfile.objects.get(apiKey__exact = postdata['apikey'])
	except ObjectDoesNotExist:
		return False, None, HttpResponseBadRequest("Bad API key.")

	return True, userinfo, None



def upload(request):
	if request.method != 'POST':
		return HttpResponseBadRequest('Not POST request')

	isSuccess, userinfo, http_response = check_post_request(request.POST)
	if not isSuccess:
		return http_response
	username = userinfo.userID.username

	if 'collection_name' in request.POST:
		collection = db[request.POST['collection_name']]
	else:
		collection = db[username]
	waveseg = json.loads(request.POST['data'])
	collection.insert(waveseg)

	return HttpResponse("Upload successful (" + username + ")")



def log(object):
	print >> sys.stderr, str(object)
	sys.stderr.flush()


@login_required
def profile(request):
	request.session.set_expiry(0) # logout when browser is closed.
	try:
		userinfo = UserProfile.objects.get(userID__exact = request.user)
		apiKey = userinfo.apiKey
	except ObjectDoesNotExist:
		apiKey = "API Key doesn't exist."
	return render_to_response('registration/profile.html', { 'apiKey': apiKey }, context_instance=RequestContext(request))


def logout_view(request):
	logout(request)
	return HttpResponseRedirect('/login/')


def register(request, url=None):
	errorMsg = []
	if request.method == 'POST':
		form = UserRegistrationForm(request.POST)

		if form.is_valid():
			error = False
			if form.data['password'] != form.data['confirm_password']:
				errorMsg.append("Password didn't match.")
				error = True
			
			# Make sure username is available and email is not already in system
			isNewUser = False
			try: 
				authUser.objects.get(username__exact=form.data['username'])
			except ObjectDoesNotExist:
			 isNewUser = True

			isNewEmail = False
			try: 
				authUser.objects.get(email__exact=form.data['email'])
			except ObjectDoesNotExist:
				isNewEmail = True

			if not isNewUser:
				errorMsg.append("Existing user name.")
				error = True
			if not isNewEmail:
				errorMsg.append("Existing email address.")
				error = True

			if not error:
				# create a user
				newUser = authUser.objects.create_user(form.data['username'], form.data['email'], form.data['password'])
				newUser.first_name = form.data['first_name']
				newUser.last_name = form.data['last_name']
				newUser.save()

				# generate keys
				apiKey = hashlib.sha1(newUser.username + str(random.random())).hexdigest()
				newUserProfile = UserProfile(userID = newUser, apiKey = apiKey) 
				newUserProfile.save()
		
				# register in broker
				try:
					params = urllib.urlencode({
						'apikey': apiKey, 
						'username': form.data['username'],
						'password': form.data['password'],
						'first_name': form.data['first_name'],
						'last_name': form.data['last_name'],
						'email': form.data['email'],
						'address': request.get_host()
					}) 
					conn = httplib.HTTPSConnection(BROKER_ADDRESS, timeout=10)
					conn.request('POST', '/broker/register_contributor/', params)
					response = conn.getresponse()
					log(str(response.status) + ' ' + response.reason)
					#print response.getheaders()
					reply = response.read()
					log(reply)
					conn.close()
				except Exception as detail:
					log('Error: ' + str(detail))

				# log the user in
				logout(request)
				user = authenticate(username=form.data['username'], password=form.data['password'])
				login(request, user)

				return HttpResponseRedirect('/profile/')
	else:
		form = UserRegistrationForm()

	return render_to_response('registration/register.html', { 'form': form, 'errorMsg': errorMsg }, context_instance=RequestContext(request))



def process_repeat_time(query, collection):
	repeat_time = query['repeat_time']
	del query['repeat_time']

	if not 'time_range' in repeat_time:
		cursor = collection.find(None, { 'timestamp': 1 }).sort('timestamp', pymongo.ASCENDING)
		repeat_time['time_range'] = [ cursor[0]['timestamp'], cursor[cursor.count()-1]['timestamp'] ]

	starttime = datetime.fromtimestamp(repeat_time['time_range'][0]/1000.0).replace(hour=0, minute=0, second=0, microsecond=0)
	endtime = datetime.fromtimestamp(repeat_time['time_range'][1]/1000.0).replace(hour=0, minute=0, second=0, microsecond=0)
	aday = timedelta(1)
	aweek = timedelta(7)
	endtime += aday

	if 'hour_min' in repeat_time:
		fromtime = datetime.strptime(repeat_time['hour_min'][0], '%I:%M%p')
		totime = datetime.strptime(repeat_time['hour_min'][1], '%I:%M%p')

		init_t1 = datetime(starttime.year, starttime.month, starttime.day, fromtime.hour, fromtime.minute, 0, 0, starttime.tzinfo)
		init_t2 = datetime(starttime.year, starttime.month, starttime.day, totime.hour, totime.minute, 0, 0, starttime.tzinfo)

		if not '$or' in query:
			query['$or'] = []

		for daystr in repeat_time['day']:
			wday = time.strptime(daystr, '%a').tm_wday

			t1 = init_t1
			t2 = init_t2

			while t1.weekday() != wday:
				t1 += aday
				t2 += aday

			while t1 <= endtime and t2 <= endtime:
				query['$or'].append( { 'timestamp': { '$gte': time.mktime(t1.timetuple())*1000, '$lte': time.mktime(t2.timetuple())*1000 } } )
				t1 += aweek
				t2 += aweek
	else: # for All day
		init_t1 = datetime(starttime.year, starttime.month, starttime.day, 0, 0, 0, 0, starttime.tzinfo)
		init_t2 = datetime(starttime.year, starttime.month, starttime.day, 0, 0, 0, 0, starttime.tzinfo)
		init_t2 += aday

		if not '$or' in query:
			query['$or'] = []

		for daystr in repeat_time['day']:
			wday = time.strptime(daystr, '%a').tm_wday

			t1 = init_t1
			t2 = init_t2

			while t1.weekday() != wday:
				t1 += aday
				t2 += aday

			while t1 <= endtime and t2 <= endtime:
				query['$or'].append( { 'timestamp': { '$gte': time.mktime(t1.timetuple())*1000, '$lt': time.mktime(t2.timetuple())*1000 } } )
				t1 += aweek
				t2 += aweek

	if not query['$or']:
		# no data for this repeat_time
		return False

	log('in process: ' + str(query))
	return True



def process_location_label(query, username):
	label_col = db[username+'_location_labels']
	if not '$or' in query:
		query['$or'] = []
	for label in query['location_label']:
		range = label_col.find_one({ 'label': label }, { 'label': 0, '_id': 0 })
		if range is not None:
			query['$or'].append(range)
	if not query['$or']:
		del query['$or']
	del query['location_label']

	return True



def reduce_address(address_str, level):
	address = address_str.rsplit(', ', 3)
	city = str(address[1])
	state = str(address[2].split(' ')[0])
	zipcode = str(address[2].split(' ')[1])
	country = str(address[3])

	if level == 'street':
		return address_str
	elif level == 'zipcode':
		return zipcode
	elif level == 'city':
		return city + ', ' + state + ', ' + country
	elif level == 'state':
		return state + ', ' + country
	elif level == 'country':
		return country



def mean(l):
	fnums = [float(x) for x in l]
	return sum(fnums) / len(l)



def modify_waveseg(waveseg, modify_rule, first_timestamp):
	gc_collection = db['geocode_cache']

	if 'location_resolution' in modify_rule:
		if not modify_rule['location_resolution'] == 'dontmodify':
			if not modify_rule['location_resolution'] == 'nolocation':
				# find geocode
				geocode = gc_collection.find_one({ 'location.latitude': waveseg['location']['latitude'], 'location.longitude': waveseg['location']['longitude'] })

				if not geocode:
					address = gmaps.latlng_to_address(waveseg['location']['latitude'], waveseg['location']['longitude'])
					gc_collection.insert({ 'location': waveseg['location'], 'address': address })
				else:
					address = geocode['address']

				location = reduce_address(address, modify_rule['location_resolution'])
				waveseg['location'] = location

			# no location
			else:
				del waveseg['location']
	
	if 'timestamp_resolution' in modify_rule:
		if not modify_rule['timestamp_resolution'] == 'dontmodify':
			timestamp = time.localtime(waveseg['timestamp'])
			waveseg['timestamp'] -= first_timestamp
			if modify_rule['timestamp_resolution'] == 'hour':
				waveseg['time_info'] = time.strftime('%H:00, %m/%d/%Y', timestamp)
			elif modify_rule['timestamp_resolution'] == 'day':
				waveseg['time_info'] = time.strftime('%m/%d/%Y', timestamp)
			elif modify_rule['timestamp_resolution'] == 'month':
				waveseg['time_info'] = time.strftime('%d/%Y', timestamp)
			elif modify_rule['timestamp_resolution'] == 'year':
				waveseg['time_info'] = time.strftime('%Y', timestamp)

	if 'sample_rate' in modify_rule:
		for sample_rate_rule in modify_rule['sample_rate']:
			if type(waveseg['data_channel']).__name__ == 'list':
				num_channels = len(waveseg['data_channel'])
				if sample_rate_rule[0] in waveseg['data_channel']:
					#log('sample_rate: ' + str(sample_rate_rule[0]) + ', rate: ' + str(sample_rate_rule[1]))a
					start_time = waveseg['timestamp']
					new_interval = 1.0 / sample_rate_rule[1]
					old_interval = waveseg['sampling_interval']
					
					#log('new_interval: ' + str(new_interval) + ', old_interval: ' + str(old_interval))
				
					cur_time = start_time
					new_time = start_time
					cur_values = []
					for i in xrange(0,num_channels):
						cur_values.append([])
					new_data = []

					for value in waveseg['data']:
						#log('  ' + str(cur_time) + ': ' + str(value))
						if cur_time >= new_time and cur_time < new_time + new_interval:
							for i in xrange(0,num_channels):
								cur_values[i].append(value[i])
						else:
							#log(str(new_time) + ': ' + str(cur_values))
							new_value = []
							for i in xrange(0,num_channels):
								new_value.append(mean(cur_values[i]))
								cur_values[i] = [value[i]]
							new_data.append(new_value)

							new_time += new_interval
						cur_time += old_interval
					
					new_value = []
					for i in xrange(0,num_channels):
						new_value.append(mean(cur_values[i]))
					new_data.append(new_value)
					
					#log(new_data)
					waveseg['data'] = new_data
					waveseg['sampling_interval'] = new_interval
			else:
				if waveseg['data_channel'] == sample_rate_rule[0]:
					#log('sample_rate: ' + str(sample_rate_rule[0]) + ', rate: ' + str(sample_rate_rule[1]))a
					start_time = waveseg['timestamp']
					new_interval = 1.0 / sample_rate_rule[1]
					old_interval = waveseg['sampling_interval']
					
					#log('new_interval: ' + str(new_interval) + ', old_interval: ' + str(old_interval))
				
					cur_time = start_time
					new_time = start_time
					cur_values = []
					new_data = []
					for value in waveseg['data']:
						#log('  ' + str(cur_time) + ': ' + str(value))
						if cur_time >= new_time and cur_time < new_time + new_interval:
							cur_values.append(value)
						else:
							#log(str(new_time) + ': ' + str(cur_values))
							new_data.append(mean(cur_values))
							cur_values = [value]
							new_time += new_interval
						cur_time += old_interval
					new_data.append(mean(cur_values))

					#log(new_data)
					waveseg['data'] = new_data
					waveseg['sampling_interval'] = new_interval



def process_modify_rules(modify_result, collection):
	first_timestamp = collection.find().sort('timestamp', pymongo.ASCENDING)[0]['timestamp']	
	for target_ids, modify_rule in modify_result:
		for id in target_ids:
			waveseg = collection.find_one(id)
			if waveseg:
				modify_waveseg(waveseg, modify_rule, first_timestamp)
				#collection.update({ '_id': id }, { '$set': { 'location': location } })
				collection.save(waveseg)



def isExistQueryOptions(message):
	return 'select' in message or 'distinct' in message or 'sort' in message or 'at' in message
					


def waveseg_preprocess(username, collection, message, rules, consumer):
	#log('--- start of waveseg_preprocess() ---')

	time_boundaries = []

	# get time stamps in query
	if 'query' in message and message['query']:
		if 'timestamp' in message['query']:
			time_boundaries.append(message['query']['timestamp']['$gte'])
			time_boundaries.append(message['query']['timestamp']['$lte'])
		if 'repeat_time' in message['query']:
			if not process_repeat_time(message['query'], collection):
				return False, HttpResponseBadRequest("There is no data")
			for tcond in message['query']['$or']:
				if 'timestamp' in tcond:
					time_boundaries.append(int(tcond['timestamp']['$gte']))
					time_boundaries.append(int(tcond['timestamp']['$lte']))

	# get time stamps in rules
	if rules != None:
		rule_cursor = rules.find({ '$or': [ { 'consumer': None }, { 'consumer': consumer } ] }, { '_id': 0 })
		
		for rule in rule_cursor:
			if 'timestamp' in rule:
				time_boundaries.append(rule['timestamp']['$gte'])
				time_boundaries.append(rule['timestamp']['$lte'])
			if 'repeat_time' in rule:
				if not process_repeat_time(rule, collection):
					continue
				for tcond in rule['$or']:
					if 'timestamp' in tcond:
						time_boundaries.append(int(tcond['timestamp']['$gte']))
						time_boundaries.append(int(tcond['timestamp']['$lte']))

	# if no time condition. return.
	if len(time_boundaries) <= 0:
		return False, None

	time_boundaries = list(set(time_boundaries))
	#log('time_boundaries: ' + str(time_boundaries))

	# make new collection
	temp_collection_name = 'temp_' + hashlib.sha1(str(random.random())).hexdigest()
	new_collection = db[temp_collection_name]
	
	#### split wavesegs in time boundaries and inser into the new collection ###
	data_channels = collection.find().distinct('data_channel')

	# get data channels by handling multi channels
	multi_channels = []
	new_data_channels = []
	for dc in data_channels:
		dcname = dc.split('.')
		if len(dcname) >= 2:
			if dcname[0] not in multi_channels:
				multi_channels.append(dcname[0])
				new_data_channels.append(dc)
		else:
			new_data_channels.append(dc)

	data_channels = new_data_channels
	
	#log(data_channels)

	# split at time boundaries	
	for dc in data_channels:
		#log('data_channel: ' + str(dc))
		cursor = collection.find({ 'data_channel': dc }, { '_id': 0 }).sort('timestamp')
		tb_idx = 0
		for waveseg in cursor:
			#log(waveseg)
			# check end of time boundaries
			if tb_idx >= len(time_boundaries):
				new_collection.insert(waveseg)
				continue

			starttime = waveseg['timestamp']
			endtime = waveseg['timestamp'] + (len(waveseg['data']) - 1) * waveseg['sampling_interval']

			while time_boundaries[tb_idx] <= starttime:
				tb_idx += 1
				if tb_idx >= len(time_boundaries):
					break
			if tb_idx >= len(time_boundaries):
				new_collection.insert(waveseg)
				continue

			#log('starttime: ' + str(starttime) + ', endtime: ' + str(endtime) + ', tb: ' + str(time_boundaries[tb_idx]))
			while time_boundaries[tb_idx] > starttime and time_boundaries[tb_idx] <= endtime:
				#log('in!')
				next_idx = int(math.ceil((time_boundaries[tb_idx] - starttime) / float(waveseg['sampling_interval'])))
				data1 = waveseg['data'][:next_idx]
				data2 = waveseg['data'][next_idx:]
				new_waveseg = copy(waveseg)
				new_waveseg['data'] = data1
				#log('new_waveseg timestamp: ' + str(new_waveseg['timestamp']))
				result = new_collection.insert(new_waveseg)
				#log(result)
				new_waveseg2 = copy(waveseg)
				new_waveseg2['data'] = data2
				new_waveseg2['timestamp'] = starttime + next_idx * waveseg['sampling_interval']
				tb_idx += 1
				waveseg = new_waveseg2
				starttime = waveseg['timestamp']

				if tb_idx >= len(time_boundaries):
					break
				
			#log('waveseg timestamp: ' + str(waveseg['timestamp']))
			result = new_collection.insert(waveseg)
			#log(result)

	#log('new_collection count: ' + str(new_collection.find().count()))

	#log('--- end of waveseg_preprocess() ---')
	return True, temp_collection_name


def query(request):
	perform_test = []

	if request.method != 'POST':
		return HttpResponseBadRequest('Not POST request')

	if not 'apikey' in request.POST:
		return HttpResponseBadRequest("No 'apikey' in post data")

	if not 'data' in request.POST:
		return HttpResponseBadRequest("No 'data' in post data")

	isConsumer = False
	try:
		userinfo = UserProfile.objects.get(apiKey__exact = request.POST['apikey'])
	except ObjectDoesNotExist:
		isConsumer = True
	
	if not isConsumer:
		username = userinfo.userID.username
	else:

		# find who is this on broker.
		try:
			params = urllib.urlencode({
				'apikey': request.POST['apikey'], 
			}) 
			conn = httplib.HTTPSConnection('fieldstream.nesl.ucla.edu', timeout=10)
			conn.request('POST', '/broker/get_username/', params)
			response = conn.getresponse()
			#log(str(response.status) + ' ' + response.reason)
			#print response.getheaders()
			reply = response.read()
			#log(reply)
			conn.close()
		except Exception as detail:
			log('Error: ' + str(detail))
	
		if response.status != 200:
			return HttpResponseBadRequest(json.dumps({'error': 'Error from broker: ' + reply}))
		
		if not 'contributor' in request.POST:
			return HttpResponseBadRequest("No 'contributor' in post data")
		username = request.POST['contributor']

		# TODO: check if this username exist

		consumer = reply

	message = json.loads(request.POST['data'])
	
	#collection = db[username]
	#collection = db[username + '_test200']
	#collection = db[username + '_test200_opt']

	collection = db[username + '_testdata_opt']
	#collection = db[username + '_testdata_opt']
	
	#collection = db[username + '_test_10000']
	#collection = db[username + '_test_1000_opt']
	#collection = db['result']
	#collection.ensure_index([('location', pymongo.GEO2D)])

	if 'test' in message:
		if message['test'] == 'opt':
			collection = db[username + '_testdata_opt']
		else:
			collection = db[username + '_testdata']

	collection.ensure_index('_id')

	log('########### NEW QUERY ##############')
	log(message)

	cursor = None
	waveseg_pre_temp_collection_name = None
	temp_collection_name = None
	isQueryOptions = isExistQueryOptions(message)
	#isQueryOptions = True

	# filter by rules...
	if isConsumer: 	
		
		# find rules apply to current consumer
		rules = db[username + '_rules']
		rule_cursor = rules.find({ '$or': [ { 'consumer': None }, { 'consumer': consumer } ] }, { '_id': 0 })

		# if rule exists
		if rule_cursor.count() > 0:

			starttime = time.time()
		
			# waveseg preprocess for time queries	
			result, waveseg_pre_temp_collection_name = waveseg_preprocess(username, collection, message, rules, consumer)
			if result:
				collection = db[waveseg_pre_temp_collection_name]

			elap_time = time.time() - starttime
			log('waveseg preprocess time: ' + str(elap_time))
			perform_test.append(elap_time)

			starttime = time.time()
			
			# first perform query
			if 'query' in message and message['query']:
				if 'location_label' in message['query']:
					if not process_location_label(message['query'], username):
						return HttpResponseBadRequest("Error from process_location_label")
				if 'repeat_time' in message['query']:
					if not process_repeat_time(message['query'], collection):
						return HttpResponseBadRequest("There is no data")
				query_result = set(collection.find(message['query']).distinct('_id'))
			else:
				query_result = set(collection.find().distinct('_id'))

			elap_time = time.time() - starttime
			log('original query processing time: ' + str(elap_time))
			perform_test.append(elap_time)
			log('before filtering # of wavesegs: ' + str(len(query_result)))

			starttime = time.time()

			# process the rules.
			allow_result = []
			deny_result = []
			modify_result = []
			for rule in rule_cursor:
				if 'consumer' in rule:
					del rule['consumer']
				if 'rule_name' in rule:
					del rule['rule_name']

				# convert rule to valid query object...
				# log('before: ' + str(rule))
				if 'location_label' in rule:
					if not process_location_label(rule, username):
						return HttpResponseBadRequest("Error from process_location_label")
				if 'repeat_time' in rule:
					if not process_repeat_time(rule, collection):
						#return HttpResponseBadRequest("There is no data")
						continue

				if 'action' in rule:
					if rule['action'] == 'allow': 
						del rule['action']
						allow_result.append(set(collection.find(rule).distinct('_id')))
					elif rule['action'] == 'modify':
						modify_rule = rule['modify']
						del rule['modify']
						del rule['action']
						modify_ids = set(collection.find(rule).distinct('_id'))
						modify_result.append((modify_ids, modify_rule))
					else:
						del rule['action']
						deny_result.append(set(collection.find(rule).distinct('_id')))
				else:
					allow_result.append(set(collection.find(rule).distinct('_id')))

				# log('after: ' + str(rule))

			# find intersection of query and rule results
			if allow_result:
				allow_result = set.union(*allow_result)
				query_result &= allow_result
			if deny_result:
				deny_result = set.union(*deny_result)
				query_result -= deny_result
	
			elap_time = time.time() - starttime
			log('rule processing time: ' + str(elap_time))
			perform_test.append(elap_time)

			if (len(query_result) <= 0):
				return HttpResponse('[]')

			if isQueryOptions:
				# make new collection with allowed documents
				temp_collection_name = 'temp_' + hashlib.sha1(str(random.random())).hexdigest()
				new_collection = db[temp_collection_name]

				starttime = time.time()
				for id in query_result:
					new_collection.insert(collection.find_one(id))
				elap_time = time.time() - starttime
				log('insert operation: ' + str(elap_time))
				perform_test.append(elap_time)

				collection = new_collection

				#starttime = time.time()
				#for id in query_result:
				#	collection.find_one(id)
				#log('find_one() operation:' + str(time.time() - starttime))
				
				# process modify
				if len(modify_result) > 0:
					starttime = time.time()
					process_modify_rules(modify_result, collection)
					log('modify rules operation: ' + str(time.time() - starttime))

				# process select
				if not 'select' in message:
					cursor = collection.find(None, {'_id': 0})
				else:
					select = message['select']
					select['_id'] = 0
					cursor = collection.find(None, select)
				
				log('after filtering: ' + str(cursor.count()))

		# when there are no rules for this consumer
		else:
			return HttpResponse('[]')

	# when it is owner.
	else:

		starttime = time.time()
		
		# waveseg preprocess for time queries
		result, waveseg_pre_temp_collection_name = waveseg_preprocess(username, collection, message, None, None)
		if result:
			collection = db[waveseg_pre_temp_collection_name]
		
		log('waveseg preprocess time: ' + str(time.time() - starttime))

		starttime = time.time()

		if not 'select' in message:
			if 'query' in message and message['query']:
				if 'location_label' in message['query']:
					if not process_location_label(message['query'], username):
						return HttpResponseBadRequest("Error from process_location_label")
				if 'repeat_time' in message['query']:
					if not process_repeat_time(message['query'], collection):
						return HttpResponseBadRequest('There is no data')
				log('after process: ' + str(message['query']))
				cursor = collection.find(message['query'], {'_id': 0})
			else:
				cursor = collection.find(None, {'_id': 0})
		else:
			select = message['select']
			select['_id'] = 0
			if 'query' in message and message['query']:
				if 'location_label' in message['query']:
					if not process_location_label(message['query'], username):
						return HttpResponseBadRequest("Error from process_location_label")
				if 'repeat_time' in message['query']:
					if not process_repeat_time(message['query'], collection):
						return HttpResponseBadRequest('There is no data')
				log('after process: ' + str(message['query']))
				cursor = collection.find(message['query'], select)
			else:
				cursor = collection.find(None, select)
	
		log('process query and getting cursor: ' + str(time.time() - starttime))

	if isQueryOptions:
		# perform query options
		if 'sort' in message and message['sort']:
			for k, v in message['sort'].iteritems():
				collection.ensure_index(k);
				if v == 1:
					cursor = cursor.sort(k, pymongo.ASCENDING)
				elif v == -1:
					cursor = cursor.sort(k, pymongo.DESCENDING)

		if 'distinct' in message and message['distinct']:
			cursor = cursor.distinct(message['distinct'])

		if 'at' in message and message['at']:
			if cursor.count() <= 0:
				return HttpResponseBadRequest(json.dumps({'error': "There are no data"}))
			if message['at'] == 'last':
				count = cursor.count()
				data = cursor[count-1]
			elif message['at'] == 'first':
				data = cursor[0]
			else:
				data = cursor[message['at']]
		else:
			starttime = time.time()
			data = []
			for obj in cursor:
				data.append(obj)
			elap_time = time.time() - starttime
			log('retrieve operation: ' + str(elap_time))
			perform_test.append(elap_time)

		if temp_collection_name:
			db.drop_collection(temp_collection_name)

	# no query options
	else:

		if not isConsumer:
			starttime = time.time()
			data = []
			for obj in cursor:
				data.append(obj)
			log('retrieve operation: ' + str(time.time() - starttime))
		else:
			cursor = collection.find()
			log('after filtering: ' + str(len(query_result)))
			starttime = time.time()
			data = []
			first_timestamp = cursor.sort('timestamp', pymongo.ASCENDING)[0]['timestamp']	
			for id in query_result:
				obj = collection.find_one(id)
				del obj['_id']
				for modify_id, modify_rule in modify_result:
					if id in modify_id:
						modify_waveseg(obj, modify_rule, first_timestamp)
				data.append(obj)

			elap_time = time.time() - starttime
			log('retrieve & modify operation: ' + str(elap_time))
			perform_test.append(elap_time)

	starttime = time.time()
	
	json_data = json.dumps(data)

	elap_time = time.time() - starttime
	log('json encoding time: ' + str(elap_time))
	perform_test.append(elap_time)

	if waveseg_pre_temp_collection_name != None:
		db.drop_collection(waveseg_pre_temp_collection_name)

	if not 'test' in message:
		return HttpResponse(json_data)
	else:
		return HttpResponse(json.dumps(perform_test))



@login_required
def display(request):
	userinfo = UserProfile.objects.get(userID__exact = request.user)
	return render_to_response('display2.html', { 'apikey': userinfo.apiKey }, context_instance=RequestContext(request))



def uploadrules(request):
	if not request.method == 'POST':
		return HttpResponseBadRequest('Not POST request')
	
	isSuccess, userinfo, http_response = check_post_request(request.POST)
	if not isSuccess:
		return http_response
	username = userinfo.userID.username
	
	rule = json.loads(request.POST['data'])
	collection = db[username + '_rules']

	if '_id' in rule:
		rule['_id'] = bson.objectid.ObjectId(rule['_id'])

	collection.save(rule, check_keys=False)

	return HttpResponse('Successfully uploaded a rule.')



def getrules(request):
	if not request.method == 'POST':
		return HttpResponseBadRequest('Not POST request')
	
	isSuccess, userinfo, http_response = check_post_request_apikey(request.POST)
	if not isSuccess:
		return http_response
	username = userinfo.userID.username
	
	collection = db[username + '_rules']
	rules = []
	for rule in collection.find(None, { '_id': 0 }):
		rules.append(rule)
	return HttpResponse(json.dumps(rules))



def deleterules(request):
	if not request.method == 'POST':
		return HttpResponseBadRequest('Not POST request')
	
	isSuccess, userinfo, http_response = check_post_request_apikey(request.POST)
	if not isSuccess:
		return http_response
	username = userinfo.userID.username

	collection = db[username + '_rules']

	rule_id_list = []
	for id in json.loads(request.POST['rule_ids']):
		rule_id_list.append(bson.objectid.ObjectId(id))

	collection.remove({ '_id': { '$in': rule_id_list} } );
	return HttpResponse('Successfully deleted rules')


@login_required
def privacyrules(request):
	userinfo = UserProfile.objects.get(userID__exact = request.user)
	username = userinfo.userID.username
	collection = db[username + '_rules']
	rules = []
	for rule in collection.find():		
		rule['_id'] = str(rule['_id'])
		rules.append({ 'rule_json': json.dumps(rule), 'rule_id': rule['_id'], 'rule_name': rule['rule_name'] })	
	return render_to_response('privacyrules.html', { 'apikey': userinfo.apiKey, 'rule_list': rules }, context_instance=RequestContext(request))



def locationlabel(request):
	if not request.method == 'POST':
		return HttpResponseBadRequest('Not POST request')
	
	isSuccess, userinfo, http_response = check_post_request_apikey(request.POST)
	if not isSuccess:
		return http_response
	username = userinfo.userID.username

	if not 'action' in request.POST:
		return HttpResponseBadRequest('No action in POST data')

	collection = db[username + '_location_labels']
	
	if request.POST['action'] == 'add':
		label = json.loads(request.POST['data'])
		if collection.find({ 'label': label['label'] }).count() >= 1:
			return HttpResponse('Error: existing label')
		collection.insert(label, check_keys=False)
	elif request.POST['action'] == 'get':
		labels = []
		for o in collection.find(None, { '_id': 0 }):
			labels.append(o)
		return HttpResponse(json.dumps(labels))
	elif request.POST['action'] == 'delete':
		collection.remove({ 'label': request.POST['label'] })
	else:
		return HttpResponseBadRequest('Unknown action: ' + request.POST['action'])

	return HttpResponse('Success');



def get_modify_list(search_cond):
	modify_list = []
	if 'location_resolution' in search_cond:
		modify_list.append('location_resolution')
	if 'timestamp_resolution' in search_cond:
		modify_list.append('timestamp_resolution')
	if 'sample_rate' in search_cond:
		modify_list.append('sample_rate')
	return modify_list



def is_time_subset(cond, rule):
	cond_start = cond['timerange']['$gte']
	cond_end = cond['timerange']['$lte']

	if 'timestamp' in rule:
		rule_start = rule['timestamp']['$gte']
		rule_end = rule['timestamp']['$lte']
		if not (cond_start >= rule_start and cond_end <= rule_end):
			return False
	
	if 'repeat_time' in rule and 'time_range' in rule['repeat_time']:
		rule_start = rule['repeat_time']['time_range'][0]
		rule_end = rule['repeat_time']['time_range'][1]
		if not (cond_start >= rule_start and cond_end <= rule_end):
			return False

	return True



def is_time_overlap(cond, rule):
	cond_start = cond['timerange']['$gte']
	cond_end = cond['timerange']['$lte']

	if 'timestamp' in rule:
		rule_start = rule['timestamp']['$gte']
		rule_end = rule['timestamp']['$lte']
		if rule_end >= cond_start and rule_start <= cond_end:
			return True

	if 'repeat_time' in rule:
		if 'time_range' in rule['repeat_time']:
			rule_start = rule['repeat_time']['time_range'][0]
			rule_end = rule['repeat_time']['time_range'][1]
			if rule_end >= cond_start and rule_start <= cond_end:
				return True
		else:
			# TODO
			return False

	return False

def rank(str):
	if str == 'dontmodify':
		return 6
	elif str == 'street':
		return 5
	elif str == 'zipcode' or str == 'hour':
		return 4
	elif str == 'city' or str == 'day':
		return 3
	elif str == 'state' or str == 'month':
		return 2
	elif str == 'country' or str == 'year':
		return 1
	elif str == 'nolocation' or str == 'notime':
		return 0



def is_modify_ok(check_item, rule):
	rule_modify = rule['modify']

	if 'location_resolution' in check_item and 'location_resolution' in rule_modify:
		if rank(check_item['location_resolution']) > rank(rule_modify['location_resolution']):
			return False
	
	if 'timestamp_resolution' in check_item and 'timestamp_resolution' in rule_modify:
		if rank(check_item['timestamp_resolution']) > rank(rule_modify['timestamp_resolution']):
			return False

	if 'sample_rate' in check_item and 'sample_rate' in rule_modify:
		for rule_sample_rate in rule_modify['sample_rate']:
			if check_item['sample_rate'][0] == rule_sample_rate[0]:
				if check_item['sample_rate'][1] > rule_sample_rate[1]:
					return False	

	return True



def is_allow_condition_match(check_item, rule):
	if 'location_label' in check_item:
		if 'location_label' in rule:
			if not check_item['location_label'] in rule['location_label']:
				return False

	if 'timestamp' in check_item:
		if 'timestamp' in rule or 'repeat_time' in rule:
			rule_time = {}
			if 'timestamp' in rule:
				rule_time['timestamp'] = rule['timestamp']
			if 'repeat_time' in rule:
				rule_time['repeat_time'] = rule['repeat_time']
			if not is_time_subset(check_item['timestamp'], rule_time):
				return False

	if 'data_channel' in check_item:
		if 'data_channel' in rule:
			if not check_item['data_channel'] in rule['data_channel']['$in']:
				return False

	return True



def is_deny_condition_match(check_item, rule):
	num_cond = 0
	if 'location_label' in rule:
		num_cond += 1
	if 'timestamp' in rule or 'repeat_time' in rule:
		num_cond += 1
	if 'data_channel' in rule:
		num_cond += 1

	if num_cond == 0:
		return True

	match_cond = 0
	if 'location_label' in check_item:
		if 'location_label' in rule:
			if not check_item['location_label'] in rule['location_label']:
				return False
			else:
				match_cond += 1

	if 'timestamp' in check_item:
		if 'timestamp' in rule or 'repeat_time' in rule:
			rule_time = {}
			if 'timestamp' in rule:
				rule_time['timestamp'] = rule['timestamp']
			if 'repeat_time' in rule:
				rule_time['repeat_time'] = rule['repeat_time']
			if not is_time_overlap(check_item['timestamp'], rule_time):
				return False
			else:
				match_cond += 1

	if 'data_channel' in check_item:
		if 'data_channel' in rule:
			if not check_item['data_channel'] in rule['data_channel']['$in']:
				return False
			else:
				match_cond += 1

	if num_cond == match_cond:
		return True
	
	return False


def search_rules(request):
	if request.method != 'POST':
		return HttpResponseBadRequest('Not POST request')

	if not 'apikey' in request.POST:
		return HttpResponseBadRequest("No 'apikey' in post data")

	if not 'query' in request.POST:
		return HttpResponseBadRequest("No 'data' in post data")

	# check identity
	isConsumer = False
	try:
		userinfo = UserProfile.objects.get(apiKey__exact = request.POST['apikey'])
	except ObjectDoesNotExist:
		isConsumer = True
	
	if not isConsumer:
		requestor_name = userinfo.userID.username
	else:
		# find who is this on broker.
		try:
			params = urllib.urlencode({
				'apikey': request.POST['apikey'], 
			}) 
			conn = httplib.HTTPSConnection('fieldstream.nesl.ucla.edu', timeout=10)
			conn.request('POST', '/broker/get_username/', params)
			response = conn.getresponse()
			#log(str(response.status) + ' ' + response.reason)
			#print response.getheaders()
			reply = response.read()
			#log(reply)
			conn.close()
		except Exception as detail:
			log('Error: ' + str(detail))
	
		if response.status != 200:
			return HttpResponseBadRequest(json.dumps({'error': 'Error from broker: ' + reply}))

		requestor_name = reply
	
	log(requestor_name)

	# make check list table

	# location_label
	search_cond = json.loads(request.POST['query'])
	check_list = []
	if 'location_label' in search_cond:
		for label in search_cond['location_label']:
			new_search_cond = copy(search_cond)
			del new_search_cond['location_label']
			new_search_cond['location_label'] = label
			check_list.append(new_search_cond)
	else:
		check_list.append(search_cond)

	# data channel
	check_list_temp = []
	for check_item in check_list:
		if 'data_channel' in check_item:
			for data_channel in check_item['data_channel']:
				new_item = copy(check_item)
				del new_item['data_channel']
				new_item['data_channel'] = data_channel
				check_list_temp.append(new_item)
		else:
			check_list_temp.append(check_item)
	check_list = check_list_temp	

	# modification
	check_list_temp = []
	for check_item in check_list:
		modify_list = get_modify_list(check_item)
		if len(modify_list) >= 2:
			for modify_item in modify_list:
				new_item = copy(check_item)
				for mi in modify_list:
					if mi != modify_item:
						del new_item[mi]
				check_list_temp.append(new_item)
		else:
			check_list_temp.append(check_item)
	check_list = check_list_temp
	
	# sample rate
	check_list_temp = []
	for check_item in check_list:
		if 'sample_rate' in check_item:
			for sample_item in check_item['sample_rate']:
				new_item = copy(check_item)
				del new_item['sample_rate']
				new_item['sample_rate'] = sample_item
				check_list_temp.append(new_item)
		else:
			check_list_temp.append(check_item)
	check_list = check_list_temp
	
	# add marking field.
	check_list_temp = []
	for check_item in check_list:
		check_list_temp.append( [False, check_item] )
	check_list = check_list_temp
	
	# search privacy rules.
	all_users = authUser.objects.all()
	satisfy_users = []
	for user in all_users:
		username = user.username
		log(username)
		rules = db[username + '_rules']

		for check_item in check_list:
			check_item[0] = False

		# get rules apply for this data consumer
		for rule in rules.find({ '$or': [ { 'consumer': None }, { 'consumer': requestor_name } ], 'action': 'allow' }, { '_id': 0 }):
			for check_item in check_list:
				if is_allow_condition_match(check_item[1], rule):
					check_item[0] = True

		for rule in rules.find({ '$or': [ { 'consumer': None }, { 'consumer': requestor_name } ], 'action': 'deny' }, { '_id': 0 }):
			for check_item in check_list:
				if is_deny_condition_match(check_item[1], rule):
					check_item[0] = False

		for rule in rules.find({ '$or': [ { 'consumer': None }, { 'consumer': requestor_name } ], 'action': 'modify' }, { '_id': 0 }):
			for check_item in check_list:
				if check_item[0] == True and is_allow_condition_match(check_item[1], rule):
					if not is_modify_ok(check_item[1], rule):
						check_item[0] = False

		log(json.dumps(check_list, indent=2))
		
		# check if this user satisfies check list.
		is_satisfy = True
		for check_item in check_list:
			if check_item[0] == False:
				is_satisfy = False
				break

		if is_satisfy:
			satisfy_users.append(username)
	
	return HttpResponse(json.dumps(satisfy_users))


@login_required
def test(request):
	#collection = db['haksoo_test5']
	#data = collection.find()[0]
	#data['_id'] = str(data['_id'])
	#data = []
	#for obj in collection.find():
	#	obj['_id'] = str(obj['_id'])
	#	data.append(obj)
	#return render_to_response('map-simple.html', {'data': json.dumps(data)})
	#return render_to_response('map-simple.html')
	#userinfo = UserProfile.objects.get(userID__exact = request.user)
	#return render_to_response('display.html', { 'apikey': userinfo.apiKey }, context_instance=RequestContext(request))
	content = 'Hello test!'

	gmaps = GoogleMaps('ABQIAAAA-BHV3Z55zCdo4z_ley123xT2yXp_ZAY8_ufC3CFXhHIE1NvwkxTGit_DA3cmLDETSlrEJ5l9J2xRaQ')
	content = gmaps.latlng_to_address(34.069221114137832, -118.44356926185242)
	lat, lng = gmaps.address_to_latlng('90034')
	content += str(lat)
	content += str(lng)
	return render_to_response('test.html', { 'content': content }, context_instance=RequestContext(request))




