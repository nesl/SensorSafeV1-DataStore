import time
from log import log
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect
import pymongo
from hotshotdecorator import hotshot_profile

import cjson
import json
# To switch to cjson: ,cjson
# To switch to json: ,json




# Default Privacy Engine Options: Best performance
FILTER_BY_MERGING_CONDITIONS = True # DONE
FILTER_BY_SET_OPERATIONS = not FILTER_BY_MERGING_CONDITIONS

ON_THE_FLY_WAVESEG_MODIFICATION = True
WAVESEG_MODIFY_AND_SAVE = not ON_THE_FLY_WAVESEG_MODIFICATION

ON_THE_FLY_WAVESEG_PROCESSING = True
PRE_QUERY_WAVESEG_PROCESSING = not ON_THE_FLY_WAVESEG_PROCESSING




# TODO: Consolidate HTTP response messages. JSON format.
HTTP_RESPONSE_NO_DATA = HttpResponse(cjson.encode([]))



db = None







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
			# make timestamp relative time
			waveseg['timestamp'] -= first_timestamp
			# add 'time_info' field and store timestamp in specified time resolution
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



def create_temporary_collection(filtered_result, collection):
	# Create a new collection
	temp_collection_name = 'temp_' + hashlib.sha1(str(random.random())).hexdigest()
	new_collection = db[temp_collection_name]

	if FILTER_BY_SET_OPERATIONS:
		# Insert the query result into the new collection
		for id in filtered_result:
			new_collection.insert(collection.find_one(id))

	elif FILTER_BY_MERGING_CONDITIONS:
		# TODO: does this work?
		new_collection.insert(collection.find(filtered_result))	

	# Replace current collection.
	collection = new_collection





def get_first_timestamp(collection):
	return collection.find().sort('timestamp', pymongo.ASCENDING)[0]['timestamp']	




def process_modify_rules_on_the_fly(modify_result, data, collection = None, cursor = None, query_result = None):
	
	data = []

	# If no modification, add wavesegs to the return data
	if not modify_result:
		if not cursor:
			cursor = collection.find()
		for waveseg in cursor:
			del waveseg['_id']
			data.append(waveseg)
		return data

	# TODO: check if this takes time!
	first_timestamp = get_first_timestamp(collection)

	if FILTER_BY_SET_OPERATIONS:
		for id in query_result:
			obj = collection.find_one(id)
			del obj['_id']
			# TODO: possibly slow when modify result is big.
			for modify_id, modify_rule in modify_result:
				if id in modify_id:
					modify_waveseg(obj, modify_rule, first_timestamp)
			data.append(obj)

	elif FILTER_BY_MERGING_CONDITIONS:
		# loop through modification list and add it to the return data.
		modified_id_set = ()
		for target_ids, modify_rule in modify_result:
			for id in target_ids:
				modified_id_set.insert(id)
				waveseg = collection.find_one(id)
				if waveseg:
					modify_waveseg(waveseg, modify_rule, first_timestamp)
					del waveseg['_id']
					data.append(waveseg)

		# We also need to add unmodified wavesegs to the return data.
		for waveseg in cursor:
			if not waveseg['_id'] in modified_id_set:
				del waveseg['_id']
				data.append(waveseg)

	return data




def process_modify_rules(modify_result, collection, query_result = None, merged_query = None):
	# process modify_rules()
	#
	# TODO: more performance optimization.
	# we can postpone this to the data retrieval time 
	# (so we can minimize collection.save(), which requires disk access) when...
	# 
	# in modify_rule,
	# if no timestamp_resolution:
	#		postpone.
	# else if selection leaves timestamp, distinct leaves timestamp, "at" != 0:
	#		postpone
	# else
	#		do it here.
	#
	# --> TODO:review this.

	# no modify result, do nothing.
	if not modify_result:
		return
	
	# Make new collection with filtered wavesegs
	if FILTER_BY_SET_OPERATIONS:
		create_temporary_collection(query_result, collection)
	elif FILTER_BY_MERGING_CONDITIONS:
		create_temporary_collection(merged_query, collection)

	# TODO: check if this takes time!
	first_timestamp = collection.find().sort('timestamp', pymongo.ASCENDING)[0]['timestamp']	

	for target_ids, modify_rule in modify_result:
		for id in target_ids:
			waveseg = collection.find_one(id)
			if waveseg:
				modify_waveseg(waveseg, modify_rule, first_timestamp)
				#collection.update({ '_id': id }, { '$set': { 'location': location } })
				collection.save(waveseg)



# TODO: bugs in processing time. add support for location range
def pre_query_waveseg_processing(username, collection, message, rules, consumer):
	#log('--- start of pre_query_waveseg_processing() ---')

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

	#log('--- end of pre_query_waveseg_processing() ---')
	return True, temp_collection_name






def process_location_label(query, username):
	label_col = db[username+'_location_labels']
	if not '$and' in query:
		query['$and'] = []
	for label in query['location_label']:
		range = label_col.find_one({ 'label': label }, { 'label': 0, '_id': 0 })
		if range is not None:
			query['$and'].append(range)
	if not query['$and']:
		del query['$and']
	del query['location_label']

	return True





def condition_preprocessing(condition_object, username):
	if 'location_label' in condition_object:
		if not process_location_label(condition_object, username):
			assert False # Debug this.

	if 'repeat_time' in condition_object:
		if not process_repeat_time(condition_object, collection):
			assert False # Debug this.. something is wrong...





def get_set_of_distinct_ids_from_query_result(message, collection, username):
	if 'query' in message and message['query']:
		condition_preprocessing(message['query'], username)
		return set(collection.find(message['query']).distinct('_id'))
	else:
		return set(collection.find().distinct('_id'))






def get_allow_deny_modify_sets_or_merged_query(allow_result, deny_result, modify_result, merged_query, rule_cursor, username, collection):
	for rule in rule_cursor:
		log('rule: ' + str(rule))

		if 'consumer' in rule:
			del rule['consumer']
		if 'rule_name' in rule:
			del rule['rule_name']

		# Condition pre-processing
		condition_preprocessing(rule, username)

		# get allow_result[], deny_result[], modify_result[]
		if 'action' in rule:
			if rule['action'] == 'allow': 
				del rule['action']

				if FILTER_BY_SET_OPERATIONS:
					allow_result.append(set(collection.find(rule).distinct('_id')))
		
				if FILTER_BY_MERGING_CONDITIONS:
						merged_query['$and'][1]['$or'].append(rule)

			elif rule['action'] == 'modify':
				modify_rule = rule['modify']
				del rule['modify']
				del rule['action']
				modify_ids = set(collection.find(rule).distinct('_id'))

				# save list of wavesegs-to-be-modified.
				modify_result.append((modify_ids, modify_rule))

			elif rule['action'] == 'deny':
				del rule['action']

				if FILTER_BY_SET_OPERATIONS:
					deny_result.append(set(collection.find(rule).distinct('_id')))
				
				if FILTER_BY_MERGING_CONDITIONS:
					# Filtering w/ query condition merging
					merged_query['$nor'].append(rule)

			else:
				assert False # invalid rule['action']

		else:
			assert False # there is no rule['action']






def clean_up_merged_query(merged_query):
	if not merged_query['$nor']:
		del merged_query['$nor']
	if '$and' in merged_query:
		if not merged_query['$and']:
			del merged_query['$and']
	if '$or' in merged_query:
		if not merged_query['$or']:
			del merged_query['$or']

	if not merged_query:
		assert False # empty merged_query{}





def perform_set_operation(query_result, allow_result, deny_result):
	# UNION of allowed wavesegs, AND query result, MINUS denied wavesegs
	
	if allow_result:
		allow_result = set.union(*allow_result)
		query_result &= allow_result

	if deny_result:
		deny_result = set.union(*deny_result)
		query_result -= deny_result





def retrieve_data_from_db(cursor):
	data = []
	for obj in cursor:
		data.append(obj)
	return data



def retrieve_data_from_db_at(cursor, at):
	if cursor.count() <= 0:
		return None

	if at == 'last':
		count = cursor.count()
		data = cursor[count-1]
	elif at == 'first':
		data = cursor[0]
	else:
		data = cursor[at]

	return data


#@hotshot_profile("PrivacyEngine.prof")
def process(dbConnection, request, message, isConsumer, consumer, username, collection, processing_options):
	global db, FILTER_BY_MERGING_CONDITIONS, FILTER_BY_SET_OPERATIONS, ON_THE_FLY_WAVESEG_MODIFICATION, WAVESEG_MODIFY_AND_SAVE, ON_THE_FLY_WAVESEG_PROCESSING, PRE_QUERY_WAVESEG_PROCESSING

	# Set processing options.
	if processing_options:
		FILTER_BY_MERGING_CONDITIONS = processing_options['filter_by_merging_conditions']
		FILTER_BY_SET_OPERATIONS = not FILTER_BY_MERGING_CONDITIONS

		ON_THE_FLY_WAVESEG_MODIFICATION = processing_options['on-the-fly_waveseg_modification']
		WAVESEG_MODIFY_AND_SAVE = not ON_THE_FLY_WAVESEG_MODIFICATION

		ON_THE_FLY_WAVESEG_PROCESSING = processing_options['on-the-fly_waveseg_processing']
		PRE_QUERY_WAVESEG_PROCESSING = not ON_THE_FLY_WAVESEG_PROCESSING

	db = dbConnection
	
	# Actual query processing. Fun part is here!

	log('########### NEW QUERY ##############')
	log('query: ' + str(message))

	# Let's do privacy filtering.
	cursor = None
	waveseg_pre_temp_collection_name = None
	temp_collection_name = None
	isQueryOptions = 'select' in message or 'distinct' in message or 'sort' in message or 'at' in message

	# when the querier is data consumer
	if isConsumer: 	
		
		# find rules that apply to this consumer
		rules = db[username + '_rules']
		rule_cursor = rules.find({ '$or': [ { 'consumer': None }, { 'consumer': consumer } ] }, { '_id': 0 })

		# if there are no rules for this consumer
		if rule_cursor.count() <= 0:
			return HttpResponse('["No privacy rules for the consumer, %s"]' % consumer)
		
		# if rules exists
		else:
			# Pre-query waveseg processing for range queries	
			# Note: this is needed only for range queries, and this checking is done in the function because we also need to check if any rules contain range conditions.
			if PRE_QUERY_WAVESEG_PROCESSING:
				result, waveseg_pre_temp_collection_name = pre_query_waveseg_processing(username, collection, message, rules, consumer)
				if result:
					collection = db[waveseg_pre_temp_collection_name]

			merged_query = None
			if FILTER_BY_MERGING_CONDITIONS:
				# UNION of allowed wavesegs, AND queried wavesegs, MINUS denied wavesegs
				merged_query = { '$and': [ message['query'], { '$or': [] } ], '$nor': [] }

			modify_result = []
			
			allow_result = None
			deny_result = None
			# First, get set of distinct ids from query result.
			if FILTER_BY_SET_OPERATIONS:
				allow_result = []
				deny_result = []
				query_result = get_set_of_distinct_ids_from_query_result(message, collection, username)

			# Get sets of wavesegs to-be-allowed, -denied, and -modified.
			get_allow_deny_modify_sets_or_merged_query(allow_result, deny_result, modify_result, merged_query, rule_cursor, username, collection)

			# Clean up merged_query
			if FILTER_BY_MERGING_CONDITIONS:
				clean_up_merged_query(merged_query)
				log('merged_query = ' + str(merged_query))

			# Perform set operations to get filtered query result.
			elif FILTER_BY_SET_OPERATIONS:
				perform_set_operation(query_result, allow_result, deny_result)

				# after applying allow and deny rules, if nothing left...
				if (len(query_result) <= 0):
					return HttpResponse('["No data left after filtering..."]')

			# Good. Process field selection for data consumer. Here we are going to process field selection first before processing other query options. Further query options are processed in the 'if isQueryOptions' block down below. The only difference between in case of query by data consumer and contributor is this field selection processing. It's all because mongoDB supports field selection as an argument of find(). Further reasons are explained down below, too.
			
			if 'select' in message:
				
				# Do process_modify_rules() here because the field selection afterwards might remove conditions required by modify_rules.				
				# TODO: on-the-fly field selection might solve this problem.
				if len(modify_result) > 0:
					if FILTER_BY_SET_OPERATIONS:
						process_modify_rules(modify_result, collection, query_result = query_result)
					elif FILTER_BY_MERGING_CONDITIONS:
						process_modify_rules(modify_result, collection, merged_query = merged_query)

				# Process field selection
				select = message['select']
				select['_id'] = 0 # deselect _id field
				if FILTER_BY_SET_OPERATIONS:
					cursor = collection.find(None, select)
				if FILTER_BY_MERGING_CONDITIONS:
					cursor = collection.find(merged_query, select)
			
			else: # no query options
				# Here, we don't remove _id field because of the on-the-fly waveseg modification.
				if FILTER_BY_SET_OPERATIONS:
					cursor = collection.find() 
				elif FILTER_BY_MERGING_CONDITIONS:
					cursor = collection.find(merged_query)

			if FILTER_BY_SET_OPERATIONS:
				log('after filtering, len(query_result) = ' + str(len(query_result)))
			elif FILTER_BY_MERGING_CONDITIONS:
				log('after filtering: find(merged_query).count() = ' + str(cursor.count()))


	# when the querier is data contributor of this server
	else:
		
		# waveseg processing for range queries
		if PRE_QUERY_WAVESEG_PROCESSING:
			result, waveseg_pre_temp_collection_name = pre_query_waveseg_processing(username, collection, message, None, None)
			if result:
				collection = db[waveseg_pre_temp_collection_name]
		
		# Query condition pre-processing
		if 'query' in message and message['query']:
			condition_preprocessing(message['query'], username)

		# Get the cursor w/ field selection, this is done here instead of if isQueryOptions block because field selection in mongoDB is done with find() function. Advanced query options are done by additionally calling functions on the cursor.
		if 'select' in message:
			select = message['select']
			select['_id'] = 0 # deselect _id field
			if 'query' in message and message['query']:
				cursor = collection.find(message['query'], select)
			else:
				cursor = collection.find(None, select)
		else:
			if 'query' in message and message['query']:
				cursor = collection.find(message['query'], {'_id': 0})
			else:
				cursor = collection.find(None, {'_id': 0})

		log('cursor.count() = ' + str(cursor.count()))





	# Common code for both data consumers and contributors.
	# Process further query options...
	if isQueryOptions:
		if 'sort' in message and message['sort']:
			for k, v in message['sort'].iteritems():
				collection.ensure_index(k);
				if v == 1:
					cursor = cursor.sort(k, pymongo.ASCENDING)
				elif v == -1:
					cursor = cursor.sort(k, pymongo.DESCENDING)

		if 'distinct' in message and message['distinct']:
			cursor = cursor.distinct(message['distinct'])

		# Data retrieval with 'at' query option.
		if 'at' in message and message['at']:
			data = retrieve_data_from_db_at(cursor, message['at'])
			if not data:
				return HTTP_RESPONSE_NO_DATA
		else:
			# Data retrieval
			data = retrieve_data_from_db(data, cursor)
			if not data:
				return HTTP_RESPONSE_NO_DATA

	# If no query options,
	else:
		
		if not isConsumer:
			# Data retreival
			data = retrieve_data_from_db(cursor)
			if not data:
				return HTTP_RESPONSE_NO_DATA
		else:
			# Retreive data object and perform modify rules "on-the-fly".
			if FILTER_BY_SET_OPERATIONS:
				data = process_modify_rules_on_the_fly(modify_result, data, collection = collection, query_result = query_result)
				if not data:
					return HTTP_RESPONSE_NO_DATA
			elif FILTER_BY_MERGING_CONDITIONS:
				# This also perform on-the-fly waveseg modification.
				data = process_modify_rules_on_the_fly(modify_result, data, collection = collection, cursor = cursor)
				if not data:
					return HTTP_RESPONSE_NO_DATA

	# Alright, we are almost done. let's json-encode it.
	json_data = cjson.encode(data)

	# Clean up temp collection
	if temp_collection_name:
		db.drop_collection(temp_collection_name)
	if waveseg_pre_temp_collection_name:
		db.drop_collection(waveseg_pre_temp_collection_name)

	return HttpResponse(json_data)


