import hotshot
import os
import time
import settings
from log import log
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect

import cjson
import json
# To switch to cjson: ,cjson
# To switch to json: ,json


try:
	PROFILE_LOG_BASE = settings.PROFILE_LOG_BASE
except:
	PROFILE_LOG_BASE = '/var/log/django-profile-logs'




# Flags for benchmark test

FILTER_BY_MERGING_CONDITIONS = False # DONE!
AND_ALLOWS = False
OR_ALLOWS = not AND_ALLOWS
# NOR for denies

FILTER_BY_SET_OPERATIONS = not FILTER_BY_MERGING_CONDITIONS
# UNION of allows
# DIFFERENCE of denies



ON_THE_FLY_WAVESEG_MODIFICATION = False
WAVESEG_MODIFY_AND_SAVE = not ON_THE_FLY_WAVESEG_MODIFICATION



ON_THE_FLY_WAVESEG_PROCESSING = True
PRE_QUERY_WAVESEG_PROCESSING = not ON_THE_FLY_WAVESEG_PROCESSING



POST_UPLOAD_WAVESEG_PROCESSING = False
NO_POST_UPLOAD_WAVESEG_PROCESSING = not POST_UPLOAD_WAVESEG_PROCESSING
POST_UPLOAD_WAVESEG_PROCESSING_ADAPTIVE = False





# This is django decorator.
def hotshot_profile(log_file):
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

	if not os.path.isabs(log_file):
		log_file = os.path.join(PROFILE_LOG_BASE, log_file)

	def _outer(f):
		def _inner(*args, **kwargs):
			# Add a timestamp to the profile output when the callable is actually called.
			(base, ext) = os.path.splitext(log_file)
			base = base + '-' + time.strftime("%Y%m%dT%H%M%S", time.gmtime())
			final_log_file = base + ext

			prof = hotshot.Profile(final_log_file)
			try:
				ret = prof.runcall(f, *args, **kwargs)
			finally:
				prof.close()
			return ret

		return _inner

	return _outer





def isExistQueryOptions(message):
	return 'select' in message or 'distinct' in message or 'sort' in message or 'at' in message
					




@hotshot_profile("PrivacyEngine.prof")
def process(request, message, isConsumer, consumer, username, collection):
	
	# Actual query processing. Fun part is here!

	log('########### NEW QUERY ##############')
	log('query: ' + str(message))

	# let's do privacy filtering.
	cursor = None
	waveseg_pre_temp_collection_name = None
	temp_collection_name = None
	isQueryOptions = isExistQueryOptions(message)
	#isQueryOptions = True

	# when the querier is data consumer
	if isConsumer: 	
		
		# find rules that apply to this consumer
		rules = db[username + '_rules']
		rule_cursor = rules.find({ '$or': [ { 'consumer': None }, { 'consumer': consumer } ] }, { '_id': 0 })

		# if there are no rules for this consumer
		if rule_cursor.count() <= 0:
			return HttpResponse('["No privacy rules for this consumer"]')
		
		# if rules exists
		else:
			
			# support for benchmarks
			#starttime = time.time()
		
			# Pre-query waveseg processing for range queries	
			# Note: this is needed only for range queries, and this checking is done in the function because we also need to check if any rules contain range conditions.
			if PRE_QUERY_WAVESEG_PROCESSING:
				result, waveseg_pre_temp_collection_name = pre_query_waveseg_processing(username, collection, message, rules, consumer)
				if result:
					collection = db[waveseg_pre_temp_collection_name]

			# support for benchmarks
			#elap_time = time.time() - starttime
			#log('waveseg preprocess time: ' + str(elap_time))
			#perform_test.append(elap_time)
			#starttime = time.time()
		
			if FILTER_BY_SET_OPERATIONS:
				# first, perform the query and get unfiltered data.

				# Condition pre-processing
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

			# support for benchmarks
			#elap_time = time.time() - starttime
			#log('original query processing time: ' + str(elap_time))
			#perform_test.append(elap_time)
			#log('before filtering # of wavesegs: ' + str(len(query_result)))

			starttime = time.time()

			if FILTER_BY_SET_OPERATIONS:
				# alright, let's apply the rules.
				allow_result = []
				deny_result = []
			
			modify_result = []

			if FILTER_BY_MERGING_CONDITIONS:
				merged_query = { '$or': [ message['query'] ], '$nor': [] }

			# since we have multiple rules.
			for rule in rule_cursor:
				log('rule: ' + str(rule))

				if 'consumer' in rule:
					del rule['consumer']
				if 'rule_name' in rule:
					del rule['rule_name']

				# Condition pre-processing
				# log('before: ' + str(rule))
				if 'location_label' in rule:
					if not process_location_label(rule, username):
						return HttpResponseBadRequest('["Error from process_location_label()"]')
				if 'repeat_time' in rule:
					if not process_repeat_time(rule, collection):
						#return HttpResponseBadRequest("There is no data") <- yes, this is the reason we continue.
						continue

				# get allow_result[], deny_result[], modify_result[]
				if 'action' in rule:
					if rule['action'] == 'allow': 
						del rule['action']

						if FILTER_BY_SET_OPERATIONS:
							allow_result.append(set(collection.find(rule).distinct('_id')))
				
						if FILTER_BY_MERGING_CONDITIONS:
							# Filtering w/ query condition merging
							if AND_ALLOWS:
								merged_query['$and'].append(rule)
							elif OR_ALLOWS:
								merged_query['$or'].append(rule)

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

				# log('after: ' + str(rule))

			# end of 'for rule in rule_cursor'

			if FILTER_BY_MERGING_CONDITIONS:
				# Clean up merged_query
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

				log('merged_query = ' + str(merged_query))

				# For debugging
				#test_count = collection.find(merged_query).count()
				#log('find(merged_query).count() = ' + str(test_count))
				#for o in cursor:
				#	log(o['_id'])

			if FILTER_BY_SET_OPERATIONS:
				# apply allow_result[] and deny_result[] to query_result[]
				if allow_result:
					allow_result = set.union(*allow_result)
					query_result &= allow_result
				if deny_result:
					deny_result = set.union(*deny_result)
					query_result -= deny_result

				# support for benchmarks
				# elap_time = time.time() - starttime
				# log('rule processing (set operation) time: ' + str(elap_time))
				# perform_test.append(elap_time)

				# after applying allow and deny rules, if nothing left...
				if (len(query_result) <= 0):
					return HttpResponse('["No data left after filtering..."]')

			# Good. Process field selection for data consumer. Here we are going to process field selection first in line of processing query options. Further query options are processed in the 'if isQueryOptions' block down below. The only difference between in case of query by data consumer and contributor is this field selection processing. It's all because mongoDB supports field selection as an argument of find(). Further reasons are explained down below, too.
			if isQueryOptions:

				if FILTER_BY_SET_OPERATIONS:
					# make new collection with allowed documents
					# create a new collection
					temp_collection_name = 'temp_' + hashlib.sha1(str(random.random())).hexdigest()
					new_collection = db[temp_collection_name]

					# support for benchmarks
					# starttime = time.time()

					# insert the query result into the new collection
					for id in query_result:
						new_collection.insert(collection.find_one(id))
					
					# support for benchmarks
					# elap_time = time.time() - starttime
					# log('insert operation: ' + str(elap_time))
					# perform_test.append(elap_time)

					# replace current collection.
					collection = new_collection

				#starttime = time.time()
				#for id in query_result:
				#	collection.find_one(id)
				#log('find_one() operation:' + str(time.time() - starttime))
				
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

				# Do process_modify_rules() here because of the field selection right after.
				if len(modify_result) > 0:
					starttime = time.time()
					process_modify_rules_and_save(modify_result, collection)
					log('modify rules operation: ' + str(time.time() - starttime))

				# process field selection
				if not 'select' in message:
					if FILTER_BY_SET_OPERATIONS:
						cursor = collection.find(None, {'_id': 0}) # deselect _id field
					if FILTER_BY_MERGING_CONDITIONS:
						cursor = collection.find(merged_query, {'_id': 0}) # deselect _id field
				else:
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
					log('after filtering, len(query_result) = ' + str(len(query_result)))
				if FILTER_BY_MERGING_CONDITIONS:
					cursor = collection.find(merged_query)
					log('after filtering: cursor.count() = ' + str(cursor.count()))

	# when the querier is data contributor of this server
	else:

		# benchmark
		# starttime = time.time()
		
		# waveseg processing for range queries
		if PRE_QUERY_WAVESEG_PROCESSING:
			result, waveseg_pre_temp_collection_name = pre_query_waveseg_processing(username, collection, message, None, None)

			if result:
				collection = db[waveseg_pre_temp_collection_name]
		
		# benchmark
		# log('waveseg preprocess time: ' + str(time.time() - starttime))
		# starttime = time.time()

		# Query condition pre-processing
		if 'query' in message and message['query']:
			if 'location_label' in message['query']:
				if not process_location_label(message['query'], username):
					return HttpResponseBadRequest("Error from process_location_label")
			if 'repeat_time' in message['query']:
				if not process_repeat_time(message['query'], collection):
					return HttpResponseBadRequest('There is no data')
			log('after making query valid: ' + str(message['query']))

		# Process field selection for data contributor, this is done here instead of if isQueryOptions block because field selection in mongoDB is done with find() function. Advanced query options are done by additionally calling functions on the cursor returned by find().
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

		#benchmark
		#log('process query and getting cursor: ' + str(time.time() - starttime))

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

		# Data retrieval
		if 'at' in message and message['at']:
			if cursor.count() <= 0:
				return HttpResponseBadRequest(cjson.encode({'error': "There are no data"}))
			if message['at'] == 'last':
				count = cursor.count()
				data = cursor[count-1]
			elif message['at'] == 'first':
				data = cursor[0]
			else:
				data = cursor[message['at']]
		else:
			# support for benchmarks
			# starttime = time.time()

			# Data retrieval
			data = []
			for obj in cursor:
				data.append(obj)

			# support for benchmarks
			# elap_time = time.time() - starttime
			# log('retrieve operation: ' + str(elap_time))
			# perform_test.append(elap_time)

		# clean up temp collection
		if temp_collection_name:
			db.drop_collection(temp_collection_name)

	# no query options
	else:
		
		if not isConsumer:
			# support for benchmakrs
			starttime = time.time()

			# Data retreival
			data = []
			for obj in cursor:
				data.append(obj)
			log('retrieve operation: ' + str(time.time() - starttime))

		else:
	
			# support for benchmarks
			# starttime = time.time()
			
			data = []
		
			# Retreive data object and perform modify rules "on-the-fly".
			if FILTER_BY_SET_OPERATIONS:
				first_timestamp = cursor.sort('timestamp', pymongo.ASCENDING)[0]['timestamp']	
				for id in query_result:
					obj = collection.find_one(id)
					del obj['_id']
					for modify_id, modify_rule in modify_result:
						if id in modify_id:
							modify_waveseg(obj, modify_rule, first_timestamp)
					data.append(obj)
			
			if FILTER_BY_MERGING_CONDITIONS:
				# This also perform on-the-fly waveseg modification.
				process_modify_rules_and_save(modify_result, isSave = False, data = data, cursor = cursor)

			# support for benchmarks
			# elap_time = time.time() - starttime
			# log('retrieve & modify operation: ' + str(elap_time))
			# perform_test.append(elap_time)

	# support for benchmark
	# elap_time = time.time() - gStartTime
	# log('Total query processing time except JSON encoding: ' + str(elap_time) + ' ms')
	# starttime = time.time()

	# alright, we are almost done. let's json-encode it.
	json_data = cjson.encode(data)

	# support for benchmarks
	# elap_time = time.time() - starttime
	# log('json encoding time: ' + str(elap_time))
	# perform_test.append(elap_time)

	# clean up temp collection of waveseg preprocessing
	if waveseg_pre_temp_collection_name != None:
		db.drop_collection(waveseg_pre_temp_collection_name)

	# benchmark
	#elap_time = time.time() - gStartTime
	#log('Total query processing time: ' + str(elap_time) + ' ms')

	# support for benchmarks.
	# if not 'test' in message:
	return HttpResponse(json_data)

	#else:
	#	return HttpResponse(cjson.encode(perform_test))




