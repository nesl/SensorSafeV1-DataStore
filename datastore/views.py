import sys
import time
from datetime import datetime, timedelta
import httplib, urllib
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect
from django.shortcuts import render_to_response
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
from log import log
from hotshotdecorator import hotshot_profile

import cjson
import json
# To switch to cjson: ,cjson
# To switch to json: ,json

# for memory profiling
from guppy import hpy

import privacyengine







BROKER_ADDRESS = 'fieldstream.nesl.ucla.edu'
GOOGLE_APIKEY = 'ABQIAAAA-BHV3Z55zCdo4z_ley123xT2yXp_ZAY8_ufC3CFXhHIE1NvwkxTGit_DA3cmLDETSlrEJ5l9J2xRaQ'

gmaps = GoogleMaps(GOOGLE_APIKEY)
db = pymongo.Connection()['sensorsafe_database']

def print_error_context():
	print 'Caught: sys.exc_type =', sys.exc_type, 'sys.exc_value =', sys.exc_value
	print 'sys.exc_traceback =', sys.exc_traceback
	print sys.exc_info()

def json_dump_pretty_html(data):
	return '<pre>' + cjson.encode(data, sort_keys=True, indent=4) + '</pre>'





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
	waveseg = cjson.decode(request.POST['data'])
	collection.insert(waveseg)

	return HttpResponse("Upload successful (" + username + ")")



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





@hotshot_profile("PrivacyEngine.prof")
def query(request):
	# Prepare for query processing.

	# Check request is valid
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

	# Check identity of querier
	consumer = None
	if not isConsumer:
		username = userinfo.userID.username
	else:
		# This is consumer.. find out who this is on broker.
		# TODO: checking data consumer identity on broker server takes time... do some caching?
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
			return HttpResponseBadRequest(cjson.encode({'error': 'Error from broker: ' + reply}))
		
		# Check if this querier specifies queriee.
		if not 'contributor' in request.POST:
			return HttpResponseBadRequest("No 'contributor' in post data")
		username = request.POST['contributor']

		# TODO: check if this username exist

		# save querier's name
		consumer = reply

	# Get queriee's db collection
	message = cjson.decode(request.POST['data'])

	# TODO: clean up this!
	#collection = db[username]
	#collection = db[username + '_test200']
	#collection = db[username + '_test200_opt']
	collection = db[username + '_testdata_opt']
	#collection = db[username + '_testdata_opt']
	#collection = db[username + '_test_10000']
	#collection = db[username + '_test_1000_opt']
	#collection = db['result']
	#collection.ensure_index([('location', pymongo.GEO2D)])

	# Yes... ensure index on the collection (w/o it, slow..)
	collection.ensure_index('_id')

	#h=hpy()
	ret = privacyengine.process(db, request, message, isConsumer, consumer,  username, collection)
	#h.heap()

	return ret


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
	
	rule = cjson.decode(request.POST['data'])
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
	return HttpResponse(cjson.encode(rules))



def deleterules(request):
	if not request.method == 'POST':
		return HttpResponseBadRequest('Not POST request')
	
	isSuccess, userinfo, http_response = check_post_request_apikey(request.POST)
	if not isSuccess:
		return http_response
	username = userinfo.userID.username

	collection = db[username + '_rules']

	rule_id_list = []
	for id in cjson.decode(request.POST['rule_ids']):
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
		rules.append({ 'rule_json': cjson.encode(rule), 'rule_id': rule['_id'], 'rule_name': rule['rule_name'] })	
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
		label = cjson.decode(request.POST['data'])
		if collection.find({ 'label': label['label'] }).count() >= 1:
			return HttpResponse('Error: existing label')
		collection.insert(label, check_keys=False)
	elif request.POST['action'] == 'get':
		labels = []
		for o in collection.find(None, { '_id': 0 }):
			labels.append(o)
		return HttpResponse(cjson.encode(labels))
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
			return HttpResponseBadRequest(cjson.encode({'error': 'Error from broker: ' + reply}))

		requestor_name = reply
	
	log(requestor_name)

	# make check list table

	# location_label
	search_cond = cjson.decode(request.POST['query'])
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

		log(cjson.encode(check_list, indent=2))
		
		# check if this user satisfies check list.
		is_satisfy = True
		for check_item in check_list:
			if check_item[0] == False:
				is_satisfy = False
				break

		if is_satisfy:
			satisfy_users.append(username)
	
	return HttpResponse(cjson.encode(satisfy_users))


@login_required
def test(request):
	#collection = db['haksoo_test5']
	#data = collection.find()[0]
	#data['_id'] = str(data['_id'])
	#data = []
	#for obj in collection.find():
	#	obj['_id'] = str(obj['_id'])
	#	data.append(obj)
	#return render_to_response('map-simple.html', {'data': cjson.encode(data)})
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




