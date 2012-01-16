import time

def reduce_address(address_str, level):
	
	# support for south korea address
	if address_str.find("South Korea") >= 0:

		address = address_str.split()
		country = address[0] + ' ' + address[1]
		city = address[2]
		
		#log('address: ' + str(address))
		#log('country: ' + str(country))
		#log('city: ' + str(city))
	
		if level is 'street':
			return address_str
		elif level == 'country':
			return country
		else:
			return city + ', ' + country

	else: # Assume US address by default
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




def generalize_location(waveseg, rule, gc_collection):
	if not rule == 'dontmodify':
		if not rule == 'nolocation':
			# find geocode
			#log('modify_waveseg: ' + str(waveseg))
			if 'location' in waveseg:
				geocode = gc_collection.find_one({ 'location.latitude': waveseg['location']['latitude'], 'location.longitude': waveseg['location']['longitude'] })
			else:
				assert False # support for no 'location' key in waveseg.
			"""
			('Latitude' in waveseg['data_channel'] 
				and 'Longitude' in waveseg['data_channel']) or
				('latitude' in waveseg['data_channel']
				and 'longitude' in waveseg['data_channel']):
				
				#geocode = gc_collection.find_one({ 'location.latitude':, 'location.longitude': })
			"""

			if not geocode:
				address = gmaps.latlng_to_address(waveseg['location']['latitude'], waveseg['location']['longitude'])
				gc_collection.insert({ 'location': waveseg['location'], 'address': address })
			else:
				address = geocode['address']

			location = reduce_address(address, rule)
			waveseg['location'] = location

		# no location
		else:
			del waveseg['location']
	



def generalize_timestamp(waveseg, rule, first_timestamp):
	if not rule == 'dontmodify':
		timestamp = time.localtime(waveseg['timestamp'])

		# make timestamp relative time
		waveseg['timestamp'] -= first_timestamp
		
		# add 'time_info' field and store timestamp in specified time resolution
		if rule == 'hour':
			waveseg['time_info'] = time.strftime('%H:00, %m/%d/%Y', timestamp)
		elif rule == 'day':
			waveseg['time_info'] = time.strftime('%m/%d/%Y', timestamp)
		elif rule == 'month':
			waveseg['time_info'] = time.strftime('%d/%Y', timestamp)
		elif rule == 'year':
			waveseg['time_info'] = time.strftime('%Y', timestamp)




def quantize_data(waveseg, rule):
	for sample_rate_rule in rule:
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



def hide_home(waveseg, rule, home_loc_collection):
	# TODO: cloaking, rounding, noise.
	pass




