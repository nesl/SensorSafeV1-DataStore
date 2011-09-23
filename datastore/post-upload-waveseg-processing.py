import pymongo
import time

db = pymongo.Connection()['sensorsafe_database']

collection_name = 'haksoo_testdata2'

collection = db[collection_name]
db.drop_collection(collection_name+'_opt')
new_collection = db[collection_name+'_opt']

collection.ensure_index('timestamp')

starttime = time.time()

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


for dc in data_channels:
	new_waveseg = collection.find({ 'data_channel': dc }, { '_id': 0 }).sort('timestamp')[0]
	waveseg = new_waveseg

	print '########## data channel: ' + str(waveseg['data_channel']) + '  ##################'

	while True:
		# concatenate continuos waveseg
		endtime = waveseg['timestamp'] + ( waveseg['sampling_interval'] * len(waveseg['data']) )
		next_waveseg = collection.find_one({ 'data_channel': dc, 'timestamp': endtime }, { '_id': 0 })
		#print 'endtime: ' + str(endtime)
		if next_waveseg:
			#print 'continuous waveseg.'
			# check if it's same location
			if waveseg['location']['latitude'] == next_waveseg['location']['latitude'] and waveseg['location']['longitude'] == next_waveseg['location']['longitude']:
				#print 'same location appending...'
				for sample in next_waveseg['data']:
					new_waveseg['data'].append(sample)
			else:
				print 'different location.'
				# make a new waveseg with new location
				new_collection.insert(new_waveseg)
				new_waveseg = next_waveseg

			waveseg = next_waveseg
		else:
			print 'not continuous. finding next waveseg.'
			# find next timestamp
			new_collection.insert(new_waveseg)

			cursor = collection.find({ 'data_channel': dc, 'timestamp': { '$gt': endtime } }, { '_id': 0 })
			if cursor.count() <= 0:
				print 'no next waveseg. next data channel'
				break
			else:
				print 'found next waveseg.'
				new_waveseg = waveseg = cursor.sort('timestamp')[0]
	
print 'waveseg optimize time: ' + str(time.time() - starttime)

num_sample = 0
num_waveseg = 0
for waveseg in collection.find():
	num_waveseg += 1 
	num_sample += len(waveseg['data'])

print 'original num sample: ' + str(num_sample) + ', original # of wavesegs: ' + str(num_waveseg)

num_sample = 0
num_waveseg = 0
for waveseg in new_collection.find():
	num_waveseg += 1
	num_sample += len(waveseg['data'])

print 'new num sample: ' + str(num_sample) + ', new # of wavesegs: ' + str(num_waveseg)


