import pymongo

db = pymongo.Connection()['sensorsafe_database']

db.drop_collection('haksoo_testdata1')
db.drop_collection('haksoo_testdata2')
db.drop_collection('haksoo_testdata3')
db.drop_collection('haksoo_testdata4')

collection = db['haksoo_testdata']

cursor = collection.find(None, { '_id': 0 }).limit(1806)
for o in cursor:
	db['haksoo_testdata1'].insert(o)

cursor = collection.find(None, { '_id': 0 }).limit(3613)
for o in cursor:
	db['haksoo_testdata2'].insert(o)

cursor = collection.find(None, { '_id': 0 }).limit(5419)
for o in cursor:
	db['haksoo_testdata3'].insert(o)

cursor = collection.find(None, { '_id': 0 }).limit(7225)
for o in cursor:
	db['haksoo_testdata4'].insert(o)

