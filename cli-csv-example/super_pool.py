from f5.bigip import ManagementRoot
import pprint
import argparse
import csv

pp = pprint.PrettyPrinter(indent=3)

class SuperPool(object):
	def __init__(self, host, username, password):
		self.mgmt = ManagementRoot(host, username, password)

	def create_pool(self, pool_name,pool_members, partition='Common'):
		pool_path = "/%s/%s" % (partition, pool_name)

		if self.mgmt.tm.ltm.pools.pool.exists(partition=partition, name=pool_name):
			raise Exception("Pool '%s' already exists" % pool_name)

		pool = self.mgmt.tm.ltm.pools.pool.create(partition=partition, name=pool_name)
		print "Created pool %s" % pool_path

		member_list = pool_members.split(',')
		for member in member_list:
			pool_member = pool.members_s.members.create(partition=partition, name=member)
			print " Added member %s" % member
	def read_pool(self, pool_name, partition='Common'):
		pool_path = "/%s/%s" % (partition, pool_name)

		if not self.mgmt.tm.ltm.pools.pool.exists(partition=partition, name=pool_name):
			raise Exception("Pool '%s' does not exist" % pool_name)

		pool = self.mgmt.tm.ltm.pools.pool.load(partition=partition, name=pool_name)
		print "Pool %s:" % pool_path
		pp.pprint(pool.raw)
	def update_pool(self,pool_name, attribute, value, partition='Common'):
		pool_path = "/%s/%s" % (partition, pool_name)

		if not self.mgmt.tm.ltm.pools.pool.exists(partition=partition, name=pool_name):
			raise Exception("Pool '%s' does not exist" % pool_name)

		pool = self.mgmt.tm.ltm.pools.pool.load(partition=partition, name=pool_name)
		pp.pprint("Current: %s=%s" % (attribute, getattr(pool, attribute)))
		kwargs = {attribute: value}
		pool.update(**kwargs)
		print "Updating pool %s" % pool_path
		pool.refresh()
		pp.pprint("New: %s=%s" % (attribute, getattr(pool, attribute)))
	def delete_pool(self, pool_name, partition='Common'):
		pool_path = "/%s/%s" % (partition, pool_name)

		if not self.mgmt.tm.ltm.pools.pool.exists(partition=partition, name=pool_name):
			raise Exception("Pool '%s' does not exist" % pool_name)

		pool = self.mgmt.tm.ltm.pools.pool.load(partition=partition, name=pool_name)
		pool.delete()
		print "Deleted pool %s" % pool_path
	
	
			
if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Script to create a pool on a BIG-IP device')
	parser.add_argument("host",             help="The IP/Hostname of the BIG-IP device")
	parser.add_argument("pool_name", nargs='?',       help="The name of the pool")
	parser.add_argument("pool_members", nargs='?',    help="A comma seperated string in the format <IP>:<port>[,<IP>:<port>]")
	parser.add_argument("value", nargs='?', help='optional value for update')
	parser.add_argument("-P", "--partition", help="The partition name", default="Common")
	parser.add_argument("-u", "--username", help="The BIG-IP username", default="admin")
	parser.add_argument("-p", "--password", help="The BIG-IP password", default="admin")
	parser.add_argument("-f","--file",help="CSV file input")
	parser.add_argument("-a","--action",help="create/read/update/delete")
	args = parser.parse_args()
	sp = SuperPool(args.host, args.username, args.password)
	if args.action == "create":
		sp.create_pool(args.pool_name, args.pool_members, args.partition)
	elif args.action == "read":
		sp.read_pool(args.pool_name, args.partition)
	elif args.action == "update":
		sp.update_pool(args.pool_name, args.pool_members, args.value, args.partition)
	elif args.action == "delete":
		sp.delete_pool(args.pool_name,args.partition)
	elif args.file:
		for row in csv.reader(open(args.file)):
			if row[0] == "create":
				sp.create_pool(row[1],row[2])
			elif row[0] == "delete":
				sp.delete_pool(row[1])	
		
	

