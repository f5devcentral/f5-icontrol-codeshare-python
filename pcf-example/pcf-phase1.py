from f5.bigip import ManagementRoot
from f5.bigip.contexts import TransactionContextManager
from cloudfoundry_client import CloudFoundryClient
import pprint
import argparse
import csv
import logging

#logger = logging.getLogger()
#logger = logging.getLogger('requests')
#logger.setLevel(logging.DEBUG)

pp = pprint.PrettyPrinter(indent=3)


class CF2BIGIP(object):
    def __init__(self, host, username, password):
        self.mgmt = ManagementRoot(host, username, password)
        self.tx = self.mgmt.tm.transactions.transaction        
    def create_app(self,app_name, pool_members, policy_name, partition='Common'):
        pool_name = "%s_pool" %(app_name)
        monitor_name = "%s_monitor" %(app_name)
        send_str = "GET /env/VCAP_APPLICATION HTTP/1.1\\r\\nhost: %s\\r\\nconnection:close\\r\\n\\r\\n" %(app_name)
        recv_str = app_name

        monitor_path = "/%s/%s" %(partition, monitor_name)

        with TransactionContextManager(self.tx) as api:
            api._meta_data['icr_session'].session.headers['X-F5-REST-Coordination-Id'] = api._meta_data['icr_session'].session.headers['X-F5-REST-Coordination-Id'].__str__()
#            sys.exit(0)
            monitor = api.tm.ltm.monitor.https.http.create(name=monitor_name, partition=partition, interval=10, timeout=31, send=send_str, recv=recv_str)
            pool_path = "/%s/%s" % (partition, pool_name)

            pool = api.tm.ltm.pools.pool.create(partition=partition, name=pool_name, minActiveMembers=1, monitor=monitor_name)
            print "Created pool %s" % pool_path

            member_list = pool_members.split(',')
            member_list.reverse()
            priority_group = 0
            for member in member_list:
                pool._meta_data['uri'] = pool._meta_data['uri'].split("/transaction/")[0] + "/ltm/pool/~%s~%s/" %(partition,pool_name)
                pool_member = pool.members_s.members.create(partition=partition, name=member, priorityGroup=priority_group)
                priority_group += 10
                print " Added member %s" % member

            policy = api.tm.ltm.policys.policy.load(name = policy_name, partition = partition)

            rules = policy.rules_s.get_collection()

            my_rule = policy.rules_s.rules.create(name=app_name)

            payload = {u'caseInsensitive': True,
                   u'equals': True,
                   u'external': True,
                   u'fullPath': u'0',
                   u'host': True,
                   u'httpHost': True,
                   u'index': 0,
                   u'name': u'0',
                   u'present': True,
                   u'remote': True,
                   u'request': True,
                   u'values': [app_name]}

            my_rule._meta_data['uri'] = policy._meta_data['uri'] + 'rules/' + app_name + '/'
            my_rule.conditions_s.conditions.create(**payload)
            payload = {
                "vlanId": 0,
                "forward": True,
                "code": 0,
                "fullPath": "0",
                "name": "0",
                "pool": pool_name,
                "request": True,
                "select": True,
                "status": 0
        }
            my_rule.actions_s.actions.create(**payload)
            print "Created policy rule %s" %(app_name)                
        
    def delete_app(self, app_name, policy_name, partition='Common'):
        pool_name = "%s_pool" %(app_name)
        monitor_name = "%s_monitor" %(app_name)
        monitor_path = "/%s/%s" %(partition, monitor_name)
        
        with TransactionContextManager(self.tx) as api:
            api._meta_data['icr_session'].session.headers['X-F5-REST-Coordination-Id'] = api._meta_data['icr_session'].session.headers['X-F5-REST-Coordination-Id'].__str__()
            policy = api.tm.ltm.policys.policy.load(name = policy_name, partition = partition)
            my_rule = policy.rules_s.rules.load(name=app_name)
            my_rule.delete()
            print "Deleted policy rule %s" %(app_name)
            pool_path = "/%s/%s" % (partition, pool_name)

            pool = api.tm.ltm.pools.pool.load(partition=partition, name=pool_name)
            pool.delete()
            print "Deleted pool %s" % pool_path

            monitor = api.tm.ltm.monitor.https.http.load(name=monitor_name, partition=partition)
            monitor.delete()
            print "Deleted monitor %s" %(monitor_path)


if __name__ == "__main__":
    import os
    password = os.getenv('PASSWORD')

    parser = argparse.ArgumentParser(description='Script to create a pool on a BIG-IP device')
    parser.add_argument("host",             help="The IP/Hostname of the BIG-IP device")
    parser.add_argument("app_name", nargs='?',       help="The name of the pool")
    parser.add_argument("pool_members", nargs='?',    help="A comma seperated string in the format <IP>:<port>[,<IP>:<port>]")
    parser.add_argument("value", nargs='?', help='optional value for update')
    parser.add_argument("-P", "--partition", help="The partition name", default="Common")
    parser.add_argument("-u", "--username", help="The BIG-IP username", default="admin")
    parser.add_argument("-p", "--password", help="The BIG-IP password", default="admin")
    parser.add_argument("-f","--file",help="CSV file input")
    parser.add_argument("-a","--action",help="create/read/update/delete")
    parser.add_argument("--policy_name",default="app_policy")

    args = parser.parse_args()
    if password:
        args.password = password
    sp = CF2BIGIP(args.host, args.username, args.password)
    pool_name = "%s_pool" %(args.app_name)
    monitor_name = "%s_monitor" %(args.app_name)
        
    if args.action == "create":

        send_str = "GET /env/VCAP_APPLICATION HTTP/1.1\\r\\nhost: %s\\r\\nconnection:close\\r\\n\\r\\n" %(args.app_name)
        recv_str = args.app_name

        sp.create_app(args.app_name, args.pool_members, args.policy_name)
               
    elif args.action == "delete":

        sp.delete_app(args.app_name, args.policy_name)

    elif args.file:
        print args.file
        for row in csv.reader(open(args.file)):
            app_name = row[1]
            pool_name = "%s_pool" %(app_name)
            monitor_name = "%s_monitor" %(app_name)
            if row[0] == "create":
                send_str = "GET /env/VCAP_APPLICATION HTTP/1.1\\r\\nhost: %s\\r\\nconnection:close\\r\\n\\r\\n" %(args.app_name)
                recv_str = app_name
                try:
                    sp.create_app(app_name, row[2], args.policy_name)                    
                except Exception, e:
                    print "error creating",app_name,e
                    # really lame/dangerous rollback
                    # row[0] = "delete"

            if row[0] == "delete":
                sp.delete_app(row[1], args.policy_name)
        



