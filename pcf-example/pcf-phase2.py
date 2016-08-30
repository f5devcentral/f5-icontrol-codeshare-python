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
    parser.add_argument("pool_members", nargs='?',    help="A comma seperated string in the format <IP>:<port>[,<IP>:<port>]")
    parser.add_argument("value", nargs='?', help='optional value for update')
    parser.add_argument("-P", "--partition", help="The partition name", default="Common")
    parser.add_argument("-u", "--username", help="The BIG-IP username", default="admin")
    parser.add_argument("-p", "--password", help="The BIG-IP password", default="admin")
    parser.add_argument("-f","--file",help="CSV file input")
    parser.add_argument("-a","--action",help="create/read/update/delete")
    parser.add_argument("--policy_name",default="app_policy")
    parser.add_argument("--api",default='https://api.local.pcfdev.io')
    parser.add_argument("--cf_username",default='admin')
    parser.add_argument("--cf_password",default='admin')

    args = parser.parse_args()
    if password:
        args.password = password
    sp = CF2BIGIP(args.host, args.username, args.password)


    skip_verification = True
    client = CloudFoundryClient(args.api, skip_verification=skip_verification)
    client.init_with_credentials(args.cf_username,args.cf_password)
    hosts = [(r.entity.host, r.entity.domain_guid) for r in client.route.list()]
    
    resp = client.credentials_manager._session.get("%s%s" %(args.api, "/v2/shared_domains"))
    jsdata = resp.json()
    domains = [(d['metadata']['guid'],d['entity']['name']) for d in  jsdata['resources']]
    domain_map = dict(domains)

    app_vars = dict([(c.entity.name, c.entity.environment_json) for c in  client.application.list()])

    # apps that have a environment variable 'F5'
    # could also use this to extract other metadata like
    # F5_MONITOR_SEND = '/test HTTP/1.1\r\n...'

    app_names = ["%s.%s" %(h[0],domain_map.get(h[1])) for h in hosts if app_vars.get(h[0],{}).get('F5')]
        
    # all apps
    # app_names = ["%s.%s" %(h[0],domain_map.get(h[1])) for h in hosts]
        
    if args.action == "create":

        for app_name in app_names:
            sp.create_app(app_name, args.pool_members, args.policy_name)
               
    elif args.action == "delete":
        
        for app_name in app_names:
            sp.delete_app(app_name, args.policy_name)

