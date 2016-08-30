from icontrol.session import iControlRESTSession
from cloudfoundry_client import CloudFoundryClient
import pprint
import argparse
import yaml
import logging

logger = logging.getLogger()
logger = logging.getLogger('requests')
logger.setLevel(logging.DEBUG)

pp = pprint.PrettyPrinter(indent=3)

class Pcf2Bigip(object):
    def __init__(self, host, username, password, admin_username, admin_password):
        self.iwf = iControlRESTSession(username,password)
        self.iwf_admin = iControlRESTSession(admin_username,admin_password)
        self.host = host
    def create_iapp(self, tenant, iapp_name, service_name, cloud_connector, app_names, pool_members):
        payload = { 'kind': 'cm:cloud:tenants:tenantserviceinstance',
                    'tenantReference': {  'link': 'https://localhost/mgmt/cm/cloud/tenants/%s' %(tenant)},
                    'tenantTemplateReference': {  'link': 'https://localhost/mgmt/cm/cloud/tenant/templates/iapp/%s' %(service_name)},
                    'vars': [],
                    'tables': [  {  'columns': ['Group', 'Parameter'],
                                    'name': 'l7policy__rulesAction',
                                    'rows': [] },
                                 {  'columns': ['Group', 'Value'],
                                    'name': 'l7policy__rulesMatch',
                                    'rows': []},
                                 {  'columns': ['Index', 'Name', 'Options'],
                                    'name': 'monitor__Monitors',
                                    'rows': []},
                                 {  'columns': [  'IPAddress',
                                                  'Index',
                                                  'PriorityGroup',
                                                  'State'],
                                    'name': 'pool__Members',
                                    'rows': []},
                                 {  'columns': ['Index', 'Monitor', 'Name'],
                                    'name': 'pool__Pools',
                                    'rows': []}] }
        payload['name'] = iapp_name
        payload['properties'] = [{'id':'cloudConnectorReference', 'isRequired': False, 'value': cloud_connector}]
        
        payload = self._merge_payload(payload, service_name, app_names, pool_members)

        resp = self.iwf.post('https://%s/mgmt/cm/cloud/tenants/%s/services/iapp' %(self.host, tenant),json=payload)
        print "Created iApp %s" % iapp_name
    def update_iapp(self, tenant, iapp_name, service_name, app_names, pool_members):
        resp = self.iwf.get('https://%s/mgmt/cm/cloud/tenants/%s/services/iapp/%s' %(self.host, tenant, iapp_name))        
        payload = resp.json()
        payload = self._merge_payload(payload, service_name, app_names, pool_members)
    
        resp = self.iwf.put('https://%s/mgmt/cm/cloud/tenants/%s/services/iapp/%s' %(self.host, tenant, iapp_name),json=payload)       
        print "Updated iApp %s" % iapp_name

    def update_iapp_service(self, tenant, iapp_name, service_name, app_names, pool_members):
        resp = self.iwf.get('https://%s/mgmt/cm/cloud/tenants/%s/services/iapp/%s' %(self.host, tenant, iapp_name))        
        payload = resp.json()
        payload = self._merge_payload(payload, service_name, app_names, pool_members)

        resp = self.iwf.put('https://%s/mgmt/cm/cloud/tenants/%s/services/iapp/%s' %(self.host, tenant, iapp_name),json=payload)
        print "Updated iApp %s Service to %s" % (iapp_name, service_name)
    def delete_iapp(self, iapp_name, tenant):
        resp = self.iwf.delete('https://%s/mgmt/cm/cloud/tenants/%s/services/iapp/%s' %(self.host, tenant, iapp_name))
        print "Deleted iApp %s" % iapp_name        
    def create_service(self, service_name, tenant, filename):        
        payload = yaml.load(open(filename))
        resp = self.iwf_admin.post('https://%s/mgmt/cm/cloud/provider/templates/iapp' %(self.host),json=payload)
        
    def delete_service(self, service_name, tenant):
        resp = self.iwf_admin.delete('https://%s/mgmt/cm/cloud/provider/templates/iapp/%s' %(self.host, service_name))

    def _merge_payload(self,payload, service_name, app_names, pool_members):
        monitor_table = None
        member_table = None
        pool_table = None
        rule_table = None
        action_table = None

        merge_payload = {}
        
        if app_names:
            monitor_str = "interval=30;timeout=91;send=GET /env/VCAP_APPLICATION HTTP/1.1\\r\\nhost: %s\\r\\nconnection:close\\r\\n\\r\\n;recv=%s" 
            monitor_table = [[str(x+1), '%s_monitor' %(app_names[x]), monitor_str %(app_names[x],app_names[x])] for x in range(num_apps)]
            monitor_table.insert(0,['0','_default_monitor',''])
            
            pool_table = [[str(x+1),str(x+1), '%s_pool' %(app_names[x])] for x in range(num_apps)]
            pool_table.insert(0,['0','0','_default_pool'])

            rule_table = [[str(x+1), app_names[x]] for x in range(num_apps)]
            action_table = [[str(x+1), '%s_pool' %(app_names[x])] for x in range(num_apps)]

            merge_payload = {'monitor__Monitors':monitor_table,
                             'pool__Pools':pool_table,
                             'l7policy__rulesMatch':rule_table,
                             'l7policy__rulesAction':action_table}        
                                    
        if pool_members:            
            member_list = pool_members.split(',')
            member_list.reverse()
            priority_group = 0

            member_table = []
            for member in member_list:
                member_table.extend([[member, str(x+1),str(priority_group), 'enabled'] for x in range(num_apps)])
                priority_group += 10
            member_table.insert(0,['192.168.11.11','0','0','enabled'])
            merge_payload['pool__Members'] = member_table

        if service_name:
            payload['tenantTemplateReference'] =  {'link': 'https://localhost/mgmt/cm/cloud/tenant/templates/iapp/%s' %(service_name)}
            
        tables = {}
        for x in range(len(payload['tables'])):
            table = payload['tables'][x]            
            tables[table['name']] = (x,table)
            table_value = merge_payload.get(table['name'])
            if table_value:
                payload['tables'][x]['rows'] = merge_payload[table['name']]
        return payload        
        

if __name__ == "__main__":
    import os
    password = os.getenv('PASSWORD')

    parser = argparse.ArgumentParser(description='Script to create a pool on a BIG-IP device')
    parser.add_argument("host",             help="The IP/Hostname of the BIG-IP device")
    parser.add_argument("pool_members", nargs='?',    help="A comma seperated string in the format <IP>,<IP>")    
    parser.add_argument("-t", "--tenant", help="The tenant name", default="pcfdev_tenant")
    parser.add_argument("-u", "--username", help="The iWorkflow username", default="pcfdev")
    parser.add_argument("-p", "--password", help="The iWorkflow password", default="pcfdev")
    parser.add_argument("--admin_username", help="The iWorkflow admin username", default="admin")
    parser.add_argument("--admin_password", help="The iWorkflow admin password", default="admin")

    parser.add_argument("-a","--action",help="create/delete/create_service/delete_service")
    parser.add_argument("--api",default='https://api.local.pcfdev.io')
    parser.add_argument("--cf_username",default='admin')
    parser.add_argument("--cf_password",default='admin')    
    parser.add_argument("--iapp_name",default="dora_app_v1.0")
    parser.add_argument("--service_name",default="dora_template_v1.0")    
    parser.add_argument("--cloud_connector",default="https://localhost/mgmt/cm/cloud/connectors/local/93e5ce56-37ad-47c4-99b0-514cc3de4872")


    args = parser.parse_args()
    
    if password:
        args.password = password
        
    pb = Pcf2Bigip(args.host, args.username, args.password, args.admin_username, args.admin_password)

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

    num_apps = len(app_names)
        
    if args.action == "create_iapp":
        pb.create_iapp(args.tenant,args.iapp_name, args.service_name, args.cloud_connector, app_names, args.pool_members)

    elif args.action == "update_iapp":
        pb.update_iapp(args.tenant, args.iapp_name, None, app_names, args.pool_members)

    elif args.action == "update_iapp_service":
        pb.update_iapp_service(args.tenant, args.iapp_name, args.service_name, None, None)        
                      
    elif args.action == "delete_iapp":
        pb.delete_iapp(args.iapp_name, args.tenant)                            

    elif args.action == "create_service":
        pb.create_service(args.service_name, args.tenant, args.file)                    
               
    elif args.action == "delete_service":
        pb.delete_service(args.service_name, args.tenant)                            
        
