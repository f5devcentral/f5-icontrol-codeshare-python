from icontrol.session import iControlRESTSession
from pprint import pprint
import yaml
import logging
import argparse

#logger = logging.getLogger()
#logger = logging.getLogger('requests')
#logger.setLevel(logging.DEBUG)

parser = argparse.ArgumentParser(description='Script to create a pool on a BIG-IP device')
parser.add_argument("host",             help="The IP/Hostname of the BIG-IP device",default='10.1.1.246')
parser.add_argument("-a","--action",help="create/read/update/delete")
parser.add_argument("--template",help="template")
parser.add_argument("--tenant",help="tenant")
parser.add_argument("--iapp",help="iapp")
parser.add_argument("-f","--file",help="template file")
args = parser.parse_args()

icr_admin = iControlRESTSession('admin','admin')
icr_tenant = iControlRESTSession('pcfdev','pcfdev')

iwf = args.host

#resp = icr_admin.get('https://%s/mgmt/cm/cloud/tenants' %(iwf))
#print pprint(resp.json())
#resp = icr_admin.get('https://%s/mgmt/cm/cloud/connectors/local' %(iwf))
#print pprint(resp.json())
if args.action == 'list_templates':
    resp = icr_admin.get('https://%s/mgmt/cm/cloud/provider/templates/iapp' %(iwf))
    data = resp.json()
    for item in data['items']:
        print item['templateName']
if args.action == 'export_template':
    resp = icr_admin.get('https://%s/mgmt/cm/cloud/provider/templates/iapp/%s' %(iwf,args.template))
    payload = resp.json()
    yaml.safe_dump(payload,open('%s.yaml' %(args.file),'w'))
elif args.action == 'import_template':
    payload = yaml.load(open(args.file))
    resp = icr_admin.post('https://%s/mgmt/cm/cloud/provider/templates/iapp' %(iwf),json=payload)
    data = resp.json()
    print pprint(data)
elif args.action == 'list_iapps':
    resp = icr_tenant.get('https://%s/mgmt/cm/cloud/tenants/%s/services/iapp' %(iwf, args.tenant))
    data = resp.json()
    for item in data['items']:
        print item['name']

elif args.action == 'export_iapp':
    resp = icr_tenant.get('https://%s/mgmt/cm/cloud/tenants/%s/services/iapp/%s' %(iwf,args.tenant,args.iapp))
    payload= resp.json()
    yaml.safe_dump(payload,open(args.file,'w'))
elif args.action == 'import_iapp':
    payload = yaml.load(open(args.file))
    resp = icr_tenant.post('https://%s/mgmt/cm/cloud/tenants/%s/services/iapp' %(iwf,args.tenant),json=payload)
    data = resp.json()
    print pprint(data)    
elif args.action == 'update_iapp':
    payload = yaml.load(open(args.file))
    resp = icr_tenant.put('https://%s/mgmt/cm/cloud/tenants/%s/services/iapp/%s' %(iwf,args.tenant,args.iapp),json=payload)
    data = resp.json()
    print pprint(data)
elif args.action == 'delete_iapp':
    resp = icr_tenant.delete('https://%s/mgmt/cm/cloud/tenants/%s/services/iapp/%s' %(iwf, args.tenant, args.iapp))
    print resp
    data = resp.json()
    print pprint(data)

