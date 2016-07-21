import sys
import operator

from f5.bigip import ManagementRoot
from icontrol.exceptions import iControlUnexpectedHTTPError
import etcd
import requests

import pprint
import json
import logging
import time
import os
from urlparse import parse_qs, urlparse
from distutils.version import LooseVersion

#import backports.ssl_match_hostname

import pykube

# Monkey-patch match_hostname with backports's match_hostname, allowing for IP addresses
# XXX: the exception that this might raise is backports.ssl_match_hostname.CertificateError
##pykube.http.requests.packages.urllib3.connection.match_hostname = backports.ssl_match_hostname.match_hostname
# https://github.com/kelproject/pykube/issues/29

#from pykube.config import KubeConfig
#from pykube.http import HTTPClient
#from pykube.objects import Pod, Service, Endpoint, Ingress


logger = logging.getLogger()
#logger = logging.getLogger('requests')
#logger.setLevel(logging.DEBUG)
# Disable alerting for self-signed certs

try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

pp = pprint.PrettyPrinter(indent=4)


class KubeToBigIP(object):
    def __init__(self, username='admin', password='admin', host='192.168.1.245'):

        # Replace with the address of your BIG-IP
        self.mgmt_url = "https://%s" %(host)

        self.url = "https://%s/mgmt/tm/sys/application/service" %(host)

        self.mgmt = ManagementRoot(host, username, password)

        # breaking into iCRs, not recommended
        # could also use requests directly
#        self.s=None
        self.s = self.mgmt._meta_data['bigip']._meta_data['icr_session']
        self.tmos_version = self._tmos_version()
        if LooseVersion(self.tmos_version) < LooseVersion('12.1.0'):
            raise Exception,"This has only been tested on 12.1."
    def _tmos_version(self):
        connect = self.mgmt._meta_data['bigip']._meta_data['icr_session']
        base_uri = self.mgmt._meta_data['uri'] + 'tm/sys/'
        response = connect.get(base_uri)
        ver = response.json()

        version = parse_qs(urlparse(ver['selfLink']).query)['ver'][0]
        return version
    def _exists(self,exist_url):
        does_exist = True
        try:
            self.s.get(exist_url)
        except iControlUnexpectedHTTPError,e:
            # iCr throws an exception for 404
            if '404' in e.__str__():
                does_exist = False
        return does_exist
    def _create(self,post_url, payload):
        self.s.post(post_url,data=json.dumps(payload))

    def create_or_update_network(self,network_type,networks,vxlan=False,partition='Common'):
        vxlan_profile_name = 'vxlan-flannel'
        vxlan_tunnel_name = 'vxlan-flannel-tun'
        vxlan_key = 1
#        print network_type
#        print networks
        bigip_self = '10.1.20.1'
        if vxlan:
            print 'create vxlan profile'
            payload = { 'name': vxlan_profile_name,
                        'partition': partition,
                        'defaultsFrom': '/Common/vxlan',
                        'floodingType': 'none',
                        'port': '8472'
                    }
            if self.mgmt.tm.net.tunnels_s.vxlans.vxlan.exists(name=vxlan_profile_name, partition=partition):
                pass
#                vxlan = self.mgmt.tm.net.tunnels_s.vxlans.vxlan.load(name=vxlan_profile_name, partition=partition)
#                vxlan.update(**payload)
            else:
                vxlan = self.mgmt.tm.net.tunnels_s.vxlans.vxlan.create(**payload)
            payload = {
                "partition": partition,
                "name": vxlan_tunnel_name,
                "key": vxlan_key,
                "localAddress": bigip_self,
                "remoteAddress": '0.0.0.0',
                "profile": vxlan_profile_name
            }
            if self.mgmt.tm.net.tunnels_s.tunnels.tunnel.exists(name=vxlan_tunnel_name, partition=partition):
               tun = self.mgmt.tm.net.tunnels_s.tunnels.tunnel.load(name=vxlan_tunnel_name, partition=partition)
#               print tun
 #               tun.update(**payload)
            else:
                tun = self.mgmt.tm.net.tunnels_s.tunnels.tunnel.create(**payload)

            payload = {
                "partition": partition,
                "name": vxlan_tunnel_name
            }

            tun_fdb = self.mgmt.tm.net.fdb.tunnels.tunnel.load(**payload)
            records = []
            for n in networks:
                value = networks[n]
#                print value
                if value['BackendType'] == 'vxlan':
                    records.append( {'name':value['BackendData']['VtepMAC'], 'endpoint':value['PublicIP']} )

            payload = {
                "records": records
            }
            tun_fdb.update(**payload)
            return records
        else:
            # just set routes
            sc = self.mgmt.tm.net.selfips.get_collection()
            my_selfips = [a.address for a in sc]
#            print my_selfips
            for subnet in  networks:
                data = networks[subnet]

                if data['PublicIP'] + '/' + subnet.split('/')[-1] in my_selfips:
                    continue

                name = data['PublicIP']
                payload = {'name': name,
                           'network': subnet,
                           'partition':partition,
                           'gw':data['PublicIP']}
#                print payload
                exist_url  = self.mgmt_url + '/mgmt/tm/net/route/~' + partition + '~' + name.replace('/','~')
                # https://github.com/F5Networks/f5-common-python/issues/543
                exist = self._exists(exist_url)
                if exist:
                    if LooseVersion(self.tmos_version) > LooseVersion('11.6.0'):
                        # 11.6.0 errors out
                        # icontrol.exceptions.iControlUnexpectedHTTPError: 400 Unexpected Error: Bad Request for uri: https://10.1.1.3:443/mgmt/tm/net/route/~Common~10.1.20.101/
                        #Text: u'{"code":400,"message":"\\"network\\" may not be specified in the context of the \\"modify\\" command. \\"network\\" may be specified using the following commands: create, list, show","errorStack":[]}'

                        route = self.mgmt.tm.net.routes.route.load(name=name,partition=partition)
                        route.update(**payload)
#                    self.s.patch(exist_url,data=json.dumps(payload))
                    # does not remove stale routes
                else:
                    print 'creating new'
                    route = self.mgmt.tm.net.routes.route.create(**payload)
            return []

    def create_or_update_network_arp(self,all_ips,ip_to_mac,route_domain=1,partition='Common'):
        "add MAC addresses to static arp table"
#        print all_ips, ip_to_mac
        for (podIP, hostIP) in all_ips:
            arp = self.mgmt.tm.net.arps.arp
            f5_ip = "%s%%%d" %(podIP,route_domain)
            name = "%s_%s" %(podIP,route_domain)
            exist = True
            try:
                arp.exists(name=name, partition=partition)
            except iControlUnexpectedHTTPError,e:
                if "arp entry not found" in e.message:
                    exist = False
                else:
                    raise
                    
            payload = { 'name': name,
                        'partition': partition,
                        'ipAddress': f5_ip,
                        'macAddress': ip_to_mac.get(hostIP) }
            if exist:
                arp = arp.load(name=name, partition=partition)
                arp.update(**payload)
            else:
                arp.create(**payload)

    def create_or_update_vs(self, my_vs):
        "create VS using iControl REST"
        hostname = my_vs['name']
        target_port = my_vs['port']
        dest = my_vs['dest']
        svc_type = 'http'
        pool_members = my_vs['pool_members']

        vs_name = "%s_%s_vs" %(hostname, target_port)
        pool_name = "%s_%s_pool" %(hostname, target_port)

        if self.mgmt.tm.ltm.pools.pool.exists(name=pool_name):
            pool = self.mgmt.tm.ltm.pools.pool.load(name=pool_name)
        else:
            pool = self.mgmt.tm.ltm.pools.pool.create(name=pool_name, monitor='/Common/tcp')

        members =  pool.members_s.get_collection()

        existing_members = set( [m.name for m in members] )
        current_members = set(['%s:%s' %(ip,port) for (ip, port) in pool_members])

        add_members = current_members - existing_members
        remove_members  = existing_members - current_members

        for m in add_members:
            member = pool.members_s.members.create(partition='Common', name=m)

        for m in remove_members:
            member = pool.members_s.members.load(partition='Common', name=m)
            member.delete()

        if not dest:
            return

        payload = { 'name': vs_name,
                    'destination': "%s:%s" %(dest, target_port),
                    'pool': '/Common/%s' %(pool_name),
                    'ipProtocol' : 'tcp'
                }
#        if 'vs__AdvPolicies' in my_vs:
#            print 'advanced policy'
#            payload['policies'] = my_vs['vs__AdvPolicies']
#        if 'vs__ProfileHTTP' in my_vs:
#            payload['profiles'] = my_vs['vs__ProfileHTTP']
#        print my_vs
        if self.mgmt.tm.ltm.virtuals.virtual.exists(name=vs_name):
            virtual = self.mgmt.tm.ltm.virtuals.virtual.load(name=vs_name, partition='Common')
            profiles =  virtual.profiles_s
            profile_collection = profiles.get_collection()
            profile_names = [a.name for a in profile_collection]
            if 'vs__ProfileHTTP' in my_vs:
                if 'http' in profile_names:
                    profile = profiles.profiles.load(name='http')
                    profile.update(fullPath=my_vs['vs__ProfileHTTP'])
                else:
                    profiles.profiles.create(name='http',fullPath=my_vs['vs__ProfileHTTP'])
            if 'vs__AdvPolicies' in my_vs:
                policy_url =  "%spolicies/%s" %(virtual._meta_data['uri'],my_vs['vs__AdvPolicies'].replace('/','~'))

                exist = self._exists(policy_url)
                if not exist:
                    print 'creating policy'
                    policy_url =  "%spolicies/" %(virtual._meta_data['uri'])
                    self._create(policy_url,{'name':my_vs['vs__AdvPolicies'].split('/')[-1],'fullPath':my_vs['vs__AdvPolicies']})

                
            virtual.update(**payload)
        else:
            virtual = self.mgmt.tm.ltm.virtuals.virtual.create(**payload)
            profiles =  virtual.profiles_s
            if 'vs__ProfileHTTP' in my_vs:
                profiles.profiles.create(name='http',fullPath=my_vs['vs__ProfileHTTP'])
        pass
    def create_or_update_dns(self,my_vs,hostname,server,dc):
        # uses raw iControl
        # check for virtual server
        target_port = my_vs['port']
        dest = my_vs['dest']

        vs_name = "%s_%s_vs" %(hostname, target_port)
        pool_name = "%s_%s_pool" %(hostname, target_port)

        vs_name = "%s_%s_vs" %(hostname, target_port)
        pool_name = "%s_%s_%s_pool" %(hostname, target_port, dc)

        exist_url  = self.mgmt_url + "/mgmt/tm/gtm/server/~Common~%s/virtual-servers/%s" %(server,vs_name)
        post_url  = self.mgmt_url + "/mgmt/tm/gtm/server/~Common~%s/virtual-servers" %(server)
        logging.debug("%s, %s" %(exist_url,post_url))
        does_exist = self._exists(exist_url)
        payload = {'kind':'tm:gtm:server:virtual-servers:virtual-serversstate',
                              'name':vs_name,
                              'destination':'%s:%s' %(dest,target_port),
                              'translationAddress':dest,
                              'translationPort':target_port,
                              'monitor':'/Common/bigip'
        }
        if not does_exist:
            resp = self._create(post_url,payload)
            does_exist = True

        # check for pool

        exist_url  = self.mgmt_url + "/mgmt/tm/gtm/pool/a/~Common~%s" %(pool_name)
        post_url  = self.mgmt_url + "/mgmt/tm/gtm/pool/a"

        does_exist = self._exists(exist_url)
        if not does_exist:
            self._create(post_url,{'kind':'tm:gtm:pool:a:astate',
                                                  'name':pool_name,
                                                  'members':['%s:%s' %(server,vs_name)]
                                              })
            does_exist = True

        # check for wideip
        exist_url  = self.mgmt_url + "/mgmt/tm/gtm/wideip/a/~Common~%s" %(hostname)
        post_url  = self.mgmt_url + "/mgmt/tm/gtm/wideip/a"

        does_exist = self._exists(exist_url)

        if not does_exist:
            self._create(post_url,{'kind':'tm:gtm:wideip:a:astate',
                                                  'name': '%s' %(hostname),
                                                  'pools': [pool_name]
                                              })
            does_exist = True

    # p[3].rules_s.get_collection()[0].actions_s.get_collection()[0].forward
    def create_or_update_policy(self, name, rules, iapp):
        policy = self.mgmt.tm.ltm.policys.policy
#        name = "%s_%d" %(name, time.time())
        draft_policy = True

        if LooseVersion(self.tmos_version) < LooseVersion('12.1.0'):
            # draft policy introduced in version 12.1
            draft_policy = False

        if not policy.exists(name=name, partition='Common'):
            payload = { "strategy": "/Common/first-match",
                        "name": name,
                        "partition": "Common",
                        "fullPath": "/Common/echomap",
                        "requires": [
                            "http"
                        ],
                        "controls": [ "forwarding"]
                    }
            if draft_policy:
                payload['legacy'] = True
            my_pol = policy.create(**payload)
        else:
            my_pol = policy.load(name=name,partition='Common')

        normalized_rules = [(a['hostname'] + a['uri'],a) for a in rules]
        normalized_rules.sort(lambda a,b: cmp(b[0],a[0]))
        all_rules = my_pol.rules_s.get_collection()
        #>>> a = [1,2,3,4]
        #>>> b = [1,2,3]
        #>>> a[len(b):]
        #[4]
        to_delete = all_rules[len(normalized_rules):]
        [a.delete() for a in to_delete]

        # not a safe way to update rules / ideally use draft policies from 12.1 
        # or version number the policy and swap to be atomic
        for x in range(len(normalized_rules)):
            rule_name = "rule_%02d" %(x+1)
            rule = normalized_rules[x][1]
            payload = { 'name':rule_name
                    }
            exist = True
            if draft_policy:
                payload['description'] = "%s%s -> %s:%d" %(rule['hostname'], rule['uri'], rule['backend'],rule['port'])
            try:
                my_rule = my_pol.rules_s.rules.load(name=payload['name'])
            except iControlUnexpectedHTTPError,e:
                exist = False
            if exist:
                my_rule.update(**payload)
            else:
                my_rule = my_pol.rules_s.rules.create(**payload)
            # match host header
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
                       u'values': [rule['hostname']]}
            my_rule.conditions_s.conditions.create(**payload)
            # match uri
            if a['uri'] != '/':
                payload = {u'caseInsensitive': True,
                           u'external': True,
                           u'fullPath': u'1',
                           u'httpUri': True,
                           u'index': 0,
                           u'name': u'1',
                           u'path': True,
                           u'present': True,
                           u'remote': True,
                           u'request': True,
                           u'startsWith': True,
                           u'values': [rule['uri']]}
                my_rule.conditions_s.conditions.create(**payload)

            if iapp:
                pool_name = "/Common/%s_%d_app.app/%s_%d_pool" %(rule['backend'],rule['port'],rule['backend'],rule['port'])
            else:
                pool_name = "/Common/%s_%d_pool" %(rule['backend'],rule['port'])
            payload = {
                "vlanId": 0,
#                "timeout": 0,
                "forward": True,
#                "expirySecs": 0,
                "code": 0,
                "fullPath": "0",
                "name": "0",
#                "length": 0,
#                "offset": 0,
                "pool": pool_name,
                "request": True,
                "select": True,
                "status": 0
            }

            my_rule.actions_s.actions.create(**payload)
            
    def create_or_update_iapp(self, hostname,target_port,dest,svc_type,pool_members,local_traffic_policy=None):
        # Set iApp name and template
        app_name = "%s_%s_app" %(hostname, target_port)
        vs_name = "%s_%s_vs" %(hostname, target_port)
        pool_name = "%s_%s_pool" %(hostname, target_port)
#        template = "/Common/appsvcs_integration_v2.0dev_001"
        template = "/Common/appsvcs_integration_v1.0_001"
        app_pool_members = []
        for (ip,port) in pool_members:
            row = {'row': [ ip, port.__str__(), '0', '1', 'enabled'] }
            app_pool_members.append(row)

        exist_url = "%s/~%s~%s.app~%s" % (self.url, 'Common', app_name, app_name)

        payload = {
                'template': template,
                'inheritedDevicegroup': 'true',
                'inheritedTrafficGroup': 'true',
                'kind': 'tm:sys:application:service:servicestate',
                'name': app_name,
        'partition': 'Common',
                # Pool Members
                'tables': [ { 'columnNames': [ 'IPAddress',
                                               'Port',
                                               'ConnectionLimit',
                                               'Ratio',
                                               'State'],
                        'name': 'pool__Members',
                              'rows': app_pool_members
                      }],

                'variables': [
                        # iApp Options
                        { 'name': 'iapp__strictUpdates',
                'value': 'enabled'},
                        { 'name': 'iapp__appStats',
                          'value': 'enabled'},
                        { 'name': 'iapp__mode',
                          'value': 'auto'},
                        { 'name': 'iapp__routeDomain',
                          'value': 'auto'},

                        # Virtual Server & Listener Configuration
                        { 'name': 'pool__addr',
                          'value': dest}, # Virtual Service Address
                        { 'name': 'pool__mask',
                          'value': '255.255.255.255'},
                        { 'name': 'pool__Name',
                          'value': pool_name},
                        { 'name': 'pool__Description',
                          'value': 'pooldescr'},
                        { 'name': 'pool__Monitor',
                          'value': '/Common/http'},
                        { 'name': 'pool__LbMethod',
                          'value': 'round-robin'},
                        { 'name': 'pool__MemberDefaultPort',
                        'value': '80'},

                        # Virtual Server Configuration
                        { 'name': 'vs__Name',
                          'value': vs_name},
                        { 'name': 'vs__Description',
                          'value': 'vsdescr'},
                        { 'name': 'vs__SourceAddress',
                          'value': '0.0.0.0/0'},
                { 'name': 'vs__IpProtocol',
                  'value': 'tcp'},
                        { 'name': 'vs__ConnectionLimit',
                          'value': '0'},
                        { 'name': 'vs__ProfileClientProtocol',
                          'value': '/Common/tcp-wan-optimized'},
                        { 'name': 'vs__ProfileServerProtocol',
                          'value': '/Common/tcp-lan-optimized'},
                { 'name': 'vs__ProfileHTTP',
                  'value': '/Common/http'},
                        { 'name': 'vs__ProfileOneConnect',
                          'value': ''},
                        { 'name': 'vs__ProfileCompression',
                          'value': ''},
                        { 'name': 'vs__ProfileDefaultPersist',
                          'value': ''},
                { 'name': 'vs__ProfileFallbackPersist',
                  'value': ''},
                        { 'name': 'vs__SNATConfig',
                          'value': 'none'},
                { 'name': 'vs__ProfileSecurityIPBlacklist',
                  'value': 'none'},
                        { 'name': 'vs__OptionSourcePort',
                          'value': 'preserve'},
                        { 'name': 'vs__OptionConnectionMirroring',
                          'value': 'disabled'},

                        # L4-7 Application Functionality
                        { 'name': 'feature__statsTLS',
                          'value': 'disabled'},
                { 'name': 'feature__statsHTTP',
                  'value': 'disabled'},
                        { 'name': 'feature__insertXForwardedFor',
                          'value': 'auto'},
                        { 'name': 'feature__sslEasyCipher',
                          'value': 'high'},
                        { 'name': 'feature__securityEnableHSTS',
                          'value': 'disabled'},
                        { 'name': 'feature__easyL4Firewall',
                        'value': 'auto'},
                ]}
        ssl_variables = [{ 'name': 'vs__ProfileClientSSLCert',
                        'value': '/Common/default.crt'},
                        { 'name': 'vs__ProfileClientSSLChain',
                          'value': '/Common/ca-bundle.crt'},
                        { 'name': 'vs__ProfileClientSSLKey',
                          'value': '/Common/default.key'},
                         { 'name': 'pool__port',
                           'value': '443'}]
        nossl_variables = [{'name': 'pool__port',
                            'value': '80'}]
        just_ssl_variables = [{ 'name': 'feature__redirectToHTTPS',
                          'value': 'enabled'}]
        payload['variables'].extend(nossl_variables)
#        print payload
#        payload['variables'].extend(ssl_variables)
#        payload['variables'].extend(just_ssl_variables)

        if not self.mgmt.tm.sys.application.services.service.exists(name=app_name, partition='Common'):
            service = self.mgmt.tm.sys.application.services.service
            service.create(**payload)
            
        else:
            svc = self.mgmt.tm.sys.application.services.service.load(name=app_name, partition = 'Common')
            payload["execute-action"] = "definition"
#            if svc.tables != payload['tables']:                
#                svc.update(**payload)

                
def get_networks():
    client = etcd.Client()
    res = client.read('/coreos.com/network/config/')
    my_networks = {}
    network_config = json.loads(res.value)
    res = client.get('/coreos.com/network/subnets')
    for subnet in [a.key for a in res.children]:
        res = client.read(subnet)
        data = json.loads(res.value)
        subnet_name =  subnet.split('/')[-1].replace('-','/')
        #        public_ip = data['PublicIP']
        #        vtep_mac_addr = data["BackendData"]["VtepMAC"]
        my_networks[subnet_name] = data

    return (network_config, my_networks)
    

def get_services_policies(config_file="/home/user/.kube/config"):
    api = pykube.http.HTTPClient(pykube.config.KubeConfig.from_file(config_file))

    pods = pykube.objects.Pod.objects(api).filter(namespace="default")
    services = pykube.objects.Service.objects(api).filter(namespace="default")
    ready_pods = filter(operator.attrgetter("ready"), pods)

    endpoints = pykube.objects.Endpoint.objects(api).filter(namespace="default")
    ingresses = pykube.objects.Ingress.objects(api).filter(namespace="default")

    my_services = {}
    my_policies = {}

    #
    # Grab L7 ingress
    #
    for ing in ingresses:
    #    print ing.obj['metadata']['name']
    #    print ing.obj['spec']['backend']['serviceName']
    #    print ing.obj['spec']['backend']['servicePort']
        ing_name = ing.obj['metadata']['name']
        my_rules = []
        for rule in  ing.obj['spec']['rules']:
    #        print rule
            hostname = rule['host'] 
            for path in rule['http']['paths']:
                uri = path['path']
                backend = path['backend']['serviceName']
                port = path['backend']['servicePort']
#                print hostname,uri, backend, port
                my_rules.append({'hostname':hostname,
                                 'uri':uri,
                                 'backend':backend,
                                 'port':port})
        my_policies[ing_name] = {'rules': my_rules }
        if 'annotations' in ing.obj['metadata']:
            if 'f5.destination' in ing.obj['metadata']['annotations']:            
                my_policies[ing_name]['dest'] =  ing.obj['metadata']['annotations']['f5.destination']
            

                # foo.bar.com /foo echoheadersx 80
    #
    # Grab endpoints (internal IPs)
    #

    #for eps in endpoints:
    #    print eps.obj['metadata']['name']
    #    for pod in eps.obj['subsets']:
    #        print pod

    #
    # Grab services L4 services
    #
    for service in services:
        skip_service = False
        svc = {'pods':[]}
    #    print service
    #    print service.obj['status']
    #    print service.obj['spec']['ports']
    #    print service.__dict__

        svc['clusterIP'] = service.obj['spec']['clusterIP']
        if 'externalIPs' in service.obj['spec']:
            svc['loadbalancerIP'] = service.obj['spec']['externalIPs'][0]
        # prefer loadbalancerIP https://github.com/kubernetes/kubernetes/pull/13005
        if 'loadbalancerIP' in service.obj['spec']:
            svc['loadbalancerIP'] = service.obj['spec']['loadbalancerIP']
        # fallback to clusterIP
        if 'loadbalancerIP' not in svc:
            svc['loadbalancerIP'] = svc['clusterIP']
        # override with f5 variables
#        print service.obj['metadata']
        if 'annotations' in service.obj['metadata']:
            if 'f5.destination' in service.obj['metadata']['annotations']:            
                svc['loadbalancerIP'] =  service.obj['metadata']['annotations']['f5.destination']
            if 'kubernetes.io/ingress.class' in service.obj['metadata']['annotations']:
                if service.obj['metadata']['annotations']["kubernetes.io/ingress.class"] != 'f5.bigip':
                    skip_service = True
            for key in service.obj['metadata']['annotations']:
#                print key
                if key.startswith('f5.vs__'):
                    svc[key[3:]] = service.obj['metadata']['annotations'][key]

        if skip_service:
            continue

        svc['ports'] = service.obj['spec']['ports']
        svc['targetPort'] = service.obj['spec']['ports'][0]['targetPort']
        if 'selector' not in service.obj['spec']:
            continue
        svc['selector'] = service.obj['spec']['selector']
    #    print service.obj['spec']
        svc['name'] = service.obj['metadata']['name']
        svc['namespace'] = service.obj['metadata']['namespace']
        svc_pods = pods.filter(namespace=svc['namespace'],selector=svc['selector'])
    #    print svc_pods
        #
        # Grab pods (external IP)
        #
        for pod in svc_pods:
    #        print pod.obj['metadata']
            my_run = pod.obj['spec']['containers'][0]['name']
            my_pod = {}
            my_pod['hostIP'] =  pod.obj['status']['hostIP']
            if 'podIP' in pod.obj['status']:
                my_pod['podIP'] =  pod.obj['status']['podIP']
            svc['pods'].append(my_pod)
        my_services[svc['name']] = svc
    return (my_services,my_policies)
def get_bigip_cfg(my_services,routed=True,pool_rd=0):
    bigip_cfg = {}
    for svc in my_services:
        my_svc = my_services[svc]
        for port in my_svc['ports']:
            vs_name = "%s_%s_vs" %(svc,port['port'])            
            protocol = port['protocol']
            pool_name = "%s_%s_pool" %(svc,port['port'])            
            members = []
            nodes = set()
            for pod in my_svc['pods']:
                if routed:
                    if pool_rd:
                        member_ip = "%s%%%d" %(pod['podIP'],pool_rd)
                    else:
                        member_ip = pod['podIP']
                    member_port = port['targetPort']
                else:
                    member_ip = pod['hostIP']
                    member_port = port['nodePort']                
                nodes.add((pod['podIP'],pod['hostIP']))
                member =  (member_ip, member_port)
                members.append(member)
            bigip_cfg[vs_name] = {'name': svc,
                                  'port': port['port'],
                                  'protocol': protocol, 
                                  'pool_name': pool_name, 
                                  'pool_members': members,
                                  'nodes': nodes}
            for key in my_svc:
                if key.startswith('vs__'):
                    bigip_cfg[vs_name][key] = my_svc[key]
            if 'loadbalancerIP' in my_svc:
                bigip_cfg[vs_name]['dest'] = my_svc['loadbalancerIP']
            else:
                bigip_cfg[vs_name]['dest'] = None # do not create vs
    return bigip_cfg

if __name__ == "__main__":
    iapp = True
    dns = True
    routed = True
    vxlan = False

    (network_config, my_networks) = get_networks()
    i_promise = os.getenv('I_PROMISE_NOT_TO_RUN_THIS_IN_PRODUCTION')
    if not i_promise:
        print "ERROR: You must promise not to run this in production or acknowledge you do so at your own risk!"
        sys.exit(1)

    iapp = os.getenv('USE_IAPP') == 'TRUE' or False
    dns = os.getenv('USE_DNS') == 'TRUE' or False
    network_type = os.getenv('NETWORK_TYPE')
    if network_type == 'VXLAN':
        routed = False
        vxlan = True
    else:        
        routed = True
        vxlan = False

    bigip_user = os.getenv('BIGIP_USER') or 'admin'
    bigip_password = os.getenv('BIGIP_PASSWD') or 'admin'
    bigip_host = os.getenv('BIGIP_HOST') or '192.168.1.245'
    kube_config = os.getenv('KUBE_CONFIG') or "/home/user/.kube/config"
    kube2bigip = KubeToBigIP(username=bigip_user, password=bigip_password, host=bigip_host)

    (my_services, my_policies) = get_services_policies(config_file=kube_config)

    if vxlan:
        my_vs = get_bigip_cfg(my_services,routed=routed,pool_rd=1)
    else:
        my_vs = get_bigip_cfg(my_services,routed=routed)

    records = kube2bigip.create_or_update_network(network_config, my_networks, vxlan=vxlan)

    ip_to_mac = dict([(a['endpoint'],a['name']) for a in records])
    all_ips = set()

#    print ip_to_mac

#    pp.pprint(my_services)
#    pp.pprint(my_policies)
#    pp.pprint(my_vs)
    for vs_name in my_vs:
        vs = my_vs[vs_name]
        logging.debug(vs)
        all_ips.update(vs['nodes'])
        if 'dest' not in vs or vs['dest'] == None:
            continue
        if iapp:
            kube2bigip.create_or_update_iapp(vs['name'],
                                             vs['port'],
                                             vs['dest'],
                                             'http',
                                             vs['pool_members'])
        else:
            kube2bigip.create_or_update_vs(vs)
        if dns:
            kube2bigip.create_or_update_dns(vs,"%s.%s" %(vs['name'],'f5demo.com'),
                                            'bigip1',
                                            'hq')
            if 'vs__AdvPolicies' in vs:
                hostnames =  [a['hostname'] for a in  my_policies[vs['vs__AdvPolicies'].split('/')[-1]]['rules']]
                for hostname in hostnames:
                    kube2bigip.create_or_update_dns(vs,hostname,
                                                    'bigip1',
                                                    'hq')

    if vxlan:
        kube2bigip.create_or_update_network_arp(all_ips, ip_to_mac)

    for policy_name in my_policies:
#        print policy_name
        policy = my_policies[policy_name]
#        print policy
        kube2bigip.create_or_update_policy(policy_name,policy['rules'],iapp=iapp)
#        sys.exit(0)


