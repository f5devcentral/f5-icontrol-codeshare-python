#!/usr/bin/python 
 
import sys 
import boto3
import requests 
import getpass 
import ConfigParser 
import base64 
import xml.etree.ElementTree as ET 

from os.path import expanduser 
from urlparse import urlparse, urlunparse 
import time
import re
import os
import json
import cPickle

DEBUG = os.getenv('DEBUG')

if DEBUG:
    try:
        import http.client as http_client
    except ImportError:
        # Python 2
        import httplib as http_client

    http_client.HTTPConnection.debuglevel = 1
        
    import logging
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propogate = True

# Author: Eric Chen 
#
# Based on 
#
# https://aws.amazon.com/blogs/security/how-to-implement-federated-api-and-cli-access-using-saml-2-0-and-ad-fs/
#
 
##########################################################################
# Variables 
 
# region: The default AWS region that this script will connect 
# to for all API calls 
region = 'us-east-1' 
 
# output format: The AWS CLI output format that will be configured in the 
# saml profile (affects subsequent CLI calls) 
outputformat = 'json'
 
# awsconfigfile: The file where this script will store the temp 
# credentials under the saml profile 
awsconfigfile = '/.aws/credentials'
 
# SSL certificate verification: Whether or not strict certificate 
# verification is done, False should only be used for dev/test 
sslverification = True 
 
# idpentryurl: The initial URL that starts the authentication process. 
idpentryurl = sys.argv[1]

##########################################################################

get_assertion = re.compile("name=\"SAMLResponse\" value=\"([^\"]+)")

# Get the federated credentials from the user
username = os.getenv('USERNAME')

if not username:
    print "Username:",
    username = raw_input()

password = os.getenv('PASSWORD')
if not password:
    password = getpass.getpass()
    print ''

mfamethod = os.getenv('MFAMETHOD')
if not mfamethod:
    print 'MFA Method [push]/token:',
    mfamethod = raw_input()

if not mfamethod:
    mfamethod = 'push'
else:
    mfamethod = mfamethod.strip()

mfatoken = ''
print 'MFA method',mfamethod

if mfamethod != 'push' and mfamethod != 'none':
    print 'MFA Token:',
    if re.search(re.compile("^\d+$"),mfamethod):
        mfatoken = mfamethod
        mfamethod = 'token'
    else:
        mfatoken = raw_input()
        mfatoken = mfatoken.strip()


# Initiate session handler 
session = requests.Session() 
if os.path.exists('session.pickle'):
    cookies = cPickle.load(open('session.pickle'))
    session.cookies = cookies
 
# Programatically get the SAML assertion 
 
# Opens the initial AD FS URL and follows all of the HTTP302 redirects 

headers = {'user-agent':'f5-aws-sts-fetcher/0.1'}

response = session.get(idpentryurl, verify=sslverification, headers=headers) 

posturl = response.url
u = urlparse(response.url)
baseurl = u.scheme + '://' + u.netloc

m = get_assertion.search(response.text)

if m:
    mfamethod = 'none'
else:
    response = session.post(posturl,data={'username':username,'password':password}, headers=headers)


if "<title>F5 Dynamic Webtop</title>" in response.text:
    # existing MFA session, skip MFA
    mfamethod = 'none'

if mfamethod != 'none':
    if ">Please select your preferred method for Multi-Factor Authentication<" not in response.text:
        print "Authentication Failed"
        sys.exit(1)

    if mfamethod == 'push':
        print 'Waiting for MFA push'

    payload = {'mfamethod':mfamethod,'mfatoken':mfatoken,'vhost':'standard'}

    response = session.post(posturl,data=payload, headers=headers)

cookies =  session.cookies.copy()
retryurl = response.url

if "<title>F5 Dynamic Webtop</title>" not in response.text and not m:
    print 'MFA failed'
    sys.exit(1)

response = session.get(baseurl +'/vdesk/resource_list.xml?resourcetype=res',verify=sslverification,headers=headers)

try:
    response = session.get(idpentryurl, verify=sslverification, headers=headers)
except requests.exceptions.ConnectionError:
    response = session.get(idpentryurl, verify=sslverification, headers=headers)

if "SAMLResponse" not in response.text:
    print 'Failed to retrieve SAML token, trying again\n\n\n\n\n\n'
    time.sleep(1)
    try:
        response = session.get(retryurl, verify=sslverification, headers=headers, cookies=cookies)        
        response = session.get(idpentryurl, verify=sslverification, headers=headers, cookies=cookies)
    except requests.exceptions.ConnectionError:
        response = session.get(idpentryurl, verify=sslverification, headers=headers, cookies=cookies)
    
if "SAMLResponse" not in response.text:
    print 'Failed to retrieve SAML token'
    sys.exit(1)

m = get_assertion.search(response.text)

if m:
    assertion =  m.groups()[0]
else:
    print 'failed to find assertion'
    sys.exit(1)
    
# Parse the returned assertion and extract the authorized roles 
awsroles = [] 
root = ET.fromstring(base64.b64decode(assertion))

for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'): 
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'): 
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)
 
 
 
# Note the format of the attribute value should be role_arn,principal_arn 
# but lots of blogs list it as principal_arn,role_arn so let's reverse 
# them if needed 
for awsrole in awsroles: 
    chunks = awsrole.split(',') 
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0] 
        index = awsroles.index(awsrole) 
        awsroles.insert(index, newawsrole) 
        awsroles.remove(awsrole)

# If I have more than one role, ask the user which one they want, 
# otherwise just proceed 
print "" 
if len(awsroles) > 1: 
    i = 0 
    print "Please choose the role you would like to assume:" 
    for awsrole in awsroles: 
        print '[', i, ']: ', awsrole.split(',')[0] 
        i += 1 

    print "Selection: ", 
    selectedroleindex = raw_input() 
 
    # Basic sanity check of input 
    if int(selectedroleindex) > (len(awsroles) - 1): 
        print 'You selected an invalid role index, please try again' 
        sys.exit(0) 
 
    role_arn = awsroles[int(selectedroleindex)].split(',')[0] 
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
 
else: 
    role_arn = awsroles[0].split(',')[0] 
    principal_arn = awsroles[0].split(',')[1]


# Use the assertion to get an AWS STS token using Assume Role with SAML
conn = boto3.client('sts',region_name=region)
token = conn.assume_role_with_saml(RoleArn=role_arn,
                                   PrincipalArn =principal_arn,
                                   SAMLAssertion=assertion)

# Write the AWS STS token into the AWS credential file
home = expanduser("~")
filename = home + awsconfigfile
 
# Read in the existing config file
config = ConfigParser.RawConfigParser()
config.read(filename)
 
# Put the credentials into a specific profile instead of clobbering
# the default credentials
if not config.has_section('saml'):
    config.add_section('saml')
 
config.set('saml', 'output', outputformat)
config.set('saml', 'region', region)
config.set('saml', 'aws_access_key_id', token['Credentials']['AccessKeyId'])
config.set('saml', 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
config.set('saml', 'aws_session_token', token['Credentials']['SessionToken'])
 
# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)
# save a copy of the cookies
#json.dump(cookies,open('session.json','w'))
cPickle.dump(cookies,open('session.pickle','w'))
