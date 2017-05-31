F5 AWS Token Fetcher
======================

### About

Uses F5 APM to retrieve SAML token and generate STS token to be used with AWS CLI.

### References

  * https://devcentral.f5.com/codeshare/saas-federation-iapp
  * https://aws.amazon.com/blogs/security/how-to-implement-federated-api-and-cli-access-using-saml-2-0-and-ad-fs/

### Requirements

  * Python
  * F5 APM

### Usage

Modify script to reference correct AWS SAML ID

```
% python f5-aws-sts-fetcher.py https://f5apm.example.com/saml/idp/res?id=/Common/awsaccess
Username: erchen
Password:

% aws --profile saml ec2 describe-instances
...

```


### Authored By

[Eric Chen](https://devcentral.f5.com/users/123940) | [@chen23](https://github.com/chen23)
