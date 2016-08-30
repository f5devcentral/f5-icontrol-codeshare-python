Pivotal Cloud Foundry (PCF) Example
===================================

DevCentral article: [Evolving Programmability with Pivotal Cloud Foundry](https://devcentral.f5.com/articles/evolving-programmability-with-pivotal-cloud-foundry-21723)
### About

* pcf-phase1.py: create monitor, pool, pool member using iControl REST
* pcf-phase2.py: phase1 + use PCF API
* pcf-phase3.py: phase2 + use iWorkflow instead of iControl REST
* iwf-helper.py: helper script for generating iWorkflow templates

### Requirements
   Python 2.7

   Python Modules: f5-sdk (1.3.1), cloudfoundry-client (0.0.13)

   F5 BIG-IP LTM 11.6.1
   F5 iWorkflow 2.x

### Example Inputs

Create two pool members in Active/Standby with custom HTTP monitor and L7
local traffic policy.

  ```
  % python pcf-phase1.py -a create 10.1.1.245 dora.local.pcfdev.io 10.0.2.10:80,10.0.12.10:80
Created pool /Common/dora.local.pcfdev.io_pool
 Added member 10.0.12.10:80
 Added member 10.0.2.10:80
Created policy rule dora.local.pcfdev.io

```
Create two pool members in Active/Standby with custom HTTP monitor and L7
local traffic policy using PCF API for application names.
```
% python pcf-phase2.py -a create 10.1.1.245 10.0.2.10:80,10.0.12.10:80
Created pool /Common/dora.local.pcfdev.io_pool
 Added member 10.0.12.10:80
 Added member 10.0.2.10:80
Created policy rule dora.local.pcfdev.io
Created pool /Common/dora2.local.pcfdev.io_pool
 Added member 10.0.12.10:80
 Added member 10.0.2.10:80
Created policy rule dora2.local.pcfdev.io

```
Create a template in iWorkflow (requires an existing tenant called "pcfdev_tenant").

```
python iwf-helper.py 10.1.1.246 -a import_template \
                     --template dora_template_v1.0 \
                     --tenant pcfdev_tenant \
                     --file  dora_template_v1.0.yaml

```
Create two pool members in Active/Standby with custom HTTP monitor and L7
local traffic policy using PCF API for application names via iWorkflow.
```
% python pcf-phase3.py 10.1.1.246 10.0.2.10,10.0.12.10 \
                          -a create_iapp \
                          --iapp dora_app_v1.0 \
                          --service_name "dora_template_v2.0"
Created iApp dora_app_v1.0
```


### Authored By

[Eric Chen](https://devcentral.f5.com/users/123940) | [@chen23](https://github.com/chen23)
