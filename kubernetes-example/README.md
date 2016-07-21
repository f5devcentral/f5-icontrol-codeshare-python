Kubernetes Service Load Balancer / Ingress
==========================================

Example of using Python to query the Kubernetes API and create LTM/DNS objects using iControl REST.

### About

This script will fetch data from Kubernetes to configure a BIG-IP.

Currently will:
 * Retrieve Service, Ingress, Pods from Kubernetes

Kubernetes Features
 * Service Load Balancer (L4)
 * Ingress Router (L7)
BIG-IP Features
 * Supports two types of networking
   * Using static routes (assumes L2 adjacent)
   * Using VXLAN (requires flanneld on K8S / SDN on BIG-IP
 * Supports two types of LTM config generation
   * iControl REST via F5 Python SDK
   * [App Services's iApp 1.0](https://github.com/0xHiteshPatel/appsvcs_integration_iapp)  via [F5 Python SDK](https://github.com/F5Networks/f5-common-python) > 1.0.0
     * Does not support Ingress Router only SLB
 * Generates GTM/DNS config using F5 Python iControl library

### Requirements
   Python 2.7

   Python Modules: f5-sdk, python-etcd, pykube

   F5 BIG-IP LTM/DNS 12.1

### Configuration

  Configuration is via environment variables.  config-sample.sh has
  examples:
  ```
export BIGIP_HOST='10.1.1.2'
export BIGIP_USER='admin'
export BIGIP_PASSWD='admin'
export USE_DNS='TRUE'
#export NETWORK_TYPE='vxlan'
#export KUBE_CONFIG='/etc/kubeconfig'
#
# You must set this variable to run the script
#
#export I_PROMISE_NOT_TO_RUN_THIS_IN_PRODUCTION='TRUE'
```
### Authored By

[Eric Chen](https://devcentral.f5.com/users/123940) | [@chen23](https://github.com/chen23)
