F5 Python SDK CLI Example
=================


Introduction
------------

The super_pool.py script is a very basic example of creating your own
CLI utility using the [F5 Python SDK](https://github.com/F5Networks/f5-common-python)
to manage LTM pool and pool members.

Prerequisites
------------

* Python
* [F5 Python SDK](https://github.com/F5Networks/f5-common-python)

Concepts
------------

The script creates a Python object that stores the connection object to the
BIG-IP
```
...
def __init__(self, host, username, password):
	self.mgmt = ManagementRoot(host, username, password)
...
```
This allows the connection to be re-used and provides a generic class that
can be included by other Python scripts.

The "```__main__```" section of the code allows it be run from the CLI and
uses the argparse library to handle inputs.

```
...
if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Script to create a pool on a BIG-IP device')
	parser.add_argument("host",             help="The IP/Hostname of the BIG-IP device")
...
```

One of the inputs includes specifying a CSV file that is formatted with the pool
information.  Completing the script to handle all possible inputs is left as
an excercise.


Usage
------------

```
% python super_pool.py --help
```


### Further Documentation

* iControlREST: https://devcentral.f5.com/wiki/iControlREST.HomePage.ashx
* F5 Python SDK: https://github.com/F5Networks/f5-common-python

### Authored By

[Eric Chen](https://devcentral.f5.com/users/123940) | [@chen23](https://github.com/chen23)
