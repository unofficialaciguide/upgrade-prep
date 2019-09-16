# upgrade-prep

A simple script that will query your fabric for upgrade readiness by checking a few things. 

Please see this unofficalaciguide article for more information!

https://unofficialaciguide.com/2018/04/03/upgrading-your-aci-fabric/

## Requirements:

Written to support direct execution on APIC or remote execution. This script supports both Python2 
and Python3. If executing remotely, ensure the proper dependencies are installed. The full list is
in requirements.txt file. If pip is available, you can install the dependencies via the following:

```
pip install -r requirements.txt
```

## Usage:

If executing on the APIC, you can zip the source code, upload to the APIC, and execute directly:
```
# create the zip manually
user1:~host$ git clone https://github.com/unofficialaciguide/upgrade-prep.git
Cloning into 'upgrade-prep'...

user1:~host$ cd upgrade-prep/
user1:~host$ zip -r upgrade-prep.zip ./*
user1:~host$ ls -al | grep zip
 rwxr-xr-x 1 admin admin 465303 Sep 16 17:40 upgrade.zip

# upload the .zip file to the APIC, change the permissions to allow execution, and execute it
fab4-apic1# chmod 755 upgrade-prep.zip
fab4-apic1# python ./upgrade-prep.zip
* executing checks, please wait...

Progress (6/6), Executing: VerifySoftwareVersion
[==================================================] 100.00%, 00:00:17

RESULTS
+------------------------- + -------------------------------------------------- + ---------- + ----------------------------------------------------------------------+
|Check                     | Description                                        | Pass/Fail  | Pass/Fail Reason                                                      |
+------------------------- + -------------------------------------------------- + ---------- + ----------------------------------------------------------------------+
|ClusterHealth             | Cluster must be in a healthy state for a           | Pass       | Cluster is healthy                                                    |
|time: 0.066               | successful upgrade. This check ensures that all    |            |                                                                       |
|                          | APICs are fully fit                                |            |                                                                       |
+------------------------- + -------------------------------------------------- + ---------- + ----------------------------------------------------------------------+
<snip>
```

You can use the same syntax when executing remotely assuming the requirements have been installed.
There are additional options for remote connectivity that you can provide via arguments. The script
will prompt the user if not provided.  Use `--help` to get full list of options.

```
user1:~host$ git clone https://github.com/unofficialaciguide/upgrade-prep.git
Cloning into 'upgrade-prep'...

user1:~host$ cd upgrade-prep/
user1:~host$ pip install -r requirements.txt
<snip>

user1:~host$ python ./
Enter apic hostname      : esc-aci-network.cisco.com:8002
Enter apic username      : admin
Enter apic password      :
* connecting to APIC https://esc-aci-network.cisco.com:8002
* executing checks, please wait...

<snip>
```

