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

If executing on the APIC, you can upload the .zip file and execute directly:
```
python ./upgrade-prep.zip
```

You can use the same syntax when executing remotely assuming the requirements have been installed.
There are additional options for remote connectivity that you can provide via arguments. The script
will prompt the user if not provided.  Use `--help` to get full list of options.

```
python ./upgrade-prep.zip
Enter apic hostname      : esc-aci-network.cisco.com:8002
Enter apic username      : admin
Enter apic password      :
[EDT 2019-09-06T22:50:02.303] INFO connecting to APIC https://esc-aci-network.cisco.com:8002
[EDT 2019-09-06T22:50:02.458] INFO executing checks, please wait...
<snip>
```

