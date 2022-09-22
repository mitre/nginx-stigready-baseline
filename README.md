# nginx-stigready-baseline

InSpec Profile to validate the secure configuration of nginx-stigready-baseline, against Web Server SRG Verson 2 Release 3 InSpec profile for nginx 1.19

## Getting Started  
It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __ssh__.

The latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

# Running This Baseline Directly from Github

```
# How to run
inspec exec https://github.com/mitre/nginx-stigready-baseline/archive/master.tar.gz -t ssh:// --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this baseline and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile baseline for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/nginx-stigready-baseline
inspec archive nginx-stigready-baseline
inspec exec <name of generated archive> -t ssh:// --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this baseline:

```
cd nginx-stigready-baseline
git pull
cd ..
inspec archive nginx-stigready-baseline --overwrite
inspec exec <name of generated archive> -t ssh:// --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Testing with Kitchen
### Dependencies

- Ruby 2.6.0 or later
- [Virtualbox](https://www.virtualbox.org)
- [Vagrant](https://www.vagrantup.com)
- [Docker](https://docs.docker.com)

### Setup Environment
1. Clone the repo via `git clone git@github.com:mitre/nginx-stigready-baseline.git`
2. cd to `nginx-stigready-baseline`
3. Run `gem install bundler`
4. Run `bundle install`
5. Run `export KITCHEN_YAML=kitchen.vagrant.yml` - Docker and EC2 Kitchen Yaml files are available for testing

### Execute Tests
1. Run `bundle exec kitchen create` - create host based on two suites, vanilla and hardened
2. Run `bundle exec kitchen list` - you should see the following choices:
   - `vanilla-ubuntu-1804`
   - `hardened-ubuntu-1804`
3. Run `bundle exec kitchen converge`
4. Run `bundle exec kitchen list` - your should see your hosts with status "converged"
5. Run `bundle exec kitchen verify` - Once finished, the results should be in the 'results' directory.

## Authors
* Timothy J Miller
* The MITRE InSpec Team

## Special Thanks 
* Mohamed El-Sharkawi - [HackerShark](https://github.com/HackerShark)
* Shivani Karikar - [karikarshivani](https://github.com/karikarshivani)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/nginx-stigready-baseline/issues/new).

### NOTICE

© 2018-2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE 

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

### NOTICE  

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx
