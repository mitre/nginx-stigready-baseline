# encoding: UTF-8

control "V-41600" do
  title "The NGINX web server must generate, at a minimum, log records for system
  startup and shutdown, system access, and system authentication events."
  desc  "Log records can be generated from various components within the web
  server (e.g., httpd, plug-ins to external backends, etc.). From a web server
  perspective, certain specific web server functionalities may be logged as well.
  The web server must allow the definition of what events are to be logged. As
  conditions change, the number and types of events to be logged may change, and
  the web server must be able to facilitate these changes.

    The minimum list of logged events should be those pertaining to system
  startup and shutdown, system access, and system authentication events. If these
  events are not logged at a minimum, any type of forensic investigation would be
  missing pertinent information needed to replay what occurred.
  "
  desc  "check", "
  Review the NGINX web server documentation and the deployed system configuration to determine 
  if, at a minimum, system startup and shutdown, system access, and system authentication events are logged.

  If there are no websites configured for NGINX, this check is Not Applicable.
    
  Check for the following:
  # grep the 'log_format' directive in the http context of the nginx.conf. 

  The logs will not include the minimum logable events if the 'log_format' directive does not exist.

  If the the 'log_format' directive does not exist, this is a finding.

  Example configuration:
  log_format  main  '$remote_addr - $remote_user [$time_local] ""$request""'
  '$status $body_bytes_sent ""$http_referer""'
  '""$http_user_agent"" ""$http_x_forwarded_for""';

  "
  desc  "fix", "Configure the 'log_format' directive in the nginx.conf file to look like the following:

  log_format  main  '$remote_addr - $remote_user [$time_local] ""$request""'
  '$status $body_bytes_sent ""$http_referer""'
  '""$http_user_agent"" ""$http_x_forwarded_for""';
  
  NOTE: Your log format may be using different variables based on your environment, 
  however it should be verified to be producing the same end result of logged elements."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000089-WSR-000047"
  tag "gid": "V-41600"
  tag "rid": "SV-54177r3_rule"
  tag "stig_id": "SRG-APP-000089-WSR-000047"
  tag "fix_id": "F-47059r3_fix"
  tag "cci": ["CCI-000169"]
  tag "nist": ["AU-12 a", "Rev_4"]

  # Verify that the log_format directive exists
  if nginx_conf.params['http'].nil?
    impact 0.0
    describe 'This check is NA because no websites have been configured.' do
      skip 'This check is NA because no websites have been configured.'
    end
  else
    nginx_conf.params['http'].each do |http|
      describe 'Each http context' do
        it 'should include a log_format directive for logging minimum logable events.' do
          expect(http).to(include "log_format")
        end
      end      
    end
  end
end

