# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-55959" do
  title "The NGINX web server must use a logging mechanism that is configured to
allocate log record storage capacity large enough to accommodate the logging
requirements of the web server."
  desc  "In order to make certain that the logging mechanism used by the web
server has sufficient storage capacity in which to write the logs, the logging
mechanism needs to be able to allocate log record storage capacity.

    The task of allocating log record storage capacity is usually performed
during initial installation of the logging mechanism. The system administrator
will usually coordinate the allocation of physical drive space with the web
server administrator along with the physical location of the partition and
disk. Refer to NIST SP 800-92 for specific requirements on log rotation and
storage dependent on the impact of the web server.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the NGINX web server documentation and deployment configuration to
  determine if the web server is using a logging mechanism to store log records.
  If a logging mechanism is in use, validate that the mechanism is configured to
  use record storage capacity in accordance with specifications within NIST SP
  800-92 for log record storage requirements.

  Check for the following:
      # grep for 'access_log' and 'error_log' directives in the nginx.conf and 
      any separated include configuration file.

  Execute the following commands:
      # file <path to access_log>/access.log
      # file <path to error_log>/error.log

  If the access_log and error_log directives do not exist and the access.log and 
  error.log files do not exist, this is a finding. 

  Work with SIEM administrator to determine log storage capacity.
  If there is no setting within a SIEM to accommodate enough a large logging 
  capacity, this is a finding.
  "
  desc  "fix", "Enable logging on the NGINX web server by configuring the 'access_log' 
  and 'error_log' directives in the NGINX configuration file(s).

  Work with the SIEM administrator to determine if the SIEM is configured to allocate 
  log record storage capacity large enough to accommodate the logging requirements of 
  the NGINX web server."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000357-WSR-000150"
  tag "gid": "V-55959"
  tag "rid": "SV-70213r2_rule"
  tag "stig_id": "SRG-APP-000357-WSR-000150"
  tag "fix_id": "F-60837r1_fix"
  tag "cci": ["CCI-001849"]
  tag "nist": ["AU-4", "Rev_4"]

  # Verify that access_log and error_log is enabled
  nginx_conf_handle = nginx_conf(conf_path)

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  Array(nginx_conf_handle.params['http']).each do |http|
    describe 'Each http context' do
      it 'should include an access_log directive.' do
        expect(http).to(include "access_log")
      end
    end
    Array(http["access_log"]).each do |access_log|
      Array(access_log).each do |access_value|
        if access_value.include? "access.log"
          describe file(access_value) do
            it 'The access log should exist.' do
              expect(subject).to(exist)
            end
          end
        end
      end
    end
  end
  Array(nginx_conf_handle.params['error_log']).each do |error_log|
    Array(error_log).each do |error_value|
      if error_value.include? "error.log"
        describe file(error_value) do
          it 'The error log should exist.' do
            expect(subject).to(exist)
          end
        end
      end
    end       
  end

  describe "Manual Step" do
    skip "Work with SIEM administrator to determine log storage capacity.
    If there is no setting within a SIEM to accommodate enough a large logging 
    capacity, this is a finding."
  end

end

