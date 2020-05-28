# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41600" do
  title "The web server must generate, at a minimum, log records for system
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
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and the deployed system configuration
to determine if, at a minimum, system startup and shutdown, system access, and
system authentication events are logged.

    If the logs do not include the minimum logable events, this is a finding.
  "
  desc  "fix", "Configure the web server to generate log records for system
startup and shutdown, system access, and system authentication events."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000089-WSR-000047"
  tag "gid": "V-41600"
  tag "rid": "SV-54177r3_rule"
  tag "stig_id": "SRG-APP-000089-WSR-000047"
  tag "fix_id": "F-47059r3_fix"
  tag "cci": ["CCI-000169"]
  tag "nist": ["AU-12 a", "Rev_4"]

  # Verify that access_log and error_log is enabled
  Array(nginx_conf(conf_path).params['http']).each do |http|
    describe 'Each http context' do
      it 'should include an access_log directive.' do
        expect(http).to(include "access_log")
      end
    end
    Array(http["access_log"]).each do |access_log|
      Array(access_log).each do |access_value|
        if access_value.include? "access.log"
          describe file(access_value) do
            it 'The access log should exist and be a file.' do
              expect(subject).to(exist)
              expect(subject).to(be_file)
            end
          end
        end
      end
    end
  end
  Array(nginx_conf(conf_path).params['error_log']).each do |error_log|
    Array(error_log).each do |error_value|
      if error_value.include? "error.log"
        describe file(error_value) do
          it 'The error log should exist and be a file.' do
            expect(subject).to(exist)
            expect(subject).to(be_file)
          end
        end
      end
    end       
  end
end

