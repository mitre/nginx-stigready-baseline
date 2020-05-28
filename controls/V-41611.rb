# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41611" do
  title "The web server must initiate session logging upon start up."
  desc  "An attacker can compromise a web server during the startup process. If
logging is not initiated until all the web server processes are started, key
information may be missed and not available during a forensic investigation. To
assure all logable events are captured, the web server must begin logging once
the first web server process is initiated."
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
if the web server captures log data as soon as the web server is started.

    If the web server does not capture logable events upon startup, this is a
finding.
  "
  desc  "fix", "Configure the web server to capture logable events upon
startup."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000092-WSR-000055"
  tag "gid": "V-41611"
  tag "rid": "SV-54188r3_rule"
  tag "stig_id": "SRG-APP-000092-WSR-000055"
  tag "fix_id": "F-47070r2_fix"
  tag "cci": ["CCI-001464"]
  tag "nist": ["AU-14 (1)", "Rev_4"]

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

