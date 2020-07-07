# encoding: UTF-8

control "V-41611" do
  title "The NGINX web server must initiate session logging upon start up."
  desc  "An attacker can compromise a web server during the startup process. If
  logging is not initiated until all the web server processes are started, key
  information may be missed and not available during a forensic investigation. To
  assure all logable events are captured, the web server must begin logging once
  the first web server process is initiated."
  
  desc  "check", "Review the NGINX web server documentation and deployed configuration to determine 
  if the NGINX web server captures log data as soon as the NGINX web server is started.

  Check for the following:
      # grep for 'access_log' and 'error_log' directives in the nginx.conf and any separated include configuration file.
  
  Execute the following commands:
      # file <path to access_log>/access.log
      # file <path to error_log>/error.log
  
  If the access_log and error_log directives do not exist and the access.log and error.log files do not exist, this is a finding.  
  "
  desc  "fix", "Enable loggin on the NGINX web server by configuring the 'access_log' and 'error_log' directives in the NGINX configuration 
  file(s) to generate log records for system startup."
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
  nginx_conf_handle = nginx_conf(input('conf_path'))

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  nginx_conf_handle.params['http'].each do |http|
    describe 'Each http context' do
      it 'should include an access_log directive.' do
        expect(http).to(include "access_log")
      end
    end
    http["access_log"].each do |access_log|
      access_log.each do |access_value|
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
  nginx_conf_handle.params['error_log'].each do |error_log|
    error_log.each do |error_value|
      if error_value.include? "error.log"
        describe file(error_value) do
          it 'The error log should exist.' do
            expect(subject).to(exist)
          end
        end
      end
    end       
  end
end

