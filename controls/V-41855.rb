# encoding: UTF-8

control "V-41855" do
  title "Debugging and trace information used to diagnose the NGINX web server must
be disabled."
  desc  "Information needed by an attacker to begin looking for possible
vulnerabilities in a web server includes any information about the web server
and plug-ins or modules being used. When debugging or trace information is
enabled in a production web server, information about the web server, such as
web server type, version, patches installed, plug-ins and modules installed,
type of code being used by the hosted application, and any backends being used
for data storage may be displayed. Since this information may be placed in logs
and general messages during normal operation of the web server, an attacker
does not need to cause an error condition to gain this information."
  
  desc  "check", "
  Review the NGINX web server documentation and deployed configuration to determine
  if debugging and trace information are enabled.

  Check for the following:
  # grep the 'error_log' directive the nginx.conf

  If the 'error_log' directive is set to error log level 'debug', this is a finding. 
  "
  desc  "fix", "The 'error_log' directive should not have the error log level set to
  'debug' to minimize the information given to clients on error conditions."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000266-WSR-000160"
  tag "gid": "V-41855"
  tag "rid": "SV-54432r3_rule"
  tag "stig_id": "SRG-APP-000266-WSR-000160"
  tag "fix_id": "F-47314r2_fix"
  tag "cci": ["CCI-001312"]
  tag "nist": ["SI-11 a", "Rev_4"]

  nginx_conf.params['error_log'].each do |error_log|
    error_log.each do |error_value|
      describe "The error log level" do
        it 'should not be set to debug.' do
          expect(error_value).not_to(eq 'debug')
        end
      end
    end       
  end
end

