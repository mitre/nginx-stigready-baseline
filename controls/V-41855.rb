# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41855" do
  title "Debugging and trace information used to diagnose the web server must
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
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
if debugging and trace information are enabled.

    If the web server is configured with debugging and trace information
enabled, this is a finding.
  "
  desc  "fix", "Configure the web server to minimize the information given to
clients on error conditions by disabling debugging and trace information."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000266-WSR-000160"
  tag "gid": "V-41855"
  tag "rid": "SV-54432r3_rule"
  tag "stig_id": "SRG-APP-000266-WSR-000160"
  tag "fix_id": "F-47314r2_fix"
  tag "cci": ["CCI-001312"]
  tag "nist": ["SI-11 a", "Rev_4"]

# Check:
  # grep 'error_log' in the nginx configuration
    # If directive error log level is set to 'debug', this is a finding.
# Fix:
    # In the Nginx configuration, the error log level should not be set to 'debug'.

  Array(nginx_conf(conf_path).params['error_log']).each do |error_log|
    Array(error_log).each do |error_value|
      describe "The error log level" do
        it 'should not be set to debug.' do
          expect(error_value).not_to(eq 'debug')
        end
      end
    end       
  end
end

