# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-55997" do
  title "The web server must be tuned to handle the operational requirements of
the hosted application."
  desc  "A Denial of Service (DoS) can occur when the web server is so
overwhelmed that it can no longer respond to additional requests. A web server
not properly tuned may become overwhelmed and cause a DoS condition even with
expected traffic from users. To avoid a DoS, the web server must be tuned to
handle the expected traffic for the hosted applications."
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
what parameters are set to tune the web server.

    Review the hosted applications along with risk analysis documents to
determine the expected user traffic.

    If the web server has not been tuned to avoid a DoS, this is a finding.
  "
  desc  "fix", "
    Analyze the expected user traffic for the hosted applications.

    Tune the web server to avoid a DoS condition under normal user traffic to
the hosted applications.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000435-WSR-000148"
  tag "gid": "V-55997"
  tag "rid": "SV-70251r2_rule"
  tag "stig_id": "SRG-APP-000435-WSR-000148"
  tag "fix_id": "F-60875r2_fix"
  tag "cci": ["CCI-002385"]
  tag "nist": ["SC-5", "Rev_4"]

  #https://www.stigviewer.com/stig/apache_server_2.4_unix_server/2019-12-19/finding/V-92597
  describe "Skip Test" do
    skip "This is a manual check"
  end
  
end

