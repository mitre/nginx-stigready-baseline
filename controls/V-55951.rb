# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-55951" do
  title "The web server must set an absolute timeout for sessions."
  desc  "Leaving sessions open indefinitely is a major security risk. An
attacker can easily use an already authenticated session to access the hosted
application as the previously authenticated user. By closing sessions after an
absolute period of time, the user is forced to re-authenticate guaranteeing the
session is still in use. Enabling an absolute timeout for sessions closes
sessions that are still active. Examples would be a runaway process accessing
the web server or an attacker using a hijacked session to slowly probe the web
server."
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to verify
that the web server is configured to close sessions after an absolute period of
time.

    If the web server is not configured to close sessions after an absolute
period of time, this is a finding.
  "
  desc  "fix", "Configure the web server to close sessions after an absolute
period of time."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000295-WSR-000012"
  tag "gid": "V-55951"
  tag "rid": "SV-70205r2_rule"
  tag "stig_id": "SRG-APP-000295-WSR-000012"
  tag "fix_id": "F-60829r1_fix"
  tag "cci": ["CCI-002361"]
  tag "nist": ["AC-12", "Rev_4"]

  describe "Skip Test" do
    skip "This is a manual check"
  end
  
end

