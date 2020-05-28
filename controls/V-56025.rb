# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-56025" do
  title "Cookies exchanged between the web server and client, such as session
cookies, must have security settings that disallow cookie access outside the
originating web server and hosted application."
  desc  "Cookies are used to exchange data between the web server and the
client. Cookies, such as a session cookie, may contain session information and
user credentials used to maintain a persistent connection between the user and
the hosted application since HTTP/HTTPS is a stateless protocol.

    When the cookie parameters are not set properly (i.e., domain and path
parameters), cookies can be shared within hosted applications residing on the
same web server or to applications hosted on different web servers residing on
the same domain.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and configuration to determine if
cookies between the web server and client are accessible by applications or web
servers other than the originating pair.

    If the cookie information is accessible outside the originating pair, this
is a finding.
  "
  desc  "fix", "Configure the web server to set properties within cookies to
disallow the cookie to be accessed by other web servers and applications."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000223-WSR-000011"
  tag "gid": "V-56025"
  tag "rid": "SV-70279r2_rule"
  tag "stig_id": "SRG-APP-000223-WSR-000011"
  tag "fix_id": "F-60903r1_fix"
  tag "cci": ["CCI-001664"]
  tag "nist": ["SC-23 (3)", "Rev_4"]

  describe "Skip Test" do
    skip "This is a manual check"
  end
  
end

