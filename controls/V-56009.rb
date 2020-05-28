# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-56009" do
  title "Cookies exchanged between the web server and the client, such as
session cookies, must have cookie properties set to force the encryption of
cookies."
  desc  "Cookies can be sent to a client using TLS/SSL to encrypt the cookies,
but TLS/SSL is not used by every hosted application since the data being
displayed does not require the encryption of the transmission. To safeguard
against cookies, especially session cookies, being sent in plaintext, a cookie
can be encrypted before transmission. To force a cookie to be encrypted before
transmission, the cookie Secure property can be set."
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to verify
that cookies are encrypted before transmission.

    If the web server is not configured to encrypt cookies, this is a finding.
  "
  desc  "fix", "Configure the web server to encrypt cookies before
transmission."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000439-WSR-000155"
  tag "gid": "V-56009"
  tag "rid": "SV-70263r2_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000155"
  tag "fix_id": "F-60887r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]

  describe "Skip Test" do
    skip "This is a manual check"
  end
  
end

