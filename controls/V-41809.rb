# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41809" do
  title "The web server must generate a session ID using as much of the
character set as possible to reduce the risk of brute force."
  desc  "Generating a session identifier (ID) that is not easily guessed
through brute force is essential to deter several types of session attacks. By
knowing the session ID, an attacker can hijack a user session that has already
been user-authenticated by the hosted application. The attacker does not need
to guess user identifiers and passwords or have a secure token since the user
session has already been authenticated.

    By generating session IDs that contain as much of the character set as
possible, i.e., A-Z, a-z, and 0-9, the session ID becomes exponentially harder
to guess.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
what characters are used in generating session IDs.

    If the web server is not configured to use at least A-Z, a-z, and 0-9 to
generate session identifiers, this is a finding.
  "
  desc  "fix", "Configure the web server to use at least A-Z, a-z, and 0-9 to
generate session IDs."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000224-WSR-000138"
  tag "gid": "V-41809"
  tag "rid": "SV-54386r3_rule"
  tag "stig_id": "SRG-APP-000224-WSR-000138"
  tag "fix_id": "F-47268r2_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]

# Nginx versions after 1.11.0 have the $request_id embedded variable by default
# This variable is a unique request identifier generated from 16 random bytes, in hexadecimal

  describe nginx do
    its('version') { should cmp > '1.11.0' }
  end
  
end

