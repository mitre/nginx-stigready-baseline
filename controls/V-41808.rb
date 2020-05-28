# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41808" do
  title "The web server must generate a session ID long enough that it cannot
be guessed through brute force."
  desc  "Generating a session identifier (ID) that is not easily guessed
through brute force is essential to deter several types of session attacks.  By
knowing the session ID, an attacker can hijack a user session that has already
been user authenticated by the hosted application.  The attacker does not need
to guess user identifiers and passwords or have a secure token since the user
session has already been authenticated.

    Generating session IDs that are at least 128 bits (16 bytes) in length will
cause an attacker to take a large amount of time and resources to guess,
reducing the likelihood of an attacker guessing a session ID.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to see how
long the generated session identifiers are.

    If the web server is not configured to generate session identifiers that
are at least 128 bits (16 bytes) in length, this is a finding.
  "
  desc  "fix", "Configure the web server to generate session identifiers that
are at least 128 bits in length."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000224-WSR-000137"
  tag "gid": "V-41808"
  tag "rid": "SV-54385r3_rule"
  tag "stig_id": "SRG-APP-000224-WSR-000137"
  tag "fix_id": "F-47267r2_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]

# Nginx versions after 1.11.0 have the $request_id embedded variable by default
# This variable is a unique request identifier generated from 16 random bytes, in hexadecimal

  describe nginx do
    its('version') { should cmp > '1.11.0' }
  end
  
end

