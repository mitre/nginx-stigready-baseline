# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41807" do
  title "The web server must generate unique session identifiers that cannot be
reliably reproduced."
  desc  "Communication between a client and the web server is done using the
HTTP protocol, but HTTP is a stateless protocol. In order to maintain a
connection or session, a web server will generate a session identifier (ID) for
each client session when the session is initiated. The session ID allows the
web server to track a user session and, in many cases, the user, if the user
previously logged into a hosted application.

    By being able to guess session IDs, an attacker can easily perform a
man-in-the-middle attack. To truly generate random session identifiers that
cannot be reproduced, the web server session ID generator, when used twice with
the same input criteria, must generate an unrelated random ID.

    The session ID generator also needs to be a FIPS 140-2 approved generator.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to verify
that random and unique session identifiers are generated.

    Access the web server ID generator function and generate two IDs using the
same input.

    If the web server is not configured to generate random and unique session
identifiers, or the ID generator generates the same ID for the same input, this
is a finding.
  "
  desc  "fix", "Configure the web server to generate random and unique session
identifiers that cannot be reliably reproduced."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000224-WSR-000136"
  tag "gid": "V-41807"
  tag "rid": "SV-54384r3_rule"
  tag "stig_id": "SRG-APP-000224-WSR-000136"
  tag "fix_id": "F-47266r2_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]
# Nginx versions after 1.11.0 have the $request_id embedded variable by default
# This variable is a unique request identifier generated from 16 random bytes, in hexadecimal

  describe nginx do
    its('version') { should cmp > '1.11.0' }
  end

end

