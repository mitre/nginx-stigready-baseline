# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-40792" do
  title "The web server must perform server-side session management."
  desc  "Session management is the practice of protecting the bulk of the user
authorization and identity information. Storing of this data can occur on the
client system or on the server.

    When the session information is stored on the client, the session ID, along
with the user authorization and identity information, is sent along with each
client request and is stored in either a cookie, embedded in the uniform
resource locator (URL), or placed in a hidden field on the displayed form. Each
of these offers advantages and disadvantages. The biggest disadvantage to all
three is the hijacking of a session along with all of the user's credentials.

    When the user authorization and identity information is stored on the
server in a protected and encrypted database, the communication between the
client and web server will only send the session identifier, and the server can
then retrieve user credentials for the session when needed. If, during
transmission, the session were to be hijacked, the user's credentials would not
be compromised.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and configuration to determine if
server-side session management is configured.

    If it is not configured, this is a finding.
  "
  desc  "fix", "Configure the web server to perform server-side session
management."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000001-WSR-000002"
  tag "gid": "V-40792"
  tag "rid": "SV-53023r3_rule"
  tag "stig_id": "SRG-APP-000001-WSR-000002"
  tag "fix_id": "F-45949r2_fix"
  tag "cci": ["CCI-000054"]
  tag "nist": ["AC-10", "Rev_4"]

  describe "Skip Test" do
    skip "This is a manual check"
  end
end

