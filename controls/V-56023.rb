# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-56023" do
  title "The web server must generate a unique session identifier for each
session using a FIPS 140-2 approved random number generator."
  desc  "Communication between a client and the web server is done using the
HTTP protocol, but HTTP is a stateless protocol. In order to maintain a
connection or session, a web server will generate a session identifier (ID) for
each client session when the session is initiated. The session ID allows the
web server to track a user session and, in many cases, the user, if the user
previously logged into a hosted application.

    Unique session IDs are the opposite of sequentially generated session IDs,
which can be easily guessed by an attacker. Unique session identifiers help to
reduce predictability of generated identifiers. Unique session IDs address
man-in-the-middle attacks, including session hijacking or insertion of false
information into a session. If the attacker is unable to identify or guess the
session information related to pending application traffic, the attacker will
have more difficulty in hijacking the session or otherwise manipulating valid
sessions.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to verify
that the web server is configured to generate unique session identifiers with a
FIPS 140-2 approved random number generator.

    Request two users access the web server and view the session identifier
generated for each user to verify that the session IDs are not sequential.

    If the web server is not configured to generate unique session identifiers
or the random number generator is not FIPS 140-2 approved, this is a finding.
  "
  desc  "fix", "Configure the web server to generate unique session identifiers
using a FIPS 140-2 random number generator."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000224-WSR-000135"
  tag "gid": "V-56023"
  tag "rid": "SV-70277r2_rule"
  tag "stig_id": "SRG-APP-000224-WSR-000135"
  tag "fix_id": "F-60901r1_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]

  describe "Skip Test" do
    skip "This is a manual check"
  end
  
end

