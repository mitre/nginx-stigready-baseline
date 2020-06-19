# encoding: UTF-8

control "V-41810" do
  title "The NGINX web server must generate unique session identifiers with definable
entropy."
  desc  "Generating a session identifier (ID) that is not easily guessed
through brute force is essential to deter several types of session attacks. By
knowing the session ID, an attacker can hijack a user session that has already
been user authenticated by the hosted application. The attacker does not need
to guess user identifiers and passwords or have a secure token since the user
session has already been authenticated.

    Random and unique session IDs are the opposite of sequentially generated
session IDs, which can be easily guessed by an attacker. Random session
identifiers help to reduce predictability of said identifiers. The session ID
must be unpredictable (random enough) to prevent guessing attacks, where an
attacker is able to guess or predict the ID of a valid session through
statistical analysis techniques. For this purpose, a good PRNG (Pseudo Random
Number Generator) must be used.

    Unique session IDs address man-in-the-middle attacks, including session
hijacking or insertion of false information into a session. If the attacker is
unable to identify or guess the session information related to pending
application traffic, they will have more difficulty in hijacking the session or
otherwise manipulating valid sessions.

    At least half of a session ID must be created using a definable source of
entropy (PRNG).
  "
  desc  "rationale", ""
  desc  "check", "
  Review the NGINX web server documentation and deployed configuration to verify
  that the web server is generating random session IDs with entropy equal to at
  least half the session ID length.

  If it is determined that the web server is not required to perform session management, 
  this check is Not Applicable. 

  Nginx web server versions after 1.11.0 have the $request_id embedded variable by default. 
  This variable is a unique request identifier generated from 16 random bytes, in hexadecimal. 

  Execute the following command to get the current version of Nginx running:
    # nginx -v

  If the current version of Nginx running is 1.11.0 or earlier, this is a finding. 
  "
  desc  "fix", "Upgrade to the lastest stable version of Nginx web server to use the '$request_id' 
  embedded variable for generating unique identifiers withminimum entropy equal to half the session 
  ID length."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000224-WSR-000139"
  tag "gid": "V-41810"
  tag "rid": "SV-54387r3_rule"
  tag "stig_id": "SRG-APP-000224-WSR-000139"
  tag "fix_id": "F-47269r2_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]

# Nginx versions after 1.11.0 have the $request_id embedded variable by default
# This variable is a unique request identifier generated from 16 random bytes, in hexadecimal

  describe nginx do
    its('version') { should cmp > '1.11.0' }
  end
  
end

