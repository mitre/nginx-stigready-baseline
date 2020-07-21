# encoding: UTF-8

control "V-56023" do
  title "The NGINX web server must generate a unique session identifier for each
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
  
  desc  "check", "Review the web server documentation and deployed configuration 
  to verify that the web server is configured to generate unique session identifiers with a
  FIPS 140-2 approved random number generator.

  NGINX web server versions after 1.11.0 have the $request_id embedded variable by 
  default. This variable is a unique request identifier generated from 16 random 
  bytes, in hexadecimal. 

  Execute the following command to get the current version of NGINX running:
    # nginx -v

  If the current version of NGINX running is 1.11.0 or earlier, this is a finding. 
  "
  desc  "fix", "Upgrade to the lastest stable version of NGINX web server to generate 
  unique session identifiers using a FIPS 140-2 random number generator."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000224-WSR-000135"
  tag "gid": "V-56023"
  tag "rid": "SV-70277r2_rule"
  tag "stig_id": "SRG-APP-000224-WSR-000135"
  tag "fix_id": "F-60901r1_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]

  describe nginx do
    its('version') { should cmp == input('nginx_version') }
  end
  
end

