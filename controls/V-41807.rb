# encoding: UTF-8

control "V-41807" do
  title "The NGINX web server must generate unique session identifiers that cannot be
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
  
  desc  "check", "Review the NGINX web server documentation and deployed configuration 
  to verify that random and unique session identifiers are generated.

  If it is determined that the web server is not required to perform session management, 
  this check is Not Applicable. 

  NGINX web server versions after 1.11.0 have the $request_id embedded variable by default. 
  This variable is a unique request identifier generated from 16 random bytes, in hexadecimal. 

  Execute the following command to get the current version of NGINX running:
    # nginx -v

  If the current version of NGINX running is 1.11.0 or earlier, this is a finding. 
  "
  desc  "fix", "Upgrade to the lastest stable version of NGINX web server to use the '$request_id' 
  embedded variable for generating an unique identifier that cannot be reliably reproduced."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000224-WSR-000136"
  tag "satisfies": ["SRG-APP-000224-WSR-000137", "SRG-APP-000224-WSR-000138", "SRG-APP-000224-WSR-000139",
  "SRG-APP-000223-WSR-000145", "SRG-APP-000224-WSR-000135"]
  tag "gid": "V-41807"
  tag "rid": "SV-54384r3_rule"
  tag "stig_id": "SRG-APP-000224-WSR-000136"
  tag "fix_id": "F-47266r2_fix"
  tag "cci": ["CCI-001188", "CCI-001664"]
  tag "nist": ["SC-23 (3)", "Rev_4"]

  if input('performs_session_management') == "false"
    impact 0.0
    describe 'This check is NA because session management is not required.' do
      skip 'This check is NA because session management is not required.'
    end
  else
    describe nginx do
      its('version') { should cmp > '1.11.0' }
    end
  end
end

