# encoding: UTF-8

control "V-41809" do
  title "The NGINX web server must generate a session ID using as much of the
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
  
  desc  "check", "Review the NGINX web server documentation and deployed configuration 
  to determine what characters are used in generating session IDs.

  If it is determined that the web server is not required to perform session management, 
  this check is Not Applicable. 

  NGINX web server versions after 1.11.0 have the $request_id embedded variable by default. 
  This variable is a unique request identifier generated from 16 random bytes, in hexadecimal. 

  Execute the following command to get the current version of NGINX running:
    # nginx -v

  If the current version of NGINX running is 1.11.0 or earlier, this is a finding. 
  "
  desc  "fix", "Upgrade to the lastest stable version of NGINX web server to use the '$request_id' 
  embedded variable for generating unique identifiers that uses at least A-Z, a-z, and 0-9 to generate 
  session IDs."
  
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000224-WSR-000138"
  tag "gid": "V-41809"
  tag "rid": "SV-54386r3_rule"
  tag "stig_id": "SRG-APP-000224-WSR-000138"
  tag "fix_id": "F-47268r2_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]

# NGINX versions after 1.11.0 have the $request_id embedded variable by default
# This variable is a unique request identifier generated from 16 random bytes, in hexadecimal

  describe nginx do
    its('version') { should cmp > '1.11.0' }
  end
  
end

