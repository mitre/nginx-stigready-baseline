# encoding: UTF-8

control "V-41808" do
  title "The NGINX web server must generate a session ID long enough that it cannot
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
  Review the NGINX web server documentation and deployed configuration to see how
  long the generated session identifiers are.

  If it is determined that the web server is not required to perform session 
  management, this check is Not Applicable. 

  NGINX web server versions after 1.11.0 have the $request_id embedded variable 
  by default. This variable is a unique request identifier generated from 16 random bytes, 
  in hexadecimal. 

  Execute the following command to get the current version of NGINX running:
    # nginx -v

  If the current version of NGINX running is 1.11.0 or earlier, this is a finding. 
  "
  desc  "fix", "Upgrade to the lastest stable version of NGINX web server to use the 
  '$request_id' embedded variable for generating unique identifiers that are at least 
  128 bits in length."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000224-WSR-000137"
  tag "gid": "V-41808"
  tag "rid": "SV-54385r3_rule"
  tag "stig_id": "SRG-APP-000224-WSR-000137"
  tag "fix_id": "F-47267r2_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]

# NGINX versions after 1.11.0 have the $request_id embedded variable by default
# This variable is a unique request identifier generated from 16 random bytes, in hexadecimal

  describe nginx do
    its('version') { should cmp > '1.11.0' }
  end
  
end

