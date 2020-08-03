# encoding: UTF-8

control "V-56031" do
  title "The NGINX web server must encrypt user identifiers and passwords."
  desc  "When data is written to digital media, such as hard drives, mobile
  computers, external/removable hard drives, personal digital assistants,
  flash/thumb drives, etc., there is risk of data loss and data compromise. User
  identities and passwords stored on the hard drive of the hosting hardware must
  be encrypted to protect the data from easily being discovered and used by an
  unauthorized user to access the hosted applications. The cryptographic
  libraries and functionality used to store and retrieve the user identifiers and
  passwords must be part of the web server."
  
  desc  "check", "Review the NGINX web server documentation and deployed configuration 
  to determine whether the web server is authorizing and managing users.

  If the NGINX web server is not authorizing and managing users, this is check is Not
  Applicable.

  If the NGINX web server is the user authenticator and manager, verify that stored
  user identifiers and passwords are being encrypted by the web server. If the
  user information is not being encrypted when stored, this is a finding.
  "
  desc  "fix", "Configure the web server to encrypt the user identifiers and
  passwords when storing them on digital media."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000429-WSR-000113"
  tag "gid": "V-56031"
  tag "rid": "SV-70285r2_rule"
  tag "stig_id": "SRG-APP-000429-WSR-000113"
  tag "fix_id": "F-60909r1_fix"
  tag "cci": ["CCI-002476"]
  tag "nist": ["SC-28 (1)", "Rev_4"]

  if input('manages_auth') == 'false'
    impact 0.0
    describe 'This check is NA because NGINX does not manage authentication.' do
      skip 'This check is NA because NGINX does not manage authentication.'
    end
  else
    describe "This test requires a Manual Review: Verify that user identifiers and passwords 
    are being encrypted by the web server." do
      skip "This test requires a Manual Review: Verify that user identifiers and passwords 
      are being encrypted by the web server."
    end
  end 
end

