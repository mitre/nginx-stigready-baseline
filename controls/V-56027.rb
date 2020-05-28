# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-56027" do
  title "The web server must only accept client certificates issued by DoD PKI
or DoD-approved PKI Certification Authorities (CAs)."
  desc  "Non-DoD approved PKIs have not been evaluated to ensure that they have
security controls and identity vetting procedures in place which are sufficient
for DoD systems to rely on the identity asserted in the certificate. PKIs
lacking sufficient security controls and identity vetting procedures risk being
compromised and issuing certificates that enable adversaries to impersonate
legitimate users."
  desc  "rationale", ""
  desc  "check", "
    Review the web server deployed configuration to determine if the web server
will accept client certificates issued by unapproved PKIs. The authoritative
list of DoD-approved PKIs is published at
http://iase.disa.mil/pki-pke/interoperability.

    If the web server will accept non-DoD approved PKI client certificates,
this is a finding.
  "
  desc  "fix", "Configure the web server to only accept DoD and DoD-approved
PKI client certificates."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000427-WSR-000186"
  tag "gid": "V-56027"
  tag "rid": "SV-70281r2_rule"
  tag "stig_id": "SRG-APP-000427-WSR-000186"
  tag "fix_id": "F-60905r1_fix"
  tag "cci": ["CCI-002470"]
  tag "nist": ["SC-23 (5)", "Rev_4"]

  describe "Skip Test" do
    skip "This is a manual check"
  end
  
end

