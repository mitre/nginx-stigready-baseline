# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-56013" do
  title "The web server must maintain the confidentiality and integrity of
information during preparation for transmission."
  desc  "Information can be either unintentionally or maliciously disclosed or
modified during preparation for transmission, including, for example, during
aggregation, at protocol transformation points, and during packing/unpacking.
These unauthorized disclosures or modifications compromise the confidentiality
or integrity of the information.

    An example of this would be an SMTP queue. This queue may be added to a web
server through an SMTP module to enhance error reporting or to allow developers
to add SMTP functionality to their applications.

    Any modules used by the web server that queue data before transmission must
maintain the confidentiality and integrity of the information before the data
is transmitted.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
if the web server maintains the confidentiality and integrity of information
during preparation before transmission.

    If the confidentiality and integrity are not maintained, this is a finding.
  "
  desc  "fix", "Configure the web server to maintain the confidentiality and
integrity of information during preparation for transmission."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000441-WSR-000181"
  tag "gid": "V-56013"
  tag "rid": "SV-70267r2_rule"
  tag "stig_id": "SRG-APP-000441-WSR-000181"
  tag "fix_id": "F-60891r1_fix"
  tag "cci": ["CCI-002420"]
  tag "nist": ["SC-8 (2)", "Rev_4"]

  describe "Skip Test" do
    skip "This is a manual check"
  end
  
end

