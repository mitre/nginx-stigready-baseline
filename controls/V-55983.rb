# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-55983" do
  title "All web server files must be verified for their integrity (e.g.,
checksums and hashes) before becoming part of the production web server."
  desc  "Being able to verify that a patch, upgrade, certificate, etc., being
added to the web server is unchanged from the producer of the file is essential
for file validation and non-repudiation of the information.

    The web server or hosting system must have a mechanism to verify that
files, before installation, are valid.

    Examples of validation methods are sha1 and md5 hashes and checksums.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployment configuration to
determine if the web server validates files before the files are implemented
into the running configuration.

    If the web server does not meet this requirement and an external facility
is not available for use, this is a finding.
  "
  desc  "fix", "Configure the web server to verify object integrity before
becoming part of the production web server or utilize an external tool designed
to meet this requirement."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000131-WSR-000051"
  tag "gid": "V-55983"
  tag "rid": "SV-70237r2_rule"
  tag "stig_id": "SRG-APP-000131-WSR-000051"
  tag "fix_id": "F-60861r1_fix"
  tag "cci": ["CCI-001749"]
  tag "nist": ["CM-5 (3)", "Rev_4"]

  describe "Skip Test" do
    skip "This is a manual check"
  end
  
end

