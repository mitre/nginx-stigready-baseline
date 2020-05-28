# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41693" do
  title "The web server must only contain services and functions necessary for
operation."
  desc  "A web server can provide many features, services, and processes. Some
of these may be deemed unnecessary or too unsecure to run on a production DoD
system.

    The web server must provide the capability to disable, uninstall, or
deactivate functionality and services that are deemed to be non-essential to
the web server mission or can adversely impact server performance.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
if web server features, services, and processes are installed that are not
needed for hosted application deployment.

    If excessive features, services, and processes are installed, this is a
finding.
  "
  desc  "fix", "Uninstall or deactivate features, services, and processes not
needed by the web server for operation."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000075"
  tag "gid": "V-41693"
  tag "rid": "SV-54270r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000075"
  tag "fix_id": "F-47152r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

  describe "Skip Test" do
    skip "This is a manual check"
  end
  
end

