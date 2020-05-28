# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

nginx_owner = input(
  'nginx_owner',
  description: "The Nginx owner",
  default: 'nginx'
)

sys_admin = input(
  'sys_admin',
  description: "The system adminstrator",
  default: ['root']
)

nginx_group = input(
  'nginx_group',
  description: "The Nginx group",
  default: 'nginx'
)

sys_admin_group = input(
  'sys_admin_group',
  description: "The system adminstrator group",
  default: ['root']
)

control "V-55947" do
  title "Non-privileged accounts on the hosting system must only access web
server security-relevant information and functions through a distinct
administrative account."
  desc  "By separating web server security functions from non-privileged users,
roles can be developed that can then be used to administer the web server.
Forcing users to change from a non-privileged account to a privileged account
when operating on the web server or on security-relevant information forces
users to only operate as a web server administrator when necessary. Operating
in this manner allows for better logging of changes and better forensic
information and limits accidental changes to the web server."
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and configuration to determine if
accounts used for administrative duties of the web server are separated from
non-privileged accounts.

    If non-privileged accounts can access web server security-relevant
information, this is a finding.
  "
  desc  "fix", "Set up accounts and roles that can be used to perform web
server security-relevant tasks and remove or modify non-privileged account
access to security-relevant tasks."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000340-WSR-000029"
  tag "gid": "V-55947"
  tag "rid": "SV-70201r2_rule"
  tag "stig_id": "SRG-APP-000340-WSR-000029"
  tag "fix_id": "F-60825r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]

# Check (from Apache 2.4):
  # Determine which tool or control file is used to control the configuration of the web server.

  # If the control of the web server is done via control files, verify who has update access to them. If tools are being used to configure the web server, determine who has access to execute the tools.

  # If accounts other than the System Administrator (SA), the Web Manager, or the Web Manager designees have access to the web administration tool or control files, this is a finding.
 
# Fix (from Apache 2.4):
  # Restrict access to the web administration tool to only the System Administrator, Web Manager, or the Web Manager designees.

  describe "Skip Test" do
    skip "This is a manual check"
  end
  
end

