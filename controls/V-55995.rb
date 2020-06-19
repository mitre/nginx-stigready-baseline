# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

sys_admin = input(
  'sys_admin',
  description: "The system adminstrator",
  value: ['root']
)

nginx_owner = input(
  'nginx_owner',
  description: "The Nginx owner",
  value: 'nginx'
)

control "V-55995" do
  title "Web server accounts accessing the directory tree, the shell, or other
operating system functions and utilities must only be administrative accounts."
  desc  "As a rule, accounts on a web server are to be kept to a minimum. Only
administrators, web managers, developers, auditors, and web authors require
accounts on the machine hosting the web server. The resources to which these
accounts have access must also be closely monitored and controlled. Only the
system administrator needs access to all the system's capabilities, while the
web administrator and associated staff require access and control of the web
content and web server configuration files."
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and configuration to determine what web
server accounts are available on the hosting server.

    If non-privileged web server accounts are available with access to
functions, directories, or files not needed for the role of the account, this
is a finding.
  "
  desc  "fix", "Limit the functions, directories, and files that are accessible
by each account and role to administrative accounts and remove or modify
non-privileged account access."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000211-WSR-000030"
  tag "gid": "V-55995"
  tag "rid": "SV-70249r2_rule"
  tag "stig_id": "SRG-APP-000211-WSR-000030"
  tag "fix_id": "F-60873r1_fix"
  tag "cci": ["CCI-001082"]
  tag "nist": ["SC-2", "Rev_4"]

  authorized_sa_user_list = sys_admin.clone << nginx_owner

  describe users.shells(/bash/).usernames do
    it { should be_in authorized_sa_user_list}
  end

  if users.shells(/bash/).usernames.empty?
    describe "Skip Message" do
      skip "Skipped: no users found with shell acccess."
    end
  end
rescue Exception => msg
  describe "Exception: #{msg}" do
    it { should be_nil }
  end
end

