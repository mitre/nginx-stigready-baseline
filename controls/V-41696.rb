# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41696" do
  title "Web server accounts not utilized by installed features (i.e., tools,
utilities, specific services, etc.) must not be created and must be deleted
when the web server feature is uninstalled."
  desc  "When accounts used for web server features such as documentation,
sample code, example applications, tutorials, utilities, and services are
created even though the feature is not installed, they become an exploitable
threat to a web server.

    These accounts become inactive, are not monitored through regular use, and
passwords for the accounts are not created or updated. An attacker, through
very little effort, can use these accounts to gain access to the web server and
begin investigating ways to elevate the account privileges.

    The accounts used for web server features not installed must not be created
and must be deleted when these features are uninstalled.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation to determine the user accounts created
when particular features are installed.

    Verify the deployed configuration to determine which features are installed
with the web server.

    If any accounts exist that are not used by the installed features, this is
a finding.
  "
  desc  "fix", "Use the web server uninstall facility or manually remove the
user accounts not used by the installed web server features."
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-APP-000141-WSR-000078"
  tag "gid": "V-41696"
  tag "rid": "SV-54273r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000078"
  tag "fix_id": "F-47155r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

 # This test assumes that Nginx has been configured to run with the account "nginx".
  # Thus there should be at least one user parameter, and the only value of that parameter
  # should be "nginx".
  describe 'At least one user directive' do
    it 'should exist.' do
      expect(nginx_conf(conf_path).params['user']).to_not(be_nil)
    end
  end
  Array(nginx_conf(conf_path).params['user']).each do |user|
    Array(user).each do |value|
      describe 'The value of user' do
        it 'should only be nginx.' do
          expect(value).to(eq "nginx")
        end
      end
    end
  end
  # /etc/passwd should include the runner account.
  # Note:  This is not a very bullet-proof test.
  describe 'The password file' do
    it 'should include the nginx account.' do
      expect(command('grep -w "nginx" /etc/passwd').stdout).to(match /.*?nginx.*?/)
    end
  end
end

