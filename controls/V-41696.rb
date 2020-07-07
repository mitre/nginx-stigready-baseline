# encoding: UTF-8

control "V-41696" do
  title "Web server accounts not utilized by installed features (i.e., tools,
  utilities, specific services, etc.) must not be created and must be deleted
  when the NGINX web server feature is uninstalled."
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
  
  desc  "check", "Review the NGINX web server documentation to determine the user 
  accounts created when particular features are installed.

  Verify that at least one 'user' directive exists:
    #grep the 'user' directive in the main context of the nginx.conf file

  Verify the accounts specified in the 'user' directive has an entry in /etc/passwd: 
    # grep -w '<user account>' /etc/passwd' 

  If at least one 'user' directive does not exist or if  any accounts exist that are 
  not used by the installed features, this is a finding.
  "
  desc  "fix", "Ensure at least one 'user' directive exists in the nginx.conf file 
  and remove user accounts not used by the installed NGINX web server features."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000078"
  tag "gid": "V-41696"
  tag "rid": "SV-54273r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000078"
  tag "fix_id": "F-47155r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

  nginx_conf_handle = nginx_conf(input('conf_path'))

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

 # This test assumes that NGINX has been configured to run with the account "nginx".
  # Thus there should be at least one user parameter, and the only value of that parameter
  # should be "nginx".
  describe 'At least one user directive' do
    it 'should exist.' do
      expect(nginx_conf_handle.params['user']).to_not(be_nil)
    end
  end
  nginx_conf_handle.params['user'].each do |user|
    user.each do |value|
      describe 'The value of user' do
        it 'should be the default nginx user or other authorized user.' do
          expect(value).to (eq input('nginx_owner')).or (be_in input('authorized_user_list'))
        end
      end
        # /etc/passwd should include the runner account.
      describe 'The password file' do
        it 'should include the nginx account.' do
          expect(command("grep -w #{value} /etc/passwd").stdout).to(match /.*?#{value}.*?/)
        end
      end
    end
  end
end

