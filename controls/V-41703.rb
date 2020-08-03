# encoding: UTF-8

control "V-41703" do
  title "The web server must protect system resources and privileged operations
  from hosted applications."
  desc  "A web server may host one too many applications.  Each application
  will need certain system resources and privileged operations to operate
  correctly.  The web server must be configured to contain and control the
  applications and protect the system resources and privileged operations from
  those not needed by the application for operation.

    Limiting the application will confine the potential harm a compromised
  application could cause to a system.
  "
  
  desc  "check", "Interview the System Administrator for the NGINX web server 
  or review the NGINX web server documentation and configuration to determine 
  the access to server resources given to hosted applications.

  Verify that the user that runs the NGINX web server is an authorized user:
  #grep the 'user' directive in the main context of the nginx.conf file

  If the user specified in the configuration file is not an authorized user,
  this is a finding. 

  Verify the permissions of the following files and directories:
    - /usr/sbin/nginx    <'authorized user'>:<'authorized group'> 550/550
    - /etc/nginx/        <'authorized user'>:<'authorized group'> 770/660
    - /etc/nginx/conf.d  <'authorized user'>:<'authorized group'> 770/660
    - /etc/nginx/modules <'authorized user'>:<'authorized group'> 770/660

  If the files and directories are not set to the following permissions or more
  restrictive, this is a finding.
  NOTE:  The permissions are noted as directories / files"
  desc  "fix", "Set the 'user' directive in the nginx.conf file to an authorized
  user. 

  Use the chmod  and chown commands to set permissions/ownership of the web server
  system directories and files as follows: 

  - /usr/sbin/nginx    <'authorized user'>:<'authorized group'> 550/550
  - /etc/nginx/        <'authorized user'>:<'authorized group'> 770/660
  - /etc/nginx/conf.d  <'authorized user'>:<'authorized group'> 770/660
  - /etc/nginx/modules <'authorized user'>:<'authorized group'> 770/660
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000086"
  tag "gid": "V-41703"
  tag "rid": "SV-54280r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000086"
  tag "fix_id": "F-47162r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

  describe "This test requires a Manual Review: Interview the SA to determine the 
  access to server resources given to hosted applications." do
    skip "This test requires a Manual Review: Interview the SA to determine the 
    access to server resources given to hosted applications."
  end

  if nginx_conf.params['user'].nil?
    impact 0.0
    describe 'This check is NA because the user directive is not configured properly.' do
      skip 'This check is NA because the user directive is not configured properly.'
    end
  else
    nginx_conf.params['user'].each do |user|
      user.each do |value|
        describe 'The value of user' do
          it 'should be the default nginx user or other authorized user.' do
            expect(value).to (eq input('nginx_owner')).or (be_in input('authorized_user_list'))
          end
        end
      end
    end
    describe file('/usr/sbin/nginx') do
      its('owner') { should be_in input('sys_admin').clone << input('nginx_owner') }
      its('group') { should be_in input('sys_admin_group').clone << input('nginx_group') }
      it { should_not be_more_permissive_than('0550') }
    end
    describe file('/etc/nginx/') do
      its('owner') { should be_in input('sys_admin').clone << input('nginx_owner') }
      its('group') { should be_in input('sys_admin_group').clone << input('nginx_group') }
      it { should_not be_more_permissive_than('0770') }
    end 
    describe file('/etc/nginx/conf.d') do
      its('owner') { should be_in input('sys_admin').clone << input('nginx_owner') }
      its('group') { should be_in input('sys_admin_group').clone << input('nginx_group') }
      it { should_not be_more_permissive_than('0770') }
    end
    describe file('/etc/nginx/modules') do
      its('owner') { should be_in input('sys_admin').clone << input('nginx_owner') }
      its('group') { should be_in input('sys_admin_group').clone << input('nginx_group') }
      it { should_not be_more_permissive_than('0770') }
    end
  end
end

