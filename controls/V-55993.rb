# encoding: UTF-8
nginx_owner = input('nginx_owner')
nginx_group = input('nginx_group')
sys_admin = input('sys_admin')
sys_admin_group = input('sys_admin_group')


control "V-55993" do
  title "Anonymous user access to the NGINX web server application directories must
be prohibited."
  desc  "In order to properly monitor the changes to the web server and the
hosted applications, logging must be enabled. Along with logging being enabled,
each record must properly contain the changes made and the names of those who
made the changes.

    Allowing anonymous users the capability to change the web server or the
hosted application will not generate proper log information that can then be
used for forensic reporting in the case of a security issue. Allowing anonymous
users to make changes will also grant change capabilities to anybody without
forcing a user to authenticate before the changes can be made.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the NGINX web server documentation and configuration to determine if
anonymous users can make changes to the web server or any applications hosted
by the web server.

    If anonymous users can make changes, this is a finding.
  "
  desc  "fix", "Configure the web server to not allow anonymous users to change
the web server or any hosted applications."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000211-WSR-000031"
  tag "gid": "V-55993"
  tag "rid": "SV-70247r2_rule"
  tag "stig_id": "SRG-APP-000211-WSR-000031"
  tag "fix_id": "F-60871r1_fix"
  tag "cci": ["CCI-001082"]
  tag "nist": ["SC-2", "Rev_4"]

  authorized_sa_user_list = sys_admin.clone << nginx_owner
  
  describe "Unauthorized users" do
    it "should not have shell access." do
      expect(users.shells(/bash/).usernames).to(be_in authorized_sa_user_list)
    end
  end

  if users.shells(/bash/).usernames.empty?
    describe "Skip Message" do
      skip "Skipped: no users found with shell acccess."
    end
  end
end

