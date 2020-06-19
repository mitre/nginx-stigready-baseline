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
  value: 'nginx'
)

sys_admin = input(
  'sys_admin',
  description: "The system adminstrator",
  value: ['root']
)

nginx_group = input(
  'nginx_group',
  description: "The Nginx group",
  value: 'nginx'
)

sys_admin_group = input(
  'sys_admin_group',
  description: "The system adminstrator group",
  value: ['root']
)

control "V-55993" do
  title "Anonymous user access to the web server application directories must
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
    Review the web server documentation and configuration to determine if
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
  authorized_sa_group_list = sys_admin_group.clone << nginx_group
  
  access_control_files = [ '.htaccess',
                          '.htpasswd', 
                          'nginx.conf' ]

  nginx_conf_handle = nginx_conf(conf_path)
  nginx_conf_handle.params
  
  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  access_control_files.each do |file|
    file_path = command("find / -name #{file}").stdout.chomp

    if file_path.empty?
      describe "Skip Message" do
        skip "Skipped: Access control file #{file} not found"
      end
    end

    file_path.split.each do |file|
      describe file(file) do
      its('owner') { should be_in authorized_sa_user_list }
      its('group') { should be_in authorized_sa_group_list }
      it { should_not be_executable }
      it { should_not be_readable.by('others') }
      it { should_not be_writable.by('others') }
      end
    end
  end

  nginx_conf_handle.contents.keys.each do |file|
    describe file(file) do
      its('owner') { should be_in authorized_sa_user_list }
      its('group') { should be_in authorized_sa_group_list }
      it { should_not be_executable }
      it { should_not be_readable.by('others') }
      it { should_not be_writable.by('others') }
    end
  end

  if nginx_conf_handle.contents.keys.empty?
    describe "Skip Message" do
      skip "Skipped: no conf files included."
    end
  end

  webserver_roots = []

  nginx_conf_handle.http.entries.each do |http|
    webserver_roots.push(http.params['root']) unless http.params['root'].nil?
  end

  nginx_conf_handle.servers.entries.each do |server|
    webserver_roots.push(server.params['root']) unless server.params['root'].nil?
  end

  nginx_conf_handle.locations.entries.each do |location|
    webserver_roots.push(location.params['root']) unless location.params['root'].nil?
  end

  webserver_roots.flatten!
  webserver_roots.uniq!

  webserver_roots.each do |directory|
    describe file(directory) do
      its('owner') { should be_in authorized_sa_user_list }
      its('group') { should be_in authorized_sa_group_list }
      its('sticky'){ should be true }
    end
  end

  if webserver_roots.empty?
    describe "Skip Message" do
      skip "Skipped: no web root directories found."
    end
  end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil }
    end
end

