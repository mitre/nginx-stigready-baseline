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

control "V-55981" do
  title "The web server application, libraries, and configuration files must
only be accessible to privileged users."
  desc  "A web server can be modified through parameter modification, patch
installation, upgrades to the web server or modules, and security parameter
changes. With each of these changes, there is the potential for an adverse
effect such as a DoS, web server instability, or hosted application instability.

    To limit changes to the web server and limit exposure to any adverse
effects from the changes, files such as the web server application files,
libraries, and configuration files must have permissions and ownership set
properly to only allow privileged users access.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and configuration to determine if the
web server provides unique account roles specifically for the purposes of
segmenting the responsibilities for managing the web server.

    Log into the hosting server using a web server role with limited
permissions (e.g., Auditor, Developer, etc.) and verify the account is not able
to perform configuration changes that are not related to that role.

    If roles are not defined with limited permissions and restrictions, this is
a finding.
  "
  desc  "fix", "
    Define roles and responsibilities to be used when managing the web server.

    Configure the hosting system to utilize specific roles that restrict access
related to web server system and configuration changes.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000380-WSR-000072"
  tag "gid": "V-55981"
  tag "rid": "SV-70235r2_rule"
  tag "stig_id": "SRG-APP-000380-WSR-000072"
  tag "fix_id": "F-60859r2_fix"
  tag "cci": ["CCI-001813"]
  tag "nist": ["CM-5 (1)", "Rev_4"]

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

