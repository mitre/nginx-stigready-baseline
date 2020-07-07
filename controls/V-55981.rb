# encoding: UTF-8

control "V-55981" do
  title "The NGINX web server application, libraries, and configuration files must
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
  
  desc  "check", "Review the NGINX web server documentation and configuration 
  to determine if the web server provides unique account roles specifically for 
  the purposes of segmenting the responsibilities for managing the web server.

  This check verifies that the SA or Web Manager controlled account owns the key 
  web server files. These same files, which control the configuration of the web 
  server, and thus its behavior, must also be accessible by the account that runs 
  the web service process.

  If it exists, the following file need to be owned by a privileged account:
    - .htaccess  
    - .htpasswd 
    - nginx.conf and its included configuration files
    - Application directories
    
  Use the following commands: 
    #  find / -name nginx.conf to find the file.  
    #  grep 'include' on the nginx.conf file to identify included configuration files. 
    
  Change to the directories that contain the nginx.conf and included configuration files. 
  Use the following command:
    #   ls -l on these files to determine ownership of the file
  
  Use the following commands: 
    #  grep 'root' on the nginx.conf file and any separate included configuration files 
    to identify all the document root directories.
    # ls -l on all document root directories found to determine the ownership of directories
   
  -The Web Manager or the SA should own all the system files and directories.
  -The configurable directories can be owned by the WebManager or equivalent user.
      -Permissions on these files should be 660 or more restrictive.
  
  If root or an authorized user does not own the web system files and directories, and the 
  permission are not correct, this is a finding.
  "
  desc  "fix", "Restrict access to the web servers access control files and application 
  directories to only the System Administrator, Web Manager, or the Web Manager designees.

  Determine where the key server files are located by running the following command (per file):
  
    # find / -name <'key server file'>
  
  Run the following commands to set permissions:
   
    # cd <'key server file location'>/
    # chown <'authorized user'>:<'authorized group'>  <'key server file'> 
    # chmod 660 <'key server file'>  
  
  Determine where the application directories are located by running the following command:
  
    # grep 'root' on the nginx.conf file and any separate included configuration files
  
  Run the following command to set permissions:
    # chown <'authorized user'>:<'authorized group'>  <'application directory'> 
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

  authorized_sa_user_list = input('sys_admin').clone << input('nginx_owner')
  authorized_sa_group_list = input('sys_admin_group').clone << input('nginx_group')

  nginx_conf_handle = nginx_conf(input('conf_path'))
  nginx_conf_handle.params
  
  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  input('access_control_files').each do |file|
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
      its('mode') { should cmp '0660'}
      end
    end
  end

  nginx_conf_handle.contents.keys.each do |file|
    describe file(file) do
      its('owner') { should be_in authorized_sa_user_list }
      its('group') { should be_in authorized_sa_group_list }
      its('mode') { should cmp '0660'}
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
end

