# encoding: UTF-8
conf_path = input('conf_path')
nginx_allowed_script_list = input('nginx_allowed_script_list')

control "V-41700" do
  title "The web server must allow the mappings to unused and vulnerable
scripts to be removed."
  desc  "Scripts allow server side processing on behalf of the hosted
application user or as processes needed in the implementation of hosted
applications. Removing scripts not needed for application operation or deemed
vulnerable helps to secure the web server.

    To assure scripts are not added to the web server and run maliciously,
those script mappings that are not needed or used by the web server for hosted
application operation must be removed.
  "
  desc  "rationale", ""
  desc  "check", "
  Review the web server documentation and deployment configuration to
  determine what script mappings are available.

  Review the scripts used by the web server and the hosted applications.

  Check the following:
    # grep 'fastcgi_param' directive in the location context of the nginx.conf 
    and any separated include configuration file.
  
  Review the 'fastcgi_param' directive and go into each directory to locate 
  cgi-bin scripts with the following command:
    # ls <fastcgi_param directory>
  
  If the 'fastcgi_param' directive exists and if there are any scripts are 
  present that are unused or vulnerable, this is a finding.
  
  If this is not documented and approved by the Information System Security 
  Officer (ISSO), this is a finding.
  "
  desc  "fix", "Review script mappings that are configured in the 'fastcgi_param' 
  directive, if it exists, and remove scripts that are not needed for the NGINX web 
  server and hosted application operation."
  
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000082"
  tag "gid": "V-41700"
  tag "rid": "SV-54277r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000082"
  tag "fix_id": "F-47159r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

  nginx_conf_handle = nginx_conf(conf_path)

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  Array(nginx_conf_handle.locations).each do |location|
    Array(location.params["fastcgi_params"]).each do |value|
      if (value[0] == "SCRIPT_FILENAME")
        cgi_script_path = command("echo #{value[1]} | cut -d '$' -f 1").stdout
        cgi_scripts = command("ls #{cgi_script_path}").stdout.split("\n")
        cgi_scripts.uniq!

        cgi_scripts.each do |script|
          describe (script) do
           it { should be_in nginx_allowed_script_list }
          end
        end
      end 
    end
  end
end
