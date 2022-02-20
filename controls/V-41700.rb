control 'V-41700' do
  title "The web server must allow the mappings to unused and vulnerable
  scripts to be removed."
  desc "Scripts allow server side processing on behalf of the hosted
  application user or as processes needed in the implementation of hosted
  applications. Removing scripts not needed for application operation or deemed
  vulnerable helps to secure the web server.

    To assure scripts are not added to the web server and run maliciously,
  those script mappings that are not needed or used by the web server for hosted
  application operation must be removed.
  "

  desc 'check', "
  Review the web server documentation and deployment configuration to
  determine what script mappings are available.

  Review the scripts used by the web server and the hosted applications.

  If NGINX is not configured to serve files, this check is Not Applicable.

  Check the following:
    # grep 'fastcgi_param' directive in the location context of the nginx.conf
    and any separated include configuration file.

  If the 'fastcgi_param' directive cannot be found in NGINX configuration files,
  this check is Not Applicable.

  Review the 'fastcgi_param' directive and go into each directory to locate
  cgi-bin scripts with the following command:
    # ls <fastcgi_param directory>

  If the 'fastcgi_params' directive exists and if there are any scripts are
  present that are unused or vulnerable, this is a finding.

  If this is not documented and approved by the Information System Security
  Officer (ISSO), this is a finding.
  "
  desc 'fix', "Review script mappings that are configured in the 'fastcgi_param'
  directive, if it exists, and remove scripts that are not needed for the NGINX web
  server and hosted application operation."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000141-WSR-000082'
  tag "gid": 'V-41700'
  tag "rid": 'SV-54277r3_rule'
  tag "stig_id": 'SRG-APP-000141-WSR-000082'
  tag "fix_id": 'F-47159r2_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', '']

  if nginx_conf.locations.nil?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.locations.each do |location|
      if location.params['fastcgi_param'].nil?
        impact 0.0
        describe 'This check is NA because the fastcgi_param directive has not been configured.' do
          skip 'This check is NA because the fastcgi_param directive has not been configured.'
        end
      else
        location.params['fastcgi_param'].each do |value|
          next unless value[0] == 'SCRIPT_FILENAME'

          cgi_script_path = command("echo #{value[1]} | cut -d '$' -f 1").stdout
          cgi_scripts = command("ls #{cgi_script_path}").stdout.split("\n")
          cgi_scripts.uniq!

          cgi_scripts.each do |script|
            describe(script) do
              it { should be_in input('nginx_allowed_script_list') }
            end
          end
        end
      end
    end
  end
end
