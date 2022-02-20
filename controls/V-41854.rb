control 'V-41854' do
  title "Warning and error messages displayed to clients must be modified to
minimize the identity of the NGINX web server, patches, loaded modules, and directory
paths."
  desc  "Information needed by an attacker to begin looking for possible
vulnerabilities in a web server includes any information about the web server,
backend systems being accessed, and plug-ins or modules being used.

    Web servers will often display error messages to client users displaying
enough information to aid in the debugging of the error. The information given
back in error messages may display the web server type, version, patches
installed, plug-ins and modules installed, type of code being used by the
hosted application, and any backends being used for data storage.

    This information could be used by an attacker to blueprint what type of
attacks might be successful. The information given to users must be minimized
to not aid in the blueprinting of the web server.
  "

  desc 'check', "Review the NGINX web server documentation and deployed configuration
  to determine whether the web server offers different modes of operation that will minimize
  the identity of the web server, patches, loaded modules, and directory paths
  given to clients on error conditions.

  If there are no websites configured or if NGINX is not configured to serve files,
  this check is Not Applicable.

  Check for the following:
      # grep the 'server_tokens' directive in the http, server, and location context
      of the nginx.conf and any separated include configuration file.

  The default value for the 'server_tokens' directive is set to 'on'. If the 'server_tokens'
  directive does not exist or is not set to 'off', this is a finding
  "
  desc 'fix', "Configure the NGINX web server to include the 'server_tokens' directive
  and set to 'off' in the NGINX configuration file(s) to mask server details and minimize
  the information provided to the client in warning and error messages."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000266-WSR-000159'
  tag "gid": 'V-41854'
  tag "rid": 'SV-54431r3_rule'
  tag "stig_id": 'SRG-APP-000266-WSR-000159'
  tag "fix_id": 'F-47313r2_fix'
  tag "cci": ['CCI-001312']
  tag "nist": ['SI-11 a', '']

  if nginx_conf.params['http'].nil?
    impact 0.0
    describe 'This check is NA because no websites have been configured.' do
      skip 'This check is NA because no websites have been configured.'
    end
  else
    nginx_conf.params['http'].each do |http|
      describe 'server_tokens directive' do
        it 'should exist and be off in the http context.' do
          expect(http).to(include 'server_tokens')
          expect(http['server_tokens'].join).to(cmp('off'))
        end
      end
    end
  end

  if nginx_conf.servers.nil?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.servers.each do |server|
      describe 'server_tokens' do
        it 'should be off if found in the server context.' do
          expect(server.params['server_tokens'].join).to(cmp('off')) unless server.params['server_tokens'].nil?
        end
      end
    end
  end

  if nginx_conf.locations.nil?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.locations.each do |location|
      describe 'server_tokens' do
        it 'should be off if found in the location context.' do
          expect(location.params['server_tokens'].join).to(cmp('off')) unless location.params['server_tokens'].nil?
        end
      end
    end
  end
end
