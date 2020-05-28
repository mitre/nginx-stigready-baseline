# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41854" do
  title "Warning and error messages displayed to clients must be modified to
minimize the identity of the web server, patches, loaded modules, and directory
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
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
whether the web server offers different modes of operation that will minimize
the identity of the web server, patches, loaded modules, and directory paths
given to clients on error conditions.

    If the web server is not configured to minimize the information given to
clients, this is a finding.
  "
  desc  "fix", "Configure the web server to minimize the information provided
to the client in warning and error messages."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000266-WSR-000159"
  tag "gid": "V-41854"
  tag "rid": "SV-54431r3_rule"
  tag "stig_id": "SRG-APP-000266-WSR-000159"
  tag "fix_id": "F-47313r2_fix"
  tag "cci": ["CCI-001312"]
  tag "nist": ["SI-11 a", "Rev_4"]

# Check:
  # grep 'server_tokens' in the nginx configuration
    # If directive is found and not set to 'off', this is a finding
# Fix:
    # Mask server details by setting server_tokens directive to off in the nginx configuration file.

  # server_tokens can exist in http, server, or location
  Array(nginx_conf(conf_path).params['http']).each do |http|
    # Within http
    describe 'server_tokens' do
      it 'should be off if found in the http context.' do
        Array(http["server_tokens"]).each do |tokens|
          expect(tokens).to(cmp 'off')
        end
      end
    end
    # Within server
    describe 'server_tokens' do
      it 'should be off if found in the server context.' do
        Array(nginx_conf(conf_path).servers).each do |server|
          Array(server.params["server_tokens"]).each do |server_token|       
            expect(server_token).to(cmp 'off')
          end 
        end
      end
    end
    # Within location
    describe 'server_tokens' do
      it 'should be off if found in the location context.' do
        Array(nginx_conf(conf_path).locations).each do |location|
          Array(location.params["server_tokens"]).each do |server_token|       
            expect(server_token).to(cmp 'off')
          end 
        end
      end
    end
  end
end

