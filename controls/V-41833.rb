# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41833" do
  title "The web server must restrict the ability of users to launch Denial of
Service (DoS) attacks against other information systems or networks."
  desc  "A web server can limit the ability of the web server being used in a
DoS attack through several methods. The methods employed will depend upon the
hosted applications and their resource needs for proper operation.

    An example setting that could be used to limit the ability of the web
server being used in a DoS attack is bandwidth throttling.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
whether the web server has been configured to limit the ability of the web
server to be used in a DoS attack.

    If not, this is a finding.
  "
  desc  "fix", "Configure the web server to limit the ability of users to use
the web server in a DoS attack."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000246-WSR-000149"
  tag "gid": "V-41833"
  tag "rid": "SV-54410r3_rule"
  tag "stig_id": "SRG-APP-000246-WSR-000149"
  tag "fix_id": "F-47292r2_fix"
  tag "cci": ["CCI-001094"]
  tag "nist": ["SC-5 (1)", "Rev_4"]
  # Check:
    # grep 'server_tokens' in the nginx configuration
      # If directive is found and not set to 'off', this is a finding
    # grep 'limit_conn_zone', 'limit_conn', and 'limit_rate'
      # If directives are not found, this is a finding.
  # Fix:
    # Mask server details setting server_tokens to off in the nginx configuration file.
    # Set a limit on bandwith and number of connections allowed in the nginx configuration file.

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
  
# limit_conn_zone - Context:	http
  Array(nginx_conf(conf_path).params['http']).each do |http|
    describe 'The HTTP context' do
      it 'should include a limit_conn_zone.' do
        expect(http).to(include "limit_conn_zone")
      end
    end
    Array(http["limit_conn_zone"]).each do |limit_conn_zone|
      describe 'The limit_conn_zone' do
        it 'should include a client address.' do
          expect(limit_conn_zone.to_s).to(include "$binary_remote_addr")
        end
      end
      describe 'The limit_conn_zone' do
        it 'should include a zone.' do
          expect(limit_conn_zone.to_s).to(include "zone=")
        end
      end
      Array(limit_conn_zone).each do |value|
        if value.start_with?("zone")
          zone = value.split(":").last
          describe 'The zone in limit_conn_zone' do
            it 'should match this regex: .*?[0-9]{1,3}.*?' do
              expect(zone).to(match /.*?[0-9]{1,3}.*?/)
            end
          end
        end
      end
    end
  end

# limit_conn - Context:	http, server, location
# limit_rate - Context: location
  Array(nginx_conf(conf_path).locations).each do |location|
    describe 'Each location context' do
      it 'should include a limit_conn directive.' do
        expect(location.params).to(include "limit_conn")
      end
    end
    Array(location.params["limit_conn"]).each do |limit_conn|
      Array(limit_conn).each do |value|
        describe 'The limit_conn setting' do
          it 'should match this regex: [a-zA-Z0-9]' do
            expect(value).to(match /^[0-9a-zA-Z]*$/)          
          end
        end
      end
    end
    describe 'Each location context' do
      it 'should include a limit_rate directive.' do
        expect(location.params).to(include "limit_rate")
      end
    end
    Array(location.params["limit_rate"]).each do |limit_rate|
      Array(limit_rate).each do |value|
        describe 'The limit_rate setting' do
          it 'should match this regex: [a-zA-Z0-9]' do
            expect(value).to(match /^[0-9a-zA-Z]*$/)          
          end
        end
      end
    end
  end
end

