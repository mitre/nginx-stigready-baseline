# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-55949" do
  title "The web server must set an inactive timeout for sessions."
  desc  "Leaving sessions open indefinitely is a major security risk. An
attacker can easily use an already authenticated session to access the hosted
application as the previously authenticated user. By closing sessions after a
set period of inactivity, the web server can make certain that those sessions
that are not closed through the user logging out of an application are
eventually closed.

    Acceptable values are 5 minutes for high-value applications, 10 minutes for
medium-value applications, and 20 minutes for low-value applications.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the hosted applications, web server documentation and deployed
configuration to verify that the web server will close an open session after a
configurable time of inactivity.

    If the web server does not close sessions after a configurable time of
inactivity or the amount of time is configured higher than 5 minutes for
high-risk applications, 10 minutes for medium-risk applications, or 20 minutes
for low-risk applications, this is a finding.
  "
  desc  "fix", "Configure the web server to close inactive sessions after 5
minutes for high-risk applications, 10 minutes for medium-risk applications, or
20 minutes for low-risk applications."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000295-WSR-000134"
  tag "gid": "V-55949"
  tag "rid": "SV-70203r2_rule"
  tag "stig_id": "SRG-APP-000295-WSR-000134"
  tag "fix_id": "F-60827r1_fix"
  tag "cci": ["CCI-002361"]
  tag "nist": ["AC-12", "Rev_4"]

  # Check:
    # Verify the "http_upstream_module" is loaded with the following command:

      # nginx -V

    # If the "http_upstream_module" is not loaded, this is a finding.

    # Verify the "keepalive_timeout" directive is configured:
      # grep 'keepalive_timeout' in the nginx.conf and any separated include configuration files

    # If the "http_upstream_module" is loaded and the "keepalive_timeout" directive is not configured, this is a finding.

  # Fix: 
    # Include the the "http_upstream_module".

    # Configure the "keepalive_timeout" directive.

    nginx_conf_handle = nginx_conf(nginx_conf_file)

    describe nginx_conf_handle do
      its ('params') { should_not be_empty }
    end

    nginx_conf_handle.http.entries.each do |http|
      describe http.params['client_header_timeout'] do
        it { should_not be_nil }
      end
      describe http.params['client_header_timeout'].flatten do
        it { should cmp <= 10 }
      end unless http.params['client_header_timeout'].nil?

      describe http.params['client_body_timeout'] do
        it { should_not be_nil }

      end
      describe http.params['client_body_timeout'].flatten do
        it { should cmp <= 10 }
      end unless http.params['client_body_timeout'].nil?
    end

    nginx_conf_handle.servers.entries.each do |server|
      describe server.params['client_header_timeout'].flatten do
        it { should cmp <= 10 }
      end unless server.params['client_header_timeout'].nil?
      describe server.params['client_body_timeout'].flatten do
        it { should cmp <= 10 }
      end unless server.params['client_body_timeout'].nil?
    end


  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil }
    end
  end


  Array(nginx_conf(conf_path).params['http']).each do |http|
    # Within http
    describe 'The HTTP context' do
      it 'should include a keepalive_timeout directive.' do
        expect(http).to(include "keepalive_timeout")
      end
    end
    # Within server
    describe 'The server context' do
      it 'should include a keepalive_timeout directive.' do
        Array(nginx_conf(conf_path).servers).each do |server|
          expect(server).to(include "keepalive_timeout")
        end
      end
    end
    # Within location
    describe 'The location context keep-alive value' do
      it 'should include a keepalive_timeout directive.' do
        Array(nginx_conf(conf_path).locations).each do |location|
          expect(location).to(include "keepalive_timeout")
        end
      end
    end
  end
end

