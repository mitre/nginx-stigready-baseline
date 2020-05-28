# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-40791" do
  title "The web server must limit the number of allowed simultaneous session
requests."
  desc  "Web server management includes the ability to control the number of
users and user sessions that utilize a web server. Limiting the number of
allowed users and sessions per user is helpful in limiting risks related to
several types of Denial of Service attacks.

    Although there is some latitude concerning the settings themselves, the
settings should follow DoD-recommended values, but the settings should be
configurable to allow for future DoD direction. While the DoD will specify
recommended values, the values can be adjusted to accommodate the operational
requirement of a given system.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and configuration to determine if the
number of simultaneous sessions is limited.

    If the parameter is not configured or is unlimited, this is a finding.
  "
  desc  "fix", "Configure the web server to limit the number of concurrent
sessions."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000001-WSR-000001"
  tag "gid": "V-40791"
  tag "rid": "SV-53018r3_rule"
  tag "stig_id": "SRG-APP-000001-WSR-000001"
  tag "fix_id": "F-45918r3_fix"
  tag "cci": ["CCI-000054"]
  tag "nist": ["AC-10", "Rev_4"]

  
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
  end
end

