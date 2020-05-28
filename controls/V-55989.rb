# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-55989" do
  title "The web server must not perform user management for hosted
applications."
  desc  "User management and authentication can be an essential part of any
application hosted by the web server. Along with authenticating users, the user
management function must perform several other tasks like password complexity,
locking users after a configurable number of failed logins, and management of
temporary and emergency accounts; and all of this must be done enterprise-wide.

    The web server contains a minimal user management function, but the web
server user management function does not offer enterprise-wide user management,
and user management is not the primary function of the web server. User
management for the hosted applications should be done through a facility that
is built for enterprise-wide user management, like LDAP and Active Directory.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and configuration to determine if the
web server is being used as a user management application.

    If the web server is being used to perform user management for the hosted
applications, this is a finding.
  "
  desc  "fix", "Configure the web server to disable user management
functionality."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000015"
  tag "gid": "V-55989"
  tag "rid": "SV-70243r2_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000015"
  tag "fix_id": "F-60867r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

    # auth_basic - Context:	http, server, location, limit_except
  # ssl_verify_client - Context:	http, server
  # ssl_client_certificate - Context:	http, server
  describe file(conf_path) do
    it 'The config file should exist and be a file.' do
      expect(subject).to(exist)
      expect(subject).to(be_file)
    end
  end
  if (File.exist?(conf_path))
    # Within http
    Array(nginx_conf(conf_path).params['http']).each do |http|
      describe 'http context:' do
        it 'There should not be an auth_basic directive.' do
          expect(http).to_not(include "auth_basic")
        end
        it 'There should not be an ssl_verify_client directive with the value of on.' do
          Array(http["ssl_verify_client"]).each do |client|
            expect(client).to_not(cmp "on")
          end
        end
        it 'There should not be an ssl_client_certificate directive.' do
          expect(http).to_not(include "ssl_client_certificate")
        end
      end
    end
    # Within server
    Array(nginx_conf(conf_path).servers).each do |server| # solid gold
      describe 'server context:' do
        it 'There should not be an auth_basic directive.' do
          expect(server.params).to_not(include "auth_basic")
        end
        it 'There should not be an ssl_verify_client directive with the value of on.' do
          Array(server.params["ssl_verify_client"]).each do |client|
            expect(client).to_not(cmp "on")
          end
        end
        it 'There should not be an ssl_client_certificate directive.' do
          expect(server.params).to_not(include "ssl_client_certificate")
        end
      end
    end
    # Within location
    Array(nginx_conf(conf_path).locations).each do |location|
      describe "location context:" do
        it 'There should not be an auth_basic directive.' do
          expect(location.params).to_not(include "auth_basic")
        end
        Array(location.params["limit_except"]).each do |limit_except|
          # Within limit_except
          describe "limit_except context:" do
            it 'There should not be an auth_basic directive.' do
              expect(limit_except).to_not(include)
            end
          end
        end
      end
    end
  end
end

