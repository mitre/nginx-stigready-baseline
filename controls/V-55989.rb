# encoding: UTF-8
conf_path = input('conf_path')

control "V-55989" do
  title "The NGINX web server must not perform user management for hosted
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
  Review the NGINX web server documentation and configuration to determine if the
  web server is being used as a user management application.

  Check for the following:
  # grep 'auth_basic' and 'auth_basic_user_file' directive in the http, server, 
  and location context of the nginx.conf and any separated include configuration file.

  If the 'auth_basic' and 'auth_basic_user_file' directives exist, this is a finding.
  "
  desc  "fix", "Remove the 'auth_basic' and 'auth_basic_user_file' directives from the 
  http, server, and location contexts of the NGINX configuration file(s)."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000015"
  tag "gid": "V-55989"
  tag "rid": "SV-70243r2_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000015"
  tag "fix_id": "F-60867r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

  nginx_conf_handle = nginx_conf(conf_path)

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  # auth_basic - Context:	http, server, location, limit_except
  # auth_basic_user_file - Context:	http, server, location, limit_except
  # Within http
  Array(nginx_conf_handle.params['http']).each do |http|
    describe 'http context:' do
      it 'There should not be an auth_basic directive.' do
        expect(http).to_not(include "auth_basic")
      end
      it 'There should not be an auth_basic_user_file directive.' do
        expect(http).to_not(include "auth_basic_user_file")
      end
    end
  end
  # Within server
  Array(nginx_conf_handle.servers).each do |server| 
    describe 'server context:' do
      it 'There should not be an auth_basic directive.' do
        expect(server.params).to_not(include "auth_basic")
      end
      it 'There should not be an auth_basic_user_file directive.' do
        expect(server.params).to_not(include "auth_basic_user_file")
      end
    end
  end
  # Within location
  Array(nginx_conf_handle.locations).each do |location|
    describe "location context:" do
      it 'There should not be an auth_basic directive.' do
        expect(location.params).to_not(include "auth_basic")
      end
      it 'There should not be an auth_basic_user_file directive.' do
        expect(location.params).to_not(include "auth_basic_user_file")
      end
      Array(location.params["limit_except"]).each do |limit_except|
        # Within limit_except
        describe "limit_except context:" do
          it 'There should not be an auth_basic directive.' do
            expect(limit_except).to_not(include "auth_basic")
          end
          it 'There should not be an auth_basic_user_file directive.' do
            expect(location.params).to_not(include "auth_basic_user_file")
          end
        end
      end
    end
  end
end

