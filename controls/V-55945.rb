# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-55945" do
  title "The NGINX web server must enforce approved authorizations for logical access
to hosted applications and resources in accordance with applicable access
control policies."
  desc  "To control access to sensitive information and hosted applications by
entities that have been issued certificates by DoD-approved PKIs, the web
server must be properly configured to incorporate a means of authorization that
does not simply rely on the possession of a valid certificate for access.
Access decisions must include a verification that the authenticated entity is
permitted to access the information or application. Authorization decisions
must leverage a variety of methods, such as mapping the validated PKI
certificate to an account with an associated set of permissions on the system.
If the web server relied only on the possession of the certificate and did not
map to system roles and privileges, each user would have the same abilities and
roles to make changes to the production system."
  desc  "rationale", ""
  desc  "check", "
  The NGINX web server must be configured to perform an authorization check to
  verify that the authenticated entity should be granted access to the requested
  content.

  Check for the following:
    #grep the 'auth_request' directive in the location context of the nginx.conf 
    and any separated include configuration file.      

  If the 'auth_request' directive does not exist inside the location context, 
  this is a finding.
  "
  desc  "fix", "Configure server to use the 'auth_request' directive in the 
  NGINX configuration file(s) to implement client authorization."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000033-WSR-000169"
  tag "gid": "V-55945"
  tag "rid": "SV-70199r2_rule"
  tag "stig_id": "SRG-APP-000033-WSR-000169"
  tag "fix_id": "F-60823r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]


  auth_uris = []
  nginx_conf_handle = nginx_conf(conf_path)

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  nginx_conf_handle.locations.entries.each do |location|
    auth_uris.push(location.params['auth_request']) unless location.params['auth_request'].nil?
  end
  auth_uris.flatten!
  auth_uris.uniq!

  Array(nginx_conf_handle.locations).each do |location|
    location.params["_"].each do |value|
      deny_values = []
      deny_values.push(location.params['deny'])
      describe "Each root directory location context" do
        it 'should include an deny all directive.' do
          expect(deny_values.to_s).to(include "all")
        end
      end unless auth_uris.include?(value) 
    end
  end
end
