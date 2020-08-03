# encoding: UTF-8

control "V-41704" do
  title "Users and scripts running on behalf of users must be contained to the
  document root or home directory tree of the NGINX web server."
  desc  "A web server is designed to deliver content and execute scripts or
  applications on the request of a client or user.  Containing user requests to
  files in the directory tree of the hosted web application and limiting the
  execution of scripts and applications guarantees that the user is not accessing
  information protected outside the application's realm.

    The web server must also prohibit users from jumping outside the hosted
  application directory tree through access to the user's home directory,
  symbolic links or shortcuts, or through search paths for missing files.
  "
  
  desc  "check", "Review the NGINX web server documentation and configuration 
  to determine where the document root or home directory for each application 
  hosted by the web server is located.

  Check for the following: 
    # grep for a 'deny' directive in the root directoy location context of the 
    nginx.conf and any separated include configuration file.

  Verify that there is a 'deny all' set in each root directory location context 
  to deny access by default. If a 'deny all' is not set in each location, 
  this is a finding."

  desc  "fix", "Add a 'deny all' in each location context in the NGINX configuration 
  file(s) to contain users and scripts to each hosted application's domain.

  Example configuration: 

  'location / { 
                  deny all; 
  }'"
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000087"
  tag "gid": "V-41704"
  tag "rid": "SV-54281r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000087"
  tag "fix_id": "F-47163r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

  if nginx_conf.locations.nil?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.locations.each do |location|
      location.params["_"].each do |value|
        if (value == '/') 
          deny_values = []
          deny_values.push(location.params['deny']) unless location.params['deny'].nil?
          describe "Each root directory location context" do
            it 'should include an deny all directive.' do
              expect(deny_values.to_s).to(include "all")
            end
          end
        end
      end
    end
  end
end

