# encoding: UTF-8

control "V-56013" do
  title "The web server must maintain the confidentiality and integrity of
  information during preparation for transmission."
  desc  "Information can be either unintentionally or maliciously disclosed or
  modified during preparation for transmission, including, for example, during
  aggregation, at protocol transformation points, and during packing/unpacking.
  These unauthorized disclosures or modifications compromise the confidentiality
  or integrity of the information.

    An example of this would be an SMTP queue. This queue may be added to a web
  server through an SMTP module to enhance error reporting or to allow developers
  to add SMTP functionality to their applications.

    Any modules used by the web server that queue data before transmission must
  maintain the confidentiality and integrity of the information before the data
  is transmitted.
  "
  
  desc  "check", "Review the web server documentation and deployed configuration 
  to determine if the web server maintains the confidentiality and integrity of 
  information during preparation before transmission.

  If NGINX is not configured to serve files, this check is Not Applicable.

  Check for the following:
  #grep the 'ssl_protocols' directive in the server context of the nginx.conf 
  and any separated include configuration file.

  If the 'ssl_protocols' directive cannot be found in NGINX configuration files, 
  this check is Not Applicable.

  If the 'ssl_protocols' directive is not set to the approved TLS version, 
  this is a finding. 
  "
  desc  "fix", "Add the 'ssl_protocols' directive to the NGINX configuration 
  file(s) and configure it to use the approved TLS protocols to maintain the 
  confidentiality and integrity of information during preparation for transmission. 

  Example:
    server {
            ssl_protocols TLSv1.2;
    }"
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000441-WSR-000181"
  tag "gid": "V-56013"
  tag "rid": "SV-70267r2_rule"
  tag "stig_id": "SRG-APP-000441-WSR-000181"
  tag "fix_id": "F-60891r1_fix"
  tag "cci": ["CCI-002420"]
  tag "nist": ["SC-8 (2)", "Rev_4"]

  if nginx_conf.servers.nil?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.servers.each do |server|
      if server.params["ssl_protocols"].nil?
        impact 0.0 
        describe 'This test is NA because the ssl_protocols directive has not been configured.' do
          skip 'This test is NA because the ssl_protocols directive has not been configured.'
        end
      else
        server.params["ssl_protocols"].each do |protocol|
          describe 'Each protocol' do
            it 'should be included in the list of protocols approved to encrypt data' do
              expect(protocol).to(be_in input('approved_ssl_protocols'))
            end
          end
        end
      end
    end
  end
end

