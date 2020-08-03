# encoding: UTF-8

control "V-41609" do
  title "The NGINX web server must capture, record, and log all content related to a
  user session."
  desc  "A user session to a web server is in the context of a user accessing a
  hosted application that extends to any plug-ins/modules and services that may
  execute on behalf of the user.

    The web server must be capable of enabling a setting for troubleshooting,
  debugging, or forensic gathering purposes which will log all user session
  information related to the hosted application session. Without the capability
  to capture, record, and log all content related to a user session,
  investigations into suspicious user activity would be hampered.
  "
  desc  "check", "
  Review the NGINX web server documentation and deployed configuration to determine 
  if the NGINX web server captures and logs all content related to a user session.

  Check for the following:
    #grep the 'log_format' directive in the http context of the nginx.conf. 
  
  If the the 'log_format' directive does not exist or does not include the '$remote_user' variable, this is a finding.
  "
  desc  "fix", "Configure the 'log_format' directive in the http context of the nginx.conf to include the '$remote_user' 
  variable to capture and log all content related to a user session."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000093-WSR-000053"
  tag "gid": "V-41609"
  tag "rid": "SV-54186r3_rule"
  tag "stig_id": "SRG-APP-000093-WSR-000053"
  tag "fix_id": "F-47068r2_fix"
  tag "cci": ["CCI-001462"]
  tag "nist": ["AU-14 (2)", "Rev_4"]

  # log_format - Context:	http
  if nginx_conf.params['http'].nil?
    impact 0.0
    describe 'This check is NA because no websites have been configured.' do
      skip 'This check is NA because no websites have been configured.'
    end
  else
    nginx_conf.params['http'].each do |http|
      http["log_format"].each do |log_format|
        describe 'remote_user' do
          it 'should be part of every log format in the http context.' do
            expect(log_format.to_s).to(match /.*?\$remote_user.*?/)
          end
        end
      end
    end 
  end 
end

