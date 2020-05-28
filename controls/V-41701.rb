# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41701" do
  title "The web server must have resource mappings set to disable the serving
of certain file types."
  desc  "Resource mapping is the process of tying a particular file type to a
process in the web server that can serve that type of file to a requesting
client and to identify which file types are not to be delivered to a client.

    By not specifying which files can and which files cannot be served to a
user, the web server could deliver to a user web server configuration files,
log files, password files, etc.

    The web server must only allow hosted application file types to be served
to a user and all other types must be disabled.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployment configuration to
determine what types of files are being used for the hosted applications.

    If the web server is configured to allow other file types not associated
with the hosted application, especially those associated with logs,
configuration files, passwords, etc., this is a finding.
  "
  desc  "fix", "Configure the web server to only serve file types to the user
that are needed by the hosted applications.  All other file types must be
disabled."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000083"
  tag "gid": "V-41701"
  tag "rid": "SV-54278r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000083"
  tag "fix_id": "F-47160r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
# https://www.stigviewer.com/stig/apache_server_2.4_unix_server/2019-12-19/finding/V-92653
# Need to verify if this check is sufficient enough
# May need to add more file types

  # Within location
  describe 'The location context' do
    it 'should not serve these file types' do
      Array(nginx_conf(conf_path).locations).each do |location|
        Array(location.params["_"]).each do |dir|     
          expect(dir).to_not(match /log|conf|bak|passwd|shadow/)
        end 
      end
    end
  end
end

