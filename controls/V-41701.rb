control 'V-41701' do
  title "The NGINX web server must have resource mappings set to disable the serving
  of certain file types."
  desc "Resource mapping is the process of tying a particular file type to a
  process in the web server that can serve that type of file to a requesting
  client and to identify which file types are not to be delivered to a client.

    By not specifying which files can and which files cannot be served to a
  user, the web server could deliver to a user web server configuration files,
  log files, password files, etc.

    The web server must only allow hosted application file types to be served
  to a user and all other types must be disabled.
  "

  desc 'check', "Review the web server documentation and deployment configuration to
  determine what types of files are being used for the hosted applications.

  Enter the following command to find the mime.types file:
    # find / mime.types

  Review the 'mime.types' file.

  If there are any MIME types enabled for .exe, .dll, .com, .bat, and
  .csh programs, this is a finding.

  "
  desc 'fix', "Configure the web server to disable all MIME types that invoke
  OS shell programs. Edit the 'mime.types' file and disable MIME types for .exe,
  .dll, .com, .bat, and .csh programs."
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000141-WSR-000083'
  tag "gid": 'V-41701'
  tag "rid": 'SV-54278r3_rule'
  tag "stig_id": 'SRG-APP-000141-WSR-000083'
  tag "fix_id": 'F-47160r2_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']

  # Checks for enabled mime types against the disallowed list
  if input('nginx_disallowed_mime_type').empty?
    describe 'This check is skipped because the disallowed mime list should not be empty.' do
      skip 'This check is skipped because the disallowed mime list should not be empty.'
    end
  else
    input('nginx_disallowed_mime_type').each do |mime_type|
      describe "The MIME type: #{mime_type}" do
        it 'should not be enabled in the configuration' do
          expect(command("grep -w #{mime_type} " + input('mime_type_path')).stdout).to(eq '')
        end
      end
    end
  end
end
