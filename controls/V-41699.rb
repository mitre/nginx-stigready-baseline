control 'V-41699' do
  title "The NGINX web server must have Multipurpose Internet Mail Extensions (MIME)
  that invoke OS shell programs disabled."
  desc "Controlling what a user of a hosted application can access is part of
  the security posture of the web server. Any time a user can access more
  functionality than is needed for the operation of the hosted application poses
  a security issue. A user with too much access can view information that is not
  needed for the user's job role, or the user could use the function in an
  unintentional manner.

    A MIME tells the web server what type of program various file types and
  extensions are and what external utilities or programs are needed to execute
  the file type.

    A shell is a program that serves as the basic interface between the user
  and the operating system, so hosted application users must not have access to
  these programs. Shell programs may execute shell escapes and can then perform
  unauthorized activities that could damage the security posture of the web
  server.
  "

  desc 'check', "Review the web server documentation and deployment configuration to
  determine if the OS shell is accessible by any MIME types that are enabled.

  Enter the following command to find the mime.types file:
  # find / mime.types

  Review the 'mime.types' file.

  If there are any MIME types enabled for  .exe, .dll, .com, .bat, and .csh
  programs, this is a finding.
  "
  desc  'fix', "Edit the 'mime.types' file and disable all MIME types for .exe,
  .dll, .com, .bat, and .csh programs.
  "

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000141-WSR-000081'
  tag "gid": 'V-41699'
  tag "rid": 'SV-54276r3_rule'
  tag "stig_id": 'SRG-APP-000141-WSR-000081'
  tag "fix_id": 'F-47158r2_fix'
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
