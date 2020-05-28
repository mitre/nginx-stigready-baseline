# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')
charset_required = input('charset_required')

control "V-41852" do
  title "The web server must limit the character set used for data entry."
  desc  "Invalid user input occurs when a user inserts data or characters into
a hosted application's data entry field and the hosted application is
unprepared to process that data. This results in unanticipated application
behavior, potentially leading to an application compromise. Invalid user input
is one of the primary methods employed when attempting to compromise an
application.

    An attacker can also enter Unicode into hosted applications in an effort to
break out of the document home or root home directory or to bypass security
checks.

    The web server, by defining the character set available for data entry, can
trap efforts to bypass security checks or to compromise an application.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
what the data set is for data entry.

    If the web server does not limit the data set used for data entry, this is
a finding.
  "
  desc  "fix", "Configure the web server to only accept the character sets
expected by the hosted applications."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000251-WSR-000157"
  tag "gid": "V-41852"
  tag "rid": "SV-54429r3_rule"
  tag "stig_id": "SRG-APP-000251-WSR-000157"
  tag "fix_id": "F-47311r2_fix"
  tag "cci": ["CCI-001310"]
  tag "nist": ["SI-10", "Rev_4"]

  
  # Check:
    # grep 'charset' in the nginx configuration
      # Compare the charset set with the charsets expected and if they do not match, this is a finding.
  # Fix:
    # In the nginx configuration file, set charset to the character sets the application expects.


  #  charset - Context:	http, server, location
  Array(nginx_conf(conf_path).params['http']).each do |http|
    # Within http
    describe 'charset' do
      it 'should be set if found in the http context.' do
        Array(http["charset"]).each do |tokens|
          expect(tokens).to(cmp charset_required)
        end
      end
    end
    # Within server
    describe 'charset' do
      it 'should be set if found in the server context.' do
        Array(nginx_conf(conf_path).servers).each do |server|
          Array(server.params["charset"]).each do |charset|       
            expect(charset).to(cmp charset_required)
          end 
        end
      end
    end
    # Within location
    describe 'charset' do
      it 'should be set if found in the location context.' do
        Array(nginx_conf(conf_path).locations).each do |location|
          Array(location.params["charset"]).each do |charset|       
            expect(charset).to(cmp charset_required)
          end 
        end
      end
    end
  end
end

