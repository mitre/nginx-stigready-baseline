# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41698" do
  title "The web server must provide install options to exclude installation of
utility programs, services, plug-ins, and modules not necessary for operation."
  desc  "Just as running unneeded services and protocols is a danger to the web
server at the lower levels of the OSI model, running unneeded utilities and
programs is also a danger at the application layer of the OSI model. Office
suites, development tools, and graphical editors are examples of such programs
that are troublesome.

    Individual productivity tools have no legitimate place or use on an
enterprise, production web server and they are also prone to their own security
risks. The web server installation process must provide options allowing the
installer to choose which utility programs, services, and modules are to be
installed or removed. By having a process for installation and removal, the web
server is guaranteed to be in a more stable and secure state than if these
services and programs were installed and removed manually.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployment configuration to
determine which web server utilities, services, and modules are installed.
Verify these options are essential to the operation of the web server. Also,
confirm the web server install process offers an option to exclude these
utilities, services, and modules from installation that are not needed for
operation and that there is an uninstall option for their removal.

    If there are more utilities, services, or modules installed than are needed
for the operation of the web server or the web server does not provide an
install facility to customize installation, this is a finding.
  "
  desc  "fix", "Use the web server uninstall facility or manually remove any
utility programs, services, or modules not needed by the web server for
operation."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000080"
  tag "gid": "V-41698"
  tag "rid": "SV-54275r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000080"
  tag "fix_id": "F-47157r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

# Check for current modules against the approved list
# nginx includes the switch "--without-select_module"
 
  nginx_authorized_modules= input(
    'nginx_authorized_modules',
    description: 'List of  authorized nginx modules.',
    value: [
              "http_addition",
              "http_auth_request",
              "http_dav",
              "http_flv",
              "http_gunzip",
              "http_gzip_static",
              "http_mp4",
              "http_random_index",
              "http_realip",
              "http_secure_link",
              "http_slice",
              "http_ssl",
              "http_stub_status",
              "http_sub",
              "http_v2",
              "mail_ssl",
              "stream_realip",
              "stream_ssl",
              "stream_ssl_preread"
             ]
  )
  nginx_unauthorized_modules= input(
    'nginx_unauthorized_modules',
    description: 'List of  unauthorized nginx modules.',
    value: [
             ]
  )

  describe nginx do
    its('modules') { should be_in nginx_authorized_modules }
  end
  describe nginx do
    its('modules') { should_not be_in nginx_unauthorized_modules }
  end
  
end

