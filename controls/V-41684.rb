# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41684" do
  title "Expansion modules must be fully reviewed, tested, and signed before
they can exist on a production web server."
  desc  "In the case of a production web server, areas for content development
and testing will not exist, as this type of content is only permissible on a
development website.  The process of developing on a functional production
website entails a degree of trial and error and repeated testing.  This process
is often accomplished in an environment where debugging, sequencing, and
formatting of content are the main goals.  The opportunity for a malicious user
to obtain files that reveal business logic and login schemes is high in this
situation.  The existence of such immature content on a web server represents a
significant security risk that is totally avoidable.

    The web server must enforce, internally or through an external utility, the
signing of modules before they are implemented into a production environment.
By signing modules, the author guarantees that the module has been reviewed and
tested before production implementation.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and configuration to determine if web
server modules are fully tested before implementation in the production
environment.

    Review the web server for modules identified as test, debug, or backup and
that cannot be reached through the hosted application.

    Review the web server to see if the web server or an external utility is in
use to enforce the signing of modules before they are put into a production
environment.

    If development and testing is taking place on the production web server or
modules are put into production without being signed, this is a finding.
  "
  desc  "fix", "Configure the web server to enforce, internally or through an
external utility, the review, testing and signing of modules before
implementation into the production environment."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000131-WSR-000073"
  tag "gid": "V-41684"
  tag "rid": "SV-54261r3_rule"
  tag "stig_id": "SRG-APP-000131-WSR-000073"
  tag "fix_id": "F-47143r2_fix"
  tag "cci": ["CCI-001749"]
  tag "nist": ["CM-5 (3)", "Rev_4"]

  # Only allow a small subset of authorized modules in an attempt to minimize the number of modules active
  
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

