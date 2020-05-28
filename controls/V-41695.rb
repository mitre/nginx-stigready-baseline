# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41695" do
  title "The web server must provide install options to exclude the
installation of documentation, sample code, example applications, and
tutorials."
  desc  "Web server documentation, sample code, example applications, and
tutorials may be an exploitable threat to a web server because this type of
code has not been evaluated and approved. A production web server must only
contain components that are operationally necessary (e.g., compiled code,
scripts, web-content, etc.).

    Any documentation, sample code, example applications, and tutorials must be
removed from a production web server. To make certain that the documentation
and code are not installed or uninstalled completely; the web server must offer
an option as part of the installation process to exclude these packages or to
uninstall the packages if necessary.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployment configuration to
determine if the web server contains documentation, sample code, example
applications, or tutorials.

    Verify the web server install process also offers an option to exclude
these elements from installation and provides an uninstall option for their
removal.

    If web server documentation, sample code, example applications, or
tutorials are installed or the web server install process does not offer an
option to exclude these elements from installation, this is a finding.
  "
  desc  "fix", "Use the web server uninstall facility or manually remove any
documentation, sample code, example applications, and tutorials."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000077"
  tag "gid": "V-41695"
  tag "rid": "SV-54272r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000077"
  tag "fix_id": "F-47154r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

  # Default installation does not include example code but this checks it anyways
  
  nginx_disallowed_file_list = input(
    'nginx_disallowed_file_list',
    description: 'File list of  documentation, sample code, example applications, and tutorials.',
    value: ["/usr/share/man/man8/nginx.8.gz"]
  )

  nginx_disallowed_file_list.each do |file|
    describe file(file) do
      it { should_not exist }
    end
  end
  
end

