control 'V-41695' do
  title "The NGINX web server must provide install options to exclude the
  installation of documentation, sample code, example applications, and
  tutorials."
  desc "Web server documentation, sample code, example applications, and
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

  desc 'check', "
  Review the NGINX web server documentation and deployment configuration to
  determine if the web server contains documentation, sample code, example
  applications, or tutorials.

  If the site requires the use of a particular piece of software, verify that
  the Information System Security Officer (ISSO) maintains documentation
  identifying this software as necessary for operations. The software must
  be operated at the vendor’s current patch level and must be a supported
  vendor release.

  If programs or utilities that meet the above criteria are installed on the
  web server and appropriate documentation and signatures are in evidence,
  this is not a finding.

  Determine whether the web server is configured with unnecessary software.
  This may change with the software versions, but the following are some
  examples of what to look for (This should not be the definitive list of
  sample files, but only an example of the common samples that are provided
  with the associated web server. This list will be updated as additional
  information is discovered.):

    #  ls -Ll /usr/share/man/man8/nginx.8.gz

  Determine whether processes other than those that support the web server
  are loaded and/or run on the web server.

  Examples of software that should not be on the web server are all web
  development tools, office suites (unless the web server is a private
  web development server), compilers, and other utilities that are not
  part of the web server suite or the basic operating system.

  Check the directory structure of the server and verify that additional,
  unintended, or unneeded applications are not loaded on the system.

  "
  desc 'fix', 'Remove any unnecessary applications per ISSO documentation.'
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000141-WSR-000077'
  tag "gid": 'V-41695'
  tag "rid": 'SV-54272r3_rule'
  tag "stig_id": 'SRG-APP-000141-WSR-000077'
  tag "fix_id": 'F-47154r2_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']

  if input('nginx_disallowed_file_list').empty?
    describe 'This check is skipped because the disallowed files list should not be empty.' do
      skip 'This check is skipped because the disallowed files list should not be empty.'
    end
  else
    input('nginx_disallowed_file_list').each do |file|
      describe file(file) do
        it { should_not exist }
      end
    end
  end
end
