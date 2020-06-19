# encoding: UTF-8
nginx_authorized_modules = input('nginx_authorized_modules')
nginx_unauthorized_modules = input('nginx_unauthorized_modules')

control "V-41698" do
  title "The NGINX web server must provide install options to exclude installation of
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
  Review the NGINX web server documentation and deployment configuration to
  determine which web server utilities, services, and modules are installed.
  Verify these options are essential to the operation of the web server. Also,
  confirm the web server install process offers an option to exclude these
  utilities, services, and modules from installation that are not needed for
  operation and that there is an uninstall option for their removal.

  Enter the following command to get a list of the modules installed: 
    # nginx -V

  If there are more modules installed than are needed for the operation of 
  the Nginx web server, this is a finding.
  "
  desc  "fix", "Use the configure script (available in the nginx download package) 
  to exclude modules not needed by Nginx using the --without {module_name} option."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000080"
  tag "gid": "V-41698"
  tag "rid": "SV-54275r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000080"
  tag "fix_id": "F-47157r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

# Only allow a small subset of authorized modules in an attempt to minimize the number of modules active
  describe nginx do
    its('modules') { should be_in nginx_authorized_modules }
  end
  describe nginx do
    its('modules') { should_not be_in nginx_unauthorized_modules }
  end
end

