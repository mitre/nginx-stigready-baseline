# encoding: UTF-8

control "V-41684" do
  title "Expansion modules must be fully reviewed, tested, and signed before
  they can exist on a production NGINX web server."
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
  
  desc  "check", "Review the NGINX web server documentation and configuration 
  to determine if web server modules are fully tested before implementation in 
  the production environment.

  Review the web server for modules identified as test, debug, or backup and
  that cannot be reached through the hosted application.

  Review the web server to see if the web server or an external utility is in
  use to enforce the signing of modules before they are put into a production
  environment.

  Enter the following command to get a list of the modules installed: 
    # nginx -V

  If there are any modules not required for operation or unsigned modules, this is a finding.
  "
  desc  "fix", "Use the configure script (available in the nginx download package) to exclude 
  modules unsigned modules using the --without {module_name} option."

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

  describe nginx do
    its('modules') { should be_in input('nginx_authorized_modules') }
  end
  describe nginx do
    its('modules') { should_not be_in input('nginx_unauthorized_modules') }
  end
  
end

