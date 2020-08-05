# encoding: UTF-8

control "V-56029" do
  title "The NGINX web server must augment re-creation to a stable and known
  baseline."
  desc  "Making certain that the web server has not been updated by an
  unauthorized user is always a concern. Adding patches, functions, and modules
  that are untested and not part of the baseline opens the possibility for
  security risks. The web server must offer, and not hinder, a method that allows
  for the quick and easy reinstallation of a verified and patched baseline to
  guarantee the production web server is up-to-date and has not been modified to
  add functionality or expose security risks.

    When the web server does not offer a method to roll back to a clean
  baseline, external methods, such as a baseline snapshot or virtualizing the web
  server, can be used.
  "
  
  desc  "check", "
  Review the NGINX web server documentation and deployed configuration to determine
  if the web server offers the capability to reinstall from a known state.

  Interview the System Administrator for the NGINX web server.

  Ask for documentation on the disaster recovery methods tested and planned for the 
  NGINX web server in the event of the necessity for rollback.
  
  If documentation for a disaster recovery has not been established, this is a finding.
  "
  desc  "fix", "Prepare documentation for disaster recovery methods for the NGINX web server 
  in the event of the necessity for rollback.

  Document and test the disaster recovery methods designed."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000225-WSR-000074"
  tag "gid": "V-56029"
  tag "rid": "SV-70283r2_rule"
  tag "stig_id": "SRG-APP-000225-WSR-000074"
  tag "fix_id": "F-60907r1_fix"
  tag "cci": ["CCI-001190"]
  tag "nist": ["SC-24", "Rev_4"]

  describe "This test requires a Manual Review: Interview the SA and ask for documentation on the 
  disaster recovery methods for the NGINX web server in the event of the necessity for rollback." do
    skip "This test requires a Manual Review: Interview the SA and ask for documentation on the 
    disaster recovery methods for the NGINX web server in the event of the necessity for rollback."
  end
end

