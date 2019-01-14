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
  impact 0.5
  tag "gtitle": "SRG-APP-000131-WSR-000073"
  tag "gid": "V-41684"
  tag "rid": "SV-54261r3_rule"
  tag "stig_id": "SRG-APP-000131-WSR-000073"
  tag "fix_id": "F-47143r2_fix"
  tag "cci": ["CCI-001749"]
  tag "nist": ["CM-5 (3)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and configuration to
determine if web server modules are fully tested before implementation in the
production environment.

Review the web server for modules identified as test, debug, or backup and that
cannot be reached through the hosted application.

Review the web server to see if the web server or an external utility is in use
to enforce the signing of modules before they are put into a production
environment.

If development and testing is taking place on the production web server or
modules are put into production without being signed, this is a finding."
  tag "fix": "Configure the web server to enforce, internally or through an
external utility, the review, testing and signing of modules before
implementation into the production environment."
end

