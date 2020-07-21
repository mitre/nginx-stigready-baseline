# encoding: UTF-8

control "V-41794" do
  title "The NGINX web server must separate the hosted applications from hosted web
  server management functionality."
  desc  "The separation of user functionality from web server management can be
  accomplished by moving management functions to a separate IP address or port.
  To further separate the management functions, separate authentication methods
  and certificates should be used.

    By moving the management functionality, the possibility of accidental
  discovery of the management functions by non-privileged users during hosted
  application use is minimized.
  "
  
  desc  "check", "Review the NGINX web server documentation and deployed configuration 
  to determine whether hosted application functionality is separated from web server
  management functions.

  If the functions are not separated, this is a finding.
  "
  desc  "fix", "Configure the web server to separate the hosted applications
  from web server management functionality."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000211-WSR-000129"
  tag "gid": "V-41794"
  tag "rid": "SV-54371r3_rule"
  tag "stig_id": "SRG-APP-000211-WSR-000129"
  tag "fix_id": "F-47253r2_fix"
  tag "cci": ["CCI-001082"]
  tag "nist": ["SC-2", "Rev_4"]

  describe "This test requires a Manual Review: Determine whether hosted application functionality is 
  separated from web server management functions." do
    skip "This test requires a Manual Review: Determine whether hosted application functionality is 
    separated from web server management functions."
  end
end

