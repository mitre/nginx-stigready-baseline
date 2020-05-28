# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-56033" do
  title "The web server must install security-relevant software updates within
the configured time period directed by an authoritative source (e.g., IAVM,
CTOs, DTMs, and STIGs)."
  desc  "Security flaws with software applications are discovered daily.
Vendors are constantly updating and patching their products to address newly
discovered security vulnerabilities. Organizations (including any contractor to
the organization) are required to promptly install security-relevant software
updates (e.g., patches, service packs, and hot fixes). Flaws discovered during
security assessments, continuous monitoring, incident response activities, or
information system error handling must also be addressed expeditiously.

    The web server will be configured to check for and install
security-relevant software updates from an authoritative source within an
identified time period from the availability of the update. By default, this
time period will be every 24 hours.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and configuration to determine if the
web server checks for patches from an authoritative source at least every 30
days.

    If there is no timeframe or the timeframe is greater than 30 days, this is
a finding.
  "
  desc  "fix", "Configure the web server to check for patches and updates from
an authoritative source at least every 30 days."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000456-WSR-000187"
  tag "gid": "V-56033"
  tag "rid": "SV-70287r3_rule"
  tag "stig_id": "SRG-APP-000456-WSR-000187"
  tag "fix_id": "F-60911r2_fix"
  tag "cci": ["CCI-002605"]
  tag "nist": ["SI-2 c", "Rev_4"]

  describe "Skip Test" do
    skip "This is a manual check"
  end
  
end

