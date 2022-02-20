control 'V-56033' do
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

  desc 'check', "
  Review the web server documentation and configuration to determine if the
  web server checks for patches from an authoritative source at least every 30
  days.

  Determine most recent patch level of NGINX with the following command:

  # nginx -v

  If the version is more than one version behind the most recent patch level,
  this is a finding.
  "
  desc 'fix', "Install the current version of the web server software and
  maintain appropriate service packs and patches."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000456-WSR-000187'
  tag "gid": 'V-56033'
  tag "rid": 'SV-70287r3_rule'
  tag "stig_id": 'SRG-APP-000456-WSR-000187'
  tag "fix_id": 'F-60911r2_fix'
  tag "cci": ['CCI-002605']
  tag "nist": ['SI-2 c']
  ref 'http://nginx.org/en/CHANGES'

  nginx_changelog = inspec.http('http://nginx.org/en/CHANGES').body.lines.map(&:chomp)
  nginx_changelog_clean = nginx_changelog.select { |line| line.include? 'Changes with nginx' }
  nginx_latest_release = nginx_changelog_clean.first.split[3]
  input_version = input('nginx_latest_version')
  nginx_installed_version = inspec.nginx.version

  if (nginx_latest_release.nil? || nginx_latest_release.empty?) && (input_version.nil? || input_version.empty?)
    describe "Your installed NGINX version is: #{nginx_installed_version}. You must review this control Manually. Either set or pass the `nginx_version` input to the profile,
    or ensure your system can reach 'http://nginx.org/en/CHANGES' to get the lastest released version of NGINX" do
      skip "Your installed NGINX version is: #{nginx_installed_version}. You must review this control Manually. Either set or pass the `nginx_version` input to the profile,
      or ensure your system can reach 'http://nginx.org/en/CHANGES' to get the lastest released version of NGINX"
    end
  else
    describe.one do
      describe 'The version of NGINX' do
        subject { nginx_installed_version }
        it { should cmp >= nginx_latest_release }
      end
      unless input_version.nil? || input_version.empty?
        describe 'The version of NGINX' do
          subject { nginx_installed_version }
          it { should cmp >= input_version }
        end
      end
    end
  end
end
