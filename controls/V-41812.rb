control 'V-41812' do
  title 'The NGINX web server must provide a clustering capability.'
  desc  "The web server may host applications that display information that
  cannot be disrupted, such as information that is time-critical or
  life-threatening. In these cases, a web server that shuts down or ceases to be
  accessible when there is a failure is not acceptable. In these types of cases,
  clustering of web servers is used.

      Clustering of multiple web servers is a common approach to providing
  fail-safe application availability. To assure application availability, the web
  server must provide clustering or some form of failover functionality.
  "

  desc 'check', "Review the NGINX web server documentation, deployed configuration,
  and risk analysis documentation to verify that the web server is configured to provide
  clustering functionality, if the web server is a high-availability web server.

  If the NGINX web server is not a high-availability web server, this finding is
  Not Applicable.

  If the web server is not configured to provide clustering or some form of failover
  functionality and the web server is a high-availability server, this is a finding.
  "
  desc 'fix', "Configure the web server to provide application failover, or participate
  in a web cluster that provides failover for high-availability web servers.
  "
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000225-WSR-000141'
  tag "gid": 'V-41812'
  tag "rid": 'SV-54389r3_rule'
  tag "stig_id": 'SRG-APP-000225-WSR-000141'
  tag "fix_id": 'F-47271r2_fix'
  tag "cci": ['CCI-001190']
  tag "nist": %w(SC-24 Rev_4)

  if input('high_availability') == 'false'
    impact 0.0
    describe 'This check is NA because NGINX is not a high-availability web server.' do
      skip 'This check is NA because NGINX is not a high-availability web server.'
    end
  elsif input('is_cluster_master') == 'false'
    describe nginx do
      its('modules') { should include 'ngx_stream_zone_sync_module' }
    end
  else
    describe nginx do
      its('modules') { should include 'ngx_stream_zone_sync_module' }
    end
    describe package('nginx-sync') do
      it { should be_installed }
    end
    describe parse_config_file('/etc/nginx-sync.conf') do
      its('NODES') { should_not be nil }
      its('CONFPATHS') { should_not be nil }
    end
  end
end
