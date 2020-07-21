# encoding: UTF-8

control "V-41616" do
  title "A NGINX web server, behind a load balancer or proxy server, must produce log
  records containing the client IP information as the source and destination and
  not the load balancer or proxy IP information with each event."
  desc  "Web server logging capability is critical for accurate forensic
  analysis. Without sufficient and accurate information, a correct replay of the
  events cannot be determined.

    Ascertaining the correct source, e.g. source IP, of the events is important
  during forensic analysis. Correctly determining the source of events will add
  information to the overall reconstruction of the logable event. By determining
  the source of the event correctly, analysis of the enterprise can be undertaken
  to determine if events tied to the source occurred in other areas within the
  enterprise.

    A web server behind a load balancer or proxy server, when not configured
  correctly, will record the load balancer or proxy server as the source of every
  logable event. When looking at the information forensically, this information
  is not helpful in the investigation of events. The web server must record with
  each event the client source of the event.
  "
  desc  "check", "Review the deployment configuration to determine if the NGINX web 
  server is sitting behind a proxy server.

  If the web server is not sitting behind a proxy server, this finding is Not Applicable. 

  If the NGINX web server is behind a proxy server, review the documentation and deployment
  configuration to determine if the web server is configured to generate sufficient 
  information to resolve the source, e.g. source IP, of the logged event and not the 
  proxy server.

  Check for the following:
      # grep for a 'log_format' directive in the http context of the nginx.conf.

  If the 'log_format' directive is not configured to contain the '$realip_remote_addr' 
  variable, this is a finding. 
  "
  desc  "fix", "Configure the 'log_format' directive in the nginx.conf to use the '$realip_remote_addr' 
  variable to generate the client source, not the load balancer or proxy server, of each logable event."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000098-WSR-000060"
  tag "gid": "V-41616"
  tag "rid": "SV-54193r3_rule"
  tag "stig_id": "SRG-APP-000098-WSR-000060"
  tag "fix_id": "F-47075r2_fix"
  tag "cci": ["CCI-000133"]
  tag "nist": ["AU-3", "Rev_4"]

  # $realip_remote_addr keeps the original client address
  nginx_conf.params['http'].each do |http|
    http["log_format"].each do |log_format|
      describe "realip_remote_addr" do
        it 'should be part of every log format in http.' do
          expect(log_format.to_s).to(match /.*?\$realip_remote_addr.*?/)
        end
      end
    end
  end
end

