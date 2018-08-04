# frozen_string_literal: true

# IPV6 rules deleted
describe powershell('netsh advfirewall firewall show rule name=all verbose') do
  its(:exit_status) { should eq 0 }
  its(:stderr) { should eq '' }
  [/dhcpv6/i, /icmpv6/i, /iphttps/i, /ipv6/i, /teredo/i].each do |name_regex|
    its(:stdout) { should_not match(name_regex) }
  end
end

# WinRM over HTTP
describe port(5985) do
  it { should be_listening }
  its(:protocols) { should include 'tcp' }
end

describe powershell('netsh advfirewall show currentprofile firewallpolicy | findstr "Firewall Policy"') do
  its(:exit_status) { should eq 0 }
  its(:stderr) { should eq '' }
  its(:stdout) { should match('BlockInbound,AllowOutbound') }
end

describe file('C:/chef/log/win_firewall.log') do
  it { should exist }
  it { should be_file }
end
