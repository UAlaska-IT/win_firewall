# frozen_string_literal: true

firewall 'default' do
  action :create
end

['dhcpv6', 'icmpv6', 'iphttps', 'ipv6', 'teredo'].each do |name_regex|
  firewall_rule_state name_regex do
    action :delete
    use_regex true
  end
end

# Simple creation
firewall_rule 'Inbound Windows Remote Management (WinRM) over HTTP or HTTPS' do
  description 'Allow inbound Windows Remote Management (WinRM) over HTTP or HTTPS from only UA address space'
  direction 'in'
  remote_ips ['all']
  local_ports [5985, 5986]
  protocol 'tcp'
  program 'System'
  firewall_action 'allow'
end

# Clear defaults to make testing clear
firewall 'default' do
  action :delete_external_rules
end

firewall 'default' do
  action :log_scripts
end
