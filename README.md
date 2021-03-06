# Windows Firewall Cookbook

__Maintainer: OIT Systems Engineering__ (<ua-oit-se@alaska.edu>)

## Purpose

The custom resources in this cookbook implement the _mechanism_ for configuring the firewall in Windows.  For an example of a _policy_ for how to configure the firewall, see the se-win-baseline cookbook.

## Requirements

### Chef

This cookbook requires Chef 13+

### Platforms

Supported Platform Families:

* Windows

Platforms validated via Test Kitchen:

* Windows Server 2016
* Windows Server 2012
* Windows Server 2008R2
* Windows 10

Notes:

* This is a low-level cookbook with precondition that Powershell 5.0 is installed
  * Custom resources will not work with previous versions of Powershell
  * Windows 2008 and 2012 require WMF update to install Powershell 5.0
  * Powershell is not installed by this cookbook

## Resources

This cookbook provides four resources for managing the firewall in Windows.  See [Netsh AdvFirewall](https://technet.microsoft.com/en-us/library/dd734783(v=ws.10).aspx) for details on configuring the Windows firewall.


### firewall

A firewall provides actions to manage the entire firewall, as when managing all rules with a single action.  A firewall also internally manages script caches and all resources multiplexed to the firewall, such as whitelists.  No default action is provided so that all actions must be explicitly specified.  See the whitelist attributes below for details on modifying internal state.

__Actions__

Five actions are provided.  These actions are associated with only attributes that were previously multiplexed to the named firewall.  For example, deleting existing rules will only respect whitelists that were assigned to the current firewall.     All `disable` and `delete` actions will skip managed rules and respect both the rule whitelist, `node['win_firewall']['firewall_to_whitelist_groups']`,  and the group whitelist, `node['win_firewall']['firewall_to_whitelist_rules']`, of the associated firewall.

* `create` - Post condition is that the named firewall exists and all resources are initialized.  A firewall must be created before any associated firewall_rule or firewall_rule_state is created.
* `log_scripts` - Post condition is that all cached scripts are written to the log_file.
* `disable_external_rules` - Post condition is that all rules that are not managed by this firewall are disabled.
* `delete_external_rules` - Post condition is that all rules that are not managed by this firewall are deleted.
* `delete_external_disabled_rules` - Post condition is that all rules that are both not managed by this firewall and are disabled are deleted.

__Attributes__

This resource has two attributes.

* `name` - The `name_property` of the resource that acts as a persistent identifier between resources.  Used to multiplex rules, states, whitelists, and logs.  It is strongly recommended that most users utilize a single firewall within a cookbook as this minimizes complexity.
* `log_file` - Defaults to `'C:/chef/log/win_firewall.log'`.  The location of the log file, where the scripts than were run can be found.

### firewall_rule

This resource is used to create or modify a single firewall rule and effectively describes the state of this rule.

__Actions__

This resource provides a single action.

* `create_synchronize` - Post condition is that the named rule exists and is configured as indicated.  Enforces the precondition that the named rule is not externally managed (is part of a system group or is managed by group policy) and will throw an exception if an attempt is made to modify an externally managed rule.  Alternatively, use the `firewall_rule_state` or `firewall_rule_group` resources to disable or delete an externally managed rule, and then create a new rule.

__Attributes__

Attributes are provided to describe most fields of a Windows firewall rule.  Attribute default values mirror netsh advfirewall default values when a netsh default exists.

* `name` - The `name_property` of the resource.  Maps to the name of the firewall rule.
* `firewall_name` - Defaults to `'default'`.  The name of the associated firewall.  In the absence of a compelling reason, almost all users should use a single firewall within a cookbook.

The following attributes are required, but have default values

* `direction` - Defaults to `'in'`.  Allowed values are `'any'`, `'in'`, and `'out'`.
* `firewall_action` - Defaults to `'allow'`.  Allowed values are `'allow'`, `'block'`, and `'bypass'`.

The following attributes are optional, and have default values that have no effect.  Each array must contain the single string `'any'` or one or more allowed values.

* `profiles` - Defaults to `['any']`.  Allowed array values are `'domain'`, `'private'`, and `'public'`.
* `interface_type` - Defaults to `'any'`.  Allowed values are `'wireless'`, `'lan'`, `'ras'`.
* `local_ips` - Defaults to `['any']`.  Allowed array values are subnets in CIDR notation, e.g. `192.168.1.0/24`, or IP ranges separated by '-', e.g. `192.168.1.0-192.168.1.48`.
* `local_ports` - Defaults to `['any']`.  Allowed array values are integers.
* `remote_ips` - Defaults to `['any']`.  Allowed array values are subnets in CIDR notation, e.g. `192.168.1.0/24`, or IP ranges separated by '-', e.g. `192.168.1.0-192.168.1.48`.
* `remote_ports` - Defaults to `['any']`.  Allowed array values are integers.
* `protocol` - Defaults to `'any'`.  Allowed values are `'icmpv4'`, `'icmpv6'`, `'tcp'`, and `'udp'`.
* `service` - Defaults to `'any'`.  The short name of a service.
* `enabled` - Defaults to `'yes'`.  Allowed values are `'yes'` and `'no'`.

These attributes are optional, and have no reasonable non-trivial default value.

* `description` - Defaults to `''`.  A description of what the rule does.
* `program` - Defaults to `''`.  The path to an executable program.

A few corollaries of the definition above:

* Stateful rules are currently not supported
* Authentication is currently not supported

If any of these features are needed, please contact OIT Systems Engineering (<ua-oit-se@alaska.edu>) or submit a pull request.

### firewall_rule_state

This resource provides actions to modify the status of matching firewall rules.  To modify the settings of a single rule, the `firewall_rule` resource can be used.

There are two modes for how the rule name is used
1. The name is used to find an exact match to the name of a single existing rule
2. The name is a regex that will be used to match names of existing rules

When regex matching is used, all actions will skip managed rules and respect the rule whitelist, `node['win_firewall']['firewall_to_whitelist_groups']`, of the associated firewall but not the group whitelist, `node['win_firewall']['firewall_to_whitelist_rules']`.

__Actions__

Three actions are provided.  If exact name matching is used, all actions except `delete` enforce the precondition that the named rule exists and will throw an exception otherwise.

* `enable` - Post condition is that the named rule is enabled.
* `disable` - Post condition is that the named rule is disabled.
* `delete` - Post condition is that the named rule does not exist.
* `set_remote_ips` - Post condition is that the named rule permits remote IPs corresponding to the `ip_list` attribute.

__Attributes__

This resource has three attributes.

* `name` - The `name_property` of the resource that maps to either the name of an existing firewall rule or a regular expression that is used for matching rule names.
* `use_regex` - Defaults to 'false'.  Boolean flag that determines the matching mode.
* `firewall_name` - Defaults to `'default'`.  The name of the associated firewall.  In the absence of a compelling reason, almost all users should use a single firewall within a cookbook.
* `ip_list` - Defaults to empty array.  The permitted IPs to be assigned to the rule, represented as an array of CIDRs.  This attribute is used only by the `set_remote_ips` action.

### firewall_rule_group

This resource manages an entire rule group with a single action.  See the `firewall_rule_whitelist` resource for details on creating whitelists to mask group actions.

__Actions__

Three actions are provided.  Both `disable` and `delete` actions will skip managed rules and respect the rule whitelist, `node['win_firewall']['firewall_to_whitelist_groups']`, of the associated firewall but not the group whitelist, `node['win_firewall']['firewall_to_whitelist_rules']`.

* `enable` - Post condition is that every rule matching the named group is enabled.
* `disable` - Post condition is that every rule matching the named group is disabled.
* `delete` - Post condition is that no rule matching the named group exists.

__Attributes__

This resource has a two attributes.

* `name` - The `name_property` of the resource.  Maps to the group field of rules within the firewall.
* `firewall_name` - Defaults to `'default'`.  The name of the associated firewall.  In the absence of a compelling reason, almost all users should use a single firewall within a cookbook.

## Attributes
All `firewall` actions and those `firewall_rule_state` actions that use regular expression matching will respect one or more whitelists.

* `node['win_firewall']['firewall_to_whitelist_groups']` - Defaults to `{'default' => ['core networking']}`; the default firewall will whitelist the 'Core Networking' group.  A hash of firewall name to array of whitelisted rule groups.  Pre-existing rules that belong to these groups will not be disabled or deleted by actions on the named firewall.
* `node['win_firewall']['firewall_to_whitelist_rules']` - Defaults to `{'default' => []}`; the default firewall has no whitelisted rules.  A hash of firewall name to array of whitelisted rules.  Pre-existing rules with name listed here will not be disabled or deleted by actions on the named firewall.

## Recipes

This is a resource-only cookbook; and adding the default recipe to a node's runlist will have no effect.

## Examples

```ruby
firewall_rule 'Inbound Windows Remote Desktop Protocol (RDP) over TCP' do
  description 'Allow inbound Windows Remote Desktop Protocol (RDP) over TCP from only UA address space'
  direction 'in'
  remote_ips ['137.229.0.0/16', '199.165.64.0/18', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
  local_ports [3389]
  protocol 'tcp'
  program 'C:\Windows\system32\svchost.exe'
  service 'termservice'
  firewall_action 'allow'
end

firewall_rule_group 'alljoyn router' do
  action :delete
end

['dhcpv6', 'icmpv6', 'iphttps', 'ipv6', 'teredo'].each do |name_regex|
  firewall_rule_state name_regex do
    action :delete
    use_regex true
  end
end

firewall_rule_state 'dhcp' do
  action :set_remote_ips
  use_regex true
  ip_list ['137.229.0.0/16', '199.165.64.0/18', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
end

firewall 'default' do
  action :delete_external_rules
end
```

## Development

Development should follow [GitHub Flow](https://guides.github.com/introduction/flow/) to foster some shared responsibility.

* Fork/branch the repository
* Make changes
* Fix all Rubocop (`rubocop`) and Foodcritic (`foodcritic .`) offenses
* Write smoke tests that reasonably cover the changes (`kitchen verify`)
* Pass all smoke tests
* Submit a Pull Request using Github
* Wait for feedback and merge from a second developer

### Requirements

For running tests in Test Kitchen a few dependencies must be installed.

* [ChefDK](https://downloads.chef.io/chef-dk/)
* [Vagrant](https://www.vagrantup.com/)
* [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
* Install the dependency tree with `berks install`
* Install the Vagrant WinRM plugin:  `vagrant plugin install vagrant-winrm`
