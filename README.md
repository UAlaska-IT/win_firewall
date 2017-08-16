# Windows Firewall Cookbook

__Maintainer: OIT Systems Engineering__ (<ua-oit-se@alaska.edu>)

## Purpose

The custom resources in this cookbook implement the _mechanism_ for configuring the firewall in Windows.  For an example of a _policy_ for how to configure the firewall, see the se-win-baseline cookbook.

## Requirements

### Chef

Version 2.0.0+ of this cookbook requires Chef 13+

### Platforms

Supported Platform Families:

* Windows

Platforms validated via Test Kitchen:

* Windows 10
* Windows Server 2016

Notes:

* Only Windows 2016 is fully tested.
* Custom resources typically use raw PowerShell scripts for converge and idempotence.  Most recipes therefore should support older versions of Windows, but these are not tested.
* Cookbook dependencies are handled via Berkshelf and are verified only to be compatible with Windows 2016/10.

## Resources

This cookbook provides four resources for managing the firewall in Windows.  See [Netsh AdvFirewall](https://technet.microsoft.com/en-us/library/dd734783(v=ws.10).aspx) for details on configuring the Windows firewall.


### firewall
A firewall provides actions to manage the entire firewall, as when managing all rules with a single action.  A firewall also internally manages script caches and all resources multiplexed to the firewall, such as whitelists.  No default action is provided so that all actions must be explicitly specified.  See the `firewall_rule_whitelist` resource for details on modifying internal state.

__Actions__
Five actions are provided.  These actions are associated with only the resources that were previously multiplexed with the named firewall.  For example, deleting existing rules will only respect whitelists that were assigned to the current firewall.  See the `firewall_rule_whitelist` resource.

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

When regex matching is used, all actions will skip managed rules and respect the rule whitelist of the associated firewall, but not the group whitelist.

__Actions__
Three actions are provided.

* `enable` - Post condition is that the named rule is enabled.  If exact name matching is used, enforces the precondition that the named rule exists and will throw an exception otherwise.
* `disable` - Post condition is that the named rule is disabled.  If exact name matching is used, enforces the precondition that the named rule exists and will throw an exception otherwise.
* `delete` - Post condition is that the named rule does not exist.

__Attributes__
This resource has three attributes.

* `name` - The `name_property` of the resource that maps to either the name of an existing firewall rule or a regular expression that is used for matching rule names.
* `use_regex` - Defaults to 'false'.  Boolean flag that determines the matching mode.
* `firewall_name` - Defaults to `'default'`.  The name of the associated firewall.  In the absence of a compelling reason, almost all users should use a single firewall within a cookbook.

### firewall_rule_group
This resource manages an entire rule group with a single action.  See the `firewall_rule_whitelist` resource for details on creating whitelists to mask group actions.

__Actions__
Three actions are provided.

* `enable` - Post condition is that every rule matching the named group is enabled.  Enforces the precondition that the named rule exists and will throw an exception otherwise.
* `disable` - Post condition is that every rule matching the named group is disabled.  Respects the rule whitelist of the associated firewall, but not the group whitelist.
* `delete` - Post condition is that no rule matching the named group exists.  Respects the rule whitelist of the associated firewall, but not the group whitelist.

__Attributes__
This resource has a two attributes.

* `name` - The `name_property` of the resource.  Maps to the group field of rules within the firewall.
* `firewall_name` - Defaults to `'default'`.  The name of the associated firewall.  In the absence of a compelling reason, almost all users should use a single firewall within a cookbook.

## Attributes
All `firewall` actions and those `firewall_rule_state` actions that use regular expression matching will respect one or more whitelists.

* `node['win_firewall']['firewall_to_whitelist_groups']` - Defaults to `{'default' => ['core networking']}`; the default firewall will whitelist the 'Core Networking' group.  Pre-existing rules that belong to these groups will not be disabled or deleted by actions on the named firewall.
* `node['win_firewall']['firewall_to_whitelist_rules']` - Defaults to `{'default' => []}`; the default firewall has no whitelisted rules.  Pre-existing rules with name listed here will not be disabled or deleted by actions on the named firewall.

## Recipes

This is a resource-only cookbook; and adding the default recipe to a node's runlist will have no effect.

## Examples

```ruby
firewall_rule 'Inbound Dynamic Host Configuration Protocol (DHCP)' do
  description 'Allow inbound Inbound Dynamic Host Configuration Protocol (DHCP) from only UA address space'
  direction 'in'
  remote_ips ['137.229.0.0/16', '199.165.64.0/18', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
  local_ports [68]
  remote_ports [67]
  protocol 'udp'
  program 'C:\Windows\system32\svchost.exe'
  service 'dhcp'
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

firewall 'default' do
  action :delete_external_rules
end
```

## Development

Development should follow [GitHub Flow](https://guides.github.com/introduction/flow/) to foster some shared responsibility.

* Fork/branch the repository
* Make changes
* Fix all Rubocop (`rubocop`) and Foodcritic (`foodcritic .`) offenses
* Write smoke tests for the testing fixture that reasonably cover the changes
* Pass all smoke tests
* Submit a Pull Request using Github
* Wait for feedback and merge from a second developer

### Requirements

+ [ChefDK](https://downloads.chef.io/chef-dk/)
+ [Vagrant](https://www.vagrantup.com/)
+ [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
+ Install dependency tree with `berks install`
+ Vagrant WinRM plugin:  `vagrant plugin install vagrant-winrm`

### Windows Server 2016 Box

This cookbook was tested using the base box at

`\\fbk-tss-store1.apps.ad.alaska.edu\Department\Technology Support Services\Engineering\Packer Boxes\win2016core-virtualbox.box`

If this box has not been cached by Vagrant, it can be placed (without .box extension) in the kitchen-generated directory

`.kitchen/kitchen-vagrant/kitchen-se-win-baseline-default-win2016gui-virtualbox/.vagrant/machines/default/virtualbox`

or added to Vagrant using the shell command

`vagrant box add <name> <base_box>.box`

Alternative base boxes can be built, for example using [boxcutter](https://github.com/boxcutter/windows).
