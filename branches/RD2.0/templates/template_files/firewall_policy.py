#
# Registry Decoder
# Copyright (c) 2011 Digital Forensics Solutions, LLC
#
# Contact email:  registrydecoder@digitalforensicssolutions.com
#
# Authors:
# Andrew Case       - andrew@digitalforensicssolutions.com
# Lodovico Marziale - vico@digitalforensicssolutions.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#
# Windows Firewall Policy Settings
#
# Kevin Moore - CERT - kevinm@cert.org



pluginname = "Windows Firewall Policy Settings"
description = "Displays Windows Firewall Policy settings including authorized applications and ports"
hive = "SYSTEM"    


def run_me():
    
    from datetime import time
    import struct
     
    ccs = reg_get_currentcontrolset()                               # Identifies system's current control set for timezone settings retrieval
    reg_report(('Current ControlSet', '00' + ccs))
    reg_report((""))
    
    regkey = reg_get_required_key("\ControlSet00" + ccs + "\Services\SharedAccess\Parameters")   # Retrieves key based on CurrentControlSe
    
    # Registry Keys containing information related to firewall policy settings
    keys = (
        "\ControlSet00" + ccs + "\Services\SharedAccess",
        "\ControlSet00" + ccs + "\Services\SharedAccess\Parameters",
        "\ControlSet00" + ccs + "\Services\SharedAccess\Parameters\FirewallPolicy",
        "\ControlSet00" + ccs + "\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
        "\ControlSet00" + ccs + "\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System",
        "\ControlSet00" + ccs + "\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
        "\ControlSet00" + ccs + "\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\AuthorizedApplications\List",  
        "\ControlSet00" + ccs + "\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System",
        "\ControlSet00" + ccs + "\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        "\ControlSet00" + ccs + "\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List",
        "\ControlSet00" + ccs + "\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\GloballyOpenPorts\List")  
    
    # Retrieve values from keys above
    for k in keys:
        reg_key = reg_get_key(k)
        if reg_key:
            reg_report((k))
            reg_report_values_name_data(reg_key)
        reg_report((""))