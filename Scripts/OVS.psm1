<#
Copyright 2014 Cloudbase Solutions Srl

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
#>

$hvassembly = [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.HyperV.PowerShell")

function Set-VMNetworkAdapterOVSPort
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Microsoft.HyperV.PowerShell.VMNetworkAdapter]$VMNetworkAdapter,

        [parameter(Mandatory=$true)]
        [string]$OVSPortName
    )
    process
    {
		$ns = "root\virtualization\v2"
		$EscapedId = $VMNetworkAdapter.Id.Replace('\', '\\')
		$sd = gwmi -namespace $ns -class Msvm_EthernetPortAllocationSettingData -Filter "InstanceId like '$EscapedId%'"

		if($sd)
		{
			$sd.ElementName = $OVSPortName

			$vsms = gwmi -namespace $ns -class Msvm_VirtualSystemManagementService
			$retVal = $vsms.ModifyResourceSettings(@($sd.GetText(1)))
			try
			{
				Check-WMIReturnValue $retVal
			}
			catch
			{
				throw "Assigning OVS port '$OVSPortName' failed"
			}
		}
	}
}

function Check-WMIReturnValue($retVal)
{
	if ($retVal.ReturnValue -ne 0)
	{
		if ($retVal.ReturnValue -eq 4096)
		{
			do
			{
				$job = [wmi]$retVal.Job
			}
			while ($job.JobState -eq 4)

			if ($job.JobState -ne 7)
			{
				#TODO get error message from job
				throw "Job Failed"
			}
		}
		else
		{
			throw "Job Failed"
		}
	}
}

function Set-OvsPortName
{
	[CmdletBinding()]
	Param([parameter(Mandatory=$True)][String]$vmName, [String]$mac)
	Process
	{
		$vnic = 0
		if ($mac)
		{
			$vnic = Get-VMNetworkAdapter -vmName $vmName * | where {$_.MacAddress -eq $mac}
		}

		elseif ($vmName)
		{
			$vnic = Get-VMNetworkAdapter -VMName $vmName
		}

		Write-Host "`nnic:`tName='$($vnic.Name)'"
		Write-Host "`tis manag os='$($vnic.IsManagementOs)'"
		Write-Host "`tvm name='$($vnic.VMName)'"
		Write-Host "`tswitch='$($vnic.SwitchName)'"
		Write-Host "`tmac address='$($vnic.MacAddress)'"
		Write-Host "`tstatus='$($vnic.Status)'"
		Write-Host "`tip addresses='$($vnic.IpAddresses)'`n"

		$portName = "port-$vmName".toLower()
		$vnic | Set-VMNetworkAdapterOVSPort -OVSPortName $portName
		Write-Host "port name set: $portName"
		
		return $portName
	}
}

function Add-Flow
{
	[CmdletBinding()]
	Param([parameter(Mandatory=$True)][String]$flowCmd)
	Process
	{
		ovs-ofctl add-flow tcp:127.0.0.1:6633 $flowCmd
	}
}

function Dump-Flows
{
	[CmdletBinding()]
	param()
	Process
	{
		ovs-ofctl dump-flows tcp:127.0.0.1:6633
	}
}

function Dump-OFPorts
{
	[CmdletBinding()]
	param()
	Process
	{
		ovs-ofctl dump-ports tcp:127.0.0.1:6633
	}
}

function Dump-OFPortsDesc
{
	[CmdletBinding()]
	param()
	Process
	{
		ovs-ofctl dump-ports-desc tcp:127.0.0.1:6633
	}
}

function Delete-Flows
{
	[CmdletBinding()]
	Param([String]$flowCmd)
	Process
	{
		ovs-ofctl del-flows tcp:127.0.0.1:6633 $flowCmd
	}
}

function Add-OvsPort
{
	[CmdletBinding()]
	Param([parameter(Mandatory=$True)][String]$bridgeName, [parameter(Mandatory=$True)][String]$vmName, [String]$mac)
	Process
	{
		$portName = Set-OvsPortName $vmName $mac
		&ovs-vsctl add-port $bridgeName $portName
	}
}
