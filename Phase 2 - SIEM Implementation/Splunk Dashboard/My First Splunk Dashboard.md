### My First Splunk Dashboard

![Dashboard1](Dashboard1.png)

##### **Top Row: Quick Stats (The "Is It On?" Indicators)**

![Dashboard2](Dashboard2.png)

**Purpose:** Instant visual verification. If these are red/zero, something is broken.

- **Total Events (Last Hour):**
    
    - **Query:** `index=windows | stats count`
- **Active Hosts:**
    
    - **Query:** `index=windows | stats dc(host)`
- **Sysmon & Security Events:**
    
    - **Query:** Filters by `sourcetype` (Sysmon vs. Security Log).

```xml
  <row>
    <panel>
      <title>Total Events (Last Hour)</title>
      <single>
        <search>
          <query>index=windows NOT (EventCode=1014 AND (QueryName="*msftncsi*" OR QueryName="*_msdcs*" OR QueryName="*_ldap*"))
| stats count</query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0x65A637","0x6DB7C6","0xF7BC38","0xF58F39","0xD93F3C"]</option>
        <option name="rangeValues">[0,1000,5000,10000]</option>
        <option name="underLabel">Events Ingested (Clean)</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    
    <panel>
      <title>Active Hosts</title>
      <single>
        <search>
          <query>index=windows 
| stats dc(host) as unique_hosts</query>
          <earliest>-15m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0xD93F3C","0xF58F39","0x6DB7C6","0x65A637"]</option>
        <option name="rangeValues">[0,2,4]</option>
        <option name="underLabel">VMs Reporting</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    
    <panel>
      <title>Sysmon Events</title>
      <single>
        <search>
          <query>index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count</query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0xD93F3C","0xF7BC38","0x65A637"]</option>
        <option name="rangeValues">[0,500]</option>
        <option name="underLabel">Sysmon Activity</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    
    <panel>
      <title>Security Events</title>
      <single>
        <search>
          <query>index=windows source="*WinEventLog:Security"
| stats count</query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0xD93F3C","0xF7BC38","0x65A637"]</option>
        <option name="rangeValues">[0,1000]</option>
        <option name="underLabel">Security Logs</option>
        <option name="useColors">1</option>
      </single>
    </panel>
  </row>
```


---

##### **Host Validation Row (Comparing Endpoints)**

![Dashboard3](Dashboard3.png)

**Purpose:** Verifying which specific machines are sending data and identifying "quiet" hosts.

- **Event Volume by Host (Area Chart):**
    
    - **Query:** `timechart span=5m count by host`
- **Host Health Check (Table):**
    
    - **Query Logic:**
        
        - `latest(_time)`: Finds the timestamp of the most recent log.
            
        - `eval Status=if(Events>10, "✓ ONLINE", "⚠ LOW ACTIVITY")`: Custom logic check. If a host has fewer than 10 events in 15 minutes, it flags it as "LOW ACTIVITY".

```xml
<row>
    <panel>
      <title>Event Volume by Host (Real-time)</title>
      <chart>
        <search>
          <query>index=windows NOT (EventCode=1014 AND (QueryName="*msftncsi*" OR QueryName="*_msdcs*" OR QueryName="*_ldap*"))
| timechart span=5m count by host</query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.legend.placement">right</option>
        <option name="refresh.display">progressbar</option>
      </chart>
    </panel>
    
    <panel>
      <title>Host Health Check</title>
      <table>
        <search>
          <query><![CDATA[index=windows NOT (EventCode=1014 AND (QueryName="*msftncsi*" OR QueryName="*_msdcs*" OR QueryName="*_ldap*")) earliest=-15m
| stats count as Events, 
        latest(_time) as LastSeen, 
        values(source) as Sources 
  by host
| eval LastSeen=strftime(LastSeen, "%H:%M:%S")
| eval Status=if(Events>10, "✓ ONLINE", "⚠ LOW ACTIVITY")
| table host, Status, Events, LastSeen, Sources
| sort - Events]]></query>
          <earliest>-15m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </table>
    </panel>
  </row>
```


---

##### **Event Type Breakdown (Count by EventCode)**

![Dashboard4](Dashboard4.png)

**Purpose:** Understanding the _mix_ of data being collected.

- **Top Event Codes (Pie Chart):**
    
    - **Query:** `stats count by EventCode`
        
    - **Explanation:** Shows the noisiest events. If 90% of your logs are Event Code 4688 (Process Creation), you know the policy is working.

```xml
<row>
    <panel>
      <title>Top Event Codes (All Sources)</title>
      <chart>
        <search>
          <query>index=windows EventCode=* NOT (EventCode=1014 AND (QueryName="*msftncsi*" OR QueryName="*_msdcs*" OR QueryName="*_ldap*"))
| stats count by EventCode
| sort - count
| head 15</query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    
    <panel>
      <title>Sysmon Event Distribution</title>
      <chart>
        <search>
          <query><![CDATA[index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by EventCode
| eval EventType=case(
    EventCode=1, "Process Create",
    EventCode=3, "Network Connect",
    EventCode=5, "Process Terminate",
    EventCode=7, "Image Load",
    EventCode=8, "CreateRemoteThread",
    EventCode=10, "Process Access",
    EventCode=11, "File Create",
    EventCode=12, "Registry Create/Delete",
    EventCode=13, "Registry Value Set",
    EventCode=22, "DNS Query",
    1=1, "Other ("+EventCode+")")
| table EventType, count
| sort - count]]></query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.chart.stackMode">default</option>
      </chart>
    </panel>
  </row>
```


---

##### **Basic Security Monitoring (Failed vs. Successful Logons)**

![Dashboard5](Dashboard5.png)

**Purpose:** A quick look at authentication activity.

- **Failed Logons (4625):**
    
    - **Query:** `index=windows EventCode=4625`
- **Successful Logons (4624):**
    
    - **Query:** `Logon_Type!=3` removes "Network" logons (which are very noisy/frequent).

```xml
  <row>
    <panel>
      <title>⚠ Failed Logons (Event 4625)</title>
      <table>
        <search>
          <query><![CDATA[index=windows EventCode=4625
| eval Time=strftime(_time, "%H:%M:%S")
| stats count as Attempts, 
        latest(Time) as LastAttempt 
  by user, src_ip, host
| sort - Attempts
| head 20]]></query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <refresh>1m</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </table>
    </panel>
    
    <panel>
      <title>✓ Successful Logons (Event 4624)</title>
      <table>
        <search>
          <query><![CDATA[index=windows EventCode=4624 Logon_Type!=3
| eval Time=strftime(_time, "%H:%M:%S")
| stats count as Logons, 
        latest(Time) as LastLogon 
  by user, Logon_Type, host
| sort - Logons
| head 20]]></query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <refresh>1m</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </table>
    </panel>
  </row>
```


---

##### **Sysmon Deep Dive (Granular Event Data)**

![Dashboard6](Dashboard6.png)

**Purpose:** validating that SwiftOnSecurity's Sysmon config is catching the details.

- **Process Creation (Event 1):**
    
    - **The SPL Trick:** `eval ProcessName=mvindex(split(Image,"\\"),-1)`
        
    - **Explanation:** The raw log gives the full path: `C:\Windows\System32\cmd.exe`.
        
        - `split` chops it up by backslashes `\`.
            
        - `mvindex(..., -1)` grabs the _last_ item in that list (`cmd.exe`).
            
    - **Result:** A clean table showing just the program names running.
        
- **Network Connections (Event 3):**
    
    - **Explanation:** Shows which processes are talking to the network, the destination IP, and the Port. Crucial for spotting Command & Control (C2) beacons.

```xml
  <row>
    <panel>
      <title>Process Creation Activity (Sysmon Event 1)</title>
      <table>
        <search>
          <query><![CDATA[index=windows EventCode=1
| eval ProcessName=mvindex(split(Image,"\\"),-1)
| stats count as Executions, 
        values(User) as Users,
        dc(host) as Hosts
  by ProcessName
| sort - Executions
| head 15]]></query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
      </table>
    </panel>
    
    <panel>
      <title>Network Connections (Sysmon Event 3)</title>
      <table>
        <search>
          <query><![CDATA[index=windows EventCode=3
| eval ProcessName=mvindex(split(Image,"\\"),-1)
| stats count as Connections,
        values(DestinationIp) as Destinations,
        values(DestinationPort) as Ports
  by ProcessName, host
| sort - Connections
| head 15]]></query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
      </table>
    </panel>
  </row>
```


---

##### **File & Registry (Recent Changes)**

![Dashboard7](Dashboard7.png)

**Purpose:** Verifying file integrity monitoring.

- **File Creation (Event 11):**
    
    - **The SPL Trick:** `rex field=TargetFilename "\.(?<Extension>\w+)$"`
        
    - **Explanation:** Uses Regex to extract just the file extension (e.g., `.exe`, `.ps1`). This helps quickly see if executable files or scripts are being dropped on disk.
        
- **Registry Mods (Event 13):**
    
    - **Explanation:** Shows registry key modifications. This is often how malware establishes persistence (Auto-Run keys).

```xml
  <row>
    <panel>
      <title>File Creation Activity (Sysmon Event 11)</title>
      <table>
        <search>
          <query><![CDATA[index=windows EventCode=11
| eval FileName=mvindex(split(TargetFilename,"\\"),-1)
| rex field=TargetFilename "\.(?<Extension>\w+)$"
| stats count as Files,
        dc(TargetFilename) as UniqueFiles
  by Extension, host
| sort - Files
| head 15]]></query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
      </table>
    </panel>
    
    <panel>
      <title>Registry Modifications (Sysmon Event 13)</title>
      <table>
        <search>
          <query><![CDATA[index=windows EventCode=13
| eval ProcessName=mvindex(split(Image,"\\"),-1)
| stats count as Modifications,
        dc(TargetObject) as UniqueKeys
  by ProcessName, host
| sort - Modifications
| head 15]]></query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
      </table>
    </panel>
  </row>
```


---

##### **Active Directory Specific (DC Sanity Check)**

![Dashboard8](Dashboard8.png)

**Purpose:** Show the raw data feed from DC01/domain controller. It proves that logs are indexing _correctly_ with the right timestamp and fields.

```xml
  <row>
    <panel>
      <title>Domain Controller Activity (DC01)</title>
      <event>
        <search>
          <query>index=windows host="DC01*" 
| head 30</query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>1m</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="list.drilldown">none</option>
        <option name="list.wrap">1</option>
        <option name="maxLines">5</option>
        <option name="raw.drilldown">full</option>
        <option name="refresh.display">progressbar</option>
      </event>
    </panel>
  </row>
```

---

##### **Bottom Rows (Errors & Raw Stream)**

![Dashboard9](Dashboard9.png)

**Purpose:** Troubleshooting the lab itself.

- **System Errors & Warnings:**
    
    - **Query:** `EventType=Error OR EventType=Warning`
        
    - **Explanation:** If a service crashes or a driver fails, it appears here. 
        
- **Live Event Stream:**
    
    - **Query:** `head 50`
        
    - **Explanation:** Just shows the raw text of the last 50 logs. 

```xml
  <row>
    <panel>
      <title>⚠ System Errors &amp; Warnings</title>
      <table>
        <search>
          <query><![CDATA[index=windows (Type="Error" OR Type="Warning" OR Level=2 OR Level=3 OR Keywords="*Audit Failure*") NOT (EventCode=1014 AND (QueryName="*msftncsi*" OR QueryName="*_msdcs*" OR QueryName="*_ldap*"))
        | eval Time=strftime(_time, "%H:%M:%S")
        | eval Severity=coalesce(Type, LevelDisplayName, "Unknown")
        | stats count as Occurrences, 
                latest(Time) as LastSeen, 
                values(Message) as Details 
          by EventCode, Severity, host
        | sort - Occurrences
        | head 20]]></query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <refresh>1m</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Live Event Stream (Last 50 Events)</title>
      <event>
        <search>
          <query>index=windows NOT (EventCode=1014 AND (QueryName="*msftncsi*" OR QueryName="*_msdcs*" OR QueryName="*_ldap*"))
| head 50</query>
          <earliest>-15m@m</earliest>
          <latest>now</latest>
          <refresh>10s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="list.drilldown">full</option>
        <option name="list.wrap">1</option>
        <option name="maxLines">3</option>
        <option name="refresh.display">progressbar</option>
      </event>
    </panel>
  </row>
```


---

### **Full XML Code**

```xml
<dashboard version="1.1" theme="dark">
  <label>Homelab Pulse - Phase 2 Validation</label>
  <description>Real-time pipeline verification across all systems (Noise Filtered)</description>
  
  <row>
    <panel>
      <title>Total Events (Last Hour)</title>
      <single>
        <search>
          <query>index=windows NOT (EventCode=1014 AND (QueryName="*msftncsi*" OR QueryName="*_msdcs*" OR QueryName="*_ldap*"))
| stats count</query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0x65A637","0x6DB7C6","0xF7BC38","0xF58F39","0xD93F3C"]</option>
        <option name="rangeValues">[0,1000,5000,10000]</option>
        <option name="underLabel">Events Ingested (Clean)</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    
    <panel>
      <title>Active Hosts</title>
      <single>
        <search>
          <query>index=windows 
| stats dc(host) as unique_hosts</query>
          <earliest>-15m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0xD93F3C","0xF58F39","0x6DB7C6","0x65A637"]</option>
        <option name="rangeValues">[0,2,4]</option>
        <option name="underLabel">VMs Reporting</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    
    <panel>
      <title>Sysmon Events</title>
      <single>
        <search>
          <query>index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count</query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0xD93F3C","0xF7BC38","0x65A637"]</option>
        <option name="rangeValues">[0,500]</option>
        <option name="underLabel">Sysmon Activity</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    
    <panel>
      <title>Security Events</title>
      <single>
        <search>
          <query>index=windows source="*WinEventLog:Security"
| stats count</query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0xD93F3C","0xF7BC38","0x65A637"]</option>
        <option name="rangeValues">[0,1000]</option>
        <option name="underLabel">Security Logs</option>
        <option name="useColors">1</option>
      </single>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Event Volume by Host (Real-time)</title>
      <chart>
        <search>
          <query>index=windows NOT (EventCode=1014 AND (QueryName="*msftncsi*" OR QueryName="*_msdcs*" OR QueryName="*_ldap*"))
| timechart span=5m count by host</query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.legend.placement">right</option>
        <option name="refresh.display">progressbar</option>
      </chart>
    </panel>
    
    <panel>
      <title>Host Health Check</title>
      <table>
        <search>
          <query><![CDATA[index=windows NOT (EventCode=1014 AND (QueryName="*msftncsi*" OR QueryName="*_msdcs*" OR QueryName="*_ldap*")) earliest=-15m
| stats count as Events, 
        latest(_time) as LastSeen, 
        values(source) as Sources 
  by host
| eval LastSeen=strftime(LastSeen, "%H:%M:%S")
| eval Status=if(Events>10, "✓ ONLINE", "⚠ LOW ACTIVITY")
| table host, Status, Events, LastSeen, Sources
| sort - Events]]></query>
          <earliest>-15m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Top Event Codes (All Sources)</title>
      <chart>
        <search>
          <query>index=windows EventCode=* NOT (EventCode=1014 AND (QueryName="*msftncsi*" OR QueryName="*_msdcs*" OR QueryName="*_ldap*"))
| stats count by EventCode
| sort - count
| head 15</query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
    
    <panel>
      <title>Sysmon Event Distribution</title>
      <chart>
        <search>
          <query><![CDATA[index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by EventCode
| eval EventType=case(
    EventCode=1, "Process Create",
    EventCode=3, "Network Connect",
    EventCode=5, "Process Terminate",
    EventCode=7, "Image Load",
    EventCode=8, "CreateRemoteThread",
    EventCode=10, "Process Access",
    EventCode=11, "File Create",
    EventCode=12, "Registry Create/Delete",
    EventCode=13, "Registry Value Set",
    EventCode=22, "DNS Query",
    1=1, "Other ("+EventCode+")")
| table EventType, count
| sort - count]]></query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.chart.stackMode">default</option>
      </chart>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>⚠ Failed Logons (Event 4625)</title>
      <table>
        <search>
          <query><![CDATA[index=windows EventCode=4625
| eval Time=strftime(_time, "%H:%M:%S")
| stats count as Attempts, 
        latest(Time) as LastAttempt 
  by user, src_ip, host
| sort - Attempts
| head 20]]></query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <refresh>1m</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </table>
    </panel>
    
    <panel>
      <title>✓ Successful Logons (Event 4624)</title>
      <table>
        <search>
          <query><![CDATA[index=windows EventCode=4624 Logon_Type!=3
| eval Time=strftime(_time, "%H:%M:%S")
| stats count as Logons, 
        latest(Time) as LastLogon 
  by user, Logon_Type, host
| sort - Logons
| head 20]]></query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <refresh>1m</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Process Creation Activity (Sysmon Event 1)</title>
      <table>
        <search>
          <query><![CDATA[index=windows EventCode=1
| eval ProcessName=mvindex(split(Image,"\\"),-1)
| stats count as Executions, 
        values(User) as Users,
        dc(host) as Hosts
  by ProcessName
| sort - Executions
| head 15]]></query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
      </table>
    </panel>
    
    <panel>
      <title>Network Connections (Sysmon Event 3)</title>
      <table>
        <search>
          <query><![CDATA[index=windows EventCode=3
| eval ProcessName=mvindex(split(Image,"\\"),-1)
| stats count as Connections,
        values(DestinationIp) as Destinations,
        values(DestinationPort) as Ports
  by ProcessName, host
| sort - Connections
| head 15]]></query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>File Creation Activity (Sysmon Event 11)</title>
      <table>
        <search>
          <query><![CDATA[index=windows EventCode=11
| eval FileName=mvindex(split(TargetFilename,"\\"),-1)
| rex field=TargetFilename "\.(?<Extension>\w+)$"
| stats count as Files,
        dc(TargetFilename) as UniqueFiles
  by Extension, host
| sort - Files
| head 15]]></query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
      </table>
    </panel>
    
    <panel>
      <title>Registry Modifications (Sysmon Event 13)</title>
      <table>
        <search>
          <query><![CDATA[index=windows EventCode=13
| eval ProcessName=mvindex(split(Image,"\\"),-1)
| stats count as Modifications,
        dc(TargetObject) as UniqueKeys
  by ProcessName, host
| sort - Modifications
| head 15]]></query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Domain Controller Activity (DC01)</title>
      <event>
        <search>
          <query>index=windows host="DC01*" 
| head 30</query>
          <earliest>-60m@m</earliest>
          <latest>now</latest>
          <refresh>1m</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="list.drilldown">none</option>
        <option name="list.wrap">1</option>
        <option name="maxLines">5</option>
        <option name="raw.drilldown">full</option>
        <option name="refresh.display">progressbar</option>
      </event>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>⚠ System Errors &amp; Warnings</title>
      <table>
        <search>
          <query><![CDATA[index=windows (Type="Error" OR Type="Warning" OR Level=2 OR Level=3 OR Keywords="*Audit Failure*") NOT (EventCode=1014 AND (QueryName="*msftncsi*" OR QueryName="*_msdcs*" OR QueryName="*_ldap*"))
        | eval Time=strftime(_time, "%H:%M:%S")
        | eval Severity=coalesce(Type, LevelDisplayName, "Unknown")
        | stats count as Occurrences, 
                latest(Time) as LastSeen, 
                values(Message) as Details 
          by EventCode, Severity, host
        | sort - Occurrences
        | head 20]]></query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <refresh>1m</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Live Event Stream (Last 50 Events)</title>
      <event>
        <search>
          <query>index=windows NOT (EventCode=1014 AND (QueryName="*msftncsi*" OR QueryName="*_msdcs*" OR QueryName="*_ldap*"))
| head 50</query>
          <earliest>-15m@m</earliest>
          <latest>now</latest>
          <refresh>10s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="list.drilldown">full</option>
        <option name="list.wrap">1</option>
        <option name="maxLines">3</option>
        <option name="refresh.display">progressbar</option>
      </event>
    </panel>
  </row>
  
</dashboard>
```