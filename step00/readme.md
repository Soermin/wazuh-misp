## Step 00 - Custom Integration

- **Add Repository**

Dalam langkah pertama, anda bisa membuat/copy file `custom-misp` dan `custom-misp.py` kedalam direktori `/var/ossec/integration`

- **Fix Permission**
```
chown root:wazuh /var/ossec/integrations/custom-misp*
chmod 750 /var/ossec/integrations/custom-misp*
```

- **Add this config to `/var/ossec/etc/ossec.conf`**
```
  <integration>
    <name>custom-misp</name>
    <group>Integration,misp,misp_alert,Network,Network_Danger,Malware,audit_rule,sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck,recon,attack,web_scan,authenticat>
    <alert_format>json</alert_format>
  </integration>
```
