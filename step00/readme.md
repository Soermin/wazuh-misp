## Step 00 - Custom Integration

- **Add Repository**

In the first step, you can create/copy the `custom-misp` and `custom-misp.py` files into the `/var/ossec/integration` directory.

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

- **Edit `custom-misp.py`**

Do not forget to change some configuration in `custom-misp.py`

```
misp_base_url = "your-misp-url"
misp_api_auth_key = "your-misp-auth-key"
```

Next to Step 01.......