## Step 03 - Active-response 

We can do many custom **active-response** on wazuh. But on the basic active-response, we can activate it to block brute force attacks.

Add configuration in /var/ossec/etc/ossec.conf

```
  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>
```

```
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100622,5705,5712,120100,5763</rules_id> #rule abou ssh access 
    <timeout>864001</timeout>
  </active-response>

```

In basically, active-response works by rule id. Simply, if rule id (100622/5705/....) was trigered the active-response will be activated by command `firewall-drop`. 

You have to read the local rules from wazuh in `/var/ossec/ruleset/rules/`, so that you can create many active response, because basically active-respone or custom rules, will be triggered from the basic rule of wazuh. 

