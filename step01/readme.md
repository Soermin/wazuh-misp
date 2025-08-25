## Step 01 - Make Custom Rule 

In this step, we only make a custom rule for triger the alert.

- **Add Repository**

Make file `custom-rule.xml` `/var/ossec/etc/rules`. You can customize the file name because by default wazuh will read all `.xml` files in the `/var/ossec/etc/rules`


- **Change Debug Value**

For trobleshooting, we have to change the debug value in `/var/ossec/etc/internal-options.conf`. Search `integrator.debug = 0` change to `integrator.debug=2`


**Next to Step 02.......**