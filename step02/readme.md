## Step 02 - Testing

You have to test the system, to make sure your integration was succeed. 

- **Make file custom in your agent**

Make file custom in agent, example : 
```
echo "file_custom" > file01.txt
```

- **Take the hash**

Take the hash of file01.txt
```
md5sum file01.txt
```

and Add to MISP Event Custom

- **Make another file testing in agent**

Because the hash value works based on the contents of the file, we can create a new file with the same contents, so that the hash value is the same, and we can use this to test whether your integration is successfull of not.

```
echo "file_custom" > file02.txt
```

- **Troubleshooting**

You can trobleshoot, if you have problem by
```
tail -f /var/ossec/logs/ossec.log
```
or 

```
tail -f /var/ossec/logs/integrations.log
```


