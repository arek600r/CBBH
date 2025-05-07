# Blacklist Filters

There are generally two common forms of validating a file extension on the back-end:

    Testing against a blacklist of types
    Testing against a whitelist of types

Tip
```
The comparison above is also case-sensitive, and is only considering lowercase extensions. 
In Windows Servers, file names are case insensitive, so we may try uploading a php with a 
mixed-case (e.g. pHp),which may bypass the blacklist as well, and should still execute as a PHP script.
```

## Fuzzing Extensions
we can fuzz it via Burp with list like
* https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt

## Non-Blacklisted Extensions
*phtml
*pHp


# Whitelist Filters
A whitelist is generally more secure than a blacklist.

## Double Extensions
If the .jpg extension was allowed, we can add it in our uploaded file name and still end our filename with .php (e.g. shell.jpg.php), in which case we should be able to pass the whitelist test, while still uploading a PHP script that can execute PHP code.

* shell.jpg.php

## Reverse Double Extension

For example, second extension can by cutted

shell.php.jpg

## Character Injection

The following are some of the characters we may try injecting:

    %20
    %0a
    %00
    %0d0a
    /
    .\
    .
    …
    :

We can write a small bash script that generates all permutations of the file name, where the above characters would be injected before and after both the PHP and JPG extensions, as follows:

``` bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done

```

# Type Filters

## Content-Type
 If we change the file name to shell.jpg.phtml or shell.php.jpg, or even if we use shell.jpg with a web shell content, our upload will fail. As the file extension does not affect the error message, the web application must be testing the file content for type validation. As mentioned earlier, this can be either in the Content-Type Header or the File Content.

```bash
Nerx600e@htb[/htb]$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
Nerx600e@htb[/htb]$ cat web-all-content-types.txt | grep 'image/' > image-content-types.txt

```

### Notes
``` 
A file upload HTTP request has two Content-Type headers, one for the attached file (at the bottom), and one for the full request (at the top). 
We usually need to modify the file's Content-Type header, but in some cases the request will only contain the main Content-Type header (e.g. if the uploaded content was sent as POST data), in which case we will need to modify the main Content-Type header.
```

## MIME-Type
The second and more common type of file content validation is testing the uploaded file's MIME-Type. Multipurpose Internet Mail Extensions (MIME) is an internet standard that determines the type of a file through its general format and bytes structure.

### Tip
```
Many other image types have non-printable bytes for their file signatures, while a GIF image starts with ASCII printable bytes (as shown above), so it is the easiest to imitate. Furthermore, as the string GIF8 is common between both GIF signatures, it is usually enough to imitate a GIF image.
```