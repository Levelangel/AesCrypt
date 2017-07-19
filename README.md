# AesCrypt
A simple Java class for encrypting and decrypting strings.  
*Well done at \*Unix/Windows/Mac OS*

## Installation
Mevan:

```xml
<dependency>
  <groupId>cn.opom</groupId>
  <artifactId>AesCrypt</artifactId>
  <version>1.0-SNAPSHOT</version>
  <type>pom</type>
</dependency>
```

## Quickstart

```java
import cn.opom.crypt.AesCrypt;

//String waitting for encrypting
String content = "This is a test content";
//Key for encrypting and decrypting content
String password = "abcd1234";

System.out.println("before:"+context);

String strEncrypt = AesCrypt.aesEncrypt(content,password,AesCrypt.KEYLEN256);
System.out.println("after encrypting:"+strEncrypt);

String strDecrypt = AesCrypt.aesDecrypt(strEncrypt,password,AesCrypt.KEYLEN256);
System.out.println("after decrypting:"+strDecrypt);
```

## Author
Maintained by Levelangel

## License
This project is open-source via the [MIT License](https://mit-license.org/).