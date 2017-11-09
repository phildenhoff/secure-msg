# secure-msg
*The number 1 way to message all your friends!*

You must add this snippet:

```
grant {
        permission java.security.AllPermission;
};
```


To the system policy file at 

```
java.home/lib/security/java.policy  (Solaris/Linux)
java.home\lib\security\java.policy  (Windows)
```

Note: java.home refers to the value of the system property named "java.home",
which specifies the directory that houses the runtime environment -- either the
jre directory in the Java SE Development Kit (JDK) or the top-level directory
of the Java SE Runtime Environment (JRE).
