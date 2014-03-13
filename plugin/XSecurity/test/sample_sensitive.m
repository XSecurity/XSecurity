// mis-detection
MutableDictionary *query = [NSMutableDictionary dictionary];

  [query setObject:(id)kSecClassGenericPassword forKey:(id)kSecClass];
  [query setObject:account forKey:(id)kSecAttrAccount];
  [query setObject:(id)kSecAttrAccessibleAlways forKey:(id)kSecAttrAccessible];
  [query setObject:[inputString dataUsingEncoding:NSUTF8StringEncoding] forKey:(id)kSecValueData];
 
  OSStatus error = SecItemAdd((CFDictionaryRef)query, NULL);

// sample 19
NSUserDefaults *credentials = [NSUserDefaults standardUserDefaults];
[credentials setObject:self.username.text forKey:@"username"];
[credentials setObject:self.password.text forKey:@"password"];
[credentials synchronize];


// sample 20
NSString *name =[[NSUserDefaults standardUserDefaults] stringForKey: USERNAME] ; 
