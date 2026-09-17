#import <BlahBranding/BlahBranding.h>

NSString *BlahBrandedString(NSString *value) {
    static NSRegularExpression *pattern;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        pattern = [NSRegularExpression regularExpressionWithPattern:
            @"(?:https?://|tg://|@)[^\\s<>\"\\])]+|(?<![\\p{L}\\p{N}_./])(?:(?:Telegram|Blah)\\s+Premium|Premium|Telegram)(?![\\p{L}\\p{N}_]|\\.[\\p{L}\\p{N}])"
            options:0 error:NULL];
    });
    NSArray<NSTextCheckingResult *> *matches = [pattern matchesInString:value options:0 range:NSMakeRange(0, value.length)];
    if (matches.count == 0) {
        return value;
    }
    NSMutableString *result = [value mutableCopy];
    for (NSTextCheckingResult *match in matches.reverseObjectEnumerator) {
        NSString *word = [value substringWithRange:match.range];
        if ([word hasPrefix:@"@"] || [word containsString:@"://"]) {
            continue;
        }
        [result replaceCharactersInRange:match.range withString:[word hasSuffix:@"Premium"] ? @"Blah Beyond" : @"Blah"];
    }
    return result;
}

NSString *BlahBrandedImageName(NSString *name) {
    static NSSet<NSString *> *logos;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        logos = [NSSet setWithArray:@[@"Chat/Links/QrLogo", @"Share/QrPlaneIcon", @"Call/CallTitleLogo", @"Call/CallKitLogo"]];
    });
    return [logos containsObject:name] ? @"Blah/LoginLogo" : name;
}
