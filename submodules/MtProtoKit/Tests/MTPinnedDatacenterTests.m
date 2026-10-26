#import <XCTest/XCTest.h>

#import <MtProtoKit/MTApiEnvironment.h>
#import <MtProtoKit/MTDatacenterAddress.h>
#import <MtProtoKit/MTDatacenterAddressSet.h>
#import <MtProtoKit/MTTcpTransport.h>

#import "MTTestSupport.h"

static MTDatacenterAddressSet *pinnedAddressSet(NSString *ip, uint16_t port) {
    return [[MTDatacenterAddressSet alloc] initWithAddressList:@[
        [[MTDatacenterAddress alloc] initWithIp:ip port:port preferForMedia:false restrictToTcp:false cdn:false preferForProxy:false secret:nil]
    ]];
}

@interface MTPinnedDatacenterTests : XCTestCase
@end

@implementation MTPinnedDatacenterTests

- (void)testUnpinnedContextsKeepOrdinaryConfigurationUpdates {
    MTContext *context = MTTestMakeContext(false);
    MTDatacenterAddressSet *first = pinnedAddressSet(@"203.0.113.1", 443);
    MTDatacenterAddressSet *second = pinnedAddressSet(@"203.0.113.2", 443);
    [context updateAddressSetForDatacenterWithId:1 addressSet:first forceUpdateSchemes:false];
    [context updateAddressSetForDatacenterWithId:1 addressSet:second forceUpdateSchemes:false];
    [context updatePublicKeysForDatacenterWithId:1 publicKeys:@[@{@"key": @"ordinary-key"}]];

    XCTAssertFalse(context.hasPinnedDatacenterConfiguration);
    XCTAssertEqualObjects([context addressSetForDatacenterWithId:1].addressList, second.addressList);
    XCTAssertEqualObjects([context publicKeysForDatacenterWithId:1], (@[@{@"key": @"ordinary-key"}]));
}

- (void)testPinsExcludeCachedServerAndOverrideEndpointsAndKeys {
    MTContext *context = MTTestMakeContext(false);
    MTDatacenterAddressSet *untrusted = pinnedAddressSet(@"203.0.113.9", 443);
    MTDatacenterAddressSet *pinned = pinnedAddressSet(@"203.0.113.1", 8443);
    NSArray *pinnedKeys = @[@{@"key": @"pinned-key"}];
    [context setSeedAddressSetForDatacenterWithId:2 seedAddressSet:untrusted];
    [context updateAddressSetForDatacenterWithId:2 addressSet:untrusted forceUpdateSchemes:false];
    [context updatePublicKeysForDatacenterWithId:2 publicKeys:@[@{@"key": @"cached-key"}]];
    context.apiEnvironment.datacenterAddressOverrides = @{@1: untrusted.addressList.firstObject};
    [context setPinnedDatacenterAddresses:@{@1: pinned} publicKeys:@{@1: pinnedKeys}];

    // help.getConfig, backup discovery and cached manual schemes cannot widen the pins.
    [context updateAddressSetForDatacenterWithId:1 addressSet:untrusted forceUpdateSchemes:true];
    [context addAddressForDatacenterWithId:1 address:untrusted.addressList.firstObject];
    [context setSeedAddressSetForDatacenterWithId:2 seedAddressSet:untrusted];
    [context updatePublicKeysForDatacenterWithId:1 publicKeys:@[@{@"key": @"server-key"}]];
    [context updateTransportSchemeForDatacenterWithId:1 transportScheme:[[MTTransportScheme alloc] initWithTransportClass:[MTTcpTransport class] address:untrusted.addressList.firstObject media:false] media:false isProxy:false];

    XCTAssertEqualObjects([context knownDatacenterIds], (@[@1]));
    XCTAssertEqualObjects([context addressSetForDatacenterWithId:1].addressList, pinned.addressList);
    XCTAssertEqual([context addressSetForDatacenterWithId:2].addressList.count, 0u);
    XCTAssertEqualObjects([context publicKeysForDatacenterWithId:1], pinnedKeys);
    XCTAssertEqual([context publicKeysForDatacenterWithId:2].count, 0u);
    NSArray<MTTransportScheme *> *schemes = [context transportSchemesForDatacenterWithId:1 media:false enforceMedia:false isProxy:false];
    XCTAssertEqual(schemes.count, 1u);
    XCTAssertEqualObjects(schemes.firstObject.address, pinned.addressList.firstObject);
    XCTAssertEqual([context transportSchemesForDatacenterWithId:2 media:false enforceMedia:false isProxy:false].count, 0u);
}

- (void)testEmptyPinsKeepBootstrapClosed {
    MTContext *context = MTTestMakeContext(false);
    MTDatacenterAddressSet *cached = pinnedAddressSet(@"203.0.113.9", 443);
    [context updateAddressSetForDatacenterWithId:1 addressSet:cached forceUpdateSchemes:false];
    [context updatePublicKeysForDatacenterWithId:1 publicKeys:@[@{@"key": @"cached-key"}]];
    [context setPinnedDatacenterAddresses:@{} publicKeys:@{}];
    [context updateAddressSetForDatacenterWithId:1 addressSet:cached forceUpdateSchemes:true];
    [context updatePublicKeysForDatacenterWithId:1 publicKeys:@[@{@"key": @"server-key"}]];

    XCTAssertTrue(context.hasPinnedDatacenterConfiguration);
    XCTAssertEqual([context knownDatacenterIds].count, 0u);
    XCTAssertEqual([context addressSetForDatacenterWithId:1].addressList.count, 0u);
    XCTAssertEqual([context publicKeysForDatacenterWithId:1].count, 0u);
    XCTAssertEqual([context transportSchemesForDatacenterWithId:1 media:false enforceMedia:false isProxy:false].count, 0u);
}

- (void)testVerifiedConfigurationCanRotateEndpointsAndRSA {
    MTContext *context = MTTestMakeContext(false);
    MTDatacenterAddressSet *before = pinnedAddressSet(@"203.0.113.1", 443);
    MTDatacenterAddressSet *after = pinnedAddressSet(@"203.0.113.2", 8443);
    NSArray *newKeys = @[@{@"key": @"rotated-key"}];
    [context setPinnedDatacenterAddresses:@{@1: before} publicKeys:@{@1: @[@{@"key": @"old-key"}]}];
    [context setPinnedDatacenterAddresses:@{@1: after} publicKeys:@{@1: newKeys}];
    [context updateAddressSetForDatacenterWithId:1 addressSet:before forceUpdateSchemes:false];

    XCTAssertEqualObjects([context addressSetForDatacenterWithId:1].addressList, after.addressList);
    XCTAssertEqualObjects([context publicKeysForDatacenterWithId:1], newKeys);
}

@end
