#import <XCTest/XCTest.h>

#import <MtProtoKit/MTApiEnvironment.h>
#import <MtProtoKit/MTIncomingMessage.h>
#import <MtProtoKit/MTMessageTransaction.h>
#import <MtProtoKit/MTOutgoingMessage.h>
#import <MtProtoKit/MTRequest.h>
#import <MtProtoKit/MTRequestContext.h>
#import <MtProtoKit/MTRequestMessageService.h>

#import "MTTestSupport.h"
#import "MTRpcResultMessage.h"

// Observe the wake-up itself: manually asking the service for a retry transaction alone
// would pass even when an idle TCP connection never sends that transaction.
@interface MTInitializationRetryProto : MTProto
@property (atomic) NSUInteger transactionRequests;
@end

@implementation MTInitializationRetryProto
- (void)requestTransportTransaction {
    self.transactionRequests += 1;
}
@end

@interface MTInitializationRetryTests : XCTestCase
@end

@implementation MTInitializationRetryTests

- (void)checkInitializationRetryForConstructor:(int32_t)constructor name:(NSString *)name {
    MTContext *context = MTTestMakeContext(true);
    MTDatacenterAuthInfo *authInfo = [MTTestMakeAuthInfo() withUpdatedAuthKeyAttributes:@{
        @"apiInitializationHash": context.apiEnvironment.apiInitializationHash
    }];
    [context updateAuthInfoForDatacenterWithId:1 authInfo:authInfo selector:MTDatacenterAuthInfoSelectorEphemeralMain];
    MTInitializationRetryProto *proto = [[MTInitializationRetryProto alloc] initWithContext:context datacenterId:1 usageCalculationInfo:nil requiredAuthToken:nil authTokenMasterDatacenterId:0];
    [proto pause];
    MTRequestMessageService *service = [[MTRequestMessageService alloc] initWithContext:context];
    [proto addMessageService:service];
    MTTestOnManagerQueue(^{});

    int32_t words[] = { (int32_t)0xfb8f651a, 1, constructor };
    NSData *payload = [NSData dataWithBytes:words length:sizeof(words)];
    MTRequest *request = [[MTRequest alloc] init];
    [request setPayload:payload metadata:name shortMetadata:name responseParser:^id(NSData *data) { return data; }];
    request.shouldContinueExecutionWithErrorContext = ^bool(__unused MTRequestErrorContext *errorContext) {
        return false; // The raw Blah request policy must not suppress protocol recovery.
    };
    __block bool completed = false;
    request.completed = ^(__unused id result, __unused MTRequestResponseInfo *info, __unused MTRpcError *error) {
        completed = true;
    };
    [service addRequest:request];
    MTTestOnManagerQueue(^{
        MTMessageTransaction *first = [service mtProtoMessageTransaction:proto authInfoSelector:MTDatacenterAuthInfoSelectorEphemeralMain sessionInfo:nil scheme:nil];
        XCTAssertEqual(first.messagePayload.count, 1u);
        XCTAssertEqualObjects(((MTOutgoingMessage *)first.messagePayload.firstObject).data, payload);
        request.requestContext = [[MTRequestContext alloc] initWithMessageId:4000 messageSeqNo:1 transactionId:@1 quickAckId:0];
        request.mayHaveReachedServer = true;
    });
    NSUInteger before = proto.transactionRequests;

    NSMutableData *errorData = [[NSMutableData alloc] init];
    int32_t errorWords[] = { (int32_t)0x2144ca19, 400 };
    [errorData appendBytes:errorWords length:sizeof(errorWords)];
    NSData *text = [@"CONNECTION_NOT_INITED" dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t length = (uint8_t)text.length;
    [errorData appendBytes:&length length:1];
    [errorData appendData:text];
    while (errorData.length % 4 != 0) {
        uint8_t zero = 0;
        [errorData appendBytes:&zero length:1];
    }
    MTRpcResultMessage *result = [[MTRpcResultMessage alloc] initWithRequestMessageId:4000 data:errorData];
    MTIncomingMessage *message = [[MTIncomingMessage alloc] initWithMessageId:4001 seqNo:1 authKeyId:0 sessionId:0 salt:0 timestamp:0 size:(NSInteger)errorData.length body:result];
    MTTestOnManagerQueue(^{
        [service mtProto:proto receivedMessage:message authInfoSelector:MTDatacenterAuthInfoSelectorEphemeralMain networkType:0];
    });
    XCTAssertTrue(MTTestWaitUntil(2.0, ^bool{ return proto.transactionRequests > before; }), @"an idle TCP request must be woken without another RPC or timer");
    MTTestOnManagerQueue(^{
        XCTAssertFalse(completed);
        XCTAssertNil(request.requestContext);
        XCTAssertNil(request.errorContext);
        MTDatacenterAuthInfo *updated = [context authInfoForDatacenterWithId:1 selector:MTDatacenterAuthInfoSelectorEphemeralMain];
        XCTAssertNil(updated.authKeyAttributes[@"apiInitializationHash"]);
        XCTAssertEqual(updated.authKeyId, authInfo.authKeyId, @"clearing initialization is not a key replacement");
        MTMessageTransaction *retry = [service mtProtoMessageTransaction:proto authInfoSelector:MTDatacenterAuthInfoSelectorEphemeralMain sessionInfo:nil scheme:nil];
        XCTAssertEqual(retry.messagePayload.count, 1u);
        NSData *bytes = ((MTOutgoingMessage *)retry.messagePayload.firstObject).data;
        XCTAssertGreaterThan(bytes.length, payload.length + 12);
        if (bytes.length > payload.length + 12) {
            int32_t layer = 0;
            int32_t initialization = 0;
            [bytes getBytes:&layer range:NSMakeRange(0, 4)];
            [bytes getBytes:&initialization range:NSMakeRange(8, 4)];
            XCTAssertEqual(layer, (int32_t)0xda9b0d0d);
            XCTAssertEqual(initialization, (int32_t)0xc1cd5ea9);
            XCTAssertEqualObjects([bytes subdataWithRange:NSMakeRange(bytes.length - payload.length, payload.length)], payload);
        }
    });
    [proto stop];
}

- (void)testChallengeIsWokenAndWrappedAfterConnectionNotInited {
    [self checkInitializationRetryForConstructor:(int32_t)0xdceefd53 name:@"blah.requestIdentityChallenge"];
}

- (void)testProofIsWokenAndWrappedAfterConnectionNotInited {
    [self checkInitializationRetryForConstructor:(int32_t)0x61b4c668 name:@"blah.invokeWithIdentityProof"];
}

@end
