// XPC within one process: an anonymous listener, a client connected to
// it through its endpoint, and a message answered with a reply.

#include <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <xpc/xpc.h>

int main(void) {
    dispatch_queue_t q = dispatch_queue_create("gex.xpc", NULL);
    xpc_connection_t listener = xpc_connection_create(NULL, q);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t peer) {
        if (xpc_get_type(peer) != XPC_TYPE_CONNECTION) {
            return;
        }
        xpc_connection_set_event_handler(peer, ^(xpc_object_t msg) {
            if (xpc_get_type(msg) != XPC_TYPE_DICTIONARY) {
                return;
            }
            xpc_object_t reply = xpc_dictionary_create_reply(msg);
            xpc_dictionary_set_int64(reply, "sum", xpc_dictionary_get_int64(msg, "a") + xpc_dictionary_get_int64(msg, "b"));
            xpc_connection_send_message(peer, reply);
        });
        xpc_connection_resume(peer);
    });
    xpc_connection_resume(listener);

    xpc_endpoint_t ep = xpc_endpoint_create(listener);
    xpc_connection_t client = xpc_connection_create_from_endpoint(ep);
    xpc_connection_set_event_handler(client, ^(xpc_object_t e) {
    });
    xpc_connection_resume(client);
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_int64(msg, "a", 40);
    xpc_dictionary_set_int64(msg, "b", 2);
    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(client, msg);
    if (xpc_get_type(reply) != XPC_TYPE_DICTIONARY) {
        printf("xpc-anon no reply\n");
        return 1;
    }
    long long sum = xpc_dictionary_get_int64(reply, "sum");
    printf("xpc-anon %lld\n", sum);
    return sum == 42 ? 0 : 1;
}
