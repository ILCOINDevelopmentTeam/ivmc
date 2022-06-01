// IVMC: Ethereum Client-VM Connector API.
// Copyright 2019-2022 The IVMC Authors.

#include "deamon.h"
#include "univalue_escapes.h"
#include "common.h"

#include <CLI/CLI.hpp>
#include <ivmc/ivmc.hpp>
#include <ivmc/hex.hpp>
#include <ivmc/loader.h>
#include <ivmc/tooling.hpp>
#include <fstream>

#include <dirent.h>
#include <iterator>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <iostream>
#include <string>
#include <syslog.h>
#include <unistd.h>
#include <vector>
#include <utility>        // std::pair
#include <map>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <future>

#include <ios>
#include <memory> // for unique_ptr
#include <functional>
#include <cassert>
#include <set>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_upper()
#include <boost/algorithm/string.hpp> // boost::trim
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/chrono/chrono.hpp>

#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/assert.hpp>
#include <boost/test/unit_test.hpp>

#include "random.h"
#include "compat.h"
#include "util.h"             // for LogPrint()
#include "support/cleanse.h"

#include <stdlib.h>
#include <limits>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <assert.h>
#include <algorithm>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/time.h>

// --------------------------------- StartHTTPServer
/** HTTP request work item */
class HTTPWorkItem : public HTTPClosure
{
public:
    HTTPWorkItem(std::unique_ptr<HTTPRequest> _req, const std::string &_path, const HTTPRequestHandler& _func):
        req(std::move(_req)), path(_path), func(_func)
    {
    }
    void operator()()
    {
        func(req.get(), path);
    }

    std::unique_ptr<HTTPRequest> req;

private:
    std::string path;
    HTTPRequestHandler func;
};

/** Simple work queue for distributing work over multiple threads.
 * Work items are simply callable objects.
 */
template <typename WorkItem>
class WorkQueue
{
private:
    /** Mutex protects entire object */
    std::mutex cs;
    std::condition_variable cond;
    std::deque<std::unique_ptr<WorkItem>> queue;
    bool running;
    size_t maxDepth;
    int numThreads;

    /** RAII object to keep track of number of running worker threads */
    class ThreadCounter
    {
    public:
        WorkQueue &wq;
        ThreadCounter(WorkQueue &w): wq(w)
        {
            std::lock_guard<std::mutex> lock(wq.cs);
            wq.numThreads += 1;
        }
        ~ThreadCounter()
        {
            std::lock_guard<std::mutex> lock(wq.cs);
            wq.numThreads -= 1;
            wq.cond.notify_all();
        }
    };

public:
    WorkQueue(size_t _maxDepth) : running(true),
                                 maxDepth(_maxDepth),
                                 numThreads(0)
    {
    }
    /** Precondition: worker threads have all stopped
     * (call WaitExit)
     */
    ~WorkQueue()
    {
    }
    /** Enqueue a work item */
    bool Enqueue(WorkItem* item)
    {
        std::unique_lock<std::mutex> lock(cs);
        if (queue.size() >= maxDepth) {
            return false;
        }
        queue.emplace_back(std::unique_ptr<WorkItem>(item));
        cond.notify_one();
        return true;
    }
    /** Thread function */
    void Run()
    {
        ThreadCounter count(*this);
        while (true) {
            std::unique_ptr<WorkItem> i;
            {
                std::unique_lock<std::mutex> lock(cs);
                while (running && queue.empty())
                    cond.wait(lock);
                if (!running)
                    break;
                i = std::move(queue.front());
                queue.pop_front();
            }
            (*i)();
        }
    }
    /** Interrupt and exit loops */
    void Interrupt()
    {
        std::unique_lock<std::mutex> lock(cs);
        running = false;
        cond.notify_all();
    }
    /** Wait for worker threads to exit */
    void WaitExit()
    {
        std::unique_lock<std::mutex> lock(cs);
        while (numThreads > 0)
            cond.wait(lock);
    }

    /** Return current depth of queue */
    size_t Depth()
    {
        std::unique_lock<std::mutex> lock(cs);
        return queue.size();
    }
};

struct HTTPPathHandler
{
    HTTPPathHandler() {}
    HTTPPathHandler(std::string _prefix, bool _exactMatch, HTTPRequestHandler _handler):
        prefix(_prefix), exactMatch(_exactMatch), handler(_handler)
    {
    }
    std::string prefix;
    bool exactMatch;
    HTTPRequestHandler handler;
};

//! libevent event loop
static struct event_base* eventBase = 0;
//! HTTP server
struct evhttp* eventHTTP = 0;
//! Work queue for handling longer requests off the event loop thread
static WorkQueue<HTTPClosure>* workQueue = 0;
//! Handlers for (sub)paths
std::vector<HTTPPathHandler> pathHandlers;
//! Bound listening sockets
std::vector<evhttp_bound_socket *> boundSockets;

CRPCTable tableRPC;

/** Check if a network address is allowed to access the HTTP server */
static bool ClientAllowed()
{
    return true;
}

/** Initialize ACL list for HTTP server */
static bool InitHTTPAllowList()
{
    return true;
}

/** HTTP request method as string - use for logging only */
static std::string RequestMethodString(HTTPRequest::RequestMethod m)
{
    switch (m) {
    case HTTPRequest::GET:
        return "GET";
        break;
    case HTTPRequest::POST:
        return "POST";
        break;
    case HTTPRequest::HEAD:
        return "HEAD";
        break;
    case HTTPRequest::PUT:
        return "PUT";
        break;
    default:
        return "unknown";
    }
}

/** HTTP request callback */
static void http_request_cb(struct evhttp_request* req, void* arg)
{
    std::unique_ptr<HTTPRequest> hreq(new HTTPRequest(req));
    syslog(LOG_NOTICE, ("Received a " + RequestMethodString(hreq->GetRequestMethod()) + " request for " + hreq->GetURI()).c_str());
    // Early reject unknown HTTP methods
    if (hreq->GetRequestMethod() == HTTPRequest::UNKNOWN) {
        hreq->WriteReply(HTTP_BADMETHOD);
        return;
    }

    // Find registered handler for prefix
    std::string strURI = hreq->GetURI();
    std::string path;
    std::vector<HTTPPathHandler>::const_iterator i = pathHandlers.begin();
    std::vector<HTTPPathHandler>::const_iterator iend = pathHandlers.end();
    for (; i != iend; ++i) {
        bool match = false;
        if (i->exactMatch)
            match = (strURI == i->prefix);
        else
            match = (strURI.substr(0, i->prefix.size()) == i->prefix);
        if (match) {
            path = strURI.substr(i->prefix.size());
            break;
        }
    }

    // Dispatch to worker thread
    if (i != iend) {
        std::unique_ptr<HTTPWorkItem> item(new HTTPWorkItem(std::move(hreq), path, i->handler));
        assert(workQueue);
        if (workQueue->Enqueue(item.get()))
            item.release(); // if true, queue took ownership
        else {
            syslog(LOG_WARNING, "WARNING: request rejected because http work queue depth exceeded, it can be increased with the -rpcworkqueue= setting");
            item->req->WriteReply(HTTP_INTERNAL, "Work queue depth exceeded");
        }
    } else {
        hreq->WriteReply(HTTP_NOTFOUND);
    }
}

/** Callback to reject HTTP requests after shutdown. */
static void http_reject_request_cb(struct evhttp_request* req, void*)
{
    syslog(LOG_NOTICE, "http: Rejecting request while shutting down.");
    evhttp_send_error(req, HTTP_SERVUNAVAIL, NULL);
}

void RenameThread(const char* name)
{
#if defined(PR_SET_NAME)
    // Only the first 15 characters are used (16 - NUL terminator)
    ::prctl(PR_SET_NAME, name, 0, 0, 0);
#elif (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
    pthread_set_name_np(pthread_self(), name);

#elif defined(MAC_OSX)
    pthread_setname_np(name);
#else
    // Prevent warnings for unused parameters...
    (void)name;
#endif
}

/** Event dispatcher thread */
static bool ThreadHTTP(struct event_base* base, struct evhttp* http)
{
    RenameThread("ilcoin-http");
    syslog(LOG_NOTICE, "http: Entering http event loop.");
    event_base_dispatch(base);
    // Event loop will be interrupted by InterruptHTTPServer()
    syslog(LOG_NOTICE, "http: Exited http event loop.");
    return event_base_got_break(base) == 0;
}

/** Bind HTTP server to specified addresses */
static bool HTTPBindAddresses(struct evhttp* http)
{
    int defaultPort = DEFAULT_PORT;
    std::vector<std::pair<std::string, uint16_t> > endpoints;

    // Determine what addresses to bind to
    endpoints.push_back(std::make_pair("::1", defaultPort));
    endpoints.push_back(std::make_pair("127.0.0.1", defaultPort));

    // Bind addresses
    for (std::vector<std::pair<std::string, uint16_t> >::iterator i = endpoints.begin(); i != endpoints.end(); ++i) {
        syslog(LOG_NOTICE, ("http: Binding RPC on address " + i->first + " port " + std::to_string(i->second) + ".").c_str());
        evhttp_bound_socket *bind_handle = evhttp_bind_socket_with_handle(http, i->first.empty() ? NULL : i->first.c_str(), i->second);
        if (bind_handle) {
            boundSockets.push_back(bind_handle);
        } else {
            syslog(LOG_ERR, ("Binding RPC on address " + i->first + " port " + std::to_string(i->second) + " failed.").c_str());
        }
    }
    return !boundSockets.empty();
}

/** Simple wrapper to set thread name and run work queue */
static void HTTPWorkQueueRun(WorkQueue<HTTPClosure>* queue)
{
    RenameThread("ilcoin-httpworker");
    queue->Run();
}

/** libevent event log callback */
static void libevent_log_cb(int severity, const char *msg)
{
#ifndef EVENT_LOG_WARN
// EVENT_LOG_WARN was added in 2.0.19; but before then _EVENT_LOG_WARN existed.
# define EVENT_LOG_WARN _EVENT_LOG_WARN
#endif
  if (severity >= EVENT_LOG_WARN) // Log warn messages and higher without debug category
      syslog(LOG_NOTICE, msg);
  else syslog(LOG_NOTICE, msg);
}

bool InitHTTPServer()
{
    struct evhttp* http = 0;
    struct event_base* base = 0;

    if (!InitHTTPAllowList())
        return false;

    evthread_use_pthreads();

    base = event_base_new(); // XXX RAII
    if (!base) {
        syslog(LOG_ERR, "Couldn't create an event_base: exiting");
        return false;
    }

    /* Create a new evhttp object to handle requests. */
    http = evhttp_new(base); // XXX RAII
    if (!http) {
        syslog(LOG_ERR, "couldn't create evhttp. Exiting.");
        event_base_free(base);
        return false;
    }

    evhttp_set_timeout(http, DEFAULT_HTTP_SERVER_TIMEOUT);
    evhttp_set_max_headers_size(http, MAX_HEADERS_SIZE);
    evhttp_set_max_body_size(http, MAX_SIZE);
    evhttp_set_gencb(http, http_request_cb, NULL);

    if (!HTTPBindAddresses(http)) {
        syslog(LOG_ERR, "Unable to bind any endpoint for RPC server");
        evhttp_free(http);
        event_base_free(base);
        return false;
    }

    syslog(LOG_NOTICE, "http: Initialized HTTP server.");
    int workQueueDepth = std::max((long)DEFAULT_HTTP_WORKQUEUE, 1L);
    syslog(LOG_NOTICE, ("http: creating work queue of depth " + std::to_string(workQueueDepth)).c_str());

    workQueue = new WorkQueue<HTTPClosure>(workQueueDepth);
    eventBase = base;
    eventHTTP = http;
    return true;
}

std::thread threadHTTP;
std::future<bool> threadResult;

bool StartHTTPServer()
{
    syslog(LOG_NOTICE, "http: Starting HTTP server.");
    int rpcThreads = std::max((long)DEFAULT_HTTP_THREADS, 1L);
    syslog(LOG_NOTICE, ("http: starting " + std::to_string(rpcThreads) + " worker threads.").c_str());
    std::packaged_task<bool(event_base*, evhttp*)> task(ThreadHTTP);
    threadResult = task.get_future();
    threadHTTP = std::thread(std::move(task), eventBase, eventHTTP);

    for (int i = 0; i < rpcThreads; i++) {
        std::thread rpc_worker(HTTPWorkQueueRun, workQueue);
        rpc_worker.detach();
    }
    return true;
}

void InterruptHTTPServer()
{
    syslog(LOG_NOTICE, "http: Interrupting HTTP server.");
    if (eventHTTP) {
        // Unlisten sockets
        for (evhttp_bound_socket *socket : boundSockets) {
            evhttp_del_accept_socket(eventHTTP, socket);
        }
        // Reject requests on current connections
        evhttp_set_gencb(eventHTTP, http_reject_request_cb, NULL);
    }
    if (workQueue)
        workQueue->Interrupt();
}

void StopHTTPServer()
{
    syslog(LOG_NOTICE, "http: Stopping HTTP server.");
    if (workQueue) {
        syslog(LOG_NOTICE, "http: Waiting for HTTP worker threads to exit.");
        workQueue->WaitExit();
        delete workQueue;
    }
    if (eventBase) {
        syslog(LOG_NOTICE, "Waiting for HTTP event thread to exit.");
        // Give event loop a few seconds to exit (to send back last RPC responses), then break it
        // Before this was solved with event_base_loopexit, but that didn't work as expected in
        // at least libevent 2.0.21 and always introduced a delay. In libevent
        // master that appears to be solved, so in the future that solution
        // could be used again (if desirable).
        // (see discussion in https://github.com/ilcoin/ilcoin/pull/6990)
        if (threadResult.valid() && threadResult.wait_for(std::chrono::milliseconds(2000)) == std::future_status::timeout) {
            syslog(LOG_NOTICE, "HTTP event loop did not exit within allotted time, sending loopbreak.");
            event_base_loopbreak(eventBase);
        }
        threadHTTP.join();
    }
    if (eventHTTP) {
        evhttp_free(eventHTTP);
        eventHTTP = 0;
    }
    if (eventBase) {
        event_base_free(eventBase);
        eventBase = 0;
    }
    syslog(LOG_NOTICE, "Stopped HTTP server.");
}

struct event_base* EventBase()
{
    return eventBase;
}

static void httpevent_callback_fn(evutil_socket_t, short, void* data)
{
    // Static handler: simply call inner handler
    HTTPEvent *self = ((HTTPEvent*)data);
    self->handler();
    if (self->deleteWhenTriggered)
        delete self;
}

HTTPEvent::HTTPEvent(struct event_base* base, bool _deleteWhenTriggered, const std::function<void(void)>& _handler): deleteWhenTriggered(_deleteWhenTriggered), handler(_handler)
{
    ev = event_new(base, -1, 0, httpevent_callback_fn, this);
    assert(ev);
}

HTTPEvent::~HTTPEvent()
{
    event_free(ev);
}

void HTTPEvent::trigger(struct timeval* tv)
{
    if (tv == NULL)
        event_active(ev, 0, 0); // immediately trigger event in main thread
    else
        evtimer_add(ev, tv); // trigger after timeval passed
}

HTTPRequest::HTTPRequest(struct evhttp_request* _req) : req(_req), replySent(false)
{
}

HTTPRequest::~HTTPRequest()
{
    if (!replySent) {
        // Keep track of whether reply was sent to avoid request leaks
        syslog(LOG_ERR, "HTTPRequest(): Unhandled request");
        WriteReply(HTTP_INTERNAL, "Unhandled request");
    }
    // evhttpd cleans up the request, as long as a reply was sent.
}

std::pair<bool, std::string> HTTPRequest::GetHeader(const std::string &hdr)
{
    const struct evkeyvalq* headers = evhttp_request_get_input_headers(req);
    assert(headers);
    const char* val = evhttp_find_header(headers, hdr.c_str());
    if (val)
        return std::make_pair(true, val);
    else
        return std::make_pair(false, "");
}

std::string HTTPRequest::ReadBody()
{
    struct evbuffer* buf = evhttp_request_get_input_buffer(req);
    if (!buf)
        return "";
    size_t size = evbuffer_get_length(buf);
    /** Trivial implementation: if this is ever a performance bottleneck,
     * internal copying can be avoided in multi-segment buffers by using
     * evbuffer_peek and an awkward loop. Though in that case, it'd be even
     * better to not copy into an intermediate string but use a stream
     * abstraction to consume the evbuffer on the fly in the parsing algorithm.
     */
    const char* data = (const char*)evbuffer_pullup(buf, size);
    if (!data) // returns NULL in case of empty buffer
        return "";
    std::string rv(data, size);
    evbuffer_drain(buf, size);
    return rv;
}

void HTTPRequest::WriteHeader(const std::string &hdr, const std::string &value)
{
    struct evkeyvalq* headers = evhttp_request_get_output_headers(req);
    assert(headers);
    evhttp_add_header(headers, hdr.c_str(), value.c_str());
}

/** Closure sent to main thread to request a reply to be sent to
 * a HTTP request.
 * Replies must be sent in the main loop in the main http thread,
 * this cannot be done from worker threads.
 */
void HTTPRequest::WriteReply(int nStatus, const std::string &strReply)
{
    assert(!replySent && req);
    // Send event to main http thread to send reply message
    struct evbuffer* evb = evhttp_request_get_output_buffer(req);
    assert(evb);
    evbuffer_add(evb, strReply.data(), strReply.size());
    HTTPEvent* ev = new HTTPEvent(eventBase, true,
        std::bind(evhttp_send_reply, req, nStatus, (const char*)NULL, (struct evbuffer *)NULL));
    ev->trigger(0);
    replySent = true;
    req = 0; // transferred back to main thread
}

std::string HTTPRequest::GetURI()
{
    return evhttp_request_get_uri(req);
}

HTTPRequest::RequestMethod HTTPRequest::GetRequestMethod()
{
    switch (evhttp_request_get_command(req)) {
    case EVHTTP_REQ_GET:
        return GET;
        break;
    case EVHTTP_REQ_POST:
        return POST;
        break;
    case EVHTTP_REQ_HEAD:
        return HEAD;
        break;
    case EVHTTP_REQ_PUT:
        return PUT;
        break;
    default:
        return UNKNOWN;
        break;
    }
}

void RegisterHTTPHandler(const std::string &prefix, bool exactMatch, const HTTPRequestHandler &handler)
{
    syslog(LOG_NOTICE, ("http: Registering HTTP handler for " + prefix + " (exactmatch " + std::to_string(exactMatch) + ")").c_str());
    pathHandlers.push_back(HTTPPathHandler(prefix, exactMatch, handler));
}

void UnregisterHTTPHandler(const std::string &prefix, bool exactMatch)
{
    std::vector<HTTPPathHandler>::iterator i = pathHandlers.begin();
    std::vector<HTTPPathHandler>::iterator iend = pathHandlers.end();
    for (; i != iend; ++i)
        if (i->prefix == prefix && i->exactMatch == exactMatch)
            break;
    if (i != iend)
    {
        syslog(LOG_NOTICE, ("http: Unregistering HTTP handler for " + prefix + " (exactmatch " + std::to_string(exactMatch) + ")").c_str());
        pathHandlers.erase(i);
    }
}

// --------------------------------- StartRPC
static bool fRPCRunning = false;
static bool fRPCInWarmup = true;
static std::string rpcWarmupStatus("RPC server started");
static CCriticalSection cs_rpcWarmup;
/* Map of name to timer. */
// static std::map<std::string, std::unique_ptr<RPCTimerBase> > deadlineTimers;

const UniValue NullUniValue;

const signed char p_util_hexdigit[256] =
{ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, };

signed char HexDigit(char c)
{
    return p_util_hexdigit[(unsigned char)c];
}

bool IsHex(const std::string &str)
{
    for(std::string::const_iterator it(str.begin()); it != str.end(); ++it)
    {
        if (HexDigit(*it) < 0)
            return false;
    }
    return (str.size() > 0) && (str.size()%2 == 0);
}

std::vector<unsigned char> ParseHex(const char* psz)
{
    // convert hex dump to std::vector
    std::vector<unsigned char> vch;
    while (true)
    {
        while (isspace(*psz))
            psz++;
        signed char c = HexDigit(*psz++);
        if (c == (signed char)-1)
            break;
        unsigned char n = (c << 4);
        c = HexDigit(*psz++);
        if (c == (signed char)-1)
            break;
        n |= c;
        vch.push_back(n);
    }
    return vch;
}

std::vector<unsigned char> ParseHex(const std::string& str)
{
    return ParseHex(str.c_str());
}

static inline bool json_isspace(int ch)
{
    switch (ch) {
    case 0x20:
    case 0x09:
    case 0x0a:
    case 0x0d:
        return true;

    default:
        return false;
    }

    // not reached
}

static bool json_isdigit(int ch)
{
    return ((ch >= '0') && (ch <= '9'));
}

static bool ParsePrechecks(const std::string& str)
{
    if (str.empty()) // No empty string allowed
        return false;
    if (str.size() >= 1 && (json_isspace(str[0]) || json_isspace(str[str.size()-1]))) // No padding allowed
        return false;
    if (str.size() != strlen(str.c_str())) // No embedded NUL characters allowed
        return false;
    return true;
}

bool ParseInt32(const std::string& str, int32_t *out)
{
    if (!ParsePrechecks(str))
        return false;
    char *endp = NULL;
    errno = 0; // strtol will not set errno if valid
    long int n = strtol(str.c_str(), &endp, 10);
    if(out) *out = (int32_t)n;
    // Note that strtol returns a *long int*, so even if strtol doesn't report a over/underflow
    // we still have to check that the returned value is within the range of an *int32_t*. On 64-bit
    // platforms the size of these types may be different.
    return endp && *endp == 0 && !errno &&
        n >= std::numeric_limits<int32_t>::min() &&
        n <= std::numeric_limits<int32_t>::max();
}

bool ParseInt64(const std::string& str, int64_t *out)
{
    if (!ParsePrechecks(str))
        return false;
    char *endp = NULL;
    errno = 0; // strtoll will not set errno if valid
    long long int n = strtoll(str.c_str(), &endp, 10);
    if(out) *out = (int64_t)n;
    // Note that strtoll returns a *long long int*, so even if strtol doesn't report a over/underflow
    // we still have to check that the returned value is within the range of an *int64_t*.
    return endp && *endp == 0 && !errno &&
        n >= std::numeric_limits<int64_t>::min() &&
        n <= std::numeric_limits<int64_t>::max();
}

bool ParseDouble(const std::string& str, double *out)
{
    if (!ParsePrechecks(str))
        return false;
    if (str.size() >= 2 && str[0] == '0' && str[1] == 'x') // No hexadecimal floats allowed
        return false;
    std::istringstream text(str);
    text.imbue(std::locale::classic());
    double result;
    text >> result;
    if(out) *out = result;
    return text.eof() && !text.fail();
}

// convert hexadecimal string to unsigned integer
static const char *hatoui(const char *first, const char *last,
                          unsigned int& out)
{
    unsigned int result = 0;
    for (; first != last; ++first)
    {
        int digit;
        if (json_isdigit(*first))
            digit = *first - '0';

        else if (*first >= 'a' && *first <= 'f')
            digit = *first - 'a' + 10;

        else if (*first >= 'A' && *first <= 'F')
            digit = *first - 'A' + 10;

        else
            break;

        result = 16 * result + digit;
    }
    out = result;

    return first;
}

enum jtokentype getJsonToken(std::string& tokenVal, unsigned int& consumed,
                            const char *raw)
{
    tokenVal.clear();
    consumed = 0;

    const char *rawStart = raw;

    while ((*raw) && (json_isspace(*raw)))             // skip whitespace
        raw++;

    switch (*raw) {

    case 0:
        return JTOK_NONE;

    case '{':
        raw++;
        consumed = (raw - rawStart);
        return JTOK_OBJ_OPEN;
    case '}':
        raw++;
        consumed = (raw - rawStart);
        return JTOK_OBJ_CLOSE;
    case '[':
        raw++;
        consumed = (raw - rawStart);
        return JTOK_ARR_OPEN;
    case ']':
        raw++;
        consumed = (raw - rawStart);
        return JTOK_ARR_CLOSE;

    case ':':
        raw++;
        consumed = (raw - rawStart);
        return JTOK_COLON;
    case ',':
        raw++;
        consumed = (raw - rawStart);
        return JTOK_COMMA;

    case 'n':
    case 't':
    case 'f':
        if (!strncmp(raw, "null", 4)) {
            raw += 4;
            consumed = (raw - rawStart);
            return JTOK_KW_NULL;
        } else if (!strncmp(raw, "true", 4)) {
            raw += 4;
            consumed = (raw - rawStart);
            return JTOK_KW_TRUE;
        } else if (!strncmp(raw, "false", 5)) {
            raw += 5;
            consumed = (raw - rawStart);
            return JTOK_KW_FALSE;
        } else
            return JTOK_ERR;

    case '-':
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9': {
        // part 1: int
        std::string numStr;

        const char *first = raw;

        const char *firstDigit = first;
        if (!json_isdigit(*firstDigit))
            firstDigit++;
        if ((*firstDigit == '0') && json_isdigit(firstDigit[1]))
            return JTOK_ERR;

        numStr += *raw;                       // copy first char
        raw++;

        if ((*first == '-') && (!json_isdigit(*raw)))
            return JTOK_ERR;

        while ((*raw) && json_isdigit(*raw)) {     // copy digits
            numStr += *raw;
            raw++;
        }

        // part 2: frac
        if (*raw == '.') {
            numStr += *raw;                   // copy .
            raw++;

            if (!json_isdigit(*raw))
                return JTOK_ERR;
            while ((*raw) && json_isdigit(*raw)) { // copy digits
                numStr += *raw;
                raw++;
            }
        }

        // part 3: exp
        if (*raw == 'e' || *raw == 'E') {
            numStr += *raw;                   // copy E
            raw++;

            if (*raw == '-' || *raw == '+') { // copy +/-
                numStr += *raw;
                raw++;
            }

            if (!json_isdigit(*raw))
                return JTOK_ERR;
            while ((*raw) && json_isdigit(*raw)) { // copy digits
                numStr += *raw;
                raw++;
            }
        }

        tokenVal = numStr;
        consumed = (raw - rawStart);
        return JTOK_NUMBER;
        }

    case '"': {
        raw++;                                // skip "

        std::string valStr;
        JSONUTF8StringFilter writer(valStr);

        while (*raw) {
            if ((unsigned char)*raw < 0x20)
                return JTOK_ERR;

            else if (*raw == '\\') {
                raw++;                        // skip backslash

                switch (*raw) {
                case '"':  writer.push_back('\"'); break;
                case '\\': writer.push_back('\\'); break;
                case '/':  writer.push_back('/'); break;
                case 'b':  writer.push_back('\b'); break;
                case 'f':  writer.push_back('\f'); break;
                case 'n':  writer.push_back('\n'); break;
                case 'r':  writer.push_back('\r'); break;
                case 't':  writer.push_back('\t'); break;

                case 'u': {
                    unsigned int codepoint;
                    if (hatoui(raw + 1, raw + 1 + 4, codepoint) !=
                               raw + 1 + 4)
                        return JTOK_ERR;
                    writer.push_back_u(codepoint);
                    raw += 4;
                    break;
                    }
                default:
                    return JTOK_ERR;

                }

                raw++;                        // skip esc'd char
            }

            else if (*raw == '"') {
                raw++;                        // skip "
                break;                        // stop scanning
            }

            else {
                writer.push_back(*raw);
                raw++;
            }
        }

        if (!writer.finalize())
            return JTOK_ERR;
        tokenVal = valStr;
        consumed = (raw - rawStart);
        return JTOK_STRING;
        }

    default:
        return JTOK_ERR;
    }
}

static bool validNumStr(const std::string& s)
{
    std::string tokenVal;
    unsigned int consumed;
    enum jtokentype tt = getJsonToken(tokenVal, consumed, s.c_str());
    return (tt == JTOK_NUMBER);
}

void UniValue::clear()
{
    typ = VNULL;
    val.clear();
    keys.clear();
    values.clear();
}

bool UniValue::setNull()
{
    clear();
    return true;
}

bool UniValue::setBool(bool val_)
{
    clear();
    typ = VBOOL;
    if (val_)
        val = "1";
    return true;
}

bool UniValue::setNumStr(const std::string& val_)
{
    if (!validNumStr(val_))
        return false;

    clear();
    typ = VNUM;
    val = val_;
    return true;
}

bool UniValue::setInt(uint64_t val_)
{
    std::ostringstream oss;

    oss << val_;

    return setNumStr(oss.str());
}

bool UniValue::setInt(int64_t val_)
{
    std::ostringstream oss;

    oss << val_;

    return setNumStr(oss.str());
}

bool UniValue::setFloat(double val_)
{
    std::ostringstream oss;

    oss << std::setprecision(16) << val_;

    bool ret = setNumStr(oss.str());
    typ = VNUM;
    return ret;
}

bool UniValue::setStr(const std::string& val_)
{
    clear();
    typ = VSTR;
    val = val_;
    return true;
}

bool UniValue::setArray()
{
    clear();
    typ = VARR;
    return true;
}

bool UniValue::setObject()
{
    clear();
    typ = VOBJ;
    return true;
}

bool UniValue::push_back(const UniValue& val_)
{
    if (typ != VARR)
        return false;

    values.push_back(val_);
    return true;
}

bool UniValue::pushKV(const std::string& key, const UniValue& val_)
{
    if (typ != VOBJ)
        return false;

    keys.push_back(key);
    values.push_back(val_);
    return true;
}

int UniValue::findKey(const std::string& key) const
{
    for (unsigned int i = 0; i < keys.size(); i++) {
        if (keys[i] == key)
            return (int) i;
    }

    return -1;
}

bool UniValue::checkObject(const std::map<std::string,UniValue::VType>& t)
{
    for (std::map<std::string,UniValue::VType>::const_iterator it = t.begin();
         it != t.end(); ++it) {
        int idx = findKey(it->first);
        if (idx < 0)
            return false;

        if (values.at(idx).getType() != it->second)
            return false;
    }

    return true;
}

const UniValue& UniValue::operator[](const std::string& key) const
{
    if (typ != VOBJ)
        return NullUniValue;

    int index = findKey(key);
    if (index < 0)
        return NullUniValue;

    return values.at(index);
}

const UniValue& UniValue::operator[](unsigned int index) const
{
    if (typ != VOBJ && typ != VARR)
        return NullUniValue;
    if (index >= values.size())
        return NullUniValue;

    return values.at(index);
}

static std::string json_escape(const std::string& inS)
{
    std::string outS;
    outS.reserve(inS.size() * 2);

    for (unsigned int i = 0; i < inS.size(); i++) {
        unsigned char ch = inS[i];
        const char *escStr = escapes[ch];

        if (escStr)
            outS += escStr;
        else
            outS += ch;
    }

    return outS;
}

std::string UniValue::write(unsigned int prettyIndent, unsigned int indentLevel) const
{
    std::string s;
    s.reserve(1024);

    unsigned int modIndent = indentLevel;
    if (modIndent == 0)
        modIndent = 1;

    switch (typ) {
    case VNULL:
        s += "null";
        break;
    case VOBJ:
        writeObject(prettyIndent, modIndent, s);
        break;
    case VARR:
        writeArray(prettyIndent, modIndent, s);
        break;
    case VSTR:
        s += "\"" + json_escape(val) + "\"";
        break;
    case VNUM:
        s += val;
        break;
    case VBOOL:
        s += (val == "1" ? "true" : "false");
        break;
    }

    return s;
}

static void indentStr(unsigned int prettyIndent, unsigned int indentLevel, std::string& s)
{
    s.append(prettyIndent * indentLevel, ' ');
}

void UniValue::writeArray(unsigned int prettyIndent, unsigned int indentLevel, std::string& s) const
{
    s += "[";
    if (prettyIndent)
        s += "\n";

    for (unsigned int i = 0; i < values.size(); i++) {
        if (prettyIndent)
            indentStr(prettyIndent, indentLevel, s);
        s += values[i].write(prettyIndent, indentLevel + 1);
        if (i != (values.size() - 1)) {
            s += ",";
            if (prettyIndent)
                s += " ";
        }
        if (prettyIndent)
            s += "\n";
    }

    if (prettyIndent)
        indentStr(prettyIndent, indentLevel - 1, s);
    s += "]";
}

void UniValue::writeObject(unsigned int prettyIndent, unsigned int indentLevel, std::string& s) const
{
    s += "{";
    if (prettyIndent)
        s += "\n";

    for (unsigned int i = 0; i < keys.size(); i++) {
        if (prettyIndent)
            indentStr(prettyIndent, indentLevel, s);
        s += "\"" + json_escape(keys[i]) + "\":";
        if (prettyIndent)
            s += " ";
        s += values.at(i).write(prettyIndent, indentLevel + 1);
        if (i != (values.size() - 1))
            s += ",";
        if (prettyIndent)
            s += "\n";
    }

    if (prettyIndent)
        indentStr(prettyIndent, indentLevel - 1, s);
    s += "}";
}

const char *uvTypeName(UniValue::VType t)
{
    switch (t) {
    case UniValue::VNULL: return "null";
    case UniValue::VBOOL: return "bool";
    case UniValue::VOBJ: return "object";
    case UniValue::VARR: return "array";
    case UniValue::VSTR: return "string";
    case UniValue::VNUM: return "number";
    }

    // not reached
    return NULL;
}

const UniValue& find_value(const UniValue& obj, const std::string& name)
{
    for (unsigned int i = 0; i < obj.keys.size(); i++)
        if (obj.keys[i] == name)
            return obj.values.at(i);

    return NullUniValue;
}

const std::vector<std::string>& UniValue::getKeys() const
{
    if (typ != VOBJ)
        throw std::runtime_error("JSON value is not an object as expected");
    return keys;
}

const std::vector<UniValue>& UniValue::getValues() const
{
    if (typ != VOBJ && typ != VARR)
        throw std::runtime_error("JSON value is not an object or array as expected");
    return values;
}

bool UniValue::get_bool() const
{
    if (typ != VBOOL)
        throw std::runtime_error("JSON value is not a boolean as expected");
    return getBool();
}

const std::string& UniValue::get_str() const
{
    if (typ != VSTR)
        throw std::runtime_error("JSON value is not a string as expected");
    return getValStr();
}

int UniValue::get_int() const
{
    if (typ != VNUM)
        throw std::runtime_error("JSON value is not an integer as expected");
    int32_t retval;
    if (!ParseInt32(getValStr(), &retval))
        throw std::runtime_error("JSON integer out of range");
    return retval;
}

const UniValue& UniValue::get_obj() const
{
    if (typ != VOBJ)
        throw std::runtime_error("JSON value is not an object as expected");
    return *this;
}

enum expect_bits {
    EXP_OBJ_NAME = (1U << 0),
    EXP_COLON = (1U << 1),
    EXP_ARR_VALUE = (1U << 2),
    EXP_VALUE = (1U << 3),
    EXP_NOT_VALUE = (1U << 4),
};

#define expect(bit) (expectMask & (EXP_##bit))
#define setExpect(bit) (expectMask |= EXP_##bit)
#define clearExpect(bit) (expectMask &= ~EXP_##bit)

bool UniValue::read(const char *raw)
{
    clear();

    uint32_t expectMask = 0;
    std::vector<UniValue*> stack;

    std::string tokenVal;
    unsigned int consumed;
    enum jtokentype tok = JTOK_NONE;
    enum jtokentype last_tok = JTOK_NONE;
    do {
        last_tok = tok;

        tok = getJsonToken(tokenVal, consumed, raw);
        if (tok == JTOK_NONE || tok == JTOK_ERR)
            return false;
        raw += consumed;

        bool isValueOpen = jsonTokenIsValue(tok) ||
            tok == JTOK_OBJ_OPEN || tok == JTOK_ARR_OPEN;

        if (expect(VALUE)) {
            if (!isValueOpen)
                return false;
            clearExpect(VALUE);

        } else if (expect(ARR_VALUE)) {
            bool isArrValue = isValueOpen || (tok == JTOK_ARR_CLOSE);
            if (!isArrValue)
                return false;

            clearExpect(ARR_VALUE);

        } else if (expect(OBJ_NAME)) {
            bool isObjName = (tok == JTOK_OBJ_CLOSE || tok == JTOK_STRING);
            if (!isObjName)
                return false;

        } else if (expect(COLON)) {
            if (tok != JTOK_COLON)
                return false;
            clearExpect(COLON);

        } else if (!expect(COLON) && (tok == JTOK_COLON)) {
            return false;
        }

        if (expect(NOT_VALUE)) {
            if (isValueOpen)
                return false;
            clearExpect(NOT_VALUE);
        }

        switch (tok) {

        case JTOK_OBJ_OPEN:
        case JTOK_ARR_OPEN: {
            VType utyp = (tok == JTOK_OBJ_OPEN ? VOBJ : VARR);
            if (!stack.size()) {
                if (utyp == VOBJ)
                    setObject();
                else
                    setArray();
                stack.push_back(this);
            } else {
                UniValue tmpVal(utyp);
                UniValue *top = stack.back();
                top->values.push_back(tmpVal);

                UniValue *newTop = &(top->values.back());
                stack.push_back(newTop);
            }

            if (utyp == VOBJ)
                setExpect(OBJ_NAME);
            else
                setExpect(ARR_VALUE);
            break;
            }

        case JTOK_OBJ_CLOSE:
        case JTOK_ARR_CLOSE: {
            if (!stack.size() || (last_tok == JTOK_COMMA))
                return false;

            VType utyp = (tok == JTOK_OBJ_CLOSE ? VOBJ : VARR);
            UniValue *top = stack.back();
            if (utyp != top->getType())
                return false;

            stack.pop_back();
            clearExpect(OBJ_NAME);
            setExpect(NOT_VALUE);
            break;
            }

        case JTOK_COLON: {
            if (!stack.size())
                return false;

            UniValue *top = stack.back();
            if (top->getType() != VOBJ)
                return false;

            setExpect(VALUE);
            break;
            }

        case JTOK_COMMA: {
            if (!stack.size() ||
                (last_tok == JTOK_COMMA) || (last_tok == JTOK_ARR_OPEN))
                return false;

            UniValue *top = stack.back();
            if (top->getType() == VOBJ)
                setExpect(OBJ_NAME);
            else
                setExpect(ARR_VALUE);
            break;
            }

        case JTOK_KW_NULL:
        case JTOK_KW_TRUE:
        case JTOK_KW_FALSE: {
            if (!stack.size())
                return false;

            UniValue tmpVal;
            switch (tok) {
            case JTOK_KW_NULL:
                // do nothing more
                break;
            case JTOK_KW_TRUE:
                tmpVal.setBool(true);
                break;
            case JTOK_KW_FALSE:
                tmpVal.setBool(false);
                break;
            default: /* impossible */ break;
            }

            UniValue *top = stack.back();
            top->values.push_back(tmpVal);

            setExpect(NOT_VALUE);
            break;
            }

        case JTOK_NUMBER: {
            if (!stack.size())
                return false;

            UniValue tmpVal(VNUM, tokenVal);
            UniValue *top = stack.back();
            top->values.push_back(tmpVal);

            setExpect(NOT_VALUE);
            break;
            }

        case JTOK_STRING: {
            if (!stack.size())
                return false;

            UniValue *top = stack.back();

            if (expect(OBJ_NAME)) {
                top->keys.push_back(tokenVal);
                clearExpect(OBJ_NAME);
                setExpect(COLON);
            } else {
                UniValue tmpVal(VSTR, tokenVal);
                top->values.push_back(tmpVal);
            }

            setExpect(NOT_VALUE);
            break;
            }

        default:
            return false;
        }
    } while (!stack.empty ());

    /* Check that nothing follows the initial construct (parsed above).  */
    tok = getJsonToken(tokenVal, consumed, raw);
    if (tok != JTOK_NONE)
        return false;

    return true;
}

const UniValue& UniValue::get_array() const
{
    if (typ != VARR)
        throw std::runtime_error("JSON value is not an array as expected");
    return *this;
}

static struct CRPCSignals
{
    boost::signals2::signal<void ()> Started;
    boost::signals2::signal<void ()> Stopped;
    boost::signals2::signal<void (const CRPCCommand&)> PreCommand;
    boost::signals2::signal<void (const CRPCCommand&)> PostCommand;
} g_rpcSignals;

void RPCServer::OnStarted(boost::function<void ()> slot)
{
    g_rpcSignals.Started.connect(slot);
}

void RPCServer::OnStopped(boost::function<void ()> slot)
{
    g_rpcSignals.Stopped.connect(slot);
}

void RPCServer::OnPreCommand(boost::function<void (const CRPCCommand&)> slot)
{
    g_rpcSignals.PreCommand.connect(boost::bind(slot, _1));
}

void RPCServer::OnPostCommand(boost::function<void (const CRPCCommand&)> slot)
{
    g_rpcSignals.PostCommand.connect(boost::bind(slot, _1));
}

void RPCTypeCheck(const UniValue& params,
                  const std::list<UniValue::VType>& typesExpected,
                  bool fAllowNull)
{
    unsigned int i = 0;
    BOOST_FOREACH(UniValue::VType t, typesExpected)
    {
        if (params.size() <= i)
            break;

        const UniValue& v = params[i];
        if (!(fAllowNull && v.isNull())) {
            RPCTypeCheckArgument(v, t);
        }
        i++;
    }
}

void RPCTypeCheckArgument(const UniValue& value, UniValue::VType typeExpected)
{
    if (value.type() != typeExpected) {
        char buffer[1024];
        sprintf(buffer, ("Expected type %s, got %s", uvTypeName(typeExpected), uvTypeName(value.type())));
        throw JSONRPCError(RPC_TYPE_ERROR, buffer);
    }
}

void RPCTypeCheckObj(const UniValue& o,
    const std::map<std::string, UniValueType>& typesExpected,
    bool fAllowNull,
    bool fStrict)
{
    for (const auto& t : typesExpected) {
        const UniValue& v = find_value(o, t.first);
        if (!fAllowNull && v.isNull()){
              char buffer[1024];
              sprintf(buffer, ("Missing %s", t.first.c_str()));
              throw JSONRPCError(RPC_TYPE_ERROR, "");
        }

        if (!(t.second.typeAny || v.type() == t.second.type || (fAllowNull && v.isNull()))) {
            char buffer[1024];
            sprintf(buffer, ("Expected type %s for %s, got %s", uvTypeName(t.second.type), t.first, uvTypeName(v.type())));
            throw JSONRPCError(RPC_TYPE_ERROR, buffer);
        }
    }

    if (fStrict)
    {
        BOOST_FOREACH(const std::string& k, o.getKeys())
        {
            if (typesExpected.count(k) == 0)
            {
                char buffer[1024];
                sprintf(buffer, ("Unexpected key %s", k.c_str()));
                throw JSONRPCError(RPC_TYPE_ERROR, buffer);
            }
        }
    }
}

std::vector<unsigned char> ParseHexV(const UniValue& v, std::string strName)
{
    std::string strHex;
    if (v.isStr())
        strHex = v.get_str();
    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, (strName+" must be hexadecimal string (not '"+strHex+"')").c_str());
    return ParseHex(strHex);
}

std::vector<unsigned char> ParseHexO(const UniValue& o, std::string strKey)
{
    return ParseHexV(find_value(o, strKey), strKey);
}

bool StartRPC()
{
    syslog(LOG_NOTICE, "rpc: Starting RPC");
    fRPCRunning = true;
    g_rpcSignals.Started();
    return true;
}

void InterruptRPC()
{
    syslog(LOG_NOTICE, "rpc: Interrupting RPC");
    // Interrupt e.g. running longpolls
    fRPCRunning = false;
}

void StopRPC()
{
    syslog(LOG_NOTICE, "rpc: Stopping RPC");
    // deadlineTimers.clear();
    g_rpcSignals.Stopped();
}

bool IsRPCRunning()
{
    return fRPCRunning;
}

void SetRPCWarmupStatus(const std::string &newStatus)
{
    LOCK(cs_rpcWarmup);
    rpcWarmupStatus = newStatus;
}

void SetRPCWarmupFinished()
{
    LOCK(cs_rpcWarmup);
    assert(fRPCInWarmup);
    fRPCInWarmup = false;
}

bool RPCIsInWarmup(std::string *outStatus)
{
    LOCK(cs_rpcWarmup);
    if (outStatus)
        *outStatus = rpcWarmupStatus;
    return fRPCInWarmup;
}

static UniValue JSONRPCExecOne(const UniValue& req)
{
    UniValue rpc_result(UniValue::VOBJ);

    JSONRPCRequest jreq;
    try {
        jreq.parse(req);

        UniValue result = tableRPC.execute(jreq);
        rpc_result = JSONRPCReplyObj(result, NullUniValue, jreq.id);
    }
    catch (const UniValue& objError)
    {
        rpc_result = JSONRPCReplyObj(NullUniValue, objError, jreq.id);
    }
    catch (const std::exception& e)
    {
        rpc_result = JSONRPCReplyObj(NullUniValue, JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
    }

    return rpc_result;
}

std::string JSONRPCExecBatch(const UniValue& vReq)
{
    UniValue ret(UniValue::VARR);
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++)
        ret.push_back(JSONRPCExecOne(vReq[reqIdx]));

    return ret.write() + "\n";
}

/** Used by SanitizeString() */
enum SafeChars
{
    SAFE_CHARS_DEFAULT, //!< The full set of allowed chars
    SAFE_CHARS_UA_COMMENT, //!< BIP-0014 subset
    SAFE_CHARS_FILENAME, //!< Chars allowed in filenames
};

static const std::string CHARS_ALPHA_NUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

static const std::string SAFE_CHARS[] =
{
    CHARS_ALPHA_NUM + " .,;-_/:?@()", // SAFE_CHARS_DEFAULT
    CHARS_ALPHA_NUM + " .,;-_?@", // SAFE_CHARS_UA_COMMENT
    CHARS_ALPHA_NUM + ".-_", // SAFE_CHARS_FILENAME
};

std::string SanitizeString(const std::string& str, int rule = SAFE_CHARS_DEFAULT)
{
    std::string strResult;
    for (std::string::size_type i = 0; i < str.size(); i++)
    {
        if (SAFE_CHARS[rule].find(str[i]) != std::string::npos)
            strResult.push_back(str[i]);
    }
    return strResult;
}

void JSONRPCRequest::parse(const UniValue& valRequest)
{
    // Parse request
    if (!valRequest.isObject())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    const UniValue& request = valRequest.get_obj();

    // Parse id now so errors from here on will have the id
    id = find_value(request, "id");

    // Parse method
    UniValue valMethod = find_value(request, "method");
    if (valMethod.isNull())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (!valMethod.isStr())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str();
    if (strMethod != "getblocktemplate")
        syslog(LOG_NOTICE, ("rpc: ThreadRPCServer method=%s\n", SanitizeString(strMethod)).c_str());

    // Parse params
    UniValue valParams = find_value(request, "params");
    if (valParams.isArray() || valParams.isObject())
        params = valParams;
    else if (valParams.isNull())
        params = UniValue(UniValue::VARR);
    else
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array or object");
}

// --------------------------------- StartHTTPRPC

/// Internal SHA-256 implementation.
namespace sha256
{
uint32_t inline Ch(uint32_t x, uint32_t y, uint32_t z) { return z ^ (x & (y ^ z)); }
uint32_t inline Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (z & (x | y)); }
uint32_t inline Sigma0(uint32_t x) { return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10); }
uint32_t inline Sigma1(uint32_t x) { return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7); }
uint32_t inline sigma0(uint32_t x) { return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3); }
uint32_t inline sigma1(uint32_t x) { return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10); }

/** One round of SHA-256. */
void inline Round(uint32_t a, uint32_t b, uint32_t c, uint32_t& d, uint32_t e, uint32_t f, uint32_t g, uint32_t& h, uint32_t k, uint32_t w)
{
    uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + k + w;
    uint32_t t2 = Sigma0(a) + Maj(a, b, c);
    d += t1;
    h = t1 + t2;
}

/** Initialize SHA-256 state. */
void inline Initialize(uint32_t* s)
{
    s[0] = 0x6a09e667ul;
    s[1] = 0xbb67ae85ul;
    s[2] = 0x3c6ef372ul;
    s[3] = 0xa54ff53aul;
    s[4] = 0x510e527ful;
    s[5] = 0x9b05688cul;
    s[6] = 0x1f83d9abul;
    s[7] = 0x5be0cd19ul;
}

/** Perform one SHA-256 transformation, processing a 64-byte chunk. */
void Transform(uint32_t* s, const unsigned char* chunk)
{
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

    Round(a, b, c, d, e, f, g, h, 0x428a2f98, w0 = ReadBE32(chunk + 0));
    Round(h, a, b, c, d, e, f, g, 0x71374491, w1 = ReadBE32(chunk + 4));
    Round(g, h, a, b, c, d, e, f, 0xb5c0fbcf, w2 = ReadBE32(chunk + 8));
    Round(f, g, h, a, b, c, d, e, 0xe9b5dba5, w3 = ReadBE32(chunk + 12));
    Round(e, f, g, h, a, b, c, d, 0x3956c25b, w4 = ReadBE32(chunk + 16));
    Round(d, e, f, g, h, a, b, c, 0x59f111f1, w5 = ReadBE32(chunk + 20));
    Round(c, d, e, f, g, h, a, b, 0x923f82a4, w6 = ReadBE32(chunk + 24));
    Round(b, c, d, e, f, g, h, a, 0xab1c5ed5, w7 = ReadBE32(chunk + 28));
    Round(a, b, c, d, e, f, g, h, 0xd807aa98, w8 = ReadBE32(chunk + 32));
    Round(h, a, b, c, d, e, f, g, 0x12835b01, w9 = ReadBE32(chunk + 36));
    Round(g, h, a, b, c, d, e, f, 0x243185be, w10 = ReadBE32(chunk + 40));
    Round(f, g, h, a, b, c, d, e, 0x550c7dc3, w11 = ReadBE32(chunk + 44));
    Round(e, f, g, h, a, b, c, d, 0x72be5d74, w12 = ReadBE32(chunk + 48));
    Round(d, e, f, g, h, a, b, c, 0x80deb1fe, w13 = ReadBE32(chunk + 52));
    Round(c, d, e, f, g, h, a, b, 0x9bdc06a7, w14 = ReadBE32(chunk + 56));
    Round(b, c, d, e, f, g, h, a, 0xc19bf174, w15 = ReadBE32(chunk + 60));

    Round(a, b, c, d, e, f, g, h, 0xe49b69c1, w0 += sigma1(w14) + w9 + sigma0(w1));
    Round(h, a, b, c, d, e, f, g, 0xefbe4786, w1 += sigma1(w15) + w10 + sigma0(w2));
    Round(g, h, a, b, c, d, e, f, 0x0fc19dc6, w2 += sigma1(w0) + w11 + sigma0(w3));
    Round(f, g, h, a, b, c, d, e, 0x240ca1cc, w3 += sigma1(w1) + w12 + sigma0(w4));
    Round(e, f, g, h, a, b, c, d, 0x2de92c6f, w4 += sigma1(w2) + w13 + sigma0(w5));
    Round(d, e, f, g, h, a, b, c, 0x4a7484aa, w5 += sigma1(w3) + w14 + sigma0(w6));
    Round(c, d, e, f, g, h, a, b, 0x5cb0a9dc, w6 += sigma1(w4) + w15 + sigma0(w7));
    Round(b, c, d, e, f, g, h, a, 0x76f988da, w7 += sigma1(w5) + w0 + sigma0(w8));
    Round(a, b, c, d, e, f, g, h, 0x983e5152, w8 += sigma1(w6) + w1 + sigma0(w9));
    Round(h, a, b, c, d, e, f, g, 0xa831c66d, w9 += sigma1(w7) + w2 + sigma0(w10));
    Round(g, h, a, b, c, d, e, f, 0xb00327c8, w10 += sigma1(w8) + w3 + sigma0(w11));
    Round(f, g, h, a, b, c, d, e, 0xbf597fc7, w11 += sigma1(w9) + w4 + sigma0(w12));
    Round(e, f, g, h, a, b, c, d, 0xc6e00bf3, w12 += sigma1(w10) + w5 + sigma0(w13));
    Round(d, e, f, g, h, a, b, c, 0xd5a79147, w13 += sigma1(w11) + w6 + sigma0(w14));
    Round(c, d, e, f, g, h, a, b, 0x06ca6351, w14 += sigma1(w12) + w7 + sigma0(w15));
    Round(b, c, d, e, f, g, h, a, 0x14292967, w15 += sigma1(w13) + w8 + sigma0(w0));

    Round(a, b, c, d, e, f, g, h, 0x27b70a85, w0 += sigma1(w14) + w9 + sigma0(w1));
    Round(h, a, b, c, d, e, f, g, 0x2e1b2138, w1 += sigma1(w15) + w10 + sigma0(w2));
    Round(g, h, a, b, c, d, e, f, 0x4d2c6dfc, w2 += sigma1(w0) + w11 + sigma0(w3));
    Round(f, g, h, a, b, c, d, e, 0x53380d13, w3 += sigma1(w1) + w12 + sigma0(w4));
    Round(e, f, g, h, a, b, c, d, 0x650a7354, w4 += sigma1(w2) + w13 + sigma0(w5));
    Round(d, e, f, g, h, a, b, c, 0x766a0abb, w5 += sigma1(w3) + w14 + sigma0(w6));
    Round(c, d, e, f, g, h, a, b, 0x81c2c92e, w6 += sigma1(w4) + w15 + sigma0(w7));
    Round(b, c, d, e, f, g, h, a, 0x92722c85, w7 += sigma1(w5) + w0 + sigma0(w8));
    Round(a, b, c, d, e, f, g, h, 0xa2bfe8a1, w8 += sigma1(w6) + w1 + sigma0(w9));
    Round(h, a, b, c, d, e, f, g, 0xa81a664b, w9 += sigma1(w7) + w2 + sigma0(w10));
    Round(g, h, a, b, c, d, e, f, 0xc24b8b70, w10 += sigma1(w8) + w3 + sigma0(w11));
    Round(f, g, h, a, b, c, d, e, 0xc76c51a3, w11 += sigma1(w9) + w4 + sigma0(w12));
    Round(e, f, g, h, a, b, c, d, 0xd192e819, w12 += sigma1(w10) + w5 + sigma0(w13));
    Round(d, e, f, g, h, a, b, c, 0xd6990624, w13 += sigma1(w11) + w6 + sigma0(w14));
    Round(c, d, e, f, g, h, a, b, 0xf40e3585, w14 += sigma1(w12) + w7 + sigma0(w15));
    Round(b, c, d, e, f, g, h, a, 0x106aa070, w15 += sigma1(w13) + w8 + sigma0(w0));

    Round(a, b, c, d, e, f, g, h, 0x19a4c116, w0 += sigma1(w14) + w9 + sigma0(w1));
    Round(h, a, b, c, d, e, f, g, 0x1e376c08, w1 += sigma1(w15) + w10 + sigma0(w2));
    Round(g, h, a, b, c, d, e, f, 0x2748774c, w2 += sigma1(w0) + w11 + sigma0(w3));
    Round(f, g, h, a, b, c, d, e, 0x34b0bcb5, w3 += sigma1(w1) + w12 + sigma0(w4));
    Round(e, f, g, h, a, b, c, d, 0x391c0cb3, w4 += sigma1(w2) + w13 + sigma0(w5));
    Round(d, e, f, g, h, a, b, c, 0x4ed8aa4a, w5 += sigma1(w3) + w14 + sigma0(w6));
    Round(c, d, e, f, g, h, a, b, 0x5b9cca4f, w6 += sigma1(w4) + w15 + sigma0(w7));
    Round(b, c, d, e, f, g, h, a, 0x682e6ff3, w7 += sigma1(w5) + w0 + sigma0(w8));
    Round(a, b, c, d, e, f, g, h, 0x748f82ee, w8 += sigma1(w6) + w1 + sigma0(w9));
    Round(h, a, b, c, d, e, f, g, 0x78a5636f, w9 += sigma1(w7) + w2 + sigma0(w10));
    Round(g, h, a, b, c, d, e, f, 0x84c87814, w10 += sigma1(w8) + w3 + sigma0(w11));
    Round(f, g, h, a, b, c, d, e, 0x8cc70208, w11 += sigma1(w9) + w4 + sigma0(w12));
    Round(e, f, g, h, a, b, c, d, 0x90befffa, w12 += sigma1(w10) + w5 + sigma0(w13));
    Round(d, e, f, g, h, a, b, c, 0xa4506ceb, w13 += sigma1(w11) + w6 + sigma0(w14));
    Round(c, d, e, f, g, h, a, b, 0xbef9a3f7, w14 + sigma1(w12) + w7 + sigma0(w15));
    Round(b, c, d, e, f, g, h, a, 0xc67178f2, w15 + sigma1(w13) + w8 + sigma0(w0));

    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
    s[5] += f;
    s[6] += g;
    s[7] += h;
}

} // namespace sha256

CSHA256::CSHA256() : bytes(0)
{
    sha256::Initialize(s);
}

CSHA256& CSHA256::Write(const unsigned char* data, size_t len)
{
    const unsigned char* end = data + len;
    size_t bufsize = bytes % 64;
    if (bufsize && bufsize + len >= 64) {
        // Fill the buffer, and process it.
        memcpy(buf + bufsize, data, 64 - bufsize);
        bytes += 64 - bufsize;
        data += 64 - bufsize;
        sha256::Transform(s, buf);
        bufsize = 0;
    }
    while (end >= data + 64) {
        // Process full chunks directly from the source.
        sha256::Transform(s, data);
        bytes += 64;
        data += 64;
    }
    if (end > data) {
        // Fill the buffer with what remains.
        memcpy(buf + bufsize, data, end - data);
        bytes += end - data;
    }
    return *this;
}

void CSHA256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    static const unsigned char pad[64] = {0x80};
    unsigned char sizedesc[8];
    WriteBE64(sizedesc, bytes << 3);
    Write(pad, 1 + ((119 - (bytes % 64)) % 64));
    Write(sizedesc, 8);
    WriteBE32(hash, s[0]);
    WriteBE32(hash + 4, s[1]);
    WriteBE32(hash + 8, s[2]);
    WriteBE32(hash + 12, s[3]);
    WriteBE32(hash + 16, s[4]);
    WriteBE32(hash + 20, s[5]);
    WriteBE32(hash + 24, s[6]);
    WriteBE32(hash + 28, s[7]);
}

CSHA256& CSHA256::Reset()
{
    bytes = 0;
    sha256::Initialize(s);
    return *this;
}

CHMAC_SHA256::CHMAC_SHA256(const unsigned char* key, size_t keylen)
{
    unsigned char rkey[64];
    if (keylen <= 64) {
        memcpy(rkey, key, keylen);
        memset(rkey + keylen, 0, 64 - keylen);
    } else {
        CSHA256().Write(key, keylen).Finalize(rkey);
        memset(rkey + 32, 0, 32);
    }

    for (int n = 0; n < 64; n++)
        rkey[n] ^= 0x5c;
    outer.Write(rkey, 64);

    for (int n = 0; n < 64; n++)
        rkey[n] ^= 0x5c ^ 0x36;
    inner.Write(rkey, 64);
}

void CHMAC_SHA256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    unsigned char temp[32];
    inner.Finalize(temp);
    outer.Write(temp, 32).Finalize(hash);
}

// --------------------------------- IVMC
CBlockTreeDB *psmartcontracttree = NULL;

/// Returns the input str if already valid hex string. Otherwise, interprets the str as a file
/// name and loads the file content.
/// @todo The file content is expected to be a hex string but not validated.
std::string load_hex(const std::string &str)
{
    const auto error_code = ivmc::validate_hex(str);
    if (!error_code)
        return str;

    // Must be a file path.
    std::ifstream file{str};
    return std::string(std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{});
}

struct HexValidator : public CLI::Validator
{
    HexValidator() : CLI::Validator{"HEX"}
    {
        name_ = "HEX";
        func_ = [](const std::string &str) -> std::string {
            const auto error_code = ivmc::validate_hex(str);
            if (error_code)
                return error_code.message();
            return {};
        };
    }
};

bool InitIVMC()
{
    static HexValidator Hex;

    std::string vm_config_arg;
    std::string code_arg;
    int64_t gas = 1000000;
    auto rev = IVMC_LATEST_STABLE_REVISION;
    std::string input_arg;
    std::string storage_arg;
    std::string recipient_arg;
    std::string sender_arg;

    return true;
}

int nFile = 0;
int ExecuteIVMC(std::string vm_config_arg, std::string code_arg, std::string input_arg, std::string storage_arg, std::string recipient_arg, std::string sender_arg)
{
    using namespace ivmc;

    static HexValidator Hex;

    int64_t gas = 1000000000; //Hard coded
    auto rev = IVMC_LATEST_STABLE_REVISION;  //Hard coded

    CLI::App app{"IVMC tool"};

    try
    {
        syslog(LOG_NOTICE, "ivmc: Init VM");

        ivmc::VM vm;
        ivmc_loader_error_code ec;
        vm = VM{ivmc_load_and_configure(vm_config_arg.c_str(), &ec)};
        if (ec != IVMC_LOADER_SUCCESS)
        {
            const auto error = ivmc_last_error_msg();
            if (error != nullptr)
                std::cerr << error << "\n";
            else
                std::cerr << "Loading error " << ec << "\n";
            return static_cast<int>(ec);
        }

        syslog(LOG_NOTICE, "ivmc: Staring execution");

        std::cout << "Config: " << vm_config_arg << "\n";

        const auto code_hex = load_hex(code_arg);
        const auto input_hex = load_hex(input_arg);
        const auto storage_hex = load_hex(storage_arg);
        std::string _out = "";

        // If code_hex or input_hex or storage_hex is not valid hex string an exception is thrown.
        tooling::run2(vm, rev, gas, code_hex, input_hex, storage_hex, recipient_arg, sender_arg, std::cout, _out);

        std::stringstream ss;
        ss << std::cout.rdbuf();
        std::string myString = ss.str();

        syslog(LOG_NOTICE, ("ivmc: run2 out " + _out).c_str());
        syslog(LOG_NOTICE, "ivmc: End execution");

        size_t _size = ::GetSerializeSize(_out, SER_DISK, CLIENT_VERSION);
        syslog(LOG_NOTICE, ("ivmc: GetSerializeSize " + std::to_string(_size)).c_str());

        int top=10000;
        ++nFile;

        CDiskBlockPos _pos(nFile, _size);

        CDiskTxPos pos(_pos, _size);
        // std::vector<std::pair<ivmc::address, CDiskTxPos> > vPos;
        std::vector<std::pair<ivmc::address, CDiskTxPos> > vPos;
        vPos.reserve(top);

        constexpr ivmc::address create_address = 0xc9ea7ed000000000000000000000000000000001_address;

        // int key_size_ = sizeof(msg.recipient.bytes) / sizeof(msg.recipient.bytes[0]);
        // std::ostringstream convert;
        // for (int a = 0; a < key_size_; a++) {
        //     convert << std::hex << (int)msg.recipient.bytes[a];
        // }
        //
        // std::string key_string = convert.str();
        // out << "Address:   " << key_string << "\n";
        int j=0;
        while (j++<top) {
          ivmc::address in = GetRandHash();
          vPos.push_back(std::make_pair(in, pos));
        }

        // WriteTxIndex
        syslog(LOG_NOTICE, ("ivmc: WriteTxIndex "));

        if (!psmartcontracttree->WriteTxIndex(vPos))
            syslog(LOG_NOTICE, "ivmc: Failed to write transaction index");

        // if (!pminiblocktree->WriteBatchSync(vFiles, nLastBlockFile, vMiniBlocks)) {
        //     syslog(LOG_NOTICE, "ivmc: Failed to write to miniblock index database");

        return 0;
    }
    catch (const CLI::ParseError& e)
    {
        return app.exit(e);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return -1;
    }
    catch (...)
    {
        return -2;
    }
}

// ------------------------------- RPC_CLIENT_P2P_DISABLED
UniValue help_rpc(const JSONRPCRequest& jsonRequest)
{
    if (jsonRequest.fHelp || jsonRequest.params.size() > 1)
        throw std::runtime_error(
            "help ( \"command\" )\n"
            "\nList all commands, or get help for a specified command.\n"
            "\nArguments:\n"
            "1. \"command\"     (string, optional) The command to get help on\n"
            "\nResult:\n"
            "\"text\"     (string) The help text\n"
        );

    std::string strCommand;
    if (jsonRequest.params.size() > 0)
        strCommand = jsonRequest.params[0].get_str();

    return tableRPC.help(strCommand, jsonRequest);
}

UniValue exe_ivmc_rpc(const JSONRPCRequest& jsonRequest)
{
    if (jsonRequest.fHelp || jsonRequest.params.size() != 4)
        throw std::runtime_error(
            "exeIVMC ( \"vm_config\", \"code\", \"input\", \"storage\" )\n"
            "\nExecute the IVMC passing the parameters code, input and storage.\n"
            "\nArguments:\n"
            "1. \"vm_config\"     (string, required) The vm congig file\n"
            "2. \"code\"          (string, required) The code to execute\n"
            "3. \"input\"         (string, required) The input parameter\n"
            "4. \"storage\"       (string, required) The storage parameter\n"
            "\nResult:\n"
            "\"output\"     (string) The execution smart contract result\n"
        );

    std::string vm_config_arg;
    if (jsonRequest.params.size() > 0)
        vm_config_arg = jsonRequest.params[0].get_str();

    std::string code_arg;
    if (jsonRequest.params.size() > 1)
        code_arg = jsonRequest.params[1].get_str();

    std::string input_arg;
    if (jsonRequest.params.size() > 2)
        input_arg = jsonRequest.params[2].get_str();

    std::string storage_arg;
    if (jsonRequest.params.size() > 3)
        storage_arg = jsonRequest.params[3].get_str();

    std::string recipient_arg = "";
    std::string sender_arg    = "";

    return ExecuteIVMC(vm_config_arg, code_arg, input_arg, storage_arg, recipient_arg, sender_arg);
}

/**
 * Process named arguments into a vector of positional arguments, based on the
 * passed-in specification for the RPC call's arguments.
 */
static inline JSONRPCRequest transformNamedArguments(const JSONRPCRequest& in, const std::vector<std::string>& argNames)
{
    JSONRPCRequest out = in;
    out.params = UniValue(UniValue::VARR);
    // Build a map of parameters, and remove ones that have been processed, so that we can throw a focused error if
    // there is an unknown one.
    const std::vector<std::string>& keys = in.params.getKeys();
    const std::vector<UniValue>& values = in.params.getValues();
    std::unordered_map<std::string, const UniValue*> argsIn;
    for (size_t i=0; i<keys.size(); ++i) {
        argsIn[keys[i]] = &values[i];
    }
    // Process expected parameters.
    int hole = 0;
    for (const std::string &argName: argNames) {
        auto fr = argsIn.find(argName);
        if (fr != argsIn.end()) {
            for (int i = 0; i < hole; ++i) {
                // Fill hole between specified parameters with JSON nulls,
                // but not at the end (for backwards compatibility with calls
                // that act based on number of specified parameters).
                out.params.push_back(UniValue());
            }
            hole = 0;
            out.params.push_back(*fr->second);
            argsIn.erase(fr);
        } else {
            hole += 1;
        }
    }
    // If there are still arguments in the argsIn map, this is an error.
    if (!argsIn.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown named parameter " + argsIn.begin()->first);
    }
    // Return request with named arguments transformed to positional arguments
    return out;
}

UniValue CRPCTable::execute(const JSONRPCRequest &request) const
{
    // Return immediately if in warmup
    {
        LOCK(cs_rpcWarmup);
        if (fRPCInWarmup)
            throw JSONRPCError(RPC_IN_WARMUP, rpcWarmupStatus);
    }

    // Find method
    syslog(LOG_NOTICE, ("execute strMethod 1 " + request.strMethod).c_str());
    const CRPCCommand *pcmd = tableRPC[request.strMethod];
    if (!pcmd)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");

    syslog(LOG_NOTICE, ("execute strMethod 2 " + request.strMethod).c_str());

    g_rpcSignals.PreCommand(*pcmd);

    syslog(LOG_NOTICE, ("execute strMethod 3 " + request.strMethod).c_str());

    try
    {
        rpcfn_type method;
        if(request.strMethod == "help") method = &help_rpc;
        else if(request.strMethod == "executeivmc") method = &exe_ivmc_rpc;

        if(method){
          // Execute, convert arguments to array if necessary
          if (request.params.isObject()) {
              syslog(LOG_NOTICE, ("execute strMethod 4 " + request.strMethod).c_str());
              UniValue result = (*method)(transformNamedArguments(request, pcmd->argNames));
              return result;
          } else {
              syslog(LOG_NOTICE, ("execute strMethod 5 " + request.strMethod).c_str());
              syslog(LOG_NOTICE, ("execute strMethod 8 " + request.strMethod).c_str());
              UniValue result = (*method)(request);
              return result;
          }
        }
        else throw JSONRPCError(RPC_MISC_ERROR, "actor empty");
    }
    catch (const std::exception& e)
    {
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }

    syslog(LOG_NOTICE, ("execute strMethod 6" + request.strMethod).c_str());

    g_rpcSignals.PostCommand(*pcmd);

    syslog(LOG_NOTICE, ("execute strMethod 7" + request.strMethod).c_str());
}

std::vector<std::string> CRPCTable::listCommands() const
{
    std::vector<std::string> commandList;
    typedef std::map<std::string, const CRPCCommand*> commandMap;

    std::transform( mapCommands.begin(), mapCommands.end(),
                   std::back_inserter(commandList),
                   boost::bind(&commandMap::value_type::first,_1) );
    return commandList;
}

std::string CRPCTable::help(const std::string& strCommand, const JSONRPCRequest& helpreq) const
{
    std::string strRet;
    std::string category;
    std::set<rpcfn_type> setDone;
    std::vector<std::pair<std::string, const CRPCCommand*> > vCommands;

    for (std::map<std::string, const CRPCCommand*>::const_iterator mi = mapCommands.begin(); mi != mapCommands.end(); ++mi)
    {
        vCommands.push_back(make_pair(mi->second->category + mi->first, mi->second));
    }

    sort(vCommands.begin(), vCommands.end());

    JSONRPCRequest jreq(helpreq);
    jreq.fHelp = true;
    jreq.params = UniValue();

    BOOST_FOREACH(const PAIRTYPE(std::string, const CRPCCommand*)& command, vCommands)
    {
        const CRPCCommand *pcmd = command.second;
        std::string strMethod = pcmd->name;
        if ((strCommand != "" || pcmd->category == "hidden") && strMethod != strCommand)
            continue;
        jreq.strMethod = strMethod;
        try
        {
            rpcfn_type pfn;
            if(pcmd->name == "help") pfn = &help_rpc;
            else if(pcmd->name == "executeivmc") pfn = &exe_ivmc_rpc;

            if (setDone.insert(pfn).second)
                (*pfn)(jreq);
        }
        catch (const std::exception& e)
        {
            syslog(LOG_NOTICE, "help funcion N");
            // Help text is returned in an exception
            std::string strHelp = std::string(e.what());
            if (strCommand == "")
            {
                if (strHelp.find('\n') != std::string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));

                if (category != pcmd->category)
                {
                    if (!category.empty())
                        strRet += "\n";
                    category = pcmd->category;
                    std::string firstLetter = category.substr(0,1);
                    boost::to_upper(firstLetter);
                    strRet += "== " + firstLetter + category.substr(1) + " ==\n";
                }
            }
            strRet += strHelp + "\n";
        }
    }
    if (strRet == "")
        strRet = ("help: unknown command: %s\n", strCommand);
    strRet = strRet.substr(0,strRet.size()-1);
    return strRet;
}

const CRPCCommand *CRPCTable::operator[](const std::string &name) const
{
    std::map<std::string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return NULL;
    return (*it).second;
}

bool CRPCTable::appendCommand(const std::string& name, const CRPCCommand* pcmd)
{
    if (IsRPCRunning())
        return false;

    // don't allow overwriting for now
    std::map<std::string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it != mapCommands.end())
        return false;

    mapCommands[name] = pcmd;
    return true;
}

CRPCTable::CRPCTable()
{
    CRPCCommand _help_cmd;
    _help_cmd.category = "control";
    _help_cmd.name = "help";
    _help_cmd.actor = &help_rpc;
    _help_cmd.okSafeMode = true;
    _help_cmd.argNames = {"command"};
    appendCommand("help", &_help_cmd);

    CRPCCommand _exe_ivmc_cmd;
    _exe_ivmc_cmd.category = "ivmc";
    _exe_ivmc_cmd.name = "executeivmc";
    _exe_ivmc_cmd.actor = &exe_ivmc_rpc;
    _exe_ivmc_cmd.okSafeMode = true;
    _exe_ivmc_cmd.argNames = {"vm_config", "code", "input", "storage"};
    appendCommand("executeivmc", &_exe_ivmc_cmd);
}

static std::map<std::string, std::vector<std::string> > _mapMultiArgs;
const std::map<std::string, std::vector<std::string> >& mapMultiArgs = _mapMultiArgs;

/* Timer-creating functions */
static RPCTimerInterface* timerInterface = NULL;

/** WWW-Authenticate to present with 401 Unauthorized response */
static const char* WWW_AUTH_HEADER_DATA = "Basic realm=\"jsonrpc\"";

/** Simple one-shot callback timer to be used by the RPC mechanism to e.g.
 * re-lock the wallet.
 */
class HTTPRPCTimer : public RPCTimerBase
{
public:
    HTTPRPCTimer(struct event_base* eventBase, boost::function<void(void)>& func, int64_t millis) :
        ev(eventBase, false, func)
    {
        struct timeval tv;
        tv.tv_sec = millis/1000;
        tv.tv_usec = (millis%1000)*1000;
        ev.trigger(&tv);
    }
private:
    HTTPEvent ev;
};

class HTTPRPCTimerInterface : public RPCTimerInterface
{
public:
    HTTPRPCTimerInterface(struct event_base* _base) : base(_base)
    {
    }
    const char* Name()
    {
        return "HTTP";
    }
    RPCTimerBase* NewTimer(boost::function<void(void)>& func, int64_t millis)
    {
        return new HTTPRPCTimer(base, func, millis);
    }
private:
    struct event_base* base;
};

/* Pre-base64-encoded authentication token */
static std::string strRPCUserColonPass;
/* Stored RPC timer interface (for unregistration) */
static HTTPRPCTimerInterface* httpRPCTimerInterface = 0;

static void JSONErrorReply(HTTPRequest* req, const UniValue& objError, const UniValue& id)
{
    // Send error reply from json-rpc error object
    int nStatus = HTTP_INTERNAL_SERVER_ERROR;
    int code = find_value(objError, "code").get_int();

    if (code == RPC_INVALID_REQUEST)
        nStatus = HTTP_BAD_REQUEST;
    else if (code == RPC_METHOD_NOT_FOUND)
        nStatus = HTTP_NOT_FOUND;

    std::string strReply = JSONRPCReply(NullUniValue, objError, id);

    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(nStatus, strReply);
}

//This function checks username and password against -rpcauth
//entries from config file.
static bool multiUserAuthorized(std::string strUserPass)
{
    if (strUserPass.find(":") == std::string::npos) {
        return false;
    }
    std::string strUser = strUserPass.substr(0, strUserPass.find(":"));
    std::string strPass = strUserPass.substr(strUserPass.find(":") + 1);

    if (mapMultiArgs.count("-rpcauth") > 0) {
        //Search for multi-user login/pass "rpcauth" from config
        BOOST_FOREACH(std::string strRPCAuth, mapMultiArgs.at("-rpcauth"))
        {
            std::vector<std::string> vFields;
            boost::split(vFields, strRPCAuth, boost::is_any_of(":$"));
            if (vFields.size() != 3) {
                //Incorrect formatting in config file
                continue;
            }

            std::string strName = vFields[0];
            if (!TimingResistantEqual(strName, strUser)) {
                continue;
            }

            std::string strSalt = vFields[1];
            std::string strHash = vFields[2];

            static const unsigned int KEY_SIZE = 32;
            unsigned char out[KEY_SIZE];

            CHMAC_SHA256(reinterpret_cast<const unsigned char*>(strSalt.c_str()), strSalt.size()).Write(reinterpret_cast<const unsigned char*>(strPass.c_str()), strPass.size()).Finalize(out);
            std::vector<unsigned char> hexvec(out, out+KEY_SIZE);
            std::string strHashFromPass = HexStr(hexvec);

            if (TimingResistantEqual(strHashFromPass, strHash)) {
                return true;
            }
        }
    }
    return false;
}

static bool RPCAuthorized(const std::string& strAuth, std::string& strAuthUsernameOut)
{
    if (strRPCUserColonPass.empty()) // Belt-and-suspenders measure if InitRPCAuthentication was not called
        return false;
    if (strAuth.substr(0, 6) != "Basic ")
        return false;
    std::string strUserPass64 = strAuth.substr(6);
    boost::trim(strUserPass64);
    std::string strUserPass = DecodeBase64(strUserPass64);

    if (strUserPass.find(":") != std::string::npos)
        strAuthUsernameOut = strUserPass.substr(0, strUserPass.find(":"));

    //Check if authorized under single-user field
    if (TimingResistantEqual(strUserPass, strRPCUserColonPass)) {
        return true;
    }
    return multiUserAuthorized(strUserPass);
}

static bool HTTPReq_JSONRPC(HTTPRequest* req, const std::string &)
{
    // JSONRPC handles only POST
    if (req->GetRequestMethod() != HTTPRequest::POST) {
        req->WriteReply(HTTP_BAD_METHOD, "JSONRPC server handles only POST requests");
        return false;
    }
    // Check authorization
    std::pair<bool, std::string> authHeader = req->GetHeader("authorization");
    if (!authHeader.first) {
        req->WriteHeader("WWW-Authenticate", WWW_AUTH_HEADER_DATA);
        req->WriteReply(HTTP_UNAUTHORIZED);
        return false;
    }

    JSONRPCRequest jreq;
    if (!RPCAuthorized(authHeader.second, jreq.authUser)) {
        syslog(LOG_NOTICE, ("ThreadRPCServer incorrect password attempt from localhost otus"));

        /* Deter brute-forcing
           If this results in a DoS the user really
           shouldn't have their RPC port exposed. */
        MilliSleep(250);

        req->WriteHeader("WWW-Authenticate", WWW_AUTH_HEADER_DATA);
        req->WriteReply(HTTP_UNAUTHORIZED);
        return false;
    }

    try {
        // Parse request
        UniValue valRequest;
        if (!valRequest.read(req->ReadBody()))
            throw JSONRPCError(RPC_PARSE_ERROR, "Parse error");

        // Set the URI
        jreq.URI = req->GetURI();

        std::string strReply;
        // singleton request
        if (valRequest.isObject()) {
            jreq.parse(valRequest);

            UniValue result = tableRPC.execute(jreq);

            // Send reply
            strReply = JSONRPCReply(result, NullUniValue, jreq.id);

        // array of requests
        } else if (valRequest.isArray())
            strReply = JSONRPCExecBatch(valRequest.get_array());
        else
            throw JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");

        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strReply);
    } catch (const UniValue& objError) {
        JSONErrorReply(req, objError, jreq.id);
        return false;
    } catch (const std::exception& e) {
        JSONErrorReply(req, JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
        return false;
    }
    return true;
}

static bool InitRPCAuthentication()
{
    strRPCUserColonPass = "user:password";
    return true;
}

void RPCSetTimerInterfaceIfUnset(RPCTimerInterface *iface)
{
    if (!timerInterface)
        timerInterface = iface;
}

void RPCSetTimerInterface(RPCTimerInterface *iface)
{
    timerInterface = iface;
}

void RPCUnsetTimerInterface(RPCTimerInterface *iface)
{
    if (timerInterface == iface)
        timerInterface = NULL;
}

bool StartHTTPRPC()
{
    syslog(LOG_NOTICE, "rpc: Starting HTTP RPC server");
    if (!InitRPCAuthentication())
        return false;

    RegisterHTTPHandler("/", true, HTTPReq_JSONRPC);

    assert(EventBase());
    httpRPCTimerInterface = new HTTPRPCTimerInterface(EventBase());
    RPCSetTimerInterface(httpRPCTimerInterface);
    return true;
}

void InterruptHTTPRPC()
{
    syslog(LOG_NOTICE, "rpc: Interrupting HTTP RPC server");
}

void StopHTTPRPC()
{
    syslog(LOG_NOTICE, "rpc: Stopping HTTP RPC server");
    UnregisterHTTPHandler("/", true);
    if (httpRPCTimerInterface) {
        RPCUnsetTimerInterface(httpRPCTimerInterface);
        delete httpRPCTimerInterface;
        httpRPCTimerInterface = 0;
    }
}

// ------------------------------- dbwrapper.cpp
static leveldb::Options GetOptions(size_t nCacheSize)
{
    leveldb::Options options;
    // options.block_cache = leveldb::NewLRUCache(nCacheSize / 2);
    options.write_buffer_size = nCacheSize / 4; // up to two write buffers may be held in memory simultaneously
    // options.filter_policy = leveldb::NewBloomFilterPolicy(10);
    options.compression = leveldb::kNoCompression;
    options.max_open_files = 64;
    if (leveldb::kMajorVersion > 1 || (leveldb::kMajorVersion == 1 && leveldb::kMinorVersion >= 16)) {
        // LevelDB versions before 1.16 consider short writes to be corruption. Only trigger error
        // on corruption in later versions.
        options.paranoid_checks = true;
    }
    // options.env = leveldb::NewMemEnv(leveldb::Env::Default());
    return options;
}

CDBWrapper::CDBWrapper(const boost::filesystem::path& path, size_t nCacheSize, bool fMemory, bool fWipe, bool obfuscate)
{
    penv = NULL;
    readoptions.verify_checksums = true;
    iteroptions.verify_checksums = true;
    iteroptions.fill_cache = false;
    syncoptions.sync = true;
    options = GetOptions(nCacheSize);
    options.create_if_missing = true;
    if (fMemory) {
        syslog(LOG_NOTICE, "ivmc: fMemory");
        // penv = leveldb::NewMemEnv(leveldb::Env::Default());
        // options.env = penv;
    } else {
        if (fWipe) {
            syslog(LOG_NOTICE, "ivmc: fWipe");
            LogPrintf("Wiping LevelDB in %s\n", path.string());
            leveldb::Status result = leveldb::DestroyDB(path.string(), options);
            dbwrapper_private::HandleError(result);
        }
        TryCreateDirectory(path);
        syslog(LOG_NOTICE, "ivmc: TryCreateDirectory");

        LogPrintf("Opening LevelDB in %s\n", path.string());
        syslog(LOG_NOTICE, ("ivmc: path " + path.string()).c_str());
    }
    leveldb::Status status = leveldb::DB::Open(options, path.string(), &pdb);
    dbwrapper_private::HandleError(status);

    LogPrintf("Opened LevelDB successfully\n");
    syslog(LOG_NOTICE, "ivmc: Opened LevelDB successfully");

    // The base-case obfuscation key, which is a noop.
    obfuscate_key = std::vector<unsigned char>(OBFUSCATE_KEY_NUM_BYTES, '\000');

    bool key_exists = Read(OBFUSCATE_KEY_KEY, obfuscate_key);

    if (!key_exists && obfuscate && IsEmpty()) {
        // Initialize non-degenerate obfuscation if it won't upset
        // existing, non-obfuscated data.
        std::vector<unsigned char> new_key = CreateObfuscateKey();

        // Write `new_key` so we don't obfuscate the key with itself
        Write(OBFUSCATE_KEY_KEY, new_key);
        obfuscate_key = new_key;

        LogPrintf("Wrote new obfuscate key for %s: %s\n", path.string(), HexStr(obfuscate_key));
    }

    LogPrintf("Using obfuscation key for %s: %s\n", path.string(), HexStr(obfuscate_key));
}

CDBWrapper::~CDBWrapper()
{
    delete pdb;
    pdb = NULL;
    // delete options.filter_policy;
    // options.filter_policy = NULL;
    // delete options.block_cache;
    // options.block_cache = NULL;
    // delete penv;
    // options.env = NULL;
}

bool CDBWrapper::WriteBatch(CDBBatch& batch, bool fSync)
{
    leveldb::Status status = pdb->Write(fSync ? syncoptions : writeoptions, &batch.batch);
    dbwrapper_private::HandleError(status);
    return true;
}

// Prefixed with null character to avoid collisions with other keys
//
// We must use a string constructor which specifies length so that we copy
// past the null-terminator.
const std::string CDBWrapper::OBFUSCATE_KEY_KEY("\000obfuscate_key", 14);

const unsigned int CDBWrapper::OBFUSCATE_KEY_NUM_BYTES = 8;

/**
 * Returns a string (consisting of 8 random bytes) suitable for use as an
 * obfuscating XOR key.
 */
std::vector<unsigned char> CDBWrapper::CreateObfuscateKey() const
{
    unsigned char buff[OBFUSCATE_KEY_NUM_BYTES];
    GetRandBytes(buff, OBFUSCATE_KEY_NUM_BYTES);
    return std::vector<unsigned char>(&buff[0], &buff[OBFUSCATE_KEY_NUM_BYTES]);

}

bool CDBWrapper::IsEmpty()
{
    std::unique_ptr<CDBIterator> it(NewIterator());
    it->SeekToFirst();
    return !(it->Valid());
}

CDBIterator::~CDBIterator() { delete piter; }
bool CDBIterator::Valid() { return piter->Valid(); }
void CDBIterator::SeekToFirst() { piter->SeekToFirst(); }
void CDBIterator::Next() { piter->Next(); }

namespace dbwrapper_private {

void HandleError(const leveldb::Status& status)
{
    if (status.ok())
        return;
    std::string _status = status.ToString();
    LogPrintf("%s\n", _status);
    if (status.IsCorruption())
        throw dbwrapper_error("Database corrupted");
    if (status.IsIOError())
        throw dbwrapper_error("Database I/O error");
    if (status.IsNotFound())
        throw dbwrapper_error("Database entry missing");
    throw dbwrapper_error("Unknown database error");
}

const std::vector<unsigned char>& GetObfuscateKey(const CDBWrapper &w)
{
    return w.obfuscate_key;
}

};

void memory_cleanse(void *ptr, size_t len)
{
    OPENSSL_cleanse(ptr, len);
}

// ------------------------------- txdb.cpp

static const char DB_COINS = 'c';
static const char DB_BLOCK_FILES = 'f';
static const char DB_TXINDEX = 't';
static const char DB_BLOCK_INDEX = 'b';

static const char DB_BEST_BLOCK = 'B';
static const char DB_FLAG = 'F';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_LAST_BLOCK = 'l';

CBlockTreeDB::CBlockTreeDB(size_t nCacheSize, bool fMemory, bool fWipe, const boost::filesystem::path& path) : CDBWrapper(path, nCacheSize, fMemory, fWipe) {
}

bool CBlockTreeDB::WriteTxIndex(const std::vector<std::pair<ivmc::address, CDiskBlockPos> >&vect) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<ivmc::address,CDiskBlockPos> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
        batch.Write(std::make_pair(DB_TXINDEX, it->first), it->second);
    return WriteBatch(batch);
}

bool CBlockTreeDB::WriteTxIndex(const std::vector<std::pair<ivmc::address, CDiskTxPos> >&vect) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<ivmc::address,CDiskTxPos> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
        batch.Write(std::make_pair(DB_TXINDEX, it->first), it->second);
    return WriteBatch(batch);
}

bool CBlockTreeDB::WriteTxIndex(const std::vector<std::pair<std::string, CDiskTxPos> >&vect) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<std::string,CDiskTxPos> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
        batch.Write(std::make_pair(DB_TXINDEX, it->first), it->second);
    return WriteBatch(batch);
}

// ------------------------------- Util
static FILE* fileout = NULL;
static boost::mutex* mutexDebugLog = NULL;
static std::list<std::string> *vMsgsBeforeOpenLog;

static boost::once_flag debugPrintInitFlag = BOOST_ONCE_INIT;

static int FileWriteStr(const std::string &str, FILE *fp)
{
    return fwrite(str.data(), 1, str.size(), fp);
}

static void DebugPrintInit()
{
    assert(mutexDebugLog == NULL);
    mutexDebugLog = new boost::mutex();
    vMsgsBeforeOpenLog = new std::list<std::string>;
}

static std::string LogTimestampStr(const std::string &str, std::atomic_bool *fStartedNewLine)
{
    std::string strStamped;

    if (!fLogTimestamps)
        return str;

    if (*fStartedNewLine) {
        int64_t nTimeMicros = GetLogTimeMicros();
        strStamped = DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nTimeMicros/1000000);
        if (fLogTimeMicros)
            strStamped += strprintf(".%06d", nTimeMicros%1000000);
        strStamped += ' ' + str;
    } else
        strStamped = str;

    if (!str.empty() && str[str.size()-1] == '\n')
        *fStartedNewLine = true;
    else
        *fStartedNewLine = false;

    return strStamped;
}

bool fDebug = false;
bool fPrintToConsole = true;
bool fPrintToDebugLog = true;

bool fLogTimestamps = DEFAULT_LOGTIMESTAMPS;
bool fLogTimeMicros = DEFAULT_LOGTIMEMICROS;

int LogPrintStr(const std::string &str)
{
    int ret = 0; // Returns total number of characters written
    static std::atomic_bool fStartedNewLine(true);

    std::string strTimestamped = LogTimestampStr(str, &fStartedNewLine);

    if (fPrintToConsole)
    {
        // print to console
        ret = fwrite(strTimestamped.data(), 1, strTimestamped.size(), stdout);
        fflush(stdout);
    }
    else if (fPrintToDebugLog)
    {
        boost::call_once(&DebugPrintInit, debugPrintInitFlag);
        boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

        // buffer if we haven't opened the log yet
        if (fileout == NULL) {
            assert(vMsgsBeforeOpenLog);
            ret = strTimestamped.length();
            vMsgsBeforeOpenLog->push_back(strTimestamped);
        }
        else
        {
            // reopen the log file, if requested
            if (fReopenDebugLog) {
                fReopenDebugLog = false;
                boost::filesystem::path pathDebug = GetDataDir() / "debug.log";
                if (freopen(pathDebug.string().c_str(),"a",fileout) != NULL)
                    setbuf(fileout, NULL); // unbuffered
            }

            ret = FileWriteStr(strTimestamped, fileout);
        }
    }
    return ret;
}

// ------------------------------- FILE
FILE* OpenDiskFile(const CDiskBlockPos &pos, const char *prefix, bool fReadOnly)
{
    if (pos.IsNull())
        return NULL;
    boost::filesystem::path path = GetStoragePosFilename(pos, prefix);
    boost::filesystem::create_directories(path.parent_path());
    FILE* file = fopen(path.string().c_str(), "rb+");
    if (!file && !fReadOnly)
        file = fopen(path.string().c_str(), "wb+");
    if (!file) {
        syslog(LOG_NOTICE, strprintf("Unable to open file %s\n", path.string()).c_str());
        return NULL;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            syslog(LOG_NOTICE, strprintf("Unable to seek to position %u of %s\n", pos.nPos, path.string()).c_str());
            fclose(file);
            return NULL;
        }
    }
    return file;
}

FILE* OpenIndexFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "idx", fReadOnly);
}

FILE* OpenStorageFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "sto", fReadOnly);
}

boost::filesystem::path GetStoragePosFilename(const CDiskBlockPos &pos, const char *prefix)
{
    return GetDataDir() / "storage" / strprintf("%s%05u.dat", prefix, pos.nFile);
}

// ------------------------------- TIME
static int64_t nMockTime = 0; //!< For unit testing

int64_t GetTime()
{
    if (nMockTime) return nMockTime;

    time_t now = time(NULL);
    assert(now > 0);
    return now;
}

void SetMockTime(int64_t nMockTimeIn)
{
    nMockTime = nMockTimeIn;
}

int64_t GetTimeMillis()
{
    int64_t now = (boost::posix_time::microsec_clock::universal_time() -
                   boost::posix_time::ptime(boost::gregorian::date(1970,1,1))).total_milliseconds();
    assert(now > 0);
    return now;
}

int64_t GetTimeMicros()
{
    int64_t now = (boost::posix_time::microsec_clock::universal_time() -
                   boost::posix_time::ptime(boost::gregorian::date(1970,1,1))).total_microseconds();
    assert(now > 0);
    return now;
}

int64_t GetSystemTimeInSeconds()
{
    return GetTimeMicros()/1000000;
}

/** Return a time useful for the debug log */
int64_t GetLogTimeMicros()
{
    if (nMockTime) return nMockTime*1000000;

    return GetTimeMicros();
}

void MilliSleep(int64_t n)
{

/**
 * Boost's sleep_for was uninterruptible when backed by nanosleep from 1.50
 * until fixed in 1.52. Use the deprecated sleep method for the broken case.
 * See: https://svn.boost.org/trac/boost/ticket/7238
 */
#if defined(HAVE_WORKING_BOOST_SLEEP_FOR)
    boost::this_thread::sleep_for(boost::chrono::milliseconds(n));
#elif defined(HAVE_WORKING_BOOST_SLEEP)
    boost::this_thread::sleep(boost::posix_time::milliseconds(n));
#else
//should never get here
#error missing boost sleep implementation
#endif
}

std::string DateTimeStrFormat(const char* pszFormat, int64_t nTime)
{
    static std::locale classic(std::locale::classic());
    // std::locale takes ownership of the pointer
    std::locale loc(classic, new boost::posix_time::time_facet(pszFormat));
    std::stringstream ss;
    ss.imbue(loc);
    ss << boost::posix_time::from_time_t(nTime);
    return ss.str();
}

// ------------------------------- RAND
static void RandFailure()
{
    LogPrintf("Failed to read randomness, aborting\n");
    abort();
}

void GetRandBytes(unsigned char* buf, int num)
{
    if (RAND_bytes(buf, num) != 1) {
        RandFailure();
    }
}

uint64_t GetRand(uint64_t nMax)
{
    if (nMax == 0)
        return 0;

    // The range of the random source must be a multiple of the modulus
    // to give every possible output value an equal possibility
    uint64_t nRange = (std::numeric_limits<uint64_t>::max() / nMax) * nMax;
    uint64_t nRand = 0;
    do {
        GetRandBytes((unsigned char*)&nRand, sizeof(nRand));
    } while (nRand >= nRange);
    return (nRand % nMax);
}

int GetRandInt(int nMax)
{
    return GetRand(nMax);
}

ivmc::address GetRandHash()
{
    ivmc::address hash;
    GetRandBytes((unsigned char*)&hash, sizeof(hash));
    return hash;
}

// ------------------------------- util.h
boost::filesystem::path GetDefaultDataDir()
{
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\Ilcoin
    namespace fs = boost::filesystem;
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\Ilcoin
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\Ilcoin
    // Mac: ~/Library/Application Support/Ilcoin
    // Unix: ~/.ilcoin
    fs::path pathRet;
    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        pathRet = fs::path("/");
    else pathRet = fs::path(pszHome);
    return pathRet / ".ivmcd";
}

static boost::filesystem::path pathCached;
static boost::filesystem::path pathCachedNetSpecific;
static CCriticalSection csPathCached;

const boost::filesystem::path &GetDataDir(bool fNetSpecific)
{
    // This can be called during exceptions by LogPrintf(), so we cache the
    namespace fs = boost::filesystem;

    LOCK(csPathCached);

    fs::path &path = fNetSpecific ? pathCachedNetSpecific : pathCached;

    // This can be called during exceptions by LogPrintf(), so we cache the
    // value so we don't have to do memory allocations after that.
    if (!path.empty())
        return path;

    // if (IsArgSet("-datadir")) {
    //     path = fs::system_complete(GetArg("-datadir", ""));
    //     if (!fs::is_directory(path)) {
    //         path = "";
    //         return path;
    //     }
    // } else {
        path = GetDefaultDataDir();
    // }

    fs::create_directories(path);

    return path;
}

/**
 * Ignores exceptions thrown by Boost's create_directory if the requested directory exists.
 * Specifically handles case where path p exists, but it wasn't possible for the user to
 * write to the parent directory.
 */
bool TryCreateDirectory(const boost::filesystem::path& p)
{
    try
    {
        return boost::filesystem::create_directory(p);
    } catch (const boost::filesystem::filesystem_error&) {
        if (!boost::filesystem::exists(p) || !boost::filesystem::is_directory(p))
            throw;
    }

    // create_directory didn't create the directory, it had to have existed already
    return false;
}

void SetupEnvironment()
{
    // On most POSIX systems (e.g. Linux, but not BSD) the environment's locale
    // may be invalid, in which case the "C" locale is used as fallback.
#if !defined(WIN32) && !defined(MAC_OSX) && !defined(__FreeBSD__) && !defined(__OpenBSD__)
    try {
        std::locale(""); // Raises a runtime error if current locale is invalid
    } catch (const std::runtime_error&) {
        setenv("LC_ALL", "C", 1);
    }
#endif
    setenv("LC_ALL", "C", 1);
    // The path locale is lazy initialized and to avoid deinitialization errors
    // in multithreading environments, it is set explicitly by the main thread.
    // A dummy locale is used to extract the internal default locale, used by
    // boost::filesystem::path, which is then used to explicitly imbue the path.
    std::locale loc = boost::filesystem::path::imbue(std::locale::classic());
    boost::filesystem::path::imbue(loc);
}

// ------------------------------- InitDB
// Test if a string consists entirely of null characters
bool is_null_key(const std::vector<unsigned char>& key) {
    bool isnull = true;

    for (unsigned int i = 0; i < key.size(); i++)
        isnull &= (key[i] == '\x00');

    return isnull;
}

const int kNumKeys = 1100000;

std::string Key1(int i) {
  char buf[100];
  snprintf(buf, sizeof(buf), "my_key_%d", i);
  return buf;
}

std::string Key2(int i) {
  return Key1(i) + "_xxx";
}

class Issue178 { };

bool InitDB()
{
  SetupEnvironment();
  // syslog(LOG_NOTICE, "ivmc: CDBWrapper Test 1");
  // // We're going to share this boost::filesystem::path between two wrappers
  // boost::filesystem::path ph = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
  // create_directories(ph);
  //
  // // Set up a non-obfuscated wrapper to write some initial data.
  // CDBWrapper* dbw = new CDBWrapper(ph, (1 << 10), false, false, false);
  // char key = 'k';
  // ivmc::address in = GetRandHash();
  // ivmc::address res;
  //
  // BOOST_CHECK(dbw->Write(key, in));
  // BOOST_CHECK(dbw->Read(key, res));
  // BOOST_CHECK_EQUAL(res.ToString(), in.ToString());
  //
  // // Call the destructor to free leveldb LOCK
  // delete dbw;
  //
  // // Now, set up another wrapper that wants to obfuscate the same directory
  // CDBWrapper odbw(ph, (1 << 10), false, false, true);
  //
  // // Check that the key/val we wrote with unobfuscated wrapper exists and
  // // is readable.
  // ivmc::address res2;
  // BOOST_CHECK(odbw.Read(key, res2));
  // BOOST_CHECK_EQUAL(res2.ToString(), in.ToString());
  //
  // BOOST_CHECK(!odbw.IsEmpty()); // There should be existing data
  // BOOST_CHECK(is_null_key(dbwrapper_private::GetObfuscateKey(odbw))); // The key should be an empty string
  //
  // ivmc::address in2 = GetRandHash();
  // ivmc::address res3;
  //
  // // Check that we can write successfully
  // BOOST_CHECK(odbw.Write(key, in2));
  // BOOST_CHECK(odbw.Read(key, res3));
  // BOOST_CHECK_EQUAL(res3.ToString(), in2.ToString());
  // syslog(LOG_NOTICE, "ivmc: CDBWrapper Test 2");
  // syslog(LOG_NOTICE, ("ivmc: CDBWrapper Test res3 " + res3.ToString()).c_str());
  // syslog(LOG_NOTICE, ("ivmc: CDBWrapper Test in2 " + in2.ToString()).c_str());

  // cache size calculations
  int64_t nTotalCache = nDefaultDbCache;
  nTotalCache = std::max(nTotalCache, nMinDbCache << 20); // total cache cannot be less than nMinDbCache
  nTotalCache = std::min(nTotalCache, nMaxDbCache << 20); // total cache cannot be greater than nMaxDbcache
  int64_t nBlockTreeDBCache = nTotalCache / 8;
  nBlockTreeDBCache = std::min(nBlockTreeDBCache, (nMaxBlockDBAndTxIndexCache) << 20);

  syslog(LOG_NOTICE, ("ivmc: datadir " + GetDataDir().string()).c_str());

  boost::filesystem::create_directories(GetDataDir() / "storage");

  syslog(LOG_NOTICE, "ivmc: CBlockTreeDB");

  psmartcontracttree = new CBlockTreeDB(nBlockTreeDBCache, false, false, GetDataDir() / "storage" / "index");

  return true;
}

namespace
{
  void do_heartbeat(int count)
  {
     // TODO: implement processing code to be performed on each heartbeat
     syslog(LOG_NOTICE, ("do_heartbeat daemon-name: " + std::to_string(count)).c_str());
  }

}  // namespace

int main(int argc, const char** argv)
{
  pid_t pid, sid;

  // Fork the current process
  pid = fork();
  // The parent process continues with a process ID greater than 0
  if(pid > 0)
  {
   exit(EXIT_SUCCESS);
  }
  // A process ID lower than 0 indicates a failure in either process
  else if(pid < 0)
  {
   exit(EXIT_FAILURE);
  }
  // The parent process has now terminated, and the forked child process will continue
  // (the pid of the child process was 0)

  // Since the child process is a daemon, the umask needs to be set so files and logs can be written
  umask(0);

  // Open system logs for the child process
  openlog("daemon-named", LOG_NOWAIT | LOG_PID, LOG_USER);
  syslog(LOG_NOTICE, "Successfully started daemon-name");

  // Generate a session ID for the child process
  sid = setsid();
  // Ensure a valid SID for the child process
  if(sid < 0)
  {
   // Log failure and exit
   syslog(LOG_ERR, "Could not generate session ID for child process");

   // If a new session ID could not be generated, we must terminate the child process
   // or it will be orphaned
   exit(EXIT_FAILURE);
  }

  // Change the current working directory to a directory guaranteed to exist
  if((chdir("/")) < 0)
  {
   // Log failure and exit
   syslog(LOG_ERR, "Could not change working directory to /");

   // If our guaranteed directory does not exist, terminate the child process to ensure
   // the daemon has not been hijacked
   exit(EXIT_FAILURE);
  }

  // A daemon cannot use the terminal, so close standard file descriptors for security reasons
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);

  // Daemon-specific intialization should go here
  const int SLEEP_INTERVAL = 60;

  // Init Server
  if (!InitHTTPServer())
      return false;
  if (!StartRPC())
      return false;
  if (!StartHTTPRPC())
      return false;
  if (!StartHTTPServer())
      return false;
  if (!InitIVMC())
      return false;
  if (!InitDB())
      return false;

  SetRPCWarmupFinished();

  // Enter daemon loop
  uint c = 0;
  while(1)
  {
    c = c + 1 > 65535 ? 0 : c + 1;

    // Execute daemon heartbeat, where your recurring activity occurs
    do_heartbeat(c);

    std::cout.flush();

    // Sleep for a period of time
    sleep(SLEEP_INTERVAL);
  }

  // Close system logs for the child process
  syslog(LOG_NOTICE, "Stopping daemon-name");
  closelog();

  // Terminate the child process when the daemon completes
  exit(EXIT_SUCCESS);
}
