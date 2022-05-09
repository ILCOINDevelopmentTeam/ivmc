// IVMC: Ethereum Client-VM Connector API.
// Copyright 2019-2022 The IVMC Authors.

#include "deamon.h"
#include "univalue_escapes.h"
#include "common.h"

#include <CLI/CLI.hpp>
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

#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
#ifdef _XOPEN_SOURCE_EXTENDED
#include <arpa/inet.h>
#endif
#endif

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
        // Execute, convert arguments to array if necessary
        if (request.params.isObject()) {
            syslog(LOG_NOTICE, ("execute strMethod 4 " + request.strMethod).c_str());
            return pcmd->actor(transformNamedArguments(request, pcmd->argNames));
        } else {
            syslog(LOG_NOTICE, ("execute strMethod 5 " + request.strMethod).c_str());

            // rpcfn_type method = pcmd->actor;
            rpcfn_type method = &help_rpc;
            if(method){
              syslog(LOG_NOTICE, ("execute strMethod 8 " + request.strMethod).c_str());
              UniValue result = (*method)(request);
              return result;
            }
            else throw JSONRPCError(RPC_MISC_ERROR, "actor empty");
            // return pcmd->actor(request);
        }
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
            rpcfn_type pfn = pcmd->actor;
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
    CRPCCommand _pcmd;
    _pcmd.category = "control";
    _pcmd.name = "help";
    _pcmd.actor = &help_rpc;
    _pcmd.okSafeMode = true;
    _pcmd.argNames = {"command"};
    appendCommand("help", &_pcmd);
}

void MilliSleep(int64_t n)
{

  /**
   * Boost's sleep_for was uninterruptible when backed by nanosleep from 1.50
   * until fixed in 1.52. Use the deprecated sleep method for the broken case.
   * See: https://svn.boost.org/trac/boost/ticket/7238
   */
   boost::this_thread::sleep_for(boost::chrono::milliseconds(n));
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

// --------------------------------- IVMC
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

    std::string vm_config;
    std::string code_arg;
    int64_t gas = 1000000;
    auto rev = IVMC_LATEST_STABLE_REVISION;
    std::string input_arg;
    std::string storage_arg;
    std::string recipient_arg;
    std::string sender_arg;

    return true;
}

int ExecuteIVMC()
{
    using namespace ivmc;

    static HexValidator Hex;

    std::string vm_config = "/root/res/ivmone/build/lib/libivmone.so"; //Hard coded
    std::string code_arg = "608060405234801561001057600080fd5b506004361061025e5760003560e01c806379cc679011610146578063a9059cbb116100c3578063d547741f11610087578063d547741f14610f36578063d8fbe99414610f84578063dd62ed3e14611008578063f1b50c1d14611080578063f2fde38b1461108a578063f5b541a6146110ce5761025e565b8063a9059cbb14610c5c578063c1d34b8914610cc0578063ca15c87314610ddb578063cae9ca5114610e1d578063d539139314610f185761025e565b80639010d07c1161010a5780639010d07c14610a9157806391d1485414610af357806395d89b4114610b57578063a217fddf14610bda578063a457c2d714610bf85761025e565b806379cc6790146109345780637afa1eed146109825780637d64bcb414610a055780638980f11f14610a0f5780638da5cb5b14610a5d5761025e565b80633177029f116101df57806340c10f19116101a357806340c10f19146107b357806342966c68146108015780634cd412d51461082f57806354fd4d501461084f57806370a08231146108d2578063715018a61461092a5761025e565b80633177029f14610584578063355274ea146105e857806336568abe1461060657806339509351146106545780634000aea0146106b85761025e565b806318160ddd1161022657806318160ddd1461043157806323b872dd1461044f578063248a9ca3146104d35780632f2ff15d14610515578063313ce567146105635761025e565b806301ffc9a71461026357806305d2035b146102c657806306fdde03146102e6578063095ea7b3146103695780631296ee62146103cd575b600080fd5b6102ae6004803603602081101561027957600080fd5b8101908080357bffffffffffffffffffffffffffffffffffffffffffffffffffffffff191690602001909291905050506110ec565b60405180821515815260200191505060405180910390f35b6102ce611154565b60405180821515815260200191505060405180910390f35b6102ee61116b565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561032e578082015181840152602081019050610313565b50505050905090810190601f16801561035b5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6103b56004803603604081101561037f57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019092919050505061120d565b60405180821515815260200191505060405180910390f35b610419600480360360408110156103e357600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019092919050505061122b565b60405180821515815260200191505060405180910390f35b61043961124f565b6040518082815260200191505060405180910390f35b6104bb6004803603606081101561046557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050611259565b60405180821515815260200191505060405180910390f35b6104ff600480360360208110156104e957600080fd5b8101908080359060200190929190505050611307565b6040518082815260200191505060405180910390f35b6105616004803603604081101561052b57600080fd5b8101908080359060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611327565b005b61056b6113b1565b604051808260ff16815260200191505060405180910390f35b6105d06004803603604081101561059a57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506113c8565b60405180821515815260200191505060405180910390f35b6105f06113ec565b6040518082815260200191505060405180910390f35b6106526004803603604081101561061c57600080fd5b8101908080359060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506113f6565b005b6106a06004803603604081101561066a57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019092919050505061148f565b60405180821515815260200191505060405180910390f35b61079b600480360360608110156106ce57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291908035906020019064010000000081111561071557600080fd5b82018360208201111561072757600080fd5b8035906020019184600183028401116401000000008311171561074957600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290505050611542565b60405180821515815260200191505060405180910390f35b6107ff600480360360408110156107c957600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506115c2565b005b61082d6004803603602081101561081757600080fd5b81019080803590602001909291905050506116d9565b005b6108376116ed565b60405180821515815260200191505060405180910390f35b610857611704565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561089757808201518184015260208101905061087c565b50505050905090810190601f1680156108c45780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b610914600480360360208110156108e857600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611741565b6040518082815260200191505060405180910390f35b610932611789565b005b6109806004803603604081101561094a57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050611914565b005b61098a611976565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156109ca5780820151818401526020810190506109af565b50505050905090810190601f1680156109f75780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b610a0d6119b3565b005b610a5b60048036036040811015610a2557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050611b49565b005b610a65611ccb565b604051808273ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b610ac760048036036040811015610aa757600080fd5b810190808035906020019092919080359060200190929190505050611cf5565b604051808273ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b610b3f60048036036040811015610b0957600080fd5b8101908080359060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611d27565b60405180821515815260200191505060405180910390f35b610b5f611d59565b6040518080602001828103825283818151815260200191508051906020019080838360005b83811015610b9f578082015181840152602081019050610b84565b50505050905090810190601f168015610bcc5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b610be2611dfb565b6040518082815260200191505060405180910390f35b610c4460048036036040811015610c0e57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050611e02565b60405180821515815260200191505060405180910390f35b610ca860048036036040811015610c7257600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050611ecf565b60405180821515815260200191505060405180910390f35b610dc360048036036080811015610cd657600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019092919080359060200190640100000000811115610d3d57600080fd5b820183602082011115610d4f57600080fd5b80359060200191846001830284011164010000000083111715610d7157600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290505050611f82565b60405180821515815260200191505060405180910390f35b610e0760048036036020811015610df157600080fd5b8101908080359060200190929190505050611ffd565b6040518082815260200191505060405180910390f35b610f0060048036036060811015610e3357600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019092919080359060200190640100000000811115610e7a57600080fd5b820183602082011115610e8c57600080fd5b80359060200191846001830284011164010000000083111715610eae57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290505050612024565b60405180821515815260200191505060405180910390f35b610f2061209c565b6040518082815260200191505060405180910390f35b610f8260048036036040811015610f4c57600080fd5b8101908080359060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506120c0565b005b610ff060048036036060811015610f9a57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019092919050505061214a565b60405180821515815260200191505060405180910390f35b61106a6004803603604081101561101e57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050612170565b6040518082815260200191505060405180910390f35b6110886121f7565b005b6110cc600480360360208110156110a057600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061230a565b005b6110d661251a565b6040518082815260200191505060405180910390f35b600060076000837bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19167bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916815260200190815260200160002060009054906101000a900460ff169050919050565b6000600960149054906101000a900460ff16905090565b606060038054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156112035780601f106111d857610100808354040283529160200191611203565b820191906000526020600020905b8154815290600101906020018083116111e657829003601f168201915b5050505050905090565b600061122161121a6126d2565b84846126da565b6001905092915050565b6000611247838360405180602001604052806000815250611542565b905092915050565b6000600254905090565b600083600960159054906101000a900460ff168061129d575061129c7f523a704056dcd17bcf83bed8b68c59416dac1119be77755efe3bde0a64e46e0c82611d27565b5b6112f2576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252604a815260200180613b09604a913960600191505060405180910390fd5b6112fd8585856128d1565b9150509392505050565b600060086000838152602001908152602001600020600201549050919050565b61134e60086000848152602001908152602001600020600201546113496126d2565b611d27565b6113a3576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602f8152602001806138ee602f913960400191505060405180910390fd5b6113ad82826129aa565b5050565b6000600560009054906101000a900460ff16905090565b60006113e4838360405180602001604052806000815250612024565b905092915050565b6000600654905090565b6113fe6126d2565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614611481576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602f815260200180613b78602f913960400191505060405180910390fd5b61148b8282612a3e565b5050565b600061153861149c6126d2565b8461153385600160006114ad6126d2565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461253e90919063ffffffff16565b6126da565b6001905092915050565b600061154e8484611ecf565b5061156261155a6126d2565b858585612ad2565b6115b7576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526026815260200180613a2d6026913960400191505060405180910390fd5b600190509392505050565b600960149054906101000a900460ff1615611645576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601e8152602001807f4552433230426173653a206d696e74696e672069732066696e6973686564000081525060200191505060405180910390fd5b6116767ff0887ba65ee2024ea881d91b74c2450ef19e1557f03bed3ea9f16b037cbe2dc96116716126d2565b611d27565b6116cb576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602b815260200180613a02602b913960400191505060405180910390fd5b6116d58282612c96565b5050565b6116ea6116e46126d2565b82612e5d565b50565b6000600960159054906101000a900460ff16905090565b60606040518060400160405280600681526020017f76332e322e300000000000000000000000000000000000000000000000000000815250905090565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b6117916126d2565b73ffffffffffffffffffffffffffffffffffffffff16600960009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614611853576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff16600960009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a36000600960006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b600061195382604051806060016040528060248152602001613a7b602491396119448661193f6126d2565b612170565b6130219092919063ffffffff16565b9050611967836119616126d2565b836126da565b6119718383612e5d565b505050565b60606040518060400160405280602081526020017f68747470733a2f2f746573742e696c636f696e6578706c6f7265722e636f6d2f815250905090565b600960149054906101000a900460ff1615611a36576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601e8152602001807f4552433230426173653a206d696e74696e672069732066696e6973686564000081525060200191505060405180910390fd5b611a3e6126d2565b73ffffffffffffffffffffffffffffffffffffffff16600960009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614611b00576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b6001600960146101000a81548160ff0219169083151502179055507fae5184fba832cb2b1f702aca6117b8d265eaf03ad33eb133f19dde0f5920fa0860405160405180910390a1565b611b516126d2565b73ffffffffffffffffffffffffffffffffffffffff16600960009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614611c13576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b8173ffffffffffffffffffffffffffffffffffffffff1663a9059cbb611c37611ccb565b836040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b158015611c8b57600080fd5b505af1158015611c9f573d6000803e3d6000fd5b505050506040513d6020811015611cb557600080fd5b8101908080519060200190929190505050505050565b6000600960009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b6000611d1f82600860008681526020019081526020016000206000016130e190919063ffffffff16565b905092915050565b6000611d5182600860008681526020019081526020016000206000016130fb90919063ffffffff16565b905092915050565b606060048054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015611df15780601f10611dc657610100808354040283529160200191611df1565b820191906000526020600020905b815481529060010190602001808311611dd457829003601f168201915b5050505050905090565b6000801b81565b6000611ec5611e0f6126d2565b84611ec085604051806060016040528060258152602001613b536025913960016000611e396126d2565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008a73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546130219092919063ffffffff16565b6126da565b6001905092915050565b6000611ed96126d2565b600960159054906101000a900460ff1680611f1a5750611f197f523a704056dcd17bcf83bed8b68c59416dac1119be77755efe3bde0a64e46e0c82611d27565b5b611f6f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252604a815260200180613b09604a913960600191505060405180910390fd5b611f79848461312b565b91505092915050565b6000611f8f858585611259565b50611f9c85858585612ad2565b611ff1576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526026815260200180613a2d6026913960400191505060405180910390fd5b60019050949350505050565b600061201d60086000848152602001908152602001600020600001613149565b9050919050565b6000612030848461120d565b5061203c84848461315e565b612091576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260258152602001806139876025913960400191505060405180910390fd5b600190509392505050565b7ff0887ba65ee2024ea881d91b74c2450ef19e1557f03bed3ea9f16b037cbe2dc981565b6120e760086000848152602001908152602001600020600201546120e26126d2565b611d27565b61213c576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260308152602001806139d26030913960400191505060405180910390fd5b6121468282612a3e565b5050565b600061216784848460405180602001604052806000815250611f82565b90509392505050565b6000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b6121ff6126d2565b73ffffffffffffffffffffffffffffffffffffffff16600960009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146122c1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b6001600960156101000a81548160ff0219169083151502179055507f75fce015c314a132947a3e42f6ab79ab8e05397dabf35b4d742dea228bbadc2d60405160405180910390a1565b6123126126d2565b73ffffffffffffffffffffffffffffffffffffffff16600960009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146123d4576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260208152602001807f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657281525060200191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141561245a576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602681526020018061393f6026913960400191505060405180910390fd5b8073ffffffffffffffffffffffffffffffffffffffff16600960009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a380600960006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b7f523a704056dcd17bcf83bed8b68c59416dac1119be77755efe3bde0a64e46e0c81565b6000808284019050838110156125bc576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601b8152602001807f536166654d6174683a206164646974696f6e206f766572666c6f77000000000081525060200191505060405180910390fd5b8091505092915050565b60006125ee836000018373ffffffffffffffffffffffffffffffffffffffff1660001b613303565b905092915050565b6126018383836126cd565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1614156126c8576006546126538261264561124f565b61253e90919063ffffffff16565b11156126c7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260198152602001807f45524332304361707065643a206361702065786365656465640000000000000081525060200191505060405180910390fd5b5b505050565b505050565b600033905090565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff161415612760576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526024815260200180613ae56024913960400191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614156127e6576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260228152602001806139656022913960400191505060405180910390fd5b80600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925836040518082815260200191505060405180910390a3505050565b60006128de848484613373565b61299f846128ea6126d2565b61299a85604051806060016040528060288152602001613a5360289139600160008b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006129506126d2565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546130219092919063ffffffff16565b6126da565b600190509392505050565b6129d281600860008581526020019081526020016000206000016125c690919063ffffffff16565b15612a3a576129df6126d2565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16837f2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d60405160405180910390a45b5050565b612a66816008600085815260200190815260200160002060000161363490919063ffffffff16565b15612ace57612a736126d2565b73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16837ff6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b60405160405180910390a45b5050565b6000612af38473ffffffffffffffffffffffffffffffffffffffff16613664565b612b005760009050612c8e565b60008473ffffffffffffffffffffffffffffffffffffffff166388a7ca5c612b266126d2565b8887876040518563ffffffff1660e01b8152600401808573ffffffffffffffffffffffffffffffffffffffff1681526020018473ffffffffffffffffffffffffffffffffffffffff16815260200183815260200180602001828103825283818151815260200191508051906020019080838360005b83811015612bb6578082015181840152602081019050612b9b565b50505050905090810190601f168015612be35780820380516001836020036101000a031916815260200191505b5095505050505050602060405180830381600087803b158015612c0557600080fd5b505af1158015612c19573d6000803e3d6000fd5b505050506040513d6020811015612c2f57600080fd5b810190808051906020019092919050505090506388a7ca5c60e01b7bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916817bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916149150505b949350505050565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161415612d39576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601f8152602001807f45524332303a206d696e7420746f20746865207a65726f20616464726573730081525060200191505060405180910390fd5b612d45600083836136af565b612d5a8160025461253e90919063ffffffff16565b600281905550612db1816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461253e90919063ffffffff16565b6000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040518082815260200191505060405180910390a35050565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161415612ee3576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526021815260200180613a9f6021913960400191505060405180910390fd5b612eef826000836136af565b612f5a8160405180606001604052806022815260200161391d602291396000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546130219092919063ffffffff16565b6000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550612fb1816002546136bf90919063ffffffff16565b600281905550600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040518082815260200191505060405180910390a35050565b60008383111582906130ce576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825283818151815260200191508051906020019080838360005b83811015613093578082015181840152602081019050613078565b50505050905090810190601f1680156130c05780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b5060008385039050809150509392505050565b60006130f08360000183613709565b60001c905092915050565b6000613123836000018373ffffffffffffffffffffffffffffffffffffffff1660001b61378c565b905092915050565b600061313f6131386126d2565b8484613373565b6001905092915050565b6000613157826000016137af565b9050919050565b600061317f8473ffffffffffffffffffffffffffffffffffffffff16613664565b61318c57600090506132fc565b60008473ffffffffffffffffffffffffffffffffffffffff16637b04a2d06131b26126d2565b86866040518463ffffffff1660e01b8152600401808473ffffffffffffffffffffffffffffffffffffffff16815260200183815260200180602001828103825283818151815260200191508051906020019080838360005b8381101561322557808201518184015260208101905061320a565b50505050905090810190601f1680156132525780820380516001836020036101000a031916815260200191505b50945050505050602060405180830381600087803b15801561327357600080fd5b505af1158015613287573d6000803e3d6000fd5b505050506040513d602081101561329d57600080fd5b81019080805190602001909291905050509050637b04a2d060e01b7bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916817bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916149150505b9392505050565b600061330f838361378c565b61336857826000018290806001815401808255809150506001900390600052602060002001600090919091909150558260000180549050836001016000848152602001908152602001600020819055506001905061336d565b600090505b92915050565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1614156133f9576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526025815260200180613ac06025913960400191505060405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16141561347f576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260238152602001806138cb6023913960400191505060405180910390fd5b61348a8383836136af565b6134f5816040518060600160405280602681526020016139ac602691396000808773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546130219092919063ffffffff16565b6000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550613588816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461253e90919063ffffffff16565b6000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040518082815260200191505060405180910390a3505050565b600061365c836000018373ffffffffffffffffffffffffffffffffffffffff1660001b6137c0565b905092915050565b60008060007fc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47060001b9050833f91508082141580156136a657506000801b8214155b92505050919050565b6136ba8383836125f6565b505050565b600061370183836040518060400160405280601e81526020017f536166654d6174683a207375627472616374696f6e206f766572666c6f770000815250613021565b905092915050565b60008183600001805490501161376a576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260228152602001806138a96022913960400191505060405180910390fd5b82600001828154811061377957fe5b9060005260206000200154905092915050565b600080836001016000848152602001908152602001600020541415905092915050565b600081600001805490509050919050565b6000808360010160008481526020019081526020016000205490506000811461389c576000600182039050600060018660000180549050039050600086600001828154811061380b57fe5b906000526020600020015490508087600001848154811061382857fe5b906000526020600020018190555060018301876001016000838152602001908152602001600020819055508660000180548061386057fe5b600190038181906000526020600020016000905590558660010160008781526020019081526020016000206000905560019450505050506138a2565b60009150505b9291505056fe456e756d657261626c655365743a20696e646578206f7574206f6620626f756e647345524332303a207472616e7366657220746f20746865207a65726f2061646472657373416363657373436f6e74726f6c3a2073656e646572206d75737420626520616e2061646d696e20746f206772616e7445524332303a206275726e20616d6f756e7420657863656564732062616c616e63654f776e61626c653a206e6577206f776e657220697320746865207a65726f206164647265737345524332303a20617070726f766520746f20746865207a65726f2061646472657373455243313336333a205f636865636b416e6443616c6c417070726f7665207265766572747345524332303a207472616e7366657220616d6f756e7420657863656564732062616c616e6365416363657373436f6e74726f6c3a2073656e646572206d75737420626520616e2061646d696e20746f207265766f6b65526f6c65733a2063616c6c657220646f6573206e6f74206861766520746865204d494e54455220726f6c65455243313336333a205f636865636b416e6443616c6c5472616e73666572207265766572747345524332303a207472616e7366657220616d6f756e74206578636565647320616c6c6f77616e636545524332303a206275726e20616d6f756e74206578636565647320616c6c6f77616e636545524332303a206275726e2066726f6d20746865207a65726f206164647265737345524332303a207472616e736665722066726f6d20746865207a65726f206164647265737345524332303a20617070726f76652066726f6d20746865207a65726f20616464726573734552433230426173653a207472616e73666572206973206e6f7420656e61626c6564206f722066726f6d20646f6573206e6f74206861766520746865204f50455241544f5220726f6c6545524332303a2064656372656173656420616c6c6f77616e63652062656c6f77207a65726f416363657373436f6e74726f6c3a2063616e206f6e6c792072656e6f756e636520726f6c657320666f722073656c66a2646970667358221220a2b4abd98f6c0e52e150d92f00ab623819b028ca0ab5e5c2188b69c6bb76b73d64736f6c63430007010033";
    int64_t gas = 1000000000; //Hard coded
    auto rev = IVMC_LATEST_STABLE_REVISION;  //Hard coded
    std::string input_arg = "70a082310000000000000000000000000e8dd98eb5bdd299766efdf3372830233456c116";
    std::string storage_arg = "c9ea7ed00000000000000000000000000000000182eca1b50a096e7f1e065cf3528c2ebeb8041672321732640dfe1bdb94c5225c00000000000000000000000000000000000000000000000000000000773594000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000007735940033a2241dcee39b6af359177b4cfe8fbe467b600d3c068f32a9164fcf871956fa000000000000000000000000c9ea7ed0000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000009502f9001142c8ae8ad77901cd97fce843895a9ccf91a8cbd5b191350a94c1d957b07f7400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000004494c430000000000000000000000000000000000000000000000000000000006857970660bf4bc6c0637d63a9c641b49a45d94c05e9c323094895e1d07834c84000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000008ba682078eba37bca8662ade60eacd8e3fb6b879f4ad882618e7fd467572c020a00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003494c434f494e000000000000000000000000000000000000000000000000000c8a4ed6a42eac0d91037867de973be14c2be8807096a515f657aaa2bb6b62e814000000000000000000000000000000000000000000000000000000000000000186173f2ec5f73f18075679f95f9247f805bcf778ab28121f9cf977533bbf39cc000000000000000000000000c9ea7ed00000000000000000000000000000000180730d89cb7c0c984b9d2d9d16f7fd85facdb01fd6bb756a28b338a7d21bce35000000000000000000000000000000000000000000000000000000000000000103ea27bf0ed06424849c5ae8c5cb739e8e5bf7923f1a2265b94bb30f52a4f49a000000000000000000000000c9ea7ed0000000000000000000000000000000015eff886ea0ce6ca488a3d6e336d6c0f75f46d19b42c06ce5ee98e42c96d256c7000000000000000000000000000000000000000000000000000000000000000101664b13362513ab56b63b3389320fb7b2437aa0dffd2f9791594db8b50c69080000000000000000000000000000000000000000000000000000000000000001404b104cf07cac45aa0efa4026e207299763a0971242cb76aca9b5c88443e9ae00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000009000000000000000000000100c9ea7ed000000000000000000000000000000001f70e373374c56d03b892e581e492f02f590f46227c64b9d4beffb150be511cc00000000000000000000000000000000000000000000000000000000000000001";
    std::string recipient_arg = "";
    std::string sender_arg = "";

    CLI::App app{"IVMC tool"};

    try
    {
        syslog(LOG_NOTICE, "ivmc: Init VM");

        ivmc::VM vm;
        ivmc_loader_error_code ec;
        vm = VM{ivmc_load_and_configure(vm_config.c_str(), &ec)};
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

        std::cout << "Config: " << vm_config << "\n";

        const auto code_hex = load_hex(code_arg);
        const auto input_hex = load_hex(input_arg);
        const auto storage_hex = load_hex(storage_arg);
        // If code_hex or input_hex or storage_hex is not valid hex string an exception is thrown.
        tooling::run2(vm, rev, gas, code_hex, input_hex, storage_hex, recipient_arg, sender_arg, std::cout);

        std::stringstream ss;
        ss << std::cout.rdbuf();
        std::string myString = ss.str();

        syslog(LOG_NOTICE, myString.c_str());

        syslog(LOG_NOTICE, "ivmc: End execution");

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
  if (ExecuteIVMC() != 0)
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
