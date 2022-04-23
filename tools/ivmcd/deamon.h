// IVMC: Ethereum Client-VM Connector API.
// Copyright 2019-2022 The IVMC Authors.

#ifndef ILCOIN_HTTPSERVER_H
#define ILCOIN_HTTPSERVER_H

#include <string>
#include <stdint.h>
#include <functional>
#include <map>

static const int DEFAULT_HTTP_THREADS        = 4;
static const int DEFAULT_HTTP_WORKQUEUE      = 16;
static const int DEFAULT_HTTP_SERVER_TIMEOUT = 30;
static const int DEFAULT_PORT                = 5005;
static const size_t MAX_HEADERS_SIZE         = 8192;
static const unsigned int MAX_SIZE           = 0x44000000;

struct evhttp_request;
struct event_base;
class HTTPRequest;

/** Handler for requests to a certain HTTP path */
typedef std::function<bool(HTTPRequest* req, const std::string &)> HTTPRequestHandler;

/** In-flight HTTP request.
 * Thin C++ wrapper around evhttp_request.
 */
class HTTPRequest
{
private:
    struct evhttp_request* req;
    bool replySent;

public:
    HTTPRequest(struct evhttp_request* req);
    ~HTTPRequest();

    enum RequestMethod {
        UNKNOWN,
        GET,
        POST,
        HEAD,
        PUT
    };

    /** Get requested URI.
     */
    std::string GetURI();

    /** Get request method.
     */
    RequestMethod GetRequestMethod();

    /**
     * Get the request header specified by hdr, or an empty string.
     * Return an pair (isPresent,string).
     */
    std::pair<bool, std::string> GetHeader(const std::string& hdr);

    /**
     * Read request body.
     *
     * @note As this consumes the underlying buffer, call this only once.
     * Repeated calls will return an empty string.
     */
    std::string ReadBody();

    /**
     * Write output header.
     *
     * @note call this before calling WriteErrorReply or Reply.
     */
    void WriteHeader(const std::string& hdr, const std::string& value);

    /**
     * Write HTTP reply.
     * nStatus is the HTTP status code to send.
     * strReply is the body of the reply. Keep it empty to send a standard message.
     *
     * @note Can be called only once. As this will give the request back to the
     * main thread, do not call any other HTTPRequest methods after calling this.
     */
    void WriteReply(int nStatus, const std::string& strReply = "");
};

/** Event handler closure.
 */
class HTTPClosure
{
public:
    virtual void operator()() = 0;
    virtual ~HTTPClosure() {}
};

/** Event class. This can be used either as an cross-thread trigger or as a timer.
 */
class HTTPEvent
{
public:
    /** Create a new event.
     * deleteWhenTriggered deletes this event object after the event is triggered (and the handler called)
     * handler is the handler to call when the event is triggered.
     */
    HTTPEvent(struct event_base* base, bool deleteWhenTriggered, const std::function<void(void)>& handler);
    ~HTTPEvent();

    /** Trigger the event. If tv is 0, trigger it immediately. Otherwise trigger it after
     * the given time has elapsed.
     */
    void trigger(struct timeval* tv);

    bool deleteWhenTriggered;
    std::function<void(void)> handler;
private:
    struct event* ev;
};

// UniValue
class UniValue {
public:
    enum VType { VNULL, VOBJ, VARR, VSTR, VNUM, VBOOL, };

    UniValue() { typ = VNULL; }
    UniValue(UniValue::VType initialType, const std::string& initialStr = "") {
        typ = initialType;
        val = initialStr;
    }
    UniValue(uint64_t val_) {
        setInt(val_);
    }
    UniValue(int64_t val_) {
        setInt(val_);
    }
    UniValue(bool val_) {
        setBool(val_);
    }
    UniValue(int val_) {
        setInt(val_);
    }
    UniValue(double val_) {
        setFloat(val_);
    }
    UniValue(const std::string& val_) {
        setStr(val_);
    }
    UniValue(const char *val_) {
        std::string s(val_);
        setStr(s);
    }
    ~UniValue() {}

    void clear();

    bool setNull();
    bool setBool(bool val);
    bool setNumStr(const std::string& val);
    bool setInt(uint64_t val);
    bool setInt(int64_t val);
    bool setInt(int val_) { return setInt((int64_t)val_); }
    bool setFloat(double val);
    bool setStr(const std::string& val);
    bool setArray();
    bool setObject();

    enum VType getType() const { return typ; }
    const std::string& getValStr() const { return val; }
    bool empty() const { return (values.size() == 0); }

    size_t size() const { return values.size(); }

    bool getBool() const { return isTrue(); }
    bool checkObject(const std::map<std::string,UniValue::VType>& memberTypes);
    const UniValue& operator[](const std::string& key) const;
    const UniValue& operator[](unsigned int index) const;
    bool exists(const std::string& key) const { return (findKey(key) >= 0); }

    bool isNull() const { return (typ == VNULL); }
    bool isTrue() const { return (typ == VBOOL) && (val == "1"); }
    bool isFalse() const { return (typ == VBOOL) && (val != "1"); }
    bool isBool() const { return (typ == VBOOL); }
    bool isStr() const { return (typ == VSTR); }
    bool isNum() const { return (typ == VNUM); }
    bool isArray() const { return (typ == VARR); }
    bool isObject() const { return (typ == VOBJ); }

    bool push_back(const UniValue& val);
    bool push_back(const std::string& val_) {
        UniValue tmpVal(VSTR, val_);
        return push_back(tmpVal);
    }
    bool push_back(const char *val_) {
        std::string s(val_);
        return push_back(s);
    }
    bool push_backV(const std::vector<UniValue>& vec);

    bool pushKV(const std::string& key, const UniValue& val);
    bool pushKV(const std::string& key, const std::string& val_) {
        UniValue tmpVal(VSTR, val_);
        return pushKV(key, tmpVal);
    }
    bool pushKV(const std::string& key, const char *val_) {
        std::string _val(val_);
        return pushKV(key, _val);
    }
    bool pushKV(const std::string& key, int64_t val_) {
        UniValue tmpVal(val_);
        return pushKV(key, tmpVal);
    }
    bool pushKV(const std::string& key, uint64_t val_) {
        UniValue tmpVal(val_);
        return pushKV(key, tmpVal);
    }
    bool pushKV(const std::string& key, int val_) {
        UniValue tmpVal((int64_t)val_);
        return pushKV(key, tmpVal);
    }
    bool pushKV(const std::string& key, double val_) {
        UniValue tmpVal(val_);
        return pushKV(key, tmpVal);
    }
    bool pushKVs(const UniValue& obj);

    std::string write(unsigned int prettyIndent = 0,
                      unsigned int indentLevel = 0) const;

    bool read(const char *raw);
    bool read(const std::string& rawStr) {
        return read(rawStr.c_str());
    }

private:
    UniValue::VType typ;
    std::string val;                       // numbers are stored as C++ strings
    std::vector<std::string> keys;
    std::vector<UniValue> values;

    int findKey(const std::string& key) const;
    void writeArray(unsigned int prettyIndent, unsigned int indentLevel, std::string& s) const;
    void writeObject(unsigned int prettyIndent, unsigned int indentLevel, std::string& s) const;

public:
    // Strict type-specific getters, these throw std::runtime_error if the
    // value is of unexpected type
    const std::vector<std::string>& getKeys() const;
    const std::vector<UniValue>& getValues() const;
    bool get_bool() const;
    const std::string& get_str() const;
    int get_int() const;
    int64_t get_int64() const;
    double get_real() const;
    const UniValue& get_obj() const;
    const UniValue& get_array() const;

    enum VType type() const { return getType(); }
    bool push_back(std::pair<std::string,UniValue> pear) {
        return pushKV(pear.first, pear.second);
    }
    friend const UniValue& find_value( const UniValue& obj, const std::string& name);
};

bool StartRPC();
void InterruptRPC();
void StopRPC();
std::string JSONRPCExecBatch(const UniValue& vReq);

/** Start HTTP RPC subsystem.
 * Precondition; HTTP and RPC has been started.
 */
bool StartHTTPRPC();
/** Interrupt HTTP RPC subsystem.
 */
void InterruptHTTPRPC();
/** Stop HTTP RPC subsystem.
 * Precondition; HTTP and RPC has been stopped.
 */
void StopHTTPRPC();

//
// The following were added for compatibility with json_spirit.
// Most duplicate other methods, and should be removed.
//
static inline std::pair<std::string,UniValue> Pair(const char *cKey, const char *cVal)
{
    std::string key(cKey);
    UniValue uVal(cVal);
    return std::make_pair(key, uVal);
}

static inline std::pair<std::string,UniValue> Pair(const char *cKey, std::string strVal)
{
    std::string key(cKey);
    UniValue uVal(strVal);
    return std::make_pair(key, uVal);
}

static inline std::pair<std::string,UniValue> Pair(const char *cKey, uint64_t u64Val)
{
    std::string key(cKey);
    UniValue uVal(u64Val);
    return std::make_pair(key, uVal);
}

static inline std::pair<std::string,UniValue> Pair(const char *cKey, int64_t i64Val)
{
    std::string key(cKey);
    UniValue uVal(i64Val);
    return std::make_pair(key, uVal);
}

static inline std::pair<std::string,UniValue> Pair(const char *cKey, bool iVal)
{
    std::string key(cKey);
    UniValue uVal(iVal);
    return std::make_pair(key, uVal);
}

static inline std::pair<std::string,UniValue> Pair(const char *cKey, int iVal)
{
    std::string key(cKey);
    UniValue uVal(iVal);
    return std::make_pair(key, uVal);
}

static inline std::pair<std::string,UniValue> Pair(const char *cKey, double dVal)
{
    std::string key(cKey);
    UniValue uVal(dVal);
    return std::make_pair(key, uVal);
}

static inline std::pair<std::string,UniValue> Pair(const char *cKey, const UniValue& uVal)
{
    std::string key(cKey);
    return std::make_pair(key, uVal);
}

static inline std::pair<std::string,UniValue> Pair(std::string key, const UniValue& uVal)
{
    return std::make_pair(key, uVal);
}

#endif // ILCOIN_HTTPSERVER_H
