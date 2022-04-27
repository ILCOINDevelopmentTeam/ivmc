// IVMC: Ethereum Client-VM Connector API.
// Copyright 2019-2022 The IVMC Authors.

#ifndef ILCOIN_HTTPSERVER_H
#define ILCOIN_HTTPSERVER_H

#include <string>
#include <stdint.h>
#include <functional>

#include <list>
#include <map>
#include <unordered_map>

#include <boost/function.hpp>

#include <cassert>
#include <iostream>
#include <sstream>        // .get_int64()
#include <utility>        // std::pair

static const int DEFAULT_HTTP_THREADS        = 4;
static const int DEFAULT_HTTP_WORKQUEUE      = 16;
static const int DEFAULT_HTTP_SERVER_TIMEOUT = 30;
static const int DEFAULT_PORT                = 5005;
static const size_t MAX_HEADERS_SIZE         = 8192;
static const unsigned int MAX_SIZE           = 0x44000000;

//! HTTP status codes
enum HTTPStatusCode
{
    HTTP_OK                    = 200,
    HTTP_BAD_REQUEST           = 400,
    HTTP_UNAUTHORIZED          = 401,
    HTTP_FORBIDDEN             = 403,
    HTTP_NOT_FOUND             = 404,
    HTTP_BAD_METHOD            = 405,
    HTTP_INTERNAL_SERVER_ERROR = 500,
    HTTP_SERVICE_UNAVAILABLE   = 503,
};

//! Ilcoin RPC error codes
enum RPCErrorCode
{
    //! Standard JSON-RPC 2.0 errors
    RPC_INVALID_REQUEST  = -32600,
    RPC_METHOD_NOT_FOUND = -32601,
    RPC_INVALID_PARAMS   = -32602,
    RPC_INTERNAL_ERROR   = -32603,
    RPC_PARSE_ERROR      = -32700,

    //! General application defined errors
    RPC_MISC_ERROR                  = -1,  //!< std::exception thrown in command handling
    RPC_FORBIDDEN_BY_SAFE_MODE      = -2,  //!< Server is in safe mode, and command is not allowed in safe mode
    RPC_TYPE_ERROR                  = -3,  //!< Unexpected type was passed as parameter
    RPC_INVALID_ADDRESS_OR_KEY      = -5,  //!< Invalid address or key
    RPC_OUT_OF_MEMORY               = -7,  //!< Ran out of memory during operation
    RPC_INVALID_PARAMETER           = -8,  //!< Invalid, missing or duplicate parameter
    RPC_DATABASE_ERROR              = -20, //!< Database error
    RPC_DESERIALIZATION_ERROR       = -22, //!< Error parsing or validating structure in raw format
    RPC_VERIFY_ERROR                = -25, //!< General error during transaction or block submission
    RPC_VERIFY_REJECTED             = -26, //!< Transaction or block was rejected by network rules
    RPC_VERIFY_ALREADY_IN_CHAIN     = -27, //!< Transaction already in chain
    RPC_IN_WARMUP                   = -28, //!< Client still warming up

    //! Aliases for backward compatibility
    RPC_TRANSACTION_ERROR           = RPC_VERIFY_ERROR,
    RPC_TRANSACTION_REJECTED        = RPC_VERIFY_REJECTED,
    RPC_TRANSACTION_ALREADY_IN_CHAIN= RPC_VERIFY_ALREADY_IN_CHAIN,

    //! P2P client errors
    RPC_CLIENT_NOT_CONNECTED        = -9,  //!< Ilcoin is not connected
    RPC_CLIENT_IN_INITIAL_DOWNLOAD  = -10, //!< Still downloading initial blocks
    RPC_CLIENT_NODE_ALREADY_ADDED   = -23, //!< Node is already added
    RPC_CLIENT_NODE_NOT_ADDED       = -24, //!< Node has not been added before
    RPC_CLIENT_NODE_NOT_CONNECTED   = -29, //!< Node to disconnect not found in connected nodes
    RPC_CLIENT_INVALID_IP_OR_SUBNET = -30, //!< Invalid IP/Subnet
    RPC_CLIENT_P2P_DISABLED         = -31, //!< No valid connection manager instance found

    //! Wallet errors
    RPC_WALLET_ERROR                = -4,  //!< Unspecified problem with wallet (key not found etc.)
    RPC_WALLET_INSUFFICIENT_FUNDS   = -6,  //!< Not enough funds in wallet or account
    RPC_WALLET_INVALID_ACCOUNT_NAME = -11, //!< Invalid account name
    RPC_WALLET_KEYPOOL_RAN_OUT      = -12, //!< Keypool ran out, call keypoolrefill first
    RPC_WALLET_UNLOCK_NEEDED        = -13, //!< Enter the wallet passphrase with walletpassphrase first
    RPC_WALLET_PASSPHRASE_INCORRECT = -14, //!< The wallet passphrase entered was incorrect
    RPC_WALLET_WRONG_ENC_STATE      = -15, //!< Command given in wrong wallet encryption state (encrypting an encrypted wallet etc.)
    RPC_WALLET_ENCRYPTION_FAILED    = -16, //!< Failed to encrypt the wallet
    RPC_WALLET_ALREADY_UNLOCKED     = -17, //!< Wallet is already unlocked
};

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

enum jtokentype {
    JTOK_ERR        = -1,
    JTOK_NONE       = 0,                           // eof
    JTOK_OBJ_OPEN,
    JTOK_OBJ_CLOSE,
    JTOK_ARR_OPEN,
    JTOK_ARR_CLOSE,
    JTOK_COLON,
    JTOK_COMMA,
    JTOK_KW_NULL,
    JTOK_KW_TRUE,
    JTOK_KW_FALSE,
    JTOK_NUMBER,
    JTOK_STRING,
};

extern enum jtokentype getJsonToken(std::string& tokenVal,
                                    unsigned int& consumed, const char *raw);

extern const UniValue NullUniValue;

class CRPCCommand;

namespace RPCServer
{
    void OnStarted(boost::function<void ()> slot);
    void OnStopped(boost::function<void ()> slot);
    void OnPreCommand(boost::function<void (const CRPCCommand&)> slot);
    void OnPostCommand(boost::function<void (const CRPCCommand&)> slot);
}

/** Wrapper for UniValue::VType, which includes typeAny:
 * Used to denote don't care type. Only used by RPCTypeCheckObj */
struct UniValueType {
    UniValueType(UniValue::VType _type) : typeAny(false), type(_type) {}
    UniValueType() : typeAny(true) {}
    bool typeAny;
    UniValue::VType type;
};

/**
 * Filter that generates and validates UTF-8, as well as collates UTF-16
 * surrogate pairs as specified in RFC4627.
 */
class JSONUTF8StringFilter
{
public:
    JSONUTF8StringFilter(std::string &s):
        str(s), is_valid(true), codepoint(0), state(0), surpair(0)
    {
    }
    // Write single 8-bit char (may be part of UTF-8 sequence)
    void push_back(unsigned char ch)
    {
        if (state == 0) {
            if (ch < 0x80) // 7-bit ASCII, fast direct pass-through
                str.push_back(ch);
            else if (ch < 0xc0) // Mid-sequence character, invalid in this state
                is_valid = false;
            else if (ch < 0xe0) { // Start of 2-byte sequence
                codepoint = (ch & 0x1f) << 6;
                state = 6;
            } else if (ch < 0xf0) { // Start of 3-byte sequence
                codepoint = (ch & 0x0f) << 12;
                state = 12;
            } else if (ch < 0xf8) { // Start of 4-byte sequence
                codepoint = (ch & 0x07) << 18;
                state = 18;
            } else // Reserved, invalid
                is_valid = false;
        } else {
            if ((ch & 0xc0) != 0x80) // Not a continuation, invalid
                is_valid = false;
            state -= 6;
            codepoint |= (ch & 0x3f) << state;
            if (state == 0)
                push_back_u(codepoint);
        }
    }
    // Write codepoint directly, possibly collating surrogate pairs
    void push_back_u(unsigned int codepoint)
    {
        if (state) // Only accept full codepoints in open state
            is_valid = false;
        if (codepoint >= 0xD800 && codepoint < 0xDC00) { // First half of surrogate pair
            if (surpair) // Two subsequent surrogate pair openers - fail
                is_valid = false;
            else
                surpair = codepoint;
        } else if (codepoint >= 0xDC00 && codepoint < 0xE000) { // Second half of surrogate pair
            if (surpair) { // Open surrogate pair, expect second half
                // Compute code point from UTF-16 surrogate pair
                append_codepoint(0x10000 | ((surpair - 0xD800)<<10) | (codepoint - 0xDC00));
                surpair = 0;
            } else // Second half doesn't follow a first half - fail
                is_valid = false;
        } else {
            if (surpair) // First half of surrogate pair not followed by second - fail
                is_valid = false;
            else
                append_codepoint(codepoint);
        }
    }
    // Check that we're in a state where the string can be ended
    // No open sequences, no open surrogate pairs, etc
    bool finalize()
    {
        if (state || surpair)
            is_valid = false;
        return is_valid;
    }
private:
    std::string &str;
    bool is_valid;
    // Current UTF-8 decoding state
    unsigned int codepoint;
    int state; // Top bit to be filled in for next UTF-8 byte, or 0

    // Keep track of the following state to handle the following section of
    // RFC4627:
    //
    //    To escape an extended character that is not in the Basic Multilingual
    //    Plane, the character is represented as a twelve-character sequence,
    //    encoding the UTF-16 surrogate pair.  So, for example, a string
    //    containing only the G clef character (U+1D11E) may be represented as
    //    "\uD834\uDD1E".
    //
    //  Two subsequent \u.... may have to be replaced with one actual codepoint.
    unsigned int surpair; // First half of open UTF-16 surrogate pair, or 0

    void append_codepoint(unsigned int codepoint)
    {
        if (codepoint <= 0x7f)
            str.push_back((char)codepoint);
        else if (codepoint <= 0x7FF) {
            str.push_back((char)(0xC0 | (codepoint >> 6)));
            str.push_back((char)(0x80 | (codepoint & 0x3F)));
        } else if (codepoint <= 0xFFFF) {
            str.push_back((char)(0xE0 | (codepoint >> 12)));
            str.push_back((char)(0x80 | ((codepoint >> 6) & 0x3F)));
            str.push_back((char)(0x80 | (codepoint & 0x3F)));
        } else if (codepoint <= 0x1FFFFF) {
            str.push_back((char)(0xF0 | (codepoint >> 18)));
            str.push_back((char)(0x80 | ((codepoint >> 12) & 0x3F)));
            str.push_back((char)(0x80 | ((codepoint >> 6) & 0x3F)));
            str.push_back((char)(0x80 | (codepoint & 0x3F)));
        }
    }
};





class JSONRPCRequest
{
public:
    UniValue id;
    std::string strMethod;
    UniValue params;
    bool fHelp;
    std::string URI;
    std::string authUser;

    JSONRPCRequest() { id = NullUniValue; params = NullUniValue; fHelp = false; }
    void parse(const UniValue& valRequest);
};

/** Query whether RPC is running */
bool IsRPCRunning();

/**
 * Set the RPC warmup status.  When this is done, all RPC calls will error out
 * immediately with RPC_IN_WARMUP.
 */
void SetRPCWarmupStatus(const std::string& newStatus);
/* Mark warmup as done.  RPC calls will be processed from now on.  */
void SetRPCWarmupFinished();

/* returns the current warmup state.  */
bool RPCIsInWarmup(std::string *statusOut);

/**
 * Type-check arguments; throws JSONRPCError if wrong type given. Does not check that
 * the right number of arguments are passed, just that any passed are the correct type.
 */
void RPCTypeCheck(const UniValue& params,
                  const std::list<UniValue::VType>& typesExpected, bool fAllowNull=false);

/**
 * Type-check one argument; throws JSONRPCError if wrong type given.
 */
void RPCTypeCheckArgument(const UniValue& value, UniValue::VType typeExpected);

/*
  Check for expected keys/value types in an Object.
*/
void RPCTypeCheckObj(const UniValue& o,
    const std::map<std::string, UniValueType>& typesExpected,
    bool fAllowNull = false,
    bool fStrict = false);

typedef UniValue(*rpcfn_type)(const JSONRPCRequest& jsonRequest);

class CRPCCommand
{
public:
    std::string category;
    std::string name;
    rpcfn_type actor;
    bool okSafeMode;
    std::vector<std::string> argNames;
};

/**
 * Ilcoin RPC command dispatcher.
 */
class CRPCTable
{
private:
    std::map<std::string, const CRPCCommand*> mapCommands;
public:
    CRPCTable();
    const CRPCCommand* operator[](const std::string& name) const;
    std::string help(const std::string& name, const JSONRPCRequest& helpreq) const;

    /**
     * Execute a method.
     * @param request The JSONRPCRequest to execute
     * @returns Result of the call.
     * @throws an exception (UniValue) when an error happens.
     */
    UniValue execute(const JSONRPCRequest &request) const;

    /**
    * Returns a list of registered commands
    * @returns List of registered commands.
    */
    std::vector<std::string> listCommands() const;


    /**
     * Appends a CRPCCommand to the dispatch table.
     * Returns false if RPC server is already running (dump concurrency protection).
     * Commands cannot be overwritten (returns false).
     */
    bool appendCommand(const std::string& name, const CRPCCommand* pcmd);
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

UniValue JSONRPCError(int code, const std::string& message);

#endif // ILCOIN_HTTPSERVER_H
