//
// Generated file, do not edit! Created by opp_msgtool 6.0 from transportlayer/tcp/flavours/TcpCubicState.msg.
//

// Disable warnings about unused variables, empty switch stmts, etc:
#ifdef _MSC_VER
#  pragma warning(disable:4101)
#  pragma warning(disable:4065)
#endif

#if defined(__clang__)
#  pragma clang diagnostic ignored "-Wshadow"
#  pragma clang diagnostic ignored "-Wconversion"
#  pragma clang diagnostic ignored "-Wunused-parameter"
#  pragma clang diagnostic ignored "-Wc++98-compat"
#  pragma clang diagnostic ignored "-Wunreachable-code-break"
#  pragma clang diagnostic ignored "-Wold-style-cast"
#elif defined(__GNUC__)
#  pragma GCC diagnostic ignored "-Wshadow"
#  pragma GCC diagnostic ignored "-Wconversion"
#  pragma GCC diagnostic ignored "-Wunused-parameter"
#  pragma GCC diagnostic ignored "-Wold-style-cast"
#  pragma GCC diagnostic ignored "-Wsuggest-attribute=noreturn"
#  pragma GCC diagnostic ignored "-Wfloat-conversion"
#endif

#include <iostream>
#include <sstream>
#include <memory>
#include <type_traits>
#include "TcpCubicState_m.h"

namespace omnetpp {

// Template pack/unpack rules. They are declared *after* a1l type-specific pack functions for multiple reasons.
// They are in the omnetpp namespace, to allow them to be found by argument-dependent lookup via the cCommBuffer argument

// Packing/unpacking an std::vector
template<typename T, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::vector<T,A>& v)
{
    int n = v.size();
    doParsimPacking(buffer, n);
    for (int i = 0; i < n; i++)
        doParsimPacking(buffer, v[i]);
}

template<typename T, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::vector<T,A>& v)
{
    int n;
    doParsimUnpacking(buffer, n);
    v.resize(n);
    for (int i = 0; i < n; i++)
        doParsimUnpacking(buffer, v[i]);
}

// Packing/unpacking an std::list
template<typename T, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::list<T,A>& l)
{
    doParsimPacking(buffer, (int)l.size());
    for (typename std::list<T,A>::const_iterator it = l.begin(); it != l.end(); ++it)
        doParsimPacking(buffer, (T&)*it);
}

template<typename T, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::list<T,A>& l)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i = 0; i < n; i++) {
        l.push_back(T());
        doParsimUnpacking(buffer, l.back());
    }
}

// Packing/unpacking an std::set
template<typename T, typename Tr, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::set<T,Tr,A>& s)
{
    doParsimPacking(buffer, (int)s.size());
    for (typename std::set<T,Tr,A>::const_iterator it = s.begin(); it != s.end(); ++it)
        doParsimPacking(buffer, *it);
}

template<typename T, typename Tr, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::set<T,Tr,A>& s)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i = 0; i < n; i++) {
        T x;
        doParsimUnpacking(buffer, x);
        s.insert(x);
    }
}

// Packing/unpacking an std::map
template<typename K, typename V, typename Tr, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::map<K,V,Tr,A>& m)
{
    doParsimPacking(buffer, (int)m.size());
    for (typename std::map<K,V,Tr,A>::const_iterator it = m.begin(); it != m.end(); ++it) {
        doParsimPacking(buffer, it->first);
        doParsimPacking(buffer, it->second);
    }
}

template<typename K, typename V, typename Tr, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::map<K,V,Tr,A>& m)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i = 0; i < n; i++) {
        K k; V v;
        doParsimUnpacking(buffer, k);
        doParsimUnpacking(buffer, v);
        m[k] = v;
    }
}

// Default pack/unpack function for arrays
template<typename T>
void doParsimArrayPacking(omnetpp::cCommBuffer *b, const T *t, int n)
{
    for (int i = 0; i < n; i++)
        doParsimPacking(b, t[i]);
}

template<typename T>
void doParsimArrayUnpacking(omnetpp::cCommBuffer *b, T *t, int n)
{
    for (int i = 0; i < n; i++)
        doParsimUnpacking(b, t[i]);
}

// Default rule to prevent compiler from choosing base class' doParsimPacking() function
template<typename T>
void doParsimPacking(omnetpp::cCommBuffer *, const T& t)
{
    throw omnetpp::cRuntimeError("Parsim error: No doParsimPacking() function for type %s", omnetpp::opp_typename(typeid(t)));
}

template<typename T>
void doParsimUnpacking(omnetpp::cCommBuffer *, T& t)
{
    throw omnetpp::cRuntimeError("Parsim error: No doParsimUnpacking() function for type %s", omnetpp::opp_typename(typeid(t)));
}

}  // namespace omnetpp

namespace inet {
namespace tcp {

TcpCubicStateVariables::TcpCubicStateVariables()
{
}

void __doPacking(omnetpp::cCommBuffer *b, const TcpCubicStateVariables& a)
{
    doParsimPacking(b,(::inet::tcp::TcpTahoeRenoFamilyStateVariables&)a);
    doParsimPacking(b,a.fast_convergence);
    doParsimPacking(b,a.max_increment);
    doParsimPacking(b,a.beta);
    doParsimPacking(b,a.bic_scale);
    doParsimPacking(b,a.tcp_friendliness);
    doParsimPacking(b,a.cube_rtt_scale);
    doParsimPacking(b,a.beta_scale);
    doParsimPacking(b,a.cube_factor);
    doParsimPacking(b,a.last_max_cwnd);
    doParsimPacking(b,a.loss_cwnd);
    doParsimPacking(b,a.last_cwnd);
    doParsimPacking(b,a.last_time);
    doParsimPacking(b,a.bic_origin_point);
    doParsimPacking(b,a.bic_K);
    doParsimPacking(b,a.delay_min);
    doParsimPacking(b,a.epoch_start);
    doParsimPacking(b,a.ack_cnt);
    doParsimPacking(b,a.tcp_cwnd);
    doParsimPacking(b,a.isConcave);
    doParsimPacking(b,a.isFriendly);
    doParsimPacking(b,a.lastJiffyTime);
    doParsimPacking(b,a.jiffyAcks);
    doParsimPacking(b,a.jiffyDupacks);
    doParsimPacking(b,a.rtt);
}

void __doUnpacking(omnetpp::cCommBuffer *b, TcpCubicStateVariables& a)
{
    doParsimUnpacking(b,(::inet::tcp::TcpTahoeRenoFamilyStateVariables&)a);
    doParsimUnpacking(b,a.fast_convergence);
    doParsimUnpacking(b,a.max_increment);
    doParsimUnpacking(b,a.beta);
    doParsimUnpacking(b,a.bic_scale);
    doParsimUnpacking(b,a.tcp_friendliness);
    doParsimUnpacking(b,a.cube_rtt_scale);
    doParsimUnpacking(b,a.beta_scale);
    doParsimUnpacking(b,a.cube_factor);
    doParsimUnpacking(b,a.last_max_cwnd);
    doParsimUnpacking(b,a.loss_cwnd);
    doParsimUnpacking(b,a.last_cwnd);
    doParsimUnpacking(b,a.last_time);
    doParsimUnpacking(b,a.bic_origin_point);
    doParsimUnpacking(b,a.bic_K);
    doParsimUnpacking(b,a.delay_min);
    doParsimUnpacking(b,a.epoch_start);
    doParsimUnpacking(b,a.ack_cnt);
    doParsimUnpacking(b,a.tcp_cwnd);
    doParsimUnpacking(b,a.isConcave);
    doParsimUnpacking(b,a.isFriendly);
    doParsimUnpacking(b,a.lastJiffyTime);
    doParsimUnpacking(b,a.jiffyAcks);
    doParsimUnpacking(b,a.jiffyDupacks);
    doParsimUnpacking(b,a.rtt);
}

class TcpCubicStateVariablesDescriptor : public omnetpp::cClassDescriptor
{
  private:
    mutable const char **propertyNames;
    enum FieldConstants {
        FIELD_fast_convergence,
        FIELD_max_increment,
        FIELD_beta,
        FIELD_bic_scale,
        FIELD_tcp_friendliness,
        FIELD_cube_rtt_scale,
        FIELD_beta_scale,
        FIELD_cube_factor,
        FIELD_last_max_cwnd,
        FIELD_loss_cwnd,
        FIELD_last_cwnd,
        FIELD_last_time,
        FIELD_bic_origin_point,
        FIELD_bic_K,
        FIELD_delay_min,
        FIELD_epoch_start,
        FIELD_ack_cnt,
        FIELD_tcp_cwnd,
        FIELD_isConcave,
        FIELD_isFriendly,
        FIELD_lastJiffyTime,
        FIELD_jiffyAcks,
        FIELD_jiffyDupacks,
        FIELD_rtt,
    };
  public:
    TcpCubicStateVariablesDescriptor();
    virtual ~TcpCubicStateVariablesDescriptor();

    virtual bool doesSupport(omnetpp::cObject *obj) const override;
    virtual const char **getPropertyNames() const override;
    virtual const char *getProperty(const char *propertyName) const override;
    virtual int getFieldCount() const override;
    virtual const char *getFieldName(int field) const override;
    virtual int findField(const char *fieldName) const override;
    virtual unsigned int getFieldTypeFlags(int field) const override;
    virtual const char *getFieldTypeString(int field) const override;
    virtual const char **getFieldPropertyNames(int field) const override;
    virtual const char *getFieldProperty(int field, const char *propertyName) const override;
    virtual int getFieldArraySize(omnetpp::any_ptr object, int field) const override;
    virtual void setFieldArraySize(omnetpp::any_ptr object, int field, int size) const override;

    virtual const char *getFieldDynamicTypeString(omnetpp::any_ptr object, int field, int i) const override;
    virtual std::string getFieldValueAsString(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldValueAsString(omnetpp::any_ptr object, int field, int i, const char *value) const override;
    virtual omnetpp::cValue getFieldValue(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldValue(omnetpp::any_ptr object, int field, int i, const omnetpp::cValue& value) const override;

    virtual const char *getFieldStructName(int field) const override;
    virtual omnetpp::any_ptr getFieldStructValuePointer(omnetpp::any_ptr object, int field, int i) const override;
    virtual void setFieldStructValuePointer(omnetpp::any_ptr object, int field, int i, omnetpp::any_ptr ptr) const override;
};

Register_ClassDescriptor(TcpCubicStateVariablesDescriptor)

TcpCubicStateVariablesDescriptor::TcpCubicStateVariablesDescriptor() : omnetpp::cClassDescriptor(omnetpp::opp_typename(typeid(inet::tcp::TcpCubicStateVariables)), "inet::tcp::TcpTahoeRenoFamilyStateVariables")
{
    propertyNames = nullptr;
}

TcpCubicStateVariablesDescriptor::~TcpCubicStateVariablesDescriptor()
{
    delete[] propertyNames;
}

bool TcpCubicStateVariablesDescriptor::doesSupport(omnetpp::cObject *obj) const
{
    return dynamic_cast<TcpCubicStateVariables *>(obj)!=nullptr;
}

const char **TcpCubicStateVariablesDescriptor::getPropertyNames() const
{
    if (!propertyNames) {
        static const char *names[] = { "descriptor",  nullptr };
        omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
        const char **baseNames = base ? base->getPropertyNames() : nullptr;
        propertyNames = mergeLists(baseNames, names);
    }
    return propertyNames;
}

const char *TcpCubicStateVariablesDescriptor::getProperty(const char *propertyName) const
{
    if (!strcmp(propertyName, "descriptor")) return "readonly";
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    return base ? base->getProperty(propertyName) : nullptr;
}

int TcpCubicStateVariablesDescriptor::getFieldCount() const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    return base ? 24+base->getFieldCount() : 24;
}

unsigned int TcpCubicStateVariablesDescriptor::getFieldTypeFlags(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldTypeFlags(field);
        field -= base->getFieldCount();
    }
    static unsigned int fieldTypeFlags[] = {
        0,    // FIELD_fast_convergence
        0,    // FIELD_max_increment
        0,    // FIELD_beta
        0,    // FIELD_bic_scale
        0,    // FIELD_tcp_friendliness
        0,    // FIELD_cube_rtt_scale
        0,    // FIELD_beta_scale
        0,    // FIELD_cube_factor
        0,    // FIELD_last_max_cwnd
        0,    // FIELD_loss_cwnd
        0,    // FIELD_last_cwnd
        0,    // FIELD_last_time
        0,    // FIELD_bic_origin_point
        0,    // FIELD_bic_K
        0,    // FIELD_delay_min
        0,    // FIELD_epoch_start
        0,    // FIELD_ack_cnt
        0,    // FIELD_tcp_cwnd
        0,    // FIELD_isConcave
        0,    // FIELD_isFriendly
        0,    // FIELD_lastJiffyTime
        0,    // FIELD_jiffyAcks
        0,    // FIELD_jiffyDupacks
        0,    // FIELD_rtt
    };
    return (field >= 0 && field < 24) ? fieldTypeFlags[field] : 0;
}

const char *TcpCubicStateVariablesDescriptor::getFieldName(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldName(field);
        field -= base->getFieldCount();
    }
    static const char *fieldNames[] = {
        "fast_convergence",
        "max_increment",
        "beta",
        "bic_scale",
        "tcp_friendliness",
        "cube_rtt_scale",
        "beta_scale",
        "cube_factor",
        "last_max_cwnd",
        "loss_cwnd",
        "last_cwnd",
        "last_time",
        "bic_origin_point",
        "bic_K",
        "delay_min",
        "epoch_start",
        "ack_cnt",
        "tcp_cwnd",
        "isConcave",
        "isFriendly",
        "lastJiffyTime",
        "jiffyAcks",
        "jiffyDupacks",
        "rtt",
    };
    return (field >= 0 && field < 24) ? fieldNames[field] : nullptr;
}

int TcpCubicStateVariablesDescriptor::findField(const char *fieldName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    int baseIndex = base ? base->getFieldCount() : 0;
    if (strcmp(fieldName, "fast_convergence") == 0) return baseIndex + 0;
    if (strcmp(fieldName, "max_increment") == 0) return baseIndex + 1;
    if (strcmp(fieldName, "beta") == 0) return baseIndex + 2;
    if (strcmp(fieldName, "bic_scale") == 0) return baseIndex + 3;
    if (strcmp(fieldName, "tcp_friendliness") == 0) return baseIndex + 4;
    if (strcmp(fieldName, "cube_rtt_scale") == 0) return baseIndex + 5;
    if (strcmp(fieldName, "beta_scale") == 0) return baseIndex + 6;
    if (strcmp(fieldName, "cube_factor") == 0) return baseIndex + 7;
    if (strcmp(fieldName, "last_max_cwnd") == 0) return baseIndex + 8;
    if (strcmp(fieldName, "loss_cwnd") == 0) return baseIndex + 9;
    if (strcmp(fieldName, "last_cwnd") == 0) return baseIndex + 10;
    if (strcmp(fieldName, "last_time") == 0) return baseIndex + 11;
    if (strcmp(fieldName, "bic_origin_point") == 0) return baseIndex + 12;
    if (strcmp(fieldName, "bic_K") == 0) return baseIndex + 13;
    if (strcmp(fieldName, "delay_min") == 0) return baseIndex + 14;
    if (strcmp(fieldName, "epoch_start") == 0) return baseIndex + 15;
    if (strcmp(fieldName, "ack_cnt") == 0) return baseIndex + 16;
    if (strcmp(fieldName, "tcp_cwnd") == 0) return baseIndex + 17;
    if (strcmp(fieldName, "isConcave") == 0) return baseIndex + 18;
    if (strcmp(fieldName, "isFriendly") == 0) return baseIndex + 19;
    if (strcmp(fieldName, "lastJiffyTime") == 0) return baseIndex + 20;
    if (strcmp(fieldName, "jiffyAcks") == 0) return baseIndex + 21;
    if (strcmp(fieldName, "jiffyDupacks") == 0) return baseIndex + 22;
    if (strcmp(fieldName, "rtt") == 0) return baseIndex + 23;
    return base ? base->findField(fieldName) : -1;
}

const char *TcpCubicStateVariablesDescriptor::getFieldTypeString(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldTypeString(field);
        field -= base->getFieldCount();
    }
    static const char *fieldTypeStrings[] = {
        "int",    // FIELD_fast_convergence
        "int",    // FIELD_max_increment
        "int",    // FIELD_beta
        "int",    // FIELD_bic_scale
        "int",    // FIELD_tcp_friendliness
        "uint32_t",    // FIELD_cube_rtt_scale
        "uint32_t",    // FIELD_beta_scale
        "uint64_t",    // FIELD_cube_factor
        "uint32_t",    // FIELD_last_max_cwnd
        "uint32_t",    // FIELD_loss_cwnd
        "uint32_t",    // FIELD_last_cwnd
        "uint32_t",    // FIELD_last_time
        "uint32_t",    // FIELD_bic_origin_point
        "uint32_t",    // FIELD_bic_K
        "uint32_t",    // FIELD_delay_min
        "uint32_t",    // FIELD_epoch_start
        "uint32_t",    // FIELD_ack_cnt
        "uint32_t",    // FIELD_tcp_cwnd
        "bool",    // FIELD_isConcave
        "bool",    // FIELD_isFriendly
        "omnetpp::simtime_t",    // FIELD_lastJiffyTime
        "uint32",    // FIELD_jiffyAcks
        "uint32",    // FIELD_jiffyDupacks
        "omnetpp::simtime_t",    // FIELD_rtt
    };
    return (field >= 0 && field < 24) ? fieldTypeStrings[field] : nullptr;
}

const char **TcpCubicStateVariablesDescriptor::getFieldPropertyNames(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldPropertyNames(field);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

const char *TcpCubicStateVariablesDescriptor::getFieldProperty(int field, const char *propertyName) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldProperty(field, propertyName);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    }
}

int TcpCubicStateVariablesDescriptor::getFieldArraySize(omnetpp::any_ptr object, int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldArraySize(object, field);
        field -= base->getFieldCount();
    }
    TcpCubicStateVariables *pp = omnetpp::fromAnyPtr<TcpCubicStateVariables>(object); (void)pp;
    switch (field) {
        default: return 0;
    }
}

void TcpCubicStateVariablesDescriptor::setFieldArraySize(omnetpp::any_ptr object, int field, int size) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldArraySize(object, field, size);
            return;
        }
        field -= base->getFieldCount();
    }
    TcpCubicStateVariables *pp = omnetpp::fromAnyPtr<TcpCubicStateVariables>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set array size of field %d of class 'TcpCubicStateVariables'", field);
    }
}

const char *TcpCubicStateVariablesDescriptor::getFieldDynamicTypeString(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldDynamicTypeString(object,field,i);
        field -= base->getFieldCount();
    }
    TcpCubicStateVariables *pp = omnetpp::fromAnyPtr<TcpCubicStateVariables>(object); (void)pp;
    switch (field) {
        default: return nullptr;
    }
}

std::string TcpCubicStateVariablesDescriptor::getFieldValueAsString(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldValueAsString(object,field,i);
        field -= base->getFieldCount();
    }
    TcpCubicStateVariables *pp = omnetpp::fromAnyPtr<TcpCubicStateVariables>(object); (void)pp;
    switch (field) {
        case FIELD_fast_convergence: return long2string(pp->fast_convergence);
        case FIELD_max_increment: return long2string(pp->max_increment);
        case FIELD_beta: return long2string(pp->beta);
        case FIELD_bic_scale: return long2string(pp->bic_scale);
        case FIELD_tcp_friendliness: return long2string(pp->tcp_friendliness);
        case FIELD_cube_rtt_scale: return ulong2string(pp->cube_rtt_scale);
        case FIELD_beta_scale: return ulong2string(pp->beta_scale);
        case FIELD_cube_factor: return uint642string(pp->cube_factor);
        case FIELD_last_max_cwnd: return ulong2string(pp->last_max_cwnd);
        case FIELD_loss_cwnd: return ulong2string(pp->loss_cwnd);
        case FIELD_last_cwnd: return ulong2string(pp->last_cwnd);
        case FIELD_last_time: return ulong2string(pp->last_time);
        case FIELD_bic_origin_point: return ulong2string(pp->bic_origin_point);
        case FIELD_bic_K: return ulong2string(pp->bic_K);
        case FIELD_delay_min: return ulong2string(pp->delay_min);
        case FIELD_epoch_start: return ulong2string(pp->epoch_start);
        case FIELD_ack_cnt: return ulong2string(pp->ack_cnt);
        case FIELD_tcp_cwnd: return ulong2string(pp->tcp_cwnd);
        case FIELD_isConcave: return bool2string(pp->isConcave);
        case FIELD_isFriendly: return bool2string(pp->isFriendly);
        case FIELD_lastJiffyTime: return simtime2string(pp->lastJiffyTime);
        case FIELD_jiffyAcks: return ulong2string(pp->jiffyAcks);
        case FIELD_jiffyDupacks: return ulong2string(pp->jiffyDupacks);
        case FIELD_rtt: return simtime2string(pp->rtt);
        default: return "";
    }
}

void TcpCubicStateVariablesDescriptor::setFieldValueAsString(omnetpp::any_ptr object, int field, int i, const char *value) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldValueAsString(object, field, i, value);
            return;
        }
        field -= base->getFieldCount();
    }
    TcpCubicStateVariables *pp = omnetpp::fromAnyPtr<TcpCubicStateVariables>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'TcpCubicStateVariables'", field);
    }
}

omnetpp::cValue TcpCubicStateVariablesDescriptor::getFieldValue(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldValue(object,field,i);
        field -= base->getFieldCount();
    }
    TcpCubicStateVariables *pp = omnetpp::fromAnyPtr<TcpCubicStateVariables>(object); (void)pp;
    switch (field) {
        case FIELD_fast_convergence: return pp->fast_convergence;
        case FIELD_max_increment: return pp->max_increment;
        case FIELD_beta: return pp->beta;
        case FIELD_bic_scale: return pp->bic_scale;
        case FIELD_tcp_friendliness: return pp->tcp_friendliness;
        case FIELD_cube_rtt_scale: return (omnetpp::intval_t)(pp->cube_rtt_scale);
        case FIELD_beta_scale: return (omnetpp::intval_t)(pp->beta_scale);
        case FIELD_cube_factor: return (omnetpp::intval_t)(pp->cube_factor);
        case FIELD_last_max_cwnd: return (omnetpp::intval_t)(pp->last_max_cwnd);
        case FIELD_loss_cwnd: return (omnetpp::intval_t)(pp->loss_cwnd);
        case FIELD_last_cwnd: return (omnetpp::intval_t)(pp->last_cwnd);
        case FIELD_last_time: return (omnetpp::intval_t)(pp->last_time);
        case FIELD_bic_origin_point: return (omnetpp::intval_t)(pp->bic_origin_point);
        case FIELD_bic_K: return (omnetpp::intval_t)(pp->bic_K);
        case FIELD_delay_min: return (omnetpp::intval_t)(pp->delay_min);
        case FIELD_epoch_start: return (omnetpp::intval_t)(pp->epoch_start);
        case FIELD_ack_cnt: return (omnetpp::intval_t)(pp->ack_cnt);
        case FIELD_tcp_cwnd: return (omnetpp::intval_t)(pp->tcp_cwnd);
        case FIELD_isConcave: return pp->isConcave;
        case FIELD_isFriendly: return pp->isFriendly;
        case FIELD_lastJiffyTime: return pp->lastJiffyTime.dbl();
        case FIELD_jiffyAcks: return (omnetpp::intval_t)(pp->jiffyAcks);
        case FIELD_jiffyDupacks: return (omnetpp::intval_t)(pp->jiffyDupacks);
        case FIELD_rtt: return pp->rtt.dbl();
        default: throw omnetpp::cRuntimeError("Cannot return field %d of class 'TcpCubicStateVariables' as cValue -- field index out of range?", field);
    }
}

void TcpCubicStateVariablesDescriptor::setFieldValue(omnetpp::any_ptr object, int field, int i, const omnetpp::cValue& value) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldValue(object, field, i, value);
            return;
        }
        field -= base->getFieldCount();
    }
    TcpCubicStateVariables *pp = omnetpp::fromAnyPtr<TcpCubicStateVariables>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'TcpCubicStateVariables'", field);
    }
}

const char *TcpCubicStateVariablesDescriptor::getFieldStructName(int field) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldStructName(field);
        field -= base->getFieldCount();
    }
    switch (field) {
        default: return nullptr;
    };
}

omnetpp::any_ptr TcpCubicStateVariablesDescriptor::getFieldStructValuePointer(omnetpp::any_ptr object, int field, int i) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount())
            return base->getFieldStructValuePointer(object, field, i);
        field -= base->getFieldCount();
    }
    TcpCubicStateVariables *pp = omnetpp::fromAnyPtr<TcpCubicStateVariables>(object); (void)pp;
    switch (field) {
        default: return omnetpp::any_ptr(nullptr);
    }
}

void TcpCubicStateVariablesDescriptor::setFieldStructValuePointer(omnetpp::any_ptr object, int field, int i, omnetpp::any_ptr ptr) const
{
    omnetpp::cClassDescriptor *base = getBaseClassDescriptor();
    if (base) {
        if (field < base->getFieldCount()){
            base->setFieldStructValuePointer(object, field, i, ptr);
            return;
        }
        field -= base->getFieldCount();
    }
    TcpCubicStateVariables *pp = omnetpp::fromAnyPtr<TcpCubicStateVariables>(object); (void)pp;
    switch (field) {
        default: throw omnetpp::cRuntimeError("Cannot set field %d of class 'TcpCubicStateVariables'", field);
    }
}

}  // namespace tcp
}  // namespace inet

namespace omnetpp {

template<> inet::tcp::TcpCubicStateVariables *fromAnyPtr(any_ptr ptr) {
    if (ptr.contains<inet::tcp::TcpStateVariables>()) return static_cast<inet::tcp::TcpCubicStateVariables*>(ptr.get<inet::tcp::TcpStateVariables>());
    if (ptr.contains<omnetpp::cObject>()) return static_cast<inet::tcp::TcpCubicStateVariables*>(ptr.get<omnetpp::cObject>());
    throw cRuntimeError("Unable to obtain inet::tcp::TcpCubicStateVariables* pointer from any_ptr(%s)", ptr.pointerTypeName());
}
}  // namespace omnetpp

