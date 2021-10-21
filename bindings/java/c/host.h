/* IVMC: Ethereum Client-VM Connector API.
 * Copyright 2019-2020 The IVMC Authors.
 * Licensed under the Apache License, Version 2.0.
 */
#include "ivmc/ivmc.h"
#include <assert.h>
#include <jni.h>

#ifndef _Included_org_ethereum_ivmc_Host
#define _Included_org_ethereum_ivmc_Host
#ifdef __cplusplus
extern "C" {
#endif

int ivmc_java_set_jvm(JNIEnv*);
const struct ivmc_host_interface* ivmc_java_get_host_interface();

static inline void* GetDirectBuffer(JNIEnv* jenv, jobject buf, size_t* size)
{
    void* ret = (uint8_t*)(*jenv)->GetDirectBufferAddress(jenv, buf);
    assert(ret != NULL);
    jlong buf_size = (*jenv)->GetDirectBufferCapacity(jenv, buf);
    assert(buf_size != -1);
    if (size)
        *size = (size_t)buf_size;
    return ret;
}

#ifdef __cplusplus
}
#endif
#endif
