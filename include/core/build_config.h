#ifndef __CORE_BUILD_CONFIG_H__
#define __CORE_BUILD_CONFIG_H__

#define FW_ENGINE_STATEFUL 1
#define FW_ENGINE_FASTCACHE 2
#define FW_ENGINE_DUALMAP 3

#ifndef FW_ENGINE
#define FW_ENGINE FW_ENGINE_FASTCACHE
#endif
#ifndef FW_TIMING
#define FW_TIMING 0
#endif
#ifndef FW_LOGGING
#define FW_LOGGING 0
#endif
#ifndef FW_OBSERVABILITY
#define FW_OBSERVABILITY 0 /* 0: full, 1: counters only, 2: none */
#endif

#if FW_ENGINE < 1 || FW_ENGINE > 3
#error "Invalid firewall engine"
#endif
#if (FW_TIMING != 0 && FW_TIMING != 1) || (FW_LOGGING != 0 && FW_LOGGING != 1)
#error "Feature flags must be 0 or 1"
#endif
#if FW_OBSERVABILITY < 0 || FW_OBSERVABILITY > 2
#error "Invalid observability mode"
#endif
#if FW_OBSERVABILITY > 0
#define MINIMAL_OBSERVABILITY
#endif
#if FW_OBSERVABILITY == 2
#define NO_OBSERVABILITY
#endif
#if FW_TIMING && FW_OBSERVABILITY == 2
#error "Timing requires observability"
#endif
#if FW_LOGGING && FW_OBSERVABILITY != 0
#error "Network logging requires full observability"
#endif

#endif
