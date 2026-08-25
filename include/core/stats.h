#ifndef __CORE_STATS_H__
#define __CORE_STATS_H__

/* Statistics map counter indices */
enum stat_counter {
    STAT_TOTAL_PACKETS = 0,
    STAT_TCP_PACKETS,
    STAT_UDP_PACKETS,
    STAT_ICMP_PACKETS,
    STAT_OTHER_PACKETS,
    STAT_MAX_COUNTERS,
};

#endif /* __CORE_STATS_H__ */
