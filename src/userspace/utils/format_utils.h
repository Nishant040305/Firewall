#ifndef __UTILS_FORMAT_UTILS_H__
#define __UTILS_FORMAT_UTILS_H__

#include <linux/types.h>
#include <core/constants.h>
#include <core/types.h>

/* Convert protocol number to human-readable string */
const char *proto_to_str(__u8 proto);

#endif /* __UTILS_FORMAT_UTILS_H__ */
