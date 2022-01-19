#pragma once

#include <intrin.h>

// Returns the number of leading 0-bits in x, starting at the most significant
// bit position. If x is 0, the result is undefined.
inline int __builtin_clzll(unsigned long long mask)
{
  unsigned long where;
// BitScanReverse scans from MSB to LSB for first set bit.
// Returns 0 if no set bit is found.
#if defined(_WIN64)
  if (_BitScanReverse64(&where, mask))
    return static_cast<int>(63 - where);
#elif defined(_WIN32)
  // Scan the high 32 bits.
  if (_BitScanReverse(&where, static_cast<unsigned long>(mask >> 32)))
    return static_cast<int>(63 -
                            (where + 32)); // Create a bit offset from the MSB.
  // Scan the low 32 bits.
  if (_BitScanReverse(&where, static_cast<unsigned long>(mask)))
    return static_cast<int>(63 - where);
#else
#error "Implementation of __builtin_clzll required"
#endif
  return 64; // Undefined Behavior.
}
