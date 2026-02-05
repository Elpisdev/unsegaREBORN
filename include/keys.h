static const GameKeyEntry embedded_keys[] = {
#if __has_include("keys.inc")
#include "keys.inc"
#endif
{NULL, {0}, {0}, false}
};
