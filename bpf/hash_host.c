/* The path hash, compiled for the HOST rather than for BPF.
 *
 * This exists so tests/hash_parity.rs can call exactly the code the probe runs
 * and compare it against the Rust implementation. If the two ever disagree,
 * every allowlist lookup misses and the filter silently becomes a no-op.
 */
#include "common.h"

void quasar_path_hash_host(const unsigned char *path, unsigned int len,
			   unsigned char out[QUASAR_HASH_LEN])
{
	quasar_path_hash(path, len, out);
}
