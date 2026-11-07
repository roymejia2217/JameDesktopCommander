// The repository's standard verify glob discovers test/test*.js files only.
// Run the existing restricted-capability policy suite on every push and in CI.
import './security/restricted-capability-policy.test.cjs';
