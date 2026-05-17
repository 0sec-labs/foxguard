/**
 * @name ESP decrypt without shared-frag guard
 * @description Finds Linux ESP decrypt handlers that call crypto_aead_decrypt
 *              without an skb_has_shared_frag guard in the same function.
 * @kind problem
 * @problem.severity error
 * @id cpp/kernel/dirty-frag/esp-shared-frag-decrypt-guard
 * @tags security
 *       external/cwe/cwe-787
 */

import cpp

predicate isEspDecryptHandler(Function f) {
  f.hasName("esp_input") or
  f.hasName("esp6_input")
}

predicate callsFunction(Function f, string name) {
  exists(FunctionCall call |
    call.getEnclosingFunction() = f and
    call.getTarget().hasName(name)
  )
}

from FunctionCall decrypt, Function f
where
  isEspDecryptHandler(f) and
  decrypt.getEnclosingFunction() = f and
  decrypt.getTarget().hasName("crypto_aead_decrypt") and
  not callsFunction(f, "skb_has_shared_frag")
select decrypt,
  "ESP decrypt calls crypto_aead_decrypt without checking skb_has_shared_frag in $@.",
  f, f.getName()
