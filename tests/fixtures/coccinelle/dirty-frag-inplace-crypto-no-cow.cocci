@@
identifier fn;
expression skb, req;
@@
fn(...) {
  <...
  when != skb_cow_data(skb, ...)
  crypto_aead_decrypt(req)
  ...>
}
