struct sk_buff;
struct aead_request;

int esp_input(struct sk_buff *skb, struct aead_request *req)
{
    int err = 0;

    if (!skb)
        return -1;

    err = skb_cow_data(skb, 0, 0);
    if (err)
        return err;

    err = crypto_aead_decrypt(req);
    if (err)
        return err;

    return 0;
}
