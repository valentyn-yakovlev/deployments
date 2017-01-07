{
  commonAcmeConfig = {
    webroot = "/var/www/challenges";
    email = "r@rkm.id.au";
    plugins = [
      "account_key.json"
      "cert.pem"
      "chain.pem"
      "fullchain.pem"
      "key.pem"
    ];
  };
}
