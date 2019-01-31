# hashiSH
yet another Hashicorp Vault client

##Very early stage project

### Usage example:
```bash
export VAULT_TOKEN=token-value-here
#TOKENS:
#create token, using policy user123. You can use it only once (num_uses), and it will expire in 10 seconds
python3 HashiSH.py -c hashish.conf create token -n user123  --num_uses 1 --ttl 10 --policies user123

#delete token, using token_display_name:
python3 HashiSH.py -c hashish.conf delete token -n user123

#create user, generate basic creds secret, and hashes secret
python3 HashiSH.py -c hashish.conf create user -n test123 -s databases -g testgroup --gen_creds --generate_hashes

#delete user
python3 HashiSH.py -c hashish.conf delete user -n test123 -s databases -g testgroup

#regenerate hashes and creds for user:
python3 HashiSH.py -c hashish.conf sync user -n test123 -s databases -g testgroup --regen_creds --regenerate_hashes

#append custom secret for user:
python3 HashiSH.py -c hashish.conf sync user -n test123 -s databases -g testgroup --append_secret '{"secret1":{"data":{"k1":"v1"}}}'

#replace existing secret by another:
python3 HashiSH.py -c hashish.conf sync user -n test123 -s databases -g testgroup --replace --append_secret '{"secret2":{"data":{"k2":"v2"}}}'

#append secret, if not alredy exists:
python3 HashiSH.py -c hashish.conf sync user -n test123 -s databases -g testgroup --append_secret '{"secret2":{"data":{"k2":"v2"}}}'

#append multiple secrets:
python3 HashiSH.py -c hashish.conf sync user -n test123 -s databases -g testgroup --append_secret '[{"secret6":{"data":{"k6":"v6"}}},{"secret5":{"data":{"k5":"v5"}}}]'

#set user WITH ONLY described secrets (remove all others)
python3 HashiSH.py -c hashish.conf sync user -n test123 -s databases -g testgroup --append_secret '{"secret_only":{"data":{"k":"v"}}}' --strict

#set user WITH ONLY creds and hashes (remove all others)
python3 HashiSH.py -c hashish.conf sync user -n test123 -s databases -g testgroup --gen_creds --generate_hashes  --strict

```

### TODO:
0) Describe client logic. It is not obvious =(
1) Rewrite HashiParse. I have absolutely no idea how to write UI's on python, so I'v tried my best.
2) Cover EVERYHING by automated tests
3) PEP PEP PEP PEP BOP BEEP BOOP (First of all check it by strict linter, then comment methods and shitty parts)
4) Сheck token {c/d} --policies for multiple policies as args
5) Check (re)gen_creds (in case with --hashes). Seems like something shitty can be found there.
6) Implement loading from yaml
7) Build as a pip package
8) May be implement approles? =)
9) Complete more tasks TO DO.


