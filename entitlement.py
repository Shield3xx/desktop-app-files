"""Verify server-signed Shield3xxAV entitlement tokens offline."""
import time
import jwt

PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApGAeLuGC2Rl8LRxiD5TF\nJ2R1AoaCXJjcSnOkN/BKnj03+RjsQmNVVso4IlUD/YVT+8AkABvVodN/ny0WPitu\n45q1QE4NPV0D3RL1Jm3vOGQ6Jvs4AsJw/WUCs8ZOcyRrQGkg943+MYKNRXPLOYO4\n/Q3enLoeAU5avPt+291SHSoSyn2zfu+ZtQ7UCa5DUP95uNEKRn8mFWPyUzIY8SbT\nRkl/6Cz2QaAG7hdGGPCbp+HmVA1TEzxBlUKo7XsGXwwFwC7AA0cfsv85D7K2UtQm\nwKLOHutvrjgwItj3RnOYs2CU6QTJIGjtWc10+oQE8zFtccQG3rzCFE+9Ijc3S38o\nywIDAQAB\n-----END PUBLIC KEY-----\n'
ISSUER = "shield3xx.onrender.com"

def verify_entitlement(token: str, email: str | None = None) -> dict:
    if not token or not isinstance(token, str):
        raise ValueError("No saved entitlement")
    claims = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"], issuer=ISSUER, options={"require": ["exp", "iat", "sub", "plan", "offline_until"]})
    now = int(time.time())
    if now >= int(claims["offline_until"]):
        raise ValueError("Offline entitlement has expired; connect to the internet to revalidate")
    if email and claims["sub"].strip().lower() != email.strip().lower():
        raise ValueError("Entitlement belongs to a different account")
    plan_expiry = claims.get("plan_expires_at")
    if claims.get("plan") == "paid" and plan_expiry and now >= int(plan_expiry):
        raise ValueError("Premium subscription has expired")
    return claims
